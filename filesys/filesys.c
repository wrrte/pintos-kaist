#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/disk.h"

#include "threads/thread.h"
#include "filesys/fat.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format (void);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) {
	filesys_disk = disk_get (0, 1);
	if (filesys_disk == NULL)
		PANIC ("hd0:1 (hdb) not present, file system initialization failed");

	inode_init ();

#ifdef EFILESYS
	fat_init ();

	if (format)
		do_format ();

	fat_open ();

	thread_current()->current_working_directory = dir_open_root();
#else
	/* Original FS */
	free_map_init ();

	if (format)
		do_format ();

	free_map_open ();
#endif
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void
filesys_done (void) {
	/* Original FS */
#ifdef EFILESYS
	fat_close ();
#else
	free_map_close ();
#endif
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) {
#ifndef EFILESYS
	disk_sector_t inode_sector = 0;
	struct dir *dir = dir_open_root ();
	bool success = (dir != NULL
			&& free_map_allocate (1, &inode_sector)
			&& inode_create (inode_sector, initial_size)
			&& dir_add (dir, name, inode_sector));
	if (!success && inode_sector != 0)
		free_map_release (inode_sector, 1);
	dir_close (dir);

	return success;
#else
    cluster_t cluster = fat_create_chain(0);
    disk_sector_t sector = cluster_to_sector(cluster);

    char file_name[128];
    file_name[0] = '\0';

    struct dir *dir = parse_linkpath(name, file_name);

    if (strcmp(file_name, "") == 0)
        return false;

    if (dir == NULL || dir_get_inode(dir)->removed)
        return false;

    ///struct dir *dir = dir_reopen(dir_path);

    bool success = (dir != NULL && inode_create(sector, initial_size, INODE_FILE) && dir_add(dir, file_name, sector));

    if (!success && sector != 0)
        fat_remove_chain(cluster, 1);

    dir_close(dir);

    return success;
#endif
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name) {
#ifndef EFIELSYS
	struct dir *dir = dir_open_root ();
	struct inode *inode = NULL;

	if (dir != NULL)
		dir_lookup (dir, name, &inode);
	dir_close (dir);

	return file_open (inode);
#else
    if (strlen(name) == 0)
        return NULL;

    if (strlen(name) == 1 && name[0] == '/')
        return file_open(dir_get_inode(dir_open_root()));

    char file_name[128];
    file_name[0] = '\0';

    struct inode *inode = NULL;
    struct dir *dir = parse_linkpath(name, file_name);

    if (dir == NULL || dir_get_inode(dir)->removed)
        return NULL;

    ///struct dir *dir = dir_reopen(dir_path);

    if (!dir_lookup(dir, file_name, &inode))
        return NULL;

    if (inode->removed)
        return NULL;

    while (inode->data.type == INODE_LINK) {
        char file_name[128];
        file_name[0] = '\0';

        struct dir *link_dir = parse_linkpath(inode->data.path, file_name);

        if (!dir_lookup(link_dir, file_name, &inode))
            return NULL;

        if (inode->removed)
            return NULL;
    }

    return file_open(inode);
#endif
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) {
#ifndef EFILESYS
	struct dir *dir = dir_open_root ();
	bool success = dir != NULL && dir_remove (dir, name);
	dir_close (dir);

	return success;
#else
    if (strlen(name) == 1 && name[0] == '/')
        return false;

    char file_name[128];
    file_name[0] = '\0';

    struct dir *dir_path = parse_linkpath(name, file_name);

    if (dir_path == NULL){
        dir_close(dir_path);
        return false;
    }

    struct inode *inode = NULL;

    dir_lookup(dir_path, file_name, &inode);

    while (inode_get_type(inode) == INODE_LINK) {
        char file_name[128];
        file_name[0] = '\0';

        struct dir *target_dir = parse_linkpath(inode_get_linkpath(inode), file_name);

        if (!dir_lookup(target_dir, file_name, &inode))
            return NULL;

        if (inode_is_removed(inode))
            return NULL;
    }

    if (inode_get_type(inode) == INODE_DIR) {
        struct dir *dir = dir_open(inode);

        if (!dir_is_empty(dir) || inode_is_removed(inode))
            return false;

        dir_finddir(dir, dir_path, file_name);
        dir_close(dir);

        return dir_remove(dir_path, file_name);
    }

    struct dir *file = dir_reopen(dir_path);

    bool success = file != NULL && dir_remove(file, file_name);

    if (dir_lookup(dir_path, file_name, &inode))
        return false;

    file_close(file);

    dir_close(dir_path);
    return success;
#endif
}

/* Formats the file system. */
static void
do_format (void) {
	printf ("Formatting file system...");

#ifdef EFILESYS
	/* Create FAT and save it to the disk. */
	fat_create ();

    disk_sector_t root = cluster_to_sector(ROOT_DIR_CLUSTER);
    if (!dir_create(root, 16))
        PANIC("root create failed");

    struct dir *root_dir = dir_open_root();
    dir_add(root_dir, ".", root);
    dir_add(root_dir, "..", root);
    dir_close(root_dir);

	fat_close ();
#else
	free_map_create ();
	if (!dir_create (ROOT_DIR_SECTOR, 16))
		PANIC ("root directory creation failed");
	free_map_close ();
#endif

	printf ("done.\n");
}

struct dir *parse_linkpath(char *path_name, char *file_name){

	struct dir *dir = dir_open_root();

	char *path = malloc(strlen(path_name) + 1);
	strlcpy(path, path_name, strlen(path_name) + 1);

	if (path[0] != '/' && thread_current()->current_working_directory != NULL) {
        dir_close(dir);
        dir = dir_reopen(thread_current()->current_working_directory);
    }

	char *ptr;
	char *token = strtok_r(path, "/", &ptr);
	struct inode *inode = NULL;

	if (token == NULL)
        return dir_open_root();

	for(char *next_token = strtok_r(NULL, "/", &ptr); next_token != NULL; next_token = strtok_r(NULL, "/", &ptr)) {

        if (!dir_lookup(dir, token, &inode))
            goto ret;

        while (inode->data.type == INODE_LINK) {
            
			char link_target[128];
            link_target[0] = '\0';

            struct dir *target_dir = parse_linkpath(inode->data.linkpath, link_target);

            if (!dir_lookup(target_dir, link_target, &inode))
                goto ret;
        }

        dir_close(dir);
        dir = dir_open(inode);

        token = next_token;
    }

    if (token == NULL || strlen(token) >= 128)
        goto ret;

    strlcpy(file_name, token, strlen(token) + 1);

    free(path);
    return dir;

ret:
    free(path);
    dir_close(dir);
    return NULL;
}

bool filesys_chdir(const char *dir_name){

    struct inode *inode = NULL;

    char file_name[128];
    file_name[0] = '\0';
	
    struct dir *dir = parse_linkpath(dir_name, file_name);

    if (!dir_lookup(dir, file_name, &inode))
        return false;

    if (inode->data.type == 0 || inode->removed)
        return false;

    dir = dir_open(inode);

    thread_current()->current_working_directory = dir;

    return true;
}

bool filesys_mkdir(const char *dir_name){

	cluster_t cluster = fat_create_chain(0);
    disk_sector_t sector = cluster_to_sector(cluster);
    char file_name[128];
	file_name[0] = '\0';

    if (strlen(dir_name) == 0)
        return false;

    struct dir *dir = parse_linkpath(dir_name, file_name);
    if (dir == NULL)
        return false;

	bool success = (dir != NULL && inode_create(sector, 0, INODE_DIR) && dir_add(dir, file_name, sector));

    if(!success && cluster != 0)
        fat_remove_chain(cluster, 0);

    if(success){
        struct inode *inode = NULL;
        dir_lookup(dir, file_name, &inode);
        struct dir *dir2 = dir_open(inode);

        if (!dir_add(dir2, ".", sector))
            success = false;
        if (!dir_add(dir2, "..", inode_get_inumber(dir_get_inode(dir))))
            success = false;

        dir_close(dir2);
    }

    dir_close(dir);

    return success;
}

bool filesys_symlink(const char *target, const char *linkpath){

	cluster_t cluster = fat_create_chain(0);
    disk_sector_t sector = cluster_to_sector(cluster);

	struct inode *target_inode = NULL;
    struct inode *inode = NULL;
	char file_name[128];
    file_name[0] = '\0';

	struct dir *dir = parse_linkpath(linkpath, file_name);

    if (strcmp(file_name, "") == 0)
        return false;

    if (dir == NULL || dir_get_inode(dir)->removed)
        return false;

    bool success = (dir != NULL && inode_create(sector, 0, INODE_LINK) && dir_add(dir, file_name, sector));

	if (!success && sector != 0) {
        fat_remove_chain(cluster, 1);
        return success;
    }

    dir_lookup(dir, file_name, &inode);

	strlcpy(inode->data.linkpath, target, 128);

    return success;
}