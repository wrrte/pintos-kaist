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
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name) {
	struct dir *dir = dir_open_root ();
	struct inode *inode = NULL;

	if (dir != NULL)
		dir_lookup (dir, name, &inode);
	dir_close (dir);

	return file_open (inode);
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) {
	struct dir *dir = dir_open_root ();
	bool success = dir != NULL && dir_remove (dir, name);
	dir_close (dir);

	return success;
}

/* Formats the file system. */
static void
do_format (void) {
	printf ("Formatting file system...");

#ifdef EFILESYS
	/* Create FAT and save it to the disk. */
	fat_create ();
	fat_close ();
#else
	free_map_create ();
	if (!dir_create (ROOT_DIR_SECTOR, 16))
		PANIC ("root directory creation failed");
	free_map_close ();
#endif

	printf ("done.\n");
}

struct dir *parse_linkpath(char *path_name, char *target){

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

    strlcpy(target, token, strlen(token) + 1);

    free(path);
    return dir;

ret:
    free(path);
    dir_close(dir);
    return NULL;
}

bool filesys_chdir(const char *dir){

    struct inode *inode = NULL;

    char link_name[128];
    link_name[0] = '\0';
	
    struct dir *dir_path = parse_linkpath(dir, link_name);

    if (!dir_lookup(dir_path, link_name, &inode))
        return false;

    if (inode->data.type == 0 || inode->removed)
        return false;

    dir_path = dir_open(inode);

    thread_current()->current_working_directory = dir_path;

    return true;
}

bool filesys_mkdir(const char *dir){

	cluster_t cluster = fat_create_chain(0);
    disk_sector_t sector = cluster_to_sector(cluster);
    char link_name[128];
	link_name[0] = '\0';

    if (strlen(dir) == 0)
        return false;

    struct dir *dir_path = parse_linkpath(dir, link_name);
    if (dir_path == NULL)
        return false;

	bool success = (dir != NULL && inode_create(sector, 0) && dir_add(dir, link_name, sector));

    if(!success && cluster != 0)
        fat_remove_chain(cluster, 0);

    if(success){
        struct inode *inode = NULL;
        dir_lookup(dir, link_name, &inode);
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
	char link_name[128];
    link_name[0] = '\0';

	struct dir *link_dir = parse_linkpath(linkpath, link_name);

    if (strcmp(link_name, "") == 0)
        return false;

    if (link_dir == NULL || dir_get_inode(link_dir)->removed)
        return false;

    bool success = (link_dir != NULL && inode_create(sector, 0) && dir_add(link_dir, link_name, sector));

	if (!success && sector != 0) {
        fat_remove_chain(cluster, 1);
        return success;
    }

    dir_lookup(link_dir, link_name, &inode);

	strlcpy(inode->data.linkpath, target, 128);

    return success;
}