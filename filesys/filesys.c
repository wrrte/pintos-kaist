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

struct dir *get_dir(char *path_name, char *target){

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
	char target[128];

	if (token == NULL)
        return dir_open_root();

	while (char *next_token = strtok_r(NULL, "/", &ptr); next_token != NULL; next_token = strtok_r(NULL, "/", &ptr)) {

        if (!dir_lookup(dir, token, &inode))
            goto ret;

        while (inode_get_type(inode) == INODE_LINK) {
            
            target[0] = '\0';

            struct dir *target_dir = parse_path(inode_get_linkpath(inode), target);

            if (!dir_lookup(target_dir, target, &inode))
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

    char target[128];
    target[0] = '\0';
	
    struct dir *dir = get_dir(dir_name, target);

    if (!dir_lookup(dir, target, &inode))
        return false;

    if (inode_get_type(inode) == 0 || inode_is_removed(inode))
        return false;

    dir = dir_open(inode);

    thread_current()->current_working_directory = dir;

    return true;
}

bool filesys_mkdir(const char *dir){

}

bool filesys_symlink(const char *target, const char *linkpath){

}