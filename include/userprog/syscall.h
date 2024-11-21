#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <stddef.h>

#include "filesys/off_t.h"

typedef int pid_t;

void syscall_init (void);

#ifndef VM
void check_addr(void *addr);
#else
void *mmap (void *addr, size_t length, int writable, int fd, off_t offset);
void munmap (void *addr);
#endif

void halt (void);
void exit (int status);
pid_t fork (const char *thread_name);
int exec (const char *cmd_line);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

extern struct lock file_lock;

int dup2(int oldfd, int newfd);

#endif /* userprog/syscall.h */
