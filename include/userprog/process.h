#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "include/filesys/off_t.h"

#define STDIN  0x1
#define STDOUT 0x2
#define STDERR 0x3

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

void pass_argument(int argc, char **argv, struct intr_frame *_if);

struct thread *get_child(int pid);
struct file *get_file(int fd);

struct page_aux {
    struct file *file;
    off_t offset;
    size_t page_read_bytes;
};

bool lazy_load_segment (struct page *page, void *aux);

#endif /* userprog/process.h */
