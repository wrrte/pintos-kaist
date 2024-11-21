#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "include/threads/synch.h"
#include "threads/palloc.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

struct lock file_lock;

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&file_lock);

}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.

#ifdef VM
    thread_current()->stack_pointer = f->rsp;
#endif

	switch (f->R.rax) {
        case SYS_HALT:
            halt();
            break;
        case SYS_EXIT:
            exit(f->R.rdi);
            break;
        case SYS_FORK:
            f->R.rax = fork(f->R.rdi);
            break;
        case SYS_EXEC:
            f->R.rax = exec(f->R.rdi);
            break;
        case SYS_WAIT:
            f->R.rax = process_wait(f->R.rdi);
            break;
        case SYS_CREATE:
            f->R.rax = create(f->R.rdi, f->R.rsi);
            break;
        case SYS_REMOVE:
            f->R.rax = remove(f->R.rdi);
            break;
        case SYS_OPEN:
            f->R.rax = open(f->R.rdi);
            break;
        case SYS_FILESIZE:
            f->R.rax = filesize(f->R.rdi);
            break;
        case SYS_READ:
            f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_WRITE:
            f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_SEEK:
            seek(f->R.rdi, f->R.rsi);
            break;
        case SYS_TELL:
            f->R.rax = tell(f->R.rdi);
            break;
        case SYS_CLOSE:
            close(f->R.rdi);
            break;
        case SYS_DUP2:
            f->R.rax = dup2(f->R.rdi, f->R.rsi);
            break;
#ifdef VM
        case SYS_MMAP:
            f->R.rax = mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
            break;
        case SYS_MUNMAP:
            munmap(f->R.rdi);
            break;
#endif
		default:
			exit(-1);
	}
}

#ifndef VM
void check_addr(void *addr) {
    struct thread *curr = thread_current();

    if (is_kernel_vaddr(addr) || addr == NULL || pml4_get_page(curr->pml4, addr) == NULL)
        exit(-1);
}
#else
static struct page *check_addr(void *addr) {

    if (is_kernel_vaddr(addr) || addr == NULL)
        exit(-1);

    return spt_find_page(&thread_current()->spt, addr);
}

void check_buffer_valid(void *buffer, unsigned size, bool write_bit){

    for(size_t i = 0; i < size; i++){
        
        struct page *page = check_addr(buffer + i);

        if(!(page && (!write_bit || (page->write_bit))))
            exit(-1);
    }
}
#endif

void halt(){
	power_off();
}

void exit (int status){

	struct thread *curr = thread_current();

    //ASSERT(status != 1);

	printf ("%s: exit(%d)\n", &curr->name, status);
	
	curr->exit_code = status;

	thread_exit();

}

pid_t fork (const char *thread_name){
	
	check_addr(thread_name);

	struct thread *curr = thread_current();

    struct intr_frame *reg = (pg_round_up(rrsp()) - sizeof(struct intr_frame));
    
	memcpy(&curr->parent_if, reg, sizeof(struct intr_frame));

    return process_fork(thread_name, NULL);

}

int exec (const char *cmd_line){
	
	check_addr(cmd_line);

	char *cmd_kernel = palloc_get_page(PAL_ZERO);

	if(cmd_kernel == NULL) return -1;

	memcpy(cmd_kernel, cmd_line, strlen(cmd_line)+1) ;

	return process_exec(cmd_kernel);

}

int wait (pid_t pid){
	return process_wait(pid);
}

bool create (const char *file, unsigned initial_size){

	check_addr(file);

	lock_acquire(&file_lock);

	bool ret = filesys_create(file, initial_size);

	lock_release(&file_lock);

	return ret;

}

bool remove (const char *file){
	
	check_addr(file);

	lock_acquire(&file_lock);

	bool ret = filesys_remove(file);

	lock_release(&file_lock);

	return ret;

}

int open(const char *file) {

    check_addr(file);

    lock_acquire(&file_lock);

    struct file *fp = filesys_open(file);

    if (fp == NULL)
        goto dest2;

    struct thread *curr = thread_current();
    struct file **fdt = curr->file_descripter_table;

    if (curr->file_descripter_index >= FDI_MAX)
        goto dest1;

    while (fdt[curr->file_descripter_index] != NULL)
        curr->file_descripter_index++;

    fdt[curr->file_descripter_index++] = fp;

    lock_release(&file_lock);

    return curr->file_descripter_index - 1;

dest1:
    file_close(fp);
dest2:
    lock_release(&file_lock);
    return -1;
}

int filesize (int fd){
	
	struct file *file = get_file(fd);

	if(file == NULL) return -1;

	return file_length(file);

}

int read (int fd, void *buffer, unsigned size){
#ifdef VM
    check_buffer_valid(buffer, size, true);
#endif

	check_addr(buffer);

    struct thread *curr = thread_current();
    struct file *file = get_file(fd);

    if (file == NULL || file == STDOUT || file == STDERR)
        return -1;

    if (file == STDIN) {

		int len;

        for (unsigned char *buffer = buffer; len < size; len++) 
            if((*buffer++ = input_getc()) == '\0')
				break;

        return len;

    }

	lock_acquire(&file_lock);

    int len = file_read(file, buffer, size);

    lock_release(&file_lock);

    return len;

}

int write (int fd, const void *buffer, unsigned size){
#ifdef VM
    check_buffer_valid(buffer, size, false);
#endif
	
	check_addr(buffer);

    struct thread *curr = thread_current();
    struct file *file = get_file(fd);

    if (file == NULL || file == STDIN)
		return -1;

    if (file == STDOUT || file == STDERR) {
		putbuf(buffer, size);
		return size;
    }

	lock_acquire(&file_lock);

    int len = file_write(file, buffer, size);

    lock_release(&file_lock);

    return len;

}

void seek (int fd, unsigned position){

	struct file *file = get_file(fd);

    if (file == NULL || file == STDIN || file == STDOUT || file == STDERR)
        return;

    file_seek(file, position);

}

unsigned tell (int fd){

	struct file *file = get_file(fd);

    if (file == NULL || file == STDIN || file == STDOUT || file == STDERR)
        return;

    file_tell(file);

}

void close (int fd){

	struct thread *curr = thread_current();
    struct file *file = get_file(fd);

    if (file == NULL) return;

	if (0 <= fd < FDI_MAX)
        curr->file_descripter_table[fd] = NULL;

    if (file == STDIN || file == STDOUT || file == STDERR)
        return;

    if (file->dup2_num == 0)
        file_close(file);
    else
        file->dup2_num--;

}

int dup2(int oldfd, int newfd){

    struct file *oldfile = get_file(oldfd);
    struct file *newfile = get_file(newfd);
    struct file **fdt = thread_current()->file_descripter_table;

    if (oldfile == NULL) return -1;

    if (oldfd == newfd || oldfile == newfile) return newfd;

    close(newfd);

    if (newfd < 0 || newfd >= FDI_MAX)
        return -1;

    if (oldfile > STDERR)
        oldfile->dup2_num++;

    fdt[newfd] = oldfile;

    return newfd;

}

#ifdef VM
void *mmap (void *addr, size_t length, int write_bit, int fd, off_t offset){

    if(!addr || is_kernel_vaddr(addr) || is_kernel_vaddr(addr + length))
        return NULL;

    if((uint64_t)addr % PGSIZE != 0 || offset % PGSIZE != 0)
        return NULL;

    if(spt_find_page(&thread_current()->spt, addr))
        return NULL;

    struct file *file = get_file(fd);

    if(file == STDIN || file == STDOUT || file == STDERR || file == NULL)
        return NULL;

    if(file_length(file) == 0 || (long)length <= 0)
        return NULL;

    return do_mmap(addr, length, write_bit, file, offset);
}

void munmap (void *addr){
    do_munmap(addr);
}
#endif