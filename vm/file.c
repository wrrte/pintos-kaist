/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"

#include "userprog/syscall.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/mmu.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;

	struct page_aux *page_aux = (struct page_aux *)page->uninit.aux;
	
    file_page->file = page_aux->file;
    file_page->offset = page_aux->offset;
    file_page->page_read_bytes = page_aux->page_read_bytes;

    return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;

	return lazy_load_segment(page, file_page);
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;

	struct thread *curr = thread_current();

	if(pml4_is_dirty(curr->pml4, page->va)){
		file_write_at(file_page->file, page->va, file_page->page_read_bytes, file_page->offset);
		pml4_set_dirty(curr->pml4, page->va, false);
	}

	page->frame->page = NULL;
	page->frame = NULL;
	pml4_clear_page(curr->pml4, page->va);

	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;

	struct thread *curr = thread_current();

	if(pml4_is_dirty(curr->pml4, page->va)){
        file_write_at(file_page->file, page->va, file_page->page_read_bytes, file_page->offset);
        pml4_set_dirty(curr->pml4, page->va, false);
    }

    if(page->frame){
        list_remove(&page->frame->frame_elem);
        page->frame->page = NULL;
        page->frame = NULL;
        free(page->frame);
    }

    pml4_clear_page(curr->pml4, page->va);
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {

	lock_acquire(&file_lock);

	struct file *newfile = file_reopen(file);

	size_t read_bytes = (length > file_length(newfile)) ? file_length(newfile) : length;
    size_t zero_bytes = PGSIZE - read_bytes % PGSIZE;
	size_t page_read_bytes, page_zero_bytes;
	struct page_aux *page_aux;

	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (addr) == 0);
	ASSERT (offset % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		
		page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		page_zero_bytes = PGSIZE - page_read_bytes;
		
		page_aux = (struct page_aux *)malloc(sizeof(struct page_aux));
		page_aux->file = newfile;
		page_aux->offset = offset;
		page_aux->page_read_bytes = page_read_bytes;

		if (!vm_alloc_page_with_initializer (VM_FILE, addr, writable, lazy_load_segment, page_aux))
			goto ret;

		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		addr += PGSIZE;
		offset += page_read_bytes;
	}

	lock_release(&file_lock);

	return addr;

ret:
	free(page_aux);
	lock_release(&file_lock);
	return NULL;
}

/* Do the munmap */
void
do_munmap (void *addr) {

	struct page *page;
	struct thread *curr = thread_current();

	lock_acquire(&file_lock);

	while(page = spt_find_page(&curr->spt, addr)){
		if(page) destroy(page);
		addr += PGSIZE;
	}

	lock_release(&file_lock);
}
