/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"

#include <bitmap.h>

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

static struct bitmap *swap_table;

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1, 1);
	swap_table = bitmap_create(disk_size(swap_disk) / SLOT_SIZE);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */

    memset(&page->uninit, 0, sizeof(struct uninit_page));

	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;

	anon_page->slot_index = BITMAP_ERROR;

	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;

	size_t si = anon_page->slot_index;
    size_t sector_ind = si * SLOT_SIZE;

    if(si == BITMAP_ERROR || !bitmap_test(swap_table, si))
        return false;

    bitmap_set(swap_table, si, false);

    for(size_t i = 0; i < SLOT_SIZE; i++)
        disk_read(swap_disk, sector_ind + i, kva + DISK_SECTOR_SIZE * i);

    return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;

	size_t got_ind = bitmap_scan_and_flip(swap_table, 0, 1, false);
	size_t sector_ind = got_ind * SLOT_SIZE;

	if(got_ind == BITMAP_ERROR)
        return false;

	for(size_t i = 0; i < SLOT_SIZE; i++)
        disk_write(swap_disk, sector_ind + i, page->va + DISK_SECTOR_SIZE * i);

	anon_page->slot_index = got_ind;

	page->frame->page = NULL;
    page->frame = NULL;
    pml4_clear_page(thread_current()->pml4, page->va);

    return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;

	if(anon_page->slot_index != BITMAP_ERROR)
        bitmap_reset(swap_table, anon_page->slot_index);

	if(page->frame){
        list_remove(&page->frame->frame_elem);
        page->frame->page = NULL;
        free(page->frame);
        page->frame = NULL;
    }
	
	pml4_clear_page(thread_current()->pml4, page->va);
}
