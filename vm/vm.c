/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

#include "threads/vaddr.h"
#include "threads/mmu.h"

static struct list frame_table;

static struct list_elem *clock_ptr;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();///추가해야할지도
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init(&frame_table);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		struct page *page = (struct page *)malloc(sizeof(struct page));

		typedef bool (*init_func)(struct page *, enum vm_type, void *);

		init_func initializer = NULL;

		switch (VM_TYPE(type)){
			case VM_ANON:
                initializer = anon_initializer;
                break;
            case VM_FILE:
                initializer = file_backed_initializer;
                break;
			default:
				ASSERT(VM_TYPE(type)<0);
		}

		uninit_new(page, upage, init, type, aux, initializer);

		page->write_bit = writable;

		/* TODO: Insert the page into the spt. */
		return spt_insert_page(spt, page);
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {

	struct page *page = (struct page *)malloc(sizeof(struct page));

	page->va = pg_round_down(va);

	struct hash_elem *he = hash_find(&spt->spt_hash, &page->hash_elem);

	free(page);

	return he ? hash_entry(he, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */

	if(!hash_insert(&spt->spt_hash, &page->hash_elem))
		succ = true;

	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	struct thread *curr = thread_current();

    // Clock 방식으로 결정
    if(clock_ptr == NULL || clock_ptr == list_end(&frame_table)) {
        clock_ptr = list_begin(&frame_table);
    }

    while (true) {
        victim = list_entry(clock_ptr, struct frame, frame_elem);
        if(!pml4_is_accessed(curr->pml4, victim->page->va)) {
            clock_ptr = list_next(clock_ptr);
            return victim;
        }
        pml4_set_accessed(curr->pml4, victim->page->va, false);
        clock_ptr = list_next(clock_ptr);
        if(clock_ptr == list_end(&frame_table)) {
            clock_ptr = list_begin(&frame_table);
        }
    }

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	if(victim->page)
		swap_out(victim->page);

	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {

	struct frame *frame = (struct frame *)malloc(sizeof(struct frame));

	ASSERT (frame != NULL);

	frame->kva = palloc_get_page(PAL_USER | PAL_ZERO);

	if(frame->kva == NULL)
        frame = vm_evict_frame(); //PANIC ("todo");
    else
        list_push_back(&frame_table, &frame->frame_elem);

	frame->page = NULL;

	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	if(vm_alloc_page(VM_ANON | VM_MARKER_0, addr, true)){
        if(vm_claim_page(addr)){
            thread_current()->stack_bottom -= PGSIZE;
        }
    }
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
	
	if(!page->rw){
		return false;
	}

	void* old_kva = page->frame->kva;

	page->frame->kva = palloc_get_page(PAL_USER | PAL_ZERO);

	if(!page->frame->kva){
		page->frame = vm_evict_frame();
	}

	memcpy(page->frame->kva, old_kva, PGSIZE);

	if (!pml4_set_page(thread_current()->pml4, page->va, page->frame->kva, page->rw)){
        return false;
	}

	return true;
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = spt_find_page(spt, addr);
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	if(addr == NULL || is_kernel_vaddr(addr))
        return false;

	if(write && !not_present){
		return vm_handle_wp(page);
	}

	if(!page) {

        void *stack_pointer = user ? f->rsp : thread_current()->stack_pointer;

        if(stack_pointer - 8 <= addr && STACK_LIMIT <= addr && addr <= USER_STACK) {

            vm_stack_growth(thread_current()->stack_bottom - PGSIZE);
			
            return true;
        }

        return false;
    }

	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {

	struct page *page = spt_find_page(&thread_current()->spt, va);

	if(page == NULL) return false;

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */

	if(!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->write_bit))
        return false;

	return swap_in (page, frame->kva);
}

static bool vm_copy_anon_page(struct supplemental_page_table *dst, void *kva, void *va, bool writable){

	struct page *page = spt_find_page(dst, va);

	struct frame *frame = (struct frame *)malloc(sizeof(struct frame));

	if(!(page && frame)){
		return false;
	}

	page->frame = frame;
	page->rw = writable;
	frame->page = page;
	frame->kva = kva;

	if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, false)) {
        free(frame);
        return false;
    }

	list_push_back(&frame_table, &frame->frame_elem);
	
	return swap_in(page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->spt_hash, spt_hash_hash, spt_hash_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	
	struct hash_iterator i;
	struct page *dst_page;
	struct page *src_page;

	hash_first (&i, &src->spt_hash);

	while (hash_next (&i))	{
		src_page = hash_entry (hash_cur (&i), struct page, hash_elem);
		
		switch (src_page->operations->type){

			case VM_UNINIT:
				ASSERT(dst == &thread_current()->spt);
				if(!vm_alloc_page_with_initializer(src_page->operations->type, src_page->va, src_page->write_bit, src_page->uninit.init, src_page->uninit.aux))
                    return false;
				///dst_page = spt_find_page(dst, src_page->va); 같은거 안 필요한가?
				break;

			case VM_ANON:
				if(!vm_alloc_page(src_page->operations->type, src_page->va, src_page->write_bit))
					return false;
				
				if (!vm_copy_anon_page(dst, src_page->frame->kva, src_page->va, src_page->write_bit))
                    return false;
					
				break;

			case VM_FILE:
				if(!vm_alloc_page_with_initializer(src_page->operations->type, src_page->va, src_page->write_bit, NULL, &src_page->file))
                    return false;

                dst_page = spt_find_page(dst, src_page->va);
                if(!file_backed_initializer(dst_page, src_page->operations->type, NULL))
                    return false;

                dst_page->frame = src_page->frame;
                if(!pml4_set_page(thread_current()->pml4, dst_page->va, src_page->frame->kva, src_page->write_bit))
                    return false;

				break;

			default:
				return false;
		}
	}

	return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&spt->spt_hash, hash_kill);
}
