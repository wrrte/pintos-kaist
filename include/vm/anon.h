#ifndef VM_ANON_H
#define VM_ANON_H
#include "vm/vm.h"

#include "threads/vaddr.h"

#define SLOT_SIZE (PGSIZE / DISK_SECTOR_SIZE)

struct page;
enum vm_type;

struct anon_page {
    size_t slot_index;
};

void vm_anon_init (void);
bool anon_initializer (struct page *page, enum vm_type type, void *kva);

#endif
