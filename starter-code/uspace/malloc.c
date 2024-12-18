#include "malloc.h"
#include "lib.h"
#include "process.h"

/**********************************************************************
 * 
 *  Custom Definitions
 * 
 **********************************************************************/

#define ALIGNMENT 16
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1)) 

#define MIN_PAYLOAD_SIZE 24

#define OVERHEAD (sizeof(vm_block_header))

// vm_block_header: start of every block (allocated/free)
// size includes header + payload
typedef struct vm_block_header {
    size_t size;
    int is_free;   // 1 if free, 0 if allocated
} vm_block_header;

// free_vm_block: stored in payload of free blocks
typedef struct free_vm_block {
    struct free_vm_block* next;
    struct free_vm_block* prev;
} free_vm_block;

static free_vm_block* free_list_head = NULL;
static int heap_initialized = 0;
static uintptr_t heap_start_addr = 0;

/**********************************************************************
 * 
 *  Custom Helpers
 * 
 **********************************************************************/

static void init_heap() {
    if (heap_initialized) 
    {
        return; // do nothing
    }
    heap_initialized = 1;
    heap_start_addr = (uintptr_t) sbrk(0);
    free_list_head = NULL;
}

static vm_block_header* extend_heap(size_t request) {
    request = ALIGN(request);

    // ensure block can hold header and free_vm_block
    if (request < (OVERHEAD + MIN_PAYLOAD_SIZE))
    {
        request = OVERHEAD + MIN_PAYLOAD_SIZE;
    }

    // initialize sbrk
    void* p = sbrk((intptr_t) request);

    if (p == (void*) -1) 
    {
        return NULL; // sbrk failed
    }

    vm_block_header* new_bh = (vm_block_header*) p;
    new_bh->size = request;
    new_bh->is_free = 1;

    return new_bh;
}

static void insert_free_vm_block(vm_block_header* bh) {
    free_vm_block* fb = (free_vm_block*)((char*)bh + sizeof(vm_block_header));
    fb->next = free_list_head;
    fb->prev = NULL;

    if (free_list_head) 
    {
        free_list_head->prev = fb;
    }
    free_list_head = fb;
}

static void remove_free_vm_block(free_vm_block* fb) {
    if (fb->prev) 
    {
        fb->prev->next = fb->next;
    } 
    else 
    {
        free_list_head = fb->next;
    }
    if (fb->next) 
    {
        fb->next->prev = fb->prev;
    }
}

static vm_block_header* find_free_vm_block(size_t aligned_size) {
    free_vm_block* fb = free_list_head;
    while (fb) 
    {
        vm_block_header* bh = (vm_block_header*)((char*)fb - sizeof(vm_block_header));
        if (bh->size >= aligned_size) 
        {
            return bh;
        }
        fb = fb->next;
    }
    return NULL;
}

static void split_block(vm_block_header* bh, size_t needed) {
    size_t block_size = bh->size;

    // Check if we have enough space to split off another free block
    if (block_size < needed + (OVERHEAD + MIN_PAYLOAD_SIZE)) 
    {
        // Not enough space for splitting
        bh->is_free = 0;
        free_vm_block* fb = (free_vm_block*)((char*)bh + sizeof(vm_block_header));
        remove_free_vm_block(fb);
        return;
    }

    // Split the block
    bh->size = needed;
    bh->is_free = 0;
    free_vm_block* fb_current = (free_vm_block*)((char*)bh + sizeof(vm_block_header));
    remove_free_vm_block(fb_current);

    vm_block_header* leftover_bh = (vm_block_header*)((char*)bh + needed);
    leftover_bh->size = block_size - needed;
    leftover_bh->is_free = 1;
    insert_free_vm_block(leftover_bh);
}

static int coalesce_if_adjacent(vm_block_header* block_header_one, vm_block_header* block_header_two) {
    uintptr_t block_header_one_end = (uintptr_t)block_header_one + block_header_one->size;
    if (block_header_one_end == (uintptr_t)block_header_two) 
    {
        // Adjacent blocks, merge block_header_two into block_header_one
        free_vm_block* vm_free_block_two = (free_vm_block*)((char*)block_header_two + sizeof(vm_block_header));
        remove_free_vm_block(vm_free_block_two);

        block_header_one->size += block_header_two->size;
        return 1;
    }
    return 0;
}

// Quicksort partition function for sorting in descending order
static int partition(long size_array[], void* ptr_array[], int low, int high) {
    long pivot = size_array[high];
    int i = low - 1;

    for (int j = low; j < high; j++) 
    {
        if (size_array[j] > pivot) 
        {
            i++;
            // swap longs
            {
                long tmp = size_array[i];
                size_array[i] = size_array[j];
                size_array[j] = tmp;
            }
            // swap pointers
            {
                void* tmp = ptr_array[i];
                ptr_array[i] = ptr_array[j];
                ptr_array[j] = tmp;
            }
        }
    }

    // swap longs for pivot placement
    {
        long tmp = size_array[i + 1];
        size_array[i + 1] = size_array[high];
        size_array[high] = tmp;
    }

    // swap pointer for pivot placement
    {
        void* tmp = ptr_array[i + 1];
        ptr_array[i + 1] = ptr_array[high];
        ptr_array[high] = tmp;
    }

    return i + 1;
}

// quicksort in descending order
static void quicksort_descending(long size_array[], void* ptr_array[], int low, int high) {
    if (low < high) 
    {
        int partition_index = partition(size_array, ptr_array, low, high);
        quicksort_descending(size_array, ptr_array, low, partition_index - 1);
        quicksort_descending(size_array, ptr_array, partition_index + 1, high);
    }
}

/**********************************************************************
 * 
 *  Begin Built In
 * 
 **********************************************************************/

void* malloc(uint64_t numbytes) {
    if (!heap_initialized) 
    {
        init_heap();
    }

    if (numbytes == 0) 
    {
        return NULL;
    }

    size_t needed = ALIGN(numbytes + OVERHEAD);
    if (needed < (OVERHEAD + MIN_PAYLOAD_SIZE)) 
    {
        needed = OVERHEAD + MIN_PAYLOAD_SIZE;
    }

    vm_block_header* bh = find_free_vm_block(needed);
    if (bh) 
    {
        split_block(bh, needed);
        return (void*)((char*)bh + sizeof(vm_block_header));
    }

    bh = extend_heap(needed);
    if (!bh) 
    {
        return NULL;
    }

    insert_free_vm_block(bh);
    split_block(bh, needed);

    return (void*)((char*)bh + sizeof(vm_block_header));
}

void free(void* ptr) {
    if (!ptr) 
    {
        return;
    }
    vm_block_header* bh = (vm_block_header*)((char*)ptr - sizeof(vm_block_header));
    bh->is_free = 1;
    insert_free_vm_block(bh);
}

void* calloc(uint64_t num, uint64_t sz) {
    // Overflow check
    if (num != 0 && (num * sz) / num != sz) 
    {
        return NULL; // overflow
    }

    uint64_t total = num * sz;
    void* ptr = malloc(total);
    if (ptr) 
    {
        memset(ptr, 0, total);
    }
    return ptr;
}

void* realloc(void* ptr, uint64_t sz) 
{
    if (!ptr) 
    {
        return malloc(sz);
    }
    if (sz == 0) 
    {
        free(ptr);
        return NULL;
    }

    vm_block_header* old_bh = (vm_block_header*)((char*)ptr - sizeof(vm_block_header));
    size_t old_size = old_bh->size - sizeof(vm_block_header);
    if (sz <= old_size) 
    {
        return ptr;
    }

    void* new_ptr = malloc(sz);
    if (!new_ptr) 
    {
        return NULL;
    }

    if (old_size > 0) 
    {
        memcpy(new_ptr, ptr, old_size);
    }

    free(ptr);
    return new_ptr;
}

// defrag: do O(n²) merging
void defrag() {
    int merged = 1;
    while (merged) 
    {
        merged = 0;
        free_vm_block* vm_free_block_one = free_list_head;
        while (vm_free_block_one) 
        {
            vm_block_header* block_header_one = (vm_block_header*)((char*)vm_free_block_one - sizeof(vm_block_header));
            free_vm_block* vm_free_block_two = vm_free_block_one->next;
            while (vm_free_block_two) 
            {
                vm_block_header* block_header_two = (vm_block_header*)((char*)vm_free_block_two - sizeof(vm_block_header));
                if (coalesce_if_adjacent(block_header_one, block_header_two)) 
                {
                    merged = 1;
                } 
                else if (coalesce_if_adjacent(block_header_two, block_header_one)) 
                {
                    merged = 1;
                }
                vm_free_block_two = vm_free_block_two->next;
            }
            vm_free_block_one = vm_free_block_one->next;
        }
    }
}

int heap_info(heap_info_struct* info) {
    if (!info) 
    {
        return -1;
    }

    info->num_allocs = 0;
    info->size_array = NULL;
    info->ptr_array = NULL;
    info->free_space = 0;
    info->largest_free_chunk = 0;

    uintptr_t current = heap_start_addr;
    uintptr_t heap_end = (uintptr_t) sbrk(0);

    while (current + sizeof(vm_block_header) <= heap_end) 
    {
        vm_block_header* bh = (vm_block_header*)current;
        if (bh->size == 0) 
        {
            break;
        }
        uintptr_t next = current + bh->size;
        if (next > heap_end) 
        {
            break;
        }

        if (!bh->is_free) 
        {
            info->num_allocs++;
        }
        current = next;
    }

    if (info->num_allocs > 0) 
    {
        info->size_array = (long*)malloc(info->num_allocs * sizeof(long));
        info->ptr_array = (void**)malloc(info->num_allocs * sizeof(void*));

        if (!info->size_array || !info->ptr_array) 
        {
            if (info->size_array) 
            {
                free(info->size_array);
            }
            if (info->ptr_array) 
            {
                free(info->ptr_array);
            }
            info->size_array = NULL;
            info->ptr_array = NULL;
            return -1;
        }
    }

    int alloc_index = 0;
    current = heap_start_addr;
    uintptr_t heapend2 = (uintptr_t)sbrk(0);
    while (current + sizeof(vm_block_header) <= heapend2) 
    {
        vm_block_header* bh = (vm_block_header*)current;
        if (bh->size == 0) 
        {
            break;
        }
        uintptr_t next = current + bh->size;
        if (next > heapend2) 
        {
            break;
        }

        if (bh->is_free) 
        {
            info->free_space += bh->size;
            if ((long)bh->size > info->largest_free_chunk) 
            {
                info->largest_free_chunk = bh->size;
            }
        } 
        else 
        {
            info->size_array[alloc_index] = (long)bh->size;
            info->ptr_array[alloc_index] = (void*)((char*)bh + sizeof(vm_block_header));
            alloc_index++;
        }

        current = next;
    }

    if (info->num_allocs > 0) 
    {
        quicksort_descending(info->size_array, info->ptr_array, 0, alloc_index - 1);
    }

    return 0;
}
