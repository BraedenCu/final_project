// malloc.c
#include "malloc.h"
#include "lib.h"      // for memset, memcpy if needed
#include "process.h"  // for sbrk(), etc.

// We avoid <stddef.h>, so define size_t & NULL manually.
typedef unsigned long size_t;
#ifndef NULL
#define NULL ((void*) 0)
#endif

// If needed, define intptr_t for sbrk() calls:
typedef long intptr_t;

/**********************************************************************
 * 
 *  Custom Definitions
 * 
 **********************************************************************/

#define ALIGNMENT 8

// Align 'sz' to the nearest multiple of ALIGNMENT
#define ALIGN(sz) (((sz) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

// block_header: at the start of every allocated/free block
// size includes the entire block (header + payload).
typedef struct block_header {
    size_t size;      // total size of this block
    int is_free;      // 1 if free, 0 if allocated
} block_header;

// free_block: used as the free-list node, overlays payload of free blocks
typedef struct free_block {
    struct free_block* next;
    struct free_block* prev;
} free_block;

// block_header + free_block must both fit in a free block
#define MIN_BLOCK_SIZE (sizeof(block_header) + sizeof(free_block))

// Global free list head
static free_block* free_list_head = NULL;

// Track if our allocator is initialized
static int heap_initialized = 0;

// We track the heap start address for heap_info() scanning
static uintptr_t heap_start_addr = 0;

/**********************************************************************
 * 
 *  Custom Helpers
 * 
 **********************************************************************/

// Initialize the heap once
static void init_heap() 
{
    if (heap_initialized) {
        return;
    }
    heap_initialized = 1;

    // Mark the initial heap "start" so we can iterate for heap_info().
    heap_start_addr = (uintptr_t) sbrk(0);

    free_list_head = NULL;
}

// Extend the heap by `request` bytes via sbrk().
// Returns pointer to the new block's header or NULL on failure.
static block_header* extend_heap(size_t request) 
{
    // Align request
    request = ALIGN(request);
    if (request < MIN_BLOCK_SIZE) {
        request = MIN_BLOCK_SIZE;
    }

    void* p = sbrk((intptr_t) request);
    if (p == (void*) -1) 
    {
        return NULL;  // sbrk failed
    }

    block_header* new_bh = (block_header*) p;
    new_bh->size = request;
    new_bh->is_free = 1;
    return new_bh;
}

// Insert a free block at the head of the free list
static void insert_free_block(block_header* bh) {
    free_block* fb = (free_block*)((char*)bh + sizeof(block_header));
    fb->next = free_list_head;
    fb->prev = NULL;
    if (free_list_head) {
        free_list_head->prev = fb;
    }
    free_list_head = fb;
}

// Remove a free block from the free list
static void remove_free_block(free_block* fb) {
    if (fb->prev) {
        fb->prev->next = fb->next;
    } else {
        free_list_head = fb->next;
    }
    if (fb->next) {
        fb->next->prev = fb->prev;
    }
}

// First-fit: find the first free block that fits `aligned_size`
static block_header* find_free_block(size_t aligned_size) {
    free_block* fb = free_list_head;
    while (fb != NULL) {
        block_header* bh = (block_header*)((char*)fb - sizeof(block_header));
        if (bh->size >= aligned_size) {
            return bh; // first fit
        }
        fb = fb->next;
    }
    return NULL;
}

// Split a free block if it has space significantly larger than `needed`
static void split_block(block_header* bh, size_t needed) {
    size_t block_size = bh->size;

    if (block_size < needed + MIN_BLOCK_SIZE) {
        // Not enough space to split; allocate entire block
        bh->is_free = 0;
        free_block* fb = (free_block*)((char*)bh + sizeof(block_header));
        remove_free_block(fb);
        return;
    }

    // Split
    bh->size = needed;
    bh->is_free = 0;
    free_block* fb_current = (free_block*)((char*)bh + sizeof(block_header));
    remove_free_block(fb_current);

    // Create leftover block
    block_header* leftover_bh = (block_header*)((char*)bh + needed);
    leftover_bh->size = block_size - needed;
    leftover_bh->is_free = 1;
    insert_free_block(leftover_bh);
}

// Coalesce two adjacent free blocks [bh1, bh2] if bh2 starts right after bh1
static int coalesce_if_adjacent(block_header* bh1, block_header* bh2) {
    // Check adjacency
    uintptr_t bh1_end = (uintptr_t)bh1 + bh1->size;
    if (bh1_end == (uintptr_t)bh2) {
        // Merge bh2 into bh1
        free_block* fb2 = (free_block*)((char*)bh2 + sizeof(block_header));
        remove_free_block(fb2);

        bh1->size += bh2->size;   // combined
        return 1;  // coalesced
    }
    return 0; // not coalesced
}

// Swap two long integers
static void swap_long(long* a, long* b) {
    long tmp = *a;
    *a = *b;
    *b = tmp;
}

// Swap two pointers
static void swap_ptr(void** a, void** b) {
    void* tmp = *a;
    *a = *b;
    *b = tmp;
}

// Partition function for QuickSort in descending order
// We pick the last element as pivot, reorder the array so that
// elements larger than pivot are before it, and smaller are after.
static int partition(long size_array[], void* ptr_array[], int low, int high) {
    long pivot = size_array[high];   // pivot value
    int i = low - 1;

    for (int j = low; j < high; j++) {
        // Descending order: compare '>' instead of '<'
        if (size_array[j] > pivot) {
            i++;
            swap_long(&size_array[i], &size_array[j]);
            swap_ptr(&ptr_array[i], &ptr_array[j]);
        }
    }
    // Place pivot in correct position
    swap_long(&size_array[i + 1], &size_array[high]);
    swap_ptr(&ptr_array[i + 1], &ptr_array[high]);
    return i + 1;
}

// QuickSort for descending order
static void quicksort_descending(long size_array[], void* ptr_array[], int low, int high) {
    if (low < high) {
        int pi = partition(size_array, ptr_array, low, high);
        quicksort_descending(size_array, ptr_array, low, pi - 1);
        quicksort_descending(size_array, ptr_array, pi + 1, high);
    }
}


/**********************************************************************
 * 
 *  End Custom Helpers
 * 
 **********************************************************************/

/**********************************************************************
 * 
 *  Base Function Declarations
 * 
 **********************************************************************/

// MALLOC
void* malloc(uint64_t numbytes) 
{
    if (numbytes == 0) 
    {
        // malloc(0) => return NULL or a unique pointer
        return NULL;
    }

    init_heap();

    // The total needed bytes: block_header + user payload
    size_t needed = ALIGN(numbytes + sizeof(block_header));

    // Find a suitable free block
    block_header* bh = find_free_block(needed);
    if (bh) 
    {
        split_block(bh, needed);
        return (void*)((char*)bh + sizeof(block_header));
    }

    // No suitable block found; extend the heap
    bh = extend_heap(needed);
    if (!bh) 
    {
        // Out of memory
        return NULL;
    }

    // Insert into free list and split
    insert_free_block(bh);
    split_block(bh, needed);

    // Return payload
    return (void*)((char*)bh + sizeof(block_header));
}

// FREE
void free(void* ptr) 
{
    if (!ptr) 
    {
        return; // free(NULL) does nothing
    }
    block_header* bh = (block_header*)((char*)ptr - sizeof(block_header));
    bh->is_free = 1;
    insert_free_block(bh);
    // No immediate coalescing; done in defrag().
}

// CALLOC
void* calloc(uint64_t num, uint64_t sz) 
{
    // Check for multiplication overflow
    uint64_t total = num * sz;
    // A rough overflow check:
    if (num != 0 && (total / num) != sz) 
    {
        return NULL; // overflow
    }

    void* ptr = malloc(total);
    if (ptr) 
    {
        // Zero-initialize
        memset(ptr, 0, total);
    }
    return ptr;
}

// REALLOC
void* realloc(void* ptr, uint64_t sz) 
{
    if (!ptr) 
    {
        // realloc(NULL, sz) is malloc(sz)
        return malloc(sz);
    }
    if (sz == 0) 
    {
        // realloc(ptr, 0) => free(ptr)
        free(ptr);
        return NULL;
    }

    // Get old block info
    block_header* old_bh = (block_header*)((char*)ptr - sizeof(block_header));
    size_t old_size = old_bh->size - sizeof(block_header); // payload
    if (sz <= old_size) 
    {
        // No need to move
        return ptr;
    } 
    else 
    {
        // Need bigger block
        void* new_ptr = malloc(sz);
        if (!new_ptr) 
        {
            return NULL; // failed
        }
        // Copy old data
        if (old_size > 0) 
        {
            memcpy(new_ptr, ptr, old_size);
        }
        // Free old block
        free(ptr);
        return new_ptr;
    }
}

// DEFRAG
// Coalesce adjacent free blocks in O(n^2) manner
void defrag() 
{
    // We'll do a naive approach: repeatedly scan the free list, and try coalescing
    // if two blocks are physically adjacent. Stop when no merges happen in a full pass.

    int merged = 1;
    while (merged) 
    {
        merged = 0;
        free_block* fb1 = free_list_head;
        while (fb1) 
        {
            block_header* bh1 = (block_header*)((char*)fb1 - sizeof(block_header));

            free_block* fb2 = fb1->next;
            while (fb2) 
            {
                block_header* bh2 = (block_header*)((char*)fb2 - sizeof(block_header));
                if (coalesce_if_adjacent(bh1, bh2)) 
                {
                    merged = 1;
                } 
                else if (coalesce_if_adjacent(bh2, bh1)) 
                {
                    merged = 1;
                }
                fb2 = fb2->next;
            }

            fb1 = fb1->next;
        }
    }
}

// HEAP_INFO
int heap_info(heap_info_struct* info) 
{
    if (!info) 
    {
        return -1;
    }

    // Initialize struct fields
    info->num_allocs = 0;
    info->size_array = NULL;
    info->ptr_array = NULL;
    info->free_space = 0;
    info->largest_free_chunk = 0;

    // Step 1: Count how many allocated blocks exist
    uintptr_t current = heap_start_addr;
    uintptr_t heap_end = (uintptr_t) sbrk(0);

    // We'll store allocated block info in a local array first
    // But we don't know how many allocated blocks in advance, so let's do a quick pass to count
    while (current + sizeof(block_header) <= heap_end) 
    {
        block_header* bh = (block_header*) current;
        if (bh->size == 0) 
        {
            break; // might be an invalid or leftover area
        }
        // Check block boundaries
        uintptr_t next = current + bh->size;
        if (next > heap_end) 
        {
            break; // safety check
        }

        if (!bh->is_free) 
        {
            info->num_allocs++;
        }
        current = next;
    }

    if (info->num_allocs == 0) 
    {
        // No allocations
        info->size_array = NULL;
        info->ptr_array = NULL;
    } 
    else 
    {
        // Allocate arrays to hold block info
        info->size_array = (long*) malloc(info->num_allocs * sizeof(long));
        info->ptr_array = (void**) malloc(info->num_allocs * sizeof(void*));

        if (!info->size_array || !info->ptr_array) 
        {
            // Cleanup on failure
            if (info->size_array) free(info->size_array);
            if (info->ptr_array) free(info->ptr_array);
            info->size_array = NULL;
            info->ptr_array = NULL;

            return -1;
        }
    }

    // Step 2: Fill arrays + measure free space
    int alloc_index = 0;
    current = heap_start_addr;
    while (current + sizeof(block_header) <= heap_end) 
    {
        block_header* bh = (block_header*) current;
        if (bh->size == 0) 
        {
            break;
        }
        uintptr_t next = current + bh->size;
        if (next > heap_end) 
        {
            break;  // safety
        }

        if (bh->is_free) 
        {
            // Count entire block size as free
            info->free_space += bh->size;
            // Track largest_free_chunk
            if ((long)bh->size > info->largest_free_chunk) 
            {
                info->largest_free_chunk = bh->size;
            }
        } 
        else 
        {
            // Allocated block
            info->size_array[alloc_index] = (long) bh->size;
            info->ptr_array[alloc_index] = (void*)((char*)bh + sizeof(block_header));
            alloc_index++;
        }
        current = next;
    }

    // step 3: sort allocated blocks with quicksort
    quicksort_descending(info->size_array, info->ptr_array, 0, alloc_index - 1);

    return 0;
}

/**********************************************************************
 * 
 *  End Base Declarations
 * 
 **********************************************************************/
