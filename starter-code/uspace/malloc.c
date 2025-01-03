#include "malloc.h"
#include "lib.h"
#include "process.h"

/**********************************************************************
 * 
 *  Custom Definitions
 * 
 **********************************************************************/

#define ALIGNMENT 8 // everything should be aligned to 16
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1)) // alignment function
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
    heap_start_addr = (uintptr_t) sbrk(0); // initialize sbrk
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

    vm_block_header* new_block_header = (vm_block_header*) p;
    new_block_header->size = request;
    new_block_header->is_free = 1;

    return new_block_header;
}

static void insert_free_vm_block(vm_block_header* block_header) {
    free_vm_block* free_block = (free_vm_block*)((char*)block_header + sizeof(vm_block_header));
    free_block->next = free_list_head;
    free_block->prev = NULL;

    if (free_list_head) 
    {
        free_list_head->prev = free_block;
    }

    // freeing insertion
    free_list_head = free_block;
}

static void remove_free_vm_block(free_vm_block* free_block) {
    if (free_block->prev) 
    {
        free_block->prev->next = free_block->next;
    } 
    else 
    {
        free_list_head = free_block->next;
    }
    if (free_block->next) 
    {
        free_block->next->prev = free_block->prev;
    }
}

static vm_block_header* find_free_vm_block(size_t aligned_size) {
    free_vm_block* free_block = free_list_head;
    while (free_block) 
    {
        vm_block_header* block_header = (vm_block_header*)((char*)free_block - sizeof(vm_block_header)); // set block header based on sizing 

        if (block_header->size >= aligned_size) 
        {
            return block_header;
        }
        free_block = free_block->next;
    }
    return NULL;
}

static void split_block(vm_block_header* block_header, size_t needed) {
    size_t block_size = block_header->size;

    // do we need to split ? check if space
    if (block_size < needed + (OVERHEAD + MIN_PAYLOAD_SIZE)) 
    {
        // not enough so thus handle
        block_header->is_free = 0;
        free_vm_block* free_block = (free_vm_block*)((char*)block_header + sizeof(vm_block_header)); // set block header based on sizing 

        remove_free_vm_block(free_block);

        return;
    }

    // Split the block
    block_header->size = needed;
    block_header->is_free = 0;
    free_vm_block* free_block_current = (free_vm_block*)((char*)block_header + sizeof(vm_block_header));
    remove_free_vm_block(free_block_current);

    // split
    vm_block_header* leftover_block_header = (vm_block_header*)((char*)block_header + needed);
    leftover_block_header->size = block_size - needed;
    leftover_block_header->is_free = 1;
    
    // final insertion
    insert_free_vm_block(leftover_block_header);
}

static int combine_blocks(vm_block_header* block_header_one, vm_block_header* block_header_two) {
    uintptr_t block_header_one_end = (uintptr_t)block_header_one + block_header_one->size;

    if (block_header_one_end == (uintptr_t)block_header_two) // checkk if can complete merging
    {
        // merge adjacent blocks
        free_vm_block* vm_free_block_two = (free_vm_block*)((char*)block_header_two + sizeof(vm_block_header));
        remove_free_vm_block(vm_free_block_two);

        block_header_one->size += block_header_two->size;

        return 1; // merge success
    }

    return 0;
}

// standard quicksort implementation
static int qs_partition(long size_array[], void* ptr_array[], int low, int high) {
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

// standard quicksort implementation
static void quick_sort(long size_array[], void* ptr_array[], int low, int high) {
    if (low < high) 
    {
        int qs_partition_index = qs_partition(size_array, ptr_array, low, high);
        quick_sort(size_array, ptr_array, low, qs_partition_index - 1);
        quick_sort(size_array, ptr_array, qs_partition_index + 1, high);
    }
}

/**********************************************************************
 * 
 *  Begin Built In
 * 
 **********************************************************************/

void* malloc(uint64_t numbytes) {
    // check if heap is initialized
    if (!heap_initialized) 
    {
        init_heap();
    }

    // error
    if (numbytes == 0) 
    {
        return NULL;
    }

    size_t needed = ALIGN(numbytes + OVERHEAD); // check how many we need for prop alignment

    if (needed < (OVERHEAD + MIN_PAYLOAD_SIZE))  // adjust needed basd on alignment miscalc
    {
        needed = OVERHEAD + MIN_PAYLOAD_SIZE;
    }

    vm_block_header* block_header = find_free_vm_block(needed); // create header

    if (block_header) 
    {
        split_block(block_header, needed); // split of needed 

        return (void*)((char*)block_header + sizeof(vm_block_header)); // return sized properly addr
    }

    block_header = extend_heap(needed); // extend heap only if needed

    // error condition check
    if (!block_header) 
    {
        return NULL;
    }

    insert_free_vm_block(block_header); // insertion
    split_block(block_header, needed); // split

    return (void*)((char*)block_header + sizeof(vm_block_header)); // return sized properly addr
}

void free(void* ptr) {
    if (!ptr) 
    {
        return;
    }
    vm_block_header* block_header = (vm_block_header*)((char*)ptr - sizeof(vm_block_header));
    block_header->is_free = 1; // validate free

    // insertion fred blocik
    insert_free_vm_block(block_header);
}

void* calloc(uint64_t num, uint64_t sz) {
    // overflow check
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
        return malloc(sz); // if doesnt exist all we need to do is malloc
    }
    if (sz == 0) 
    {
        free(ptr);
        return NULL;
    }

    vm_block_header* old_block_header = (vm_block_header*)((char*)ptr - sizeof(vm_block_header));
    size_t old_size = old_block_header->size - sizeof(vm_block_header);

    if (sz <= old_size) 
    {
        return ptr;
    }

    void* new_ptr = malloc(sz); // create new allocation
    if (!new_ptr) 
    {
        return NULL;
    }

    if (old_size > 0) 
    {
        memcpy(new_ptr, ptr, old_size); // copy over allocation
    }

    free(ptr);
    return new_ptr;
}

// defrag: do O(n^2) merging
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
                if (combine_blocks(block_header_one, block_header_two)) 
                {
                    merged = 1;
                } 
                else if (combine_blocks(block_header_two, block_header_one)) 
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
    uintptr_t heap_end = (uintptr_t)sbrk(0);

    // First pass: Count allocations and calculate free space/largest free chunk
    while (current + sizeof(vm_block_header) <= heap_end) 
    {
        vm_block_header* block_header = (vm_block_header*)current;
        if (block_header->size == 0) 
        {
            break;
        }
        uintptr_t next = current + block_header->size;
        if (next > heap_end) 
        {
            break;
        }

        if (!block_header->is_free) 
        {
            info->num_allocs++;
        } 
        else 
        {
            info->free_space += block_header->size;
            if ((long)block_header->size > info->largest_free_chunk) 
            {
                info->largest_free_chunk = block_header->size;
            }
        }
        current = next;
    }

    if (info->num_allocs == 0) 
    {
        return 0; // no alloc to report
    }

    // alloc memory for size_array and ptr_array
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

    // pop size_array and ptr_array
    int alloc_index = 0;
    current = heap_start_addr;

    while (current + sizeof(vm_block_header) <= heap_end) 
    {
        vm_block_header* block_header = (vm_block_header*)current;
        if (block_header->size == 0) 
        {
            break;
        }
        uintptr_t next = current + block_header->size;
        if (next > heap_end) {
            
            break;
        }

        if (!block_header->is_free) 
        {
            info->size_array[alloc_index] = (long)block_header->size;
            info->ptr_array[alloc_index] = (void*)((char*)block_header + sizeof(vm_block_header));
            alloc_index++;
        }

        current = next;
    }

    quick_sort(info->size_array, info->ptr_array, 0, alloc_index - 1);

    return 0;
}
