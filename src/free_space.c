#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>
#include "../include/free_space.h"
#include "../include/ram_bptree.h"
#include "../include/wal.h"

// NVRAM mapping and device file descriptor
void *nvram_map = NULL;
int fd = -1;
pthread_mutex_t free_space_mutex = PTHREAD_MUTEX_INITIALIZER;

// In-RAM structure for a free space block
typedef struct FreeBlock
{
    size_t size;
    size_t offset; // Offset from start of nvram_map
    struct FreeBlock *next;
} FreeBlock;

// In-NVRAM structure for persisting a free block
typedef struct PersistedFreeBlock
{
    size_t size;
    size_t offset;
} PersistedFreeBlock;

// In-RAM head of the free space list
FreeBlock *freeList = NULL;

// In-RAM pointer to the master database header in NVRAM
// DatabaseHeader *db_header = NULL; // Defined in ram_bptree.c

// Helper to get the total number of blocks in the free list
static int count_free_blocks()
{
    int count = 0;
    FreeBlock *current = freeList;
    while (current)
    {
        count++;
        current = current->next;
    }
    return count;
}

// Initialize NVRAM mapping. Must be called once at the very start.
static void init_nvram_map()
{
    if (nvram_map)
        return;

    fd = open(FILEPATH, O_RDWR);
    if (fd == -1)
    {
        perror("Error opening NVRAM file");
        exit(1);
    }

    nvram_map = mmap(NULL, FILESIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (nvram_map == MAP_FAILED)
    {
        perror("Error mapping NVRAM file");
        close(fd);
        exit(1);
    }
    db_header = (DatabaseHeader *)nvram_map;
}

// Initialize the free space system for the very first time.
void init_free_space_first_time()
{
    init_nvram_map();

    // The entire NVRAM space, minus the header, is one big free block.
    size_t initial_offset = sizeof(DatabaseHeader);
    freeList = (FreeBlock *)malloc(sizeof(FreeBlock));
    freeList->size = FILESIZE - initial_offset;
    freeList->offset = initial_offset;
    freeList->next = NULL;
}

// Serialize the in-memory free list to NVRAM for a clean shutdown.
void persist_free_list()
{
    pthread_mutex_lock(&free_space_mutex);
    if (!db_header->free_list_offset)
    {
        printf("Error: Free list storage area not allocated in NVRAM.\n");
        pthread_mutex_unlock(&free_space_mutex);
        return;
    }

    int num_blocks = count_free_blocks();
    PersistedFreeBlock *p_list_start = (PersistedFreeBlock *)((char *)nvram_map + db_header->free_list_offset);

    // First element in the persisted area is the count of blocks.
    *(size_t *)p_list_start = (size_t)num_blocks;
    PersistedFreeBlock *p_block = p_list_start + 1; // Start writing after the count

    FreeBlock *current = freeList;
    for (int i = 0; i < num_blocks; i++)
    {
        p_block->offset = current->offset;
        p_block->size = current->size;
        p_block++;
        current = current->next;
    }

    // Persist the entire free list snapshot to NVRAM
    size_t persist_size = sizeof(size_t) + (num_blocks * sizeof(PersistedFreeBlock));
    flush_range(p_list_start, persist_size);
    pthread_mutex_unlock(&free_space_mutex);
}

// Reconstruct the in-memory free list from an NVRAM snapshot.
void reload_free_list()
{
    init_nvram_map();
    pthread_mutex_lock(&free_space_mutex);

    // Clear any existing in-RAM list
    while (freeList)
    {
        FreeBlock *temp = freeList;
        freeList = freeList->next;
        free(temp);
    }

    PersistedFreeBlock *p_list_start = (PersistedFreeBlock *)((char *)nvram_map + db_header->free_list_offset);
    size_t num_blocks = *(size_t *)p_list_start;
    PersistedFreeBlock *p_block = p_list_start + 1;

    FreeBlock *tail = NULL;
    for (size_t i = 0; i < num_blocks; i++)
    {
        FreeBlock *new_block = (FreeBlock *)malloc(sizeof(FreeBlock));
        new_block->offset = p_block->offset;
        new_block->size = p_block->size;
        new_block->next = NULL;

        if (!freeList)
        {
            freeList = new_block;
            tail = new_block;
        }
        else
        {
            tail->next = new_block;
            tail = new_block;
        }
        p_block++;
    }
    pthread_mutex_unlock(&free_space_mutex);
    printf("Reloaded %zu free blocks from NVRAM snapshot.\n", num_blocks);
}

// A helper struct for rebuilding the free list
typedef struct
{
    size_t offset;
    size_t size;
} UsedBlock;

// Comparison function for qsort
static int compare_used_blocks(const void *a, const void *b)
{
    UsedBlock *blockA = (UsedBlock *)a;
    UsedBlock *blockB = (UsedBlock *)b;
    if (blockA->offset < blockB->offset)
        return -1;
    if (blockA->offset > blockB->offset)
        return 1;
    return 0;
}

// Rebuilds the free list from scratch by finding all used space.
void rebuild_free_list_after_recovery(Table *tables[], int num_tables)
{
    printf("Rebuilding free space list after crash recovery...\n");
    pthread_mutex_lock(&free_space_mutex);

    // Clear any existing in-RAM list
    while (freeList)
    {
        FreeBlock *temp = freeList;
        freeList = freeList->next;
        free(temp);
    }
    freeList = NULL;

    int capacity = 1024;
    int count = 0;
    UsedBlock *used_blocks = malloc(capacity * sizeof(UsedBlock));

    // 1. Account for the Database Header
    used_blocks[count++] = (UsedBlock){0, sizeof(DatabaseHeader)};

    // 2. Traverse all tables and collect all used blocks (WAL data, row data)
    for (int i = 0; i < num_tables; i++)
    {
        if (!tables[i])
            continue;
        Table *table = tables[i];

        // Account for the WALTable structure itself
        used_blocks[count++] = (UsedBlock){table->wal_table_offset, sizeof(WALTable)};

        // Traverse the WAL for this table
        WALTable *wal_table = (WALTable *)((char *)nvram_map + table->wal_table_offset);
        WALEntry *current_entry = wal_table->entry_head;
        while (current_entry)
        {
            // Account for the WALEntry structure
            used_blocks[count++] = (UsedBlock){(size_t)((char *)current_entry - (char *)nvram_map), sizeof(WALEntry)};
            // Account for the row data pointed to by the entry
            if (current_entry->data_ptr)
            {
                used_blocks[count++] = (UsedBlock){(size_t)((char *)current_entry->data_ptr - (char *)nvram_map), current_entry->data_size};
            }
            if (count >= capacity)
            {
                capacity *= 2;
                used_blocks = realloc(used_blocks, capacity * sizeof(UsedBlock));
            }
            current_entry = current_entry->next;
        }
    }

    // 3. Sort the used blocks by offset
    qsort(used_blocks, count, sizeof(UsedBlock), compare_used_blocks);

    // 4. Create free blocks from the gaps
    size_t last_offset = 0;
    FreeBlock *tail = NULL;

    for (int i = 0; i < count; i++)
    {
        if (used_blocks[i].offset > last_offset)
        {
            // Found a gap, create a free block
            FreeBlock *new_block = malloc(sizeof(FreeBlock));
            new_block->offset = last_offset;
            new_block->size = used_blocks[i].offset - last_offset;
            new_block->next = NULL;
            if (!freeList)
            {
                freeList = new_block;
            }
            else
            {
                tail->next = new_block;
            }
            tail = new_block;
        }
        last_offset = used_blocks[i].offset + used_blocks[i].size;
    }

    // 5. Account for the final free block at the end of NVRAM
    if (last_offset < FILESIZE)
    {
        FreeBlock *new_block = malloc(sizeof(FreeBlock));
        new_block->offset = last_offset;
        new_block->size = FILESIZE - last_offset;
        new_block->next = NULL;
        if (!freeList)
        {
            freeList = new_block;
        }
        else
        {
            tail->next = new_block;
        }
    }

    free(used_blocks);
    pthread_mutex_unlock(&free_space_mutex);
    printf("Free space list rebuilt.\n");
}

// Allocate memory using first-fit algorithm
void *allocate_memory(size_t size)
{
    if (size == 0)
        return NULL;
    // Align size to 8 bytes for safety
    size = (size + 7) & ~7;

    pthread_mutex_lock(&free_space_mutex);
    init_nvram_map();

    FreeBlock *current = freeList, *prev = NULL;

    while (current)
    {
        if (current->size >= size)
        {
            size_t offset = current->offset;
            if (current->size == size)
            {
                if (prev)
                {
                    prev->next = current->next;
                }
                else
                {
                    freeList = current->next;
                }
                free(current);
            }
            else
            {
                current->offset += size;
                current->size -= size;
            }
            pthread_mutex_unlock(&free_space_mutex);
            return (char *)nvram_map + offset;
        }
        prev = current;
        current = current->next;
    }
    pthread_mutex_unlock(&free_space_mutex);
    fprintf(stderr, "NVRAM out of memory!\n");
    return NULL;
}

// Free allocated memory and merge free blocks
void free_memory(void *ptr, size_t size)
{
    if (!ptr || size == 0)
        return;
    // Align size to 8 bytes for safety
    size = (size + 7) & ~7;

    pthread_mutex_lock(&free_space_mutex);
    size_t offset = (char *)ptr - (char *)nvram_map;
    FreeBlock *newBlock = (FreeBlock *)malloc(sizeof(FreeBlock));
    newBlock->size = size;
    newBlock->offset = offset;
    newBlock->next = NULL;

    FreeBlock *current = freeList, *prev = NULL;
    if (!current || current->offset > offset)
    {
        newBlock->next = current;
        freeList = newBlock;
    }
    else
    {
        while (current && current->offset < offset)
        {
            prev = current;
            current = current->next;
        }
        newBlock->next = current;
        prev->next = newBlock;
    }

    // Merge with next block if adjacent
    if (newBlock->next && newBlock->offset + newBlock->size == newBlock->next->offset)
    {
        newBlock->size += newBlock->next->size;
        FreeBlock *temp = newBlock->next;
        newBlock->next = temp->next;
        free(temp);
    }

    // Merge with previous block if adjacent
    if (prev && prev->offset + prev->size == newBlock->offset)
    {
        prev->size += newBlock->size;
        prev->next = newBlock->next;
        free(newBlock);
    }
    pthread_mutex_unlock(&free_space_mutex);
}

// Cleanup function
void cleanup_free_space()
{
    munmap(nvram_map, FILESIZE);
    close(fd);
    nvram_map = NULL;
    fd = -1;

    FreeBlock *current = freeList;
    while (current)
    {
        FreeBlock *temp = current;
        current = current->next;
        free(temp);
    }
    freeList = NULL;
}
