#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#define FILEPATH "/dev/dax0.0"
#define FILESIZE (2L * 1024 * 1024 * 1024) // 2GB

pthread_mutex_t free_space_mutex = PTHREAD_MUTEX_INITIALIZER;

// Structure for free space block
typedef struct FreeBlock
{
    size_t size;
    size_t offset; // Offset in NVRAM
    struct FreeBlock *next;
} FreeBlock;

FreeBlock *freeList = NULL; // Head of free space list
void *nvram_map = NULL;     // Pointer to mapped NVRAM
int fd = -1;

// Initialize NVRAM mapping and free space list
void init_free_space()
{
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

    // Initially, all 2GB is free
    freeList = (FreeBlock *)malloc(sizeof(FreeBlock));
    freeList->size = FILESIZE;
    freeList->offset = 0;
    freeList->next = NULL;
}

// Allocate memory using first-fit algorithm
void *allocate_memory(size_t size)
{
    pthread_mutex_lock(&free_space_mutex);
    FreeBlock *current = freeList, *prev = NULL;

    while (current)
    {
        if (current->size >= size)
        {
            void *allocated_memory = (char *)nvram_map + current->offset;
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
            return allocated_memory;
        }
        prev = current;
        current = current->next;
    }
    pthread_mutex_unlock(&free_space_mutex);
    return NULL;
}

// Free allocated memory and merge free blocks
void free_memory(void *ptr, size_t size)
{
    pthread_mutex_lock(&free_space_mutex);
    size_t offset = (char *)ptr - (char *)nvram_map;
    FreeBlock *newBlock = (FreeBlock *)malloc(sizeof(FreeBlock));
    newBlock->size = size;
    newBlock->offset = offset;
    newBlock->next = NULL;

    FreeBlock *current = freeList, *prev = NULL;
    while (current && current->offset < newBlock->offset)
    {
        prev = current;
        current = current->next;
    }

    newBlock->next = current;
    if (prev)
    {
        prev->next = newBlock;
    }
    else
    {
        freeList = newBlock;
    }

    if (newBlock->next && newBlock->offset + newBlock->size == newBlock->next->offset)
    {
        newBlock->size += newBlock->next->size;
        FreeBlock *temp = newBlock->next;
        newBlock->next = temp->next;
        free(temp);
    }

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

    FreeBlock *current = freeList;
    while (current)
    {
        FreeBlock *temp = current;
        current = current->next;
        free(temp);
    }
}
