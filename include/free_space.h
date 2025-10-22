#ifndef FREE_SPACE_H
#define FREE_SPACE_H

#include <stddef.h>
#include <pthread.h>
#include "ram_bptree.h" // For Table struct definition

#define FILEPATH "/dev/dax0.0"
#define FILESIZE (2L * 1024 * 1024 * 1024) // 2GB

extern pthread_mutex_t free_space_mutex;

// --- System Lifecycle Functions ---
// Initialize free space management system for the first time.
void init_free_space_first_time();

// Serialize the in-memory free list to a snapshot in NVRAM.
void persist_free_list();

// Reconstruct the in-memory free list from an NVRAM snapshot.
void reload_free_list();

// Rebuild a correct free list from scratch after a crash recovery.
void rebuild_free_list_after_recovery(Table* tables[], int num_tables);

// --- Memory Management Operations ---
// Allocate memory from NVRAM using first-fit.
void *allocate_memory(size_t size);

// Free allocated memory and merge adjacent blocks.
void free_memory(void *ptr, size_t size);

// Cleanup function to release resources.
void cleanup_free_space();

#endif // FREE_SPACE_H


// #ifndef FREE_SPACE_H
// #define FREE_SPACE_H

// #include <stddef.h>

// #define FILEPATH "/dev/dax0.0"

// #define FILESIZE (2L * 1024 * 1024 * 1024) // 2GB

// extern pthread_mutex_t free_space_mutex;

// // Initialize free space management system
// void init_free_space();

// // Allocate memory from NVRAM using first-fit
// void *allocate_memory(size_t size);

// // Free allocated memory and merge adjacent blocks
// void free_memory(void *ptr, size_t size);

// // Cleanup function to release resources
// void cleanup_free_space();

// #endif // FREE_SPACE_H
