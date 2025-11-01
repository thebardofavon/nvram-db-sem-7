#ifndef WAL_H
#define WAL_H

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>      // For mutex support
#include <stdint.h>
#include "ram_bptree.h"   // For Table struct

// #define MAX_TABLES 10 // Maximum number of tables - This should be defined in a central place, like ram_bptree.h

// Operation types for the WAL
typedef enum {
    WAL_DELETE = 0,
    WAL_INSERT = 1
} WALOperation;

// WAL Entry Structure
typedef struct WALEntry {
    WALOperation op_flag;   // Operation type (WAL_INSERT or WAL_DELETE)
    int key;                // Key of row/data
    void *data_ptr;         // Pointer to actual data in NVRAM
    size_t data_size;       // Size of the data
    struct WALEntry *next;  // Pointer to next WAL entry (this is an NVRAM pointer)
} WALEntry;

// WAL Table Structure (This entire structure lives in NVRAM)
typedef struct WALTable {
    int table_id;           // Unique Table ID
    WALEntry *entry_head;   // NVRAM Pointer to first WAL entry
    WALEntry *entry_tail;   // NVRAM Pointer to last WAL entry (for fast append)
    WALEntry *commit_ptr;   // NVRAM Commit pointer (points to last committed entry)
    pthread_mutex_t mutex;  // Mutex for thread-safe WAL operations
} WALTable;

// Global array of RAM pointers to the NVRAM WALTable structures
extern WALTable *wal_tables[MAX_TABLES];

// --- NVRAM Persistence Functions ---
void flush_range(void *start, size_t size);
void atomic_write_64(void *dest, uint64_t val);

// --- WAL Operations ---
int wal_create_table(int table_id, void *memory_ptr);
void* wal_add_entry(int table_id, int key, void *data_ptr, WALOperation op, void *entry_ptr, size_t data_size);
void wal_advance_commit_ptr(int table_id);
void wal_show_data();

// --- Crash Recovery Function ---
// Replays the log for a single table to rebuild its B+Tree index.
void wal_replay_log_for_table(Table *table);

#endif // WAL_H
