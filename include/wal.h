#ifndef WAL_H
#define WAL_H

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h> // For mutex support
#include <stdint.h>

#define MAX_TABLES 10   // Maximum number of tables

// WAL Entry Structure
typedef struct WALEntry {
    int op_flag;           // Operation type (0 = Add, 1 = Delete)
    int key;               // Key of row/data (formerly row_id)
    void *data_ptr;        // Pointer to actual data in NVRAM (KP in diagram)
    size_t data_size;      // Size of the data
    struct WALEntry *next; // Pointer to next WAL entry
} WALEntry;

// WAL Table Structure
typedef struct WALTable {
    int table_id;              // Unique Table ID
    WALEntry *entry_head;      // Pointer to first WAL entry
    WALEntry *entry_tail;      // Pointer to last WAL entry (for fast append)
    WALEntry *commit_ptr;      // Commit pointer (points to last committed entry)
    pthread_mutex_t mutex;     // Mutex for thread-safe WAL operations
} WALTable;

extern WALTable *wal_tables[MAX_TABLES];

// Function Declarations
void flush_range(void *start, size_t size);
void atomic_write_64(void *dest, uint64_t val);

// WAL Operations
int wal_create_table(int table_id, void *memory_ptr);
int wal_add_entry(int table_id, int key, void *data_ptr, int op, void *entry_ptr, size_t data_size);
void wal_advance_commit_ptr(int table_id, int txn_id);
void wal_show_data();
void wal_recover();  // New function for crash recovery

#endif // WAL_H
