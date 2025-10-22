#ifndef RAM_BPTREE_H
#define RAM_BPTREE_H
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include "lock_manager.h"

// Define the order of the B+ Tree (maximum number of children)
#define BP_ORDER 5

// --- Magic Numbers for Clean/Dirty Shutdown ---
#define CLEAN_SHUTDOWN_MAGIC 0xCAFEF00DD00DF00D
#define DIRTY_SHUTDOWN_MAGIC 0xDEADBEEFDEADBEEF

// Pointer to data in NVRAM
typedef void* NVRAMPtr;

// Forward declarations
typedef struct BPTreeNode BPTreeNode;
typedef struct BPTree BPTree;
typedef struct Table Table;

// Global lock manager
extern LockManager g_lock_manager;

// --- Core On-Disk (NVRAM) Structures ---
// The master header, located at the very start of the NVRAM device.
// It acts as the root of all other metadata.
typedef struct {
    uint64_t magic_number;       // To check for clean shutdown
    size_t free_list_offset;     // NVRAM offset to the start of the serialized free list
    size_t table_catalog_offset; // NVRAM offset to the start of the table metadata
    int num_tables;              // Number of tables persisted
    int next_table_id;           // The next available table ID
} DatabaseHeader;

// --- Core In-RAM Structures ---
// Table structure (in RAM)
struct Table {
    char name[64];           // Table name
    int table_id;            // Unique ID
    BPTree *index;           // B+ Tree index
    bool is_open;            // Is table open
    size_t wal_table_offset; // Offset to this table's WALTable in NVRAM
};

// --- System Lifecycle Functions ---
// Initialize or recover the database system at startup.
// This is the main entry point for the database core.
void db_startup();

// Perform a graceful shutdown, serializing all in-memory structures to NVRAM.
void db_shutdown();

// --- Transaction operations ---
int db_begin_transaction();
bool db_commit_transaction(int txn_id);
bool db_abort_transaction(int txn_id);

// --- Table operations ---
int db_create_table(const char name);
Table db_open_table(const char *name);
void db_close_table(Table *table);

// NEW FUNCTION FOR SQL PARSER
// Find a table by name and return a pointer to its structure
Table* get_table(const char *name);

// --- Row operations ---
NVRAMPtr db_get_row(Table *table, int txn_id, int key, size_t *size);
bool db_put_row(Table *table, int txn_id, int key, void *data, size_t size);
bool db_delete_row(Table *table, int txn_id, int key);
int db_get_next_row(Table *table, int current_key);

#endif // RAM_BPTREE_H




// #ifndef RAM_BPTREE_H
// #define RAM_BPTREE_H

// #include <stddef.h>
// #include <stdbool.h>
// #include "lock_manager.h"

// // Define the order of the B+ Tree (maximum number of children)
// #define BP_ORDER 5

// // Pointer to data in NVRAM
// typedef void* NVRAMPtr;

// // Forward declarations
// typedef struct BPTreeNode BPTreeNode;
// typedef struct BPTree BPTree;
// typedef struct Table Table;

// // Global lock manager
// extern LockManager g_lock_manager;

// // Standard database operations
// // All structures except the actual data are in RAM

// // Initialize database system
// void db_init();

// // Shutdown database system
// void db_shutdown();

// // Transaction operations
// int db_begin_transaction();
// bool db_commit_transaction(int txn_id);
// bool db_abort_transaction(int txn_id);

// // Table operations
// int db_create_table(const char *name);
// Table* db_open_table(const char *name);
// void db_close_table(Table *table);

// // Row operations
// NVRAMPtr db_get_row(Table *table, int txn_id, int key, size_t *size);
// bool db_put_row(Table *table, int txn_id, int key, void *data, size_t size);
// bool db_delete_row(Table *table, int txn_id, int key);
// int db_get_next_row(Table *table, int current_key);

// #endif // RAM_BPTREE_H