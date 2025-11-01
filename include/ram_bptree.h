#ifndef RAM_BPTREE_H
#define RAM_BPTREE_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include "lock_manager.h"

// Define the order of the B+ Tree (maximum number of children)
#define BP_ORDER 5
#define MAX_TABLES 32 // Arbitrary limit on the number of tables

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

// The master header, located at the very start of the NVRAM device.
typedef struct {
    uint64_t magic_number;
    size_t free_list_offset;
    size_t table_catalog_offset;
    int num_tables;
    int next_table_id;
    // For checkpointing: stores the offset of the commit_ptr for each table's WAL
    size_t wal_commit_offsets[MAX_TABLES];
} DatabaseHeader;

// Table structure (in RAM)
struct Table {
    char name[64];
    int table_id;
    BPTree *index;
    bool is_open;
    size_t wal_table_offset;
};

// --- System Lifecycle Functions ---
void db_startup();
void db_shutdown();
void db_checkpoint(); // New function for checkpointing

// --- Transaction operations ---
int db_begin_transaction();
bool db_commit_transaction(int txn_id);
bool db_abort_transaction(int txn_id);

// --- Table operations ---
int db_create_table(const char *name);
Table* db_open_table(const char *name);
void db_close_table(Table *table);
Table* get_table(const char *name);
Table* get_table_by_id(int table_id); // New helper
NVRAMPtr* db_get_table_all_rows(Table *table);

// --- Row operations ---
NVRAMPtr db_get_row(Table *table, int txn_id, int key, size_t *size);
bool db_put_row(Table *table, int txn_id, int key, void *data, size_t size);
bool db_delete_row(Table *table, int txn_id, int key);
int db_get_next_row(Table *table, int current_key);

#endif // RAM_BPTREE_H

