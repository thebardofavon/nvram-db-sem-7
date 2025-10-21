#ifndef RAM_BPTREE_H
#define RAM_BPTREE_H

#include <stddef.h>
#include <stdbool.h>
#include "lock_manager.h"

// Define the order of the B+ Tree (maximum number of children)
#define BP_ORDER 5

// Pointer to data in NVRAM
typedef void* NVRAMPtr;

// Forward declarations
typedef struct BPTreeNode BPTreeNode;
typedef struct BPTree BPTree;
typedef struct Table Table;

// Global lock manager
extern LockManager g_lock_manager;

// Standard database operations
// All structures except the actual data are in RAM

// Initialize database system
void db_init();

// Shutdown database system
void db_shutdown();

// Transaction operations
int db_begin_transaction();
bool db_commit_transaction(int txn_id);
bool db_abort_transaction(int txn_id);

// Table operations
int db_create_table(const char *name);
Table* db_open_table(const char *name);
void db_close_table(Table *table);

// Row operations
NVRAMPtr db_get_row(Table *table, int txn_id, int key, size_t *size);
bool db_put_row(Table *table, int txn_id, int key, void *data, size_t size);
bool db_delete_row(Table *table, int txn_id, int key);
int db_get_next_row(Table *table, int current_key);

#endif // RAM_BPTREE_H