// REPLACE THE ENTIRE CONTENTS of include/ram_bptree.h with this.
// This version includes the full struct definitions.
#ifndef RAM_BPTREE_H
#define RAM_BPTREE_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include "lock_manager.h"

#define BP_ORDER 5
#define MAX_TABLES 32
#define MAX_TABLE_NAME 64
#define CLEAN_SHUTDOWN_MAGIC 0xCAFEF00DD00DF00D
#define DIRTY_SHUTDOWN_MAGIC 0xDEADBEEFDEADBEEF

typedef void* NVRAMPtr;

// Global lock manager
extern LockManager g_lock_manager;

// --- B+ Tree Structures (RAM-only) ---
// FIXED: Moved definitions from .c file to .h file
typedef struct BPTreeNode
{
    bool is_leaf;
    int num_keys;
    int keys[BP_ORDER - 1];
    union
    {
        struct BPTreeNode *children[BP_ORDER];
        struct
        {
            NVRAMPtr data_ptrs[BP_ORDER - 1];
            size_t data_sizes[BP_ORDER - 1];
        };
    };
    struct BPTreeNode *next_leaf;
} BPTreeNode;

typedef struct BPTree
{
    BPTreeNode *root;
    int height;
    int node_count;
    int record_count;
} BPTree;

typedef struct {
    uint64_t magic_number;
    size_t free_list_offset;
    size_t table_catalog_offset;
    int num_tables;
    int next_table_id;
    size_t wal_commit_offsets[MAX_TABLES];
} DatabaseHeader;

typedef struct {
    char name[MAX_TABLE_NAME];
    int table_id;
    size_t wal_table_offset;
    size_t root_offset;
} PersistedTable;

typedef struct Table {
    char name[64];
    int table_id;
    BPTree *index;
    bool is_open;
    size_t wal_table_offset;
} Table;

// Global database header pointer
extern DatabaseHeader *db_header;

// --- System Lifecycle Functions ---
void db_startup();
void db_shutdown();
void db_checkpoint();

// --- Transaction operations ---
int db_begin_transaction();
bool db_commit_transaction(int txn_id);
bool db_abort_transaction(int txn_id);

// --- Table operations ---
int db_create_table(const char *name);
Table* db_open_table(const char *name);
void db_close_table(Table *table);
Table* get_table(const char *name);
Table* get_table_by_id(int table_id);
NVRAMPtr* db_get_table_all_rows(Table *table);

// --- Row operations ---
NVRAMPtr db_get_row(Table *table, int txn_id, int key, size_t *size);
bool db_put_row(Table *table, int txn_id, int key, void *data, size_t size);
bool db_delete_row(Table *table, int txn_id, int key);
int db_get_next_row(Table *table, int current_key);

#endif // RAM_BPTREE_H

