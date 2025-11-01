#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "../include/free_space.h"
#include "../include/ram_bptree.h"
#include "../include/wal.h"
#include "../include/lock_manager.h"

// --- Global State ---
#define MAX_TABLES 10
#define MAX_TABLE_NAME 64

// In-RAM array of pointers to Table structures
static Table *tables[MAX_TABLES] = {NULL};
static bool is_initialized = false;
extern void *nvram_map; // From free_space.c
DatabaseHeader *db_header = NULL; // Mapped pointer to the NVRAM header
LockManager g_lock_manager;

// --- B+ Tree Structures (RAM-only) ---
struct BPTreeNode
{
    bool is_leaf;
    int num_keys;
    int keys[BP_ORDER - 1];
    union
    {
        BPTreeNode *children[BP_ORDER];
        struct
        {
            NVRAMPtr data_ptrs[BP_ORDER - 1];
            size_t data_sizes[BP_ORDER - 1];
        };
    };
    BPTreeNode *next_leaf;
};

struct BPTree
{
    BPTreeNode *root;
    int height;
    int node_count;
    int record_count;
};

// --- B+ Tree Helper Function Prototypes ---
static BPTreeNode *create_node(bool is_leaf);
static BPTree *create_tree();
static void free_tree(BPTree *tree);
BPTreeNode *find_leaf(BPTree *tree, int key);
int find_key_in_leaf(BPTreeNode *leaf, int key);
bool insert_recursive(BPTree *tree, BPTreeNode *node, int key, void *data, size_t size, int *up_key, BPTreeNode **new_node);
bool remove_recursive(BPTree *tree, BPTreeNode *node, int key, BPTreeNode *parent, int parent_idx);

// --- Serialization/Deserialization Structures & Helpers ---
// Structure used to serialize a B+ Tree node to NVRAM
typedef struct
{
    bool is_leaf;
    int num_keys;
    int keys[BP_ORDER - 1];
    union
    {
        size_t children_offsets[BP_ORDER]; // NVRAM offsets to child nodes
        struct
        {
            NVRAMPtr data_ptrs[BP_ORDER - 1];
            size_t data_sizes[BP_ORDER - 1];
        };
    };
    size_t next_leaf_offset;
} PersistedBPTreeNode;

// Structure used to serialize table metadata
typedef struct
{
    char name[MAX_TABLE_NAME];
    int table_id;
    size_t root_offset; // NVRAM offset to the B+Tree root node
    size_t wal_table_offset;
} PersistedTable;

// --- Core Database Lifecycle Functions ---
// Initialize the database for the very first time.
void db_first_time_init()
{
    printf("Performing first-time database initialization...\n");
    // 1. Init free space manager, which maps NVRAM and sets up db_header
    init_free_space_first_time();

    // 2. Initialize the header in NVRAM
    db_header->magic_number = DIRTY_SHUTDOWN_MAGIC; // Start dirty
    db_header->num_tables = 0;
    db_header->next_table_id = 0;

    // 3. Allocate space for the free list snapshot and table catalog
    // Max possible size for free list: 1 block per 8 bytes allocated... too big.
    // Let's allocate a generous but fixed size, e.g., 1MB.
    size_t free_list_snapshot_size = 1024 * 1024;
    void *free_list_storage = allocate_memory(free_list_snapshot_size);
    db_header->free_list_offset = (char *)free_list_storage - (char *)nvram_map;

    size_t catalog_size = sizeof(PersistedTable) * MAX_TABLES;
    void *catalog_storage = allocate_memory(catalog_size);
    db_header->table_catalog_offset = (char *)catalog_storage - (char *)nvram_map;

    // 4. Persist the header
    flush_range(db_header, sizeof(DatabaseHeader));

    // 5. Init other managers
    lock_manager_init(&g_lock_manager);
    is_initialized = true;
    printf("Database system initialized for the first time.\n");
}

// Serialize all in-memory state to NVRAM for a clean shutdown.
static void persist_state()
{
    printf("Persisting database state to NVRAM...\n");

    // 1. Update header with current table count and next ID
    int count = 0;
    for (int i = 0; i < MAX_TABLES; ++i)
        if (tables[i])
            count++;
    db_header->num_tables = count;
    // next_table_id is already up to date from db_create_table

    // 2. Persist the free list
    persist_free_list();

    // 3. Persist the table catalog and B+Tree indexes
    PersistedTable *p_catalog = (PersistedTable *)((char *)nvram_map + db_header->table_catalog_offset);
    for (int i = 0; i < MAX_TABLES; i++)
    {
        if (tables[i])
        {
            Table *table = tables[i];
            PersistedTable *p_table = &p_catalog[i];

            strncpy(p_table->name, table->name, MAX_TABLE_NAME);
            p_table->table_id = table->table_id;
            p_table->wal_table_offset = table->wal_table_offset;
            p_table->root_offset = 0; // Will be set by serialization

            // Serialization logic is complex and omitted for this step.
            // In a real implementation, you'd traverse the B+Tree here, allocate
            // PersistedBPTreeNodes in NVRAM, and fill in p_table->root_offset.
            // For now, we rely on WAL recovery. A true snapshot would be an optimization.
            printf("Table '%s' metadata prepared for persistence.\n", table->name);
        }
    }
    flush_range(p_catalog, sizeof(PersistedTable) * MAX_TABLES);
    flush_range(db_header, sizeof(DatabaseHeader));
    printf("Database state persisted.\n");
}

// Reconstruct in-memory state from the NVRAM snapshot.
void db_reload_state()
{
    printf("Reloading database state from NVRAM snapshot...\n");
    db_header = (DatabaseHeader *)nvram_map;

    // 1. Reload the free list
    reload_free_list();

    // 2. Reload table metadata and reconstruct B+Trees
    PersistedTable *p_catalog = (PersistedTable *)((char *)nvram_map + db_header->table_catalog_offset);
    for (int i = 0; i < db_header->num_tables; ++i)
    {
        // This simplified version reloads metadata but relies on WAL for index state
        PersistedTable *p_table = &p_catalog[i];
        if (p_table->name[0] == '\0')
            continue; // Skip empty slots

        Table *table = (Table *)malloc(sizeof(Table));
        strncpy(table->name, p_table->name, MAX_TABLE_NAME);
        table->table_id = p_table->table_id;
        table->index = create_tree(); // Create an empty tree
        table->is_open = true;
        table->wal_table_offset = p_table->wal_table_offset;

        tables[table->table_id] = table;
        wal_tables[table->table_id] = (WALTable *)((char *)nvram_map + table->wal_table_offset);

        // After reloading metadata, we MUST replay the WAL to reconstruct the index
        wal_replay_log_for_table(table);
    }

    lock_manager_init(&g_lock_manager);
    is_initialized = true;
    printf("Database state reloaded.\n");
}

// Rebuild in-memory state from the WAL after a crash.
void db_recover_from_wal()
{
    printf("CRASH DETECTED. Starting recovery from Write-Ahead Log...\n");
    db_header = (DatabaseHeader *)nvram_map;

    // 1. Initialize lock manager and other basic state
    lock_manager_init(&g_lock_manager);

    // 2. Load table metadata from the persisted catalog
    PersistedTable *p_catalog = (PersistedTable *)((char *)nvram_map + db_header->table_catalog_offset);
    int num_tables = 0;
    for (int i = 0; i < MAX_TABLES; ++i)
    {
        PersistedTable *p_table = &p_catalog[i];
        if (p_table->name[0] == '\0' || p_table->name[0] == -1)
            continue;

        Table *table = (Table *)malloc(sizeof(Table));
        strncpy(table->name, p_table->name, MAX_TABLE_NAME);
        table->table_id = p_table->table_id;
        table->index = create_tree(); // Start with an empty tree
        table->is_open = true;
        table->wal_table_offset = p_table->wal_table_offset;

        tables[table->table_id] = table;
        wal_tables[table->table_id] = (WALTable *)((char *)nvram_map + table->wal_table_offset);
        num_tables++;
    }

    // 3. For each table, replay its WAL to rebuild the B+Tree index
    for (int i = 0; i < MAX_TABLES; ++i)
    {
        if (tables[i])
        {
            wal_replay_log_for_table(tables[i]);
        }
    }

    // 4. After all indexes are rebuilt, reconstruct the free space list
    rebuild_free_list_after_recovery(tables, MAX_TABLES);

    is_initialized = true;
    printf("Database recovery complete.\n");
}

void db_startup()
{
    nvram_map = mmap(NULL, FILESIZE, PROT_READ | PROT_WRITE, MAP_SHARED, open(FILEPATH, O_RDWR), 0);
    if (nvram_map == MAP_FAILED)
    {
        perror("mmap on startup");
        exit(1);
    }
    db_header = (DatabaseHeader *)nvram_map;

    // Check if this is the very first run (NVRAM is all zeros)
    bool first_run = true;
    for (size_t i = 0; i < sizeof(DatabaseHeader); ++i)
    {
        if (*((char *)db_header + i) != 0)
        {
            first_run = false;
            break;
        }
    }

    if (first_run)
    {
        db_first_time_init();
    }
    else if (db_header->magic_number == CLEAN_SHUTDOWN_MAGIC)
    {
        printf("Clean shutdown detected. Reloading state...\n");
        db_reload_state();
    }
    else
    {
        printf("Dirty shutdown detected. Starting recovery...\n");
        db_recover_from_wal();
    }

    // Arm the system for a potential crash
    db_header->magic_number = DIRTY_SHUTDOWN_MAGIC;
    flush_range(db_header, sizeof(uint64_t));
    printf("System is now live. Shutdown flag set to DIRTY.\n");
}

void db_shutdown()
{
    if (!is_initialized)
        return;

    printf("Database shutdown sequence initiated...\n");
    // 1. Persist all in-memory structures to NVRAM
    persist_state();

    // 2. Set the clean shutdown flag as the VERY LAST step
    db_header->magic_number = CLEAN_SHUTDOWN_MAGIC;
    flush_range(db_header, sizeof(uint64_t));
    printf("Shutdown flag set to CLEAN.\n");

    // 3. Clean up RAM resources
    for (int i = 0; i < MAX_TABLES; i++)
    {
        if (tables[i])
        {
            free_tree(tables[i]->index);
            free(tables[i]);
            tables[i] = NULL;
        }
    }
    lock_manager_cleanup(&g_lock_manager);
    cleanup_free_space();
    is_initialized = false;
    printf("Database system shut down.\n");
}

int db_create_table(const char *name)
{
    if (!is_initialized)
        return -1;

    int table_id = db_header->next_table_id;
    if (table_id >= MAX_TABLES)
    {
        printf("Error: Maximum number of tables reached\n");
        return -1;
    }

    for (int i = 0; i < MAX_TABLES; i++)
    {
        if (tables[i] && strcmp(tables[i]->name, name) == 0)
        {
            printf("Error: Table '%s' already exists\n", name);
            return -1;
        }
    }

    Table *table = (Table *)malloc(sizeof(Table));
    table->index = create_tree();
    strncpy(table->name, name, MAX_TABLE_NAME - 1);
    table->name[MAX_TABLE_NAME - 1] = '\0';
    table->table_id = table_id;
    table->is_open = true;

    void *wal_table_ptr = allocate_memory(sizeof(WALTable));
    if (!wal_create_table(table->table_id, wal_table_ptr))
    {
        free_tree(table->index);
        free(table);
        return -1;
    }
    table->wal_table_offset = (char *)wal_table_ptr - (char *)nvram_map;

    tables[table_id] = table;
    db_header->next_table_id++;

    printf("Table '%s' created with ID %d\n", name, table->table_id);
    return table->table_id;
}

// Find a table by name and return a pointer to its structure
Table *get_table(const char *name)
{
    if (!is_initialized || !name)
        return NULL;
    for (int i = 0; i < MAX_TABLES; i++)
    {
        if (tables[i] && strcmp(tables[i]->name, name) == 0)
        {
            return tables[i];
        }
    }
    return NULL;
}

// Begin a transaction
int db_begin_transaction()
{
    return transaction_begin(&g_lock_manager);
}

// Modified commit transaction to update WAL commit pointers
bool db_commit_transaction(int txn_id)
{
    bool result = transaction_commit(&g_lock_manager, txn_id);

    if (result)
    {
        for (int i = 0; i < MAX_TABLES; i++)
        {
            if (tables[i] != NULL)
            {
                wal_advance_commit_ptr(tables[i]->table_id, txn_id);
            }
        }
    }

    return result;
}

// Abort a transaction
// In src/ram_bptree.c
bool db_abort_transaction(int txn_id)
{
    // FIXME: This is still incorrect. It should perform a rollback.
    // This will be fixed in Phase 2.
    return transaction_abort(&g_lock_manager, txn_id);
}

// Open an existing table
Table *db_open_table(const char *name)
{
    return get_table(name);
}

// Close a table
void db_close_table(Table *table)
{
    if (table)
    {
        table->is_open = false;
        printf("Table '%s' closed\n", table->name);
    }
}

// Get a row by its key
NVRAMPtr db_get_row(Table *table, int txn_id, int key, size_t *size)
{
    if (!table || !table->is_open)
        return NULL;
    if (!lock_acquire(&g_lock_manager, txn_id, table->table_id, true, LOCK_SHARED) ||
        !lock_acquire(&g_lock_manager, txn_id, key, false, LOCK_SHARED))
    {
        // Simplified error handling
        return NULL;
    }
    BPTreeNode *leaf = find_leaf(table->index, key);
    if (!leaf)
        return NULL;
    int pos = find_key_in_leaf(leaf, key);
    if (pos == -1)
        return NULL;
    if (size)
        *size = leaf->data_sizes[pos];
    return leaf->data_ptrs[pos];
}

// Insert or update a row
bool db_put_row(Table *table, int txn_id, int key, void *data, size_t size)
{
    if (!table || !table->is_open)
        return false;

    if (!lock_acquire(&g_lock_manager, txn_id, table->table_id, true, LOCK_SHARED) ||
        !lock_acquire(&g_lock_manager, txn_id, key, false, LOCK_EXCLUSIVE))
    {
        return false;
    }

    if (find_key_in_leaf(find_leaf(table->index, key), key) != -1)
    {
        return false; // Row already exists
    }

    void *wal_entry_ptr = allocate_memory(sizeof(WALEntry));
    NVRAMPtr nvram_data = allocate_memory(size);
    if (!wal_entry_ptr || !nvram_data)
    {
        // Handle allocation failure
        if (wal_entry_ptr)
            free_memory(wal_entry_ptr, sizeof(WALEntry));
        if (nvram_data)
            free_memory(nvram_data, size);
        return false;
    }

    memcpy(nvram_data, data, size);
    flush_range(nvram_data, size);

    if (!wal_add_entry(table->table_id, key, nvram_data, 1, wal_entry_ptr, size))
    {
        free_memory(nvram_data, size);
        free_memory(wal_entry_ptr, sizeof(WALEntry));
        return false;
    }

    int up_key;
    BPTreeNode *new_node = NULL;
    if (!insert_recursive(table->index, table->index->root, key, nvram_data, size, &up_key, &new_node))
    {
        // This indicates an internal error, as we already checked for duplicates.
        // A real implementation would need to undo the WAL entry.
        return false;
    }

    if (new_node != NULL)
    {
        BPTreeNode *new_root = create_node(false);
        new_root->keys[0] = up_key;
        new_root->children[0] = table->index->root;
        new_root->children[1] = new_node;
        new_root->num_keys = 1;
        table->index->root = new_root;
        table->index->height++;
    }
    table->index->record_count++;
    return true;
}

// Delete a row
bool db_delete_row(Table *table, int txn_id, int key)
{
    if (!table || !table->is_open)
        return false;

    if (!lock_acquire(&g_lock_manager, txn_id, table->table_id, true, LOCK_SHARED) ||
        !lock_acquire(&g_lock_manager, txn_id, key, false, LOCK_EXCLUSIVE))
    {
        return false;
    }

    BPTreeNode *leaf = find_leaf(table->index, key);
    int pos = find_key_in_leaf(leaf, key);
    if (pos == -1)
        return false; // Not found

    size_t data_size = leaf->data_sizes[pos];
    void *data_ptr = leaf->data_ptrs[pos];

    void *wal_entry_ptr = allocate_memory(sizeof(WALEntry));
    if (!wal_entry_ptr)
        return false;

    if (!wal_add_entry(table->table_id, key, data_ptr, 0, wal_entry_ptr, data_size))
    {
        free_memory(wal_entry_ptr, sizeof(WALEntry));
        return false;
    }

    bool result = remove_recursive(table->index, table->index->root, key, NULL, 0);
    if (result)
    {
        table->index->record_count--;
    }
    return result;
}


static BPTreeNode *create_node(bool is_leaf)
{
    BPTreeNode *node = (BPTreeNode *)malloc(sizeof(BPTreeNode));
    if (!node)
        return NULL;
    node->is_leaf = is_leaf;
    node->num_keys = 0;
    node->next_leaf = NULL;
    memset(node->keys, 0, sizeof(node->keys));
    if (is_leaf)
    {
        memset(node->data_ptrs, 0, sizeof(node->data_ptrs));
        memset(node->data_sizes, 0, sizeof(node->data_sizes));
    }
    else
    {
        memset(node->children, 0, sizeof(node->children));
    }
    return node;
}

// Helper function to create a new B+ Tree
static BPTree *create_tree()
{
    BPTree *tree = (BPTree *)malloc(sizeof(BPTree));
    if (!tree)
        return NULL;
    tree->root = create_node(true);
    if (!tree->root)
    {
        free(tree);
        return NULL;
    }
    tree->height = 1;
    tree->node_count = 1;
    tree->record_count = 0;
    return tree;
}

static BPTreeNode *split_leaf(BPTree *tree, BPTreeNode *leaf, int *up_key)
{
    BPTreeNode *new_leaf = create_node(true);
    if (!new_leaf)
        return NULL;
    int mid = (BP_ORDER - 1) / 2;
    *up_key = leaf->keys[mid];
    for (int i = mid; i < leaf->num_keys; i++)
    {
        new_leaf->keys[i - mid] = leaf->keys[i];
        new_leaf->data_ptrs[i - mid] = leaf->data_ptrs[i];
        new_leaf->data_sizes[i - mid] = leaf->data_sizes[i];
        leaf->keys[i] = 0;
        leaf->data_ptrs[i] = NULL;
        leaf->data_sizes[i] = 0;
    }
    new_leaf->num_keys = leaf->num_keys - mid;
    leaf->num_keys = mid;
    new_leaf->next_leaf = leaf->next_leaf;
    leaf->next_leaf = new_leaf;
    tree->node_count++;
    return new_leaf;
}

static BPTreeNode *split_internal(BPTree *tree, BPTreeNode *node, int *up_key)
{
    BPTreeNode *new_node = create_node(false);
    if (!new_node)
        return NULL;
    int mid = (BP_ORDER - 1) / 2;
    *up_key = node->keys[mid];
    for (int i = mid + 1; i < node->num_keys; i++)
    {
        new_node->keys[i - (mid + 1)] = node->keys[i];
        node->keys[i] = 0;
    }
    for (int i = mid + 1; i <= node->num_keys; i++)
    {
        new_node->children[i - (mid + 1)] = node->children[i];
        node->children[i] = NULL;
    }
    new_node->num_keys = node->num_keys - (mid + 1);
    node->num_keys = mid;
    tree->node_count++;
    return new_node;
}

static bool insert_in_internal(BPTree *tree, BPTreeNode *node, int key, BPTreeNode *right_child)
{
    int i = node->num_keys - 1;
    while (i >= 0 && node->keys[i] > key)
    {
        node->keys[i + 1] = node->keys[i];
        node->children[i + 2] = node->children[i + 1];
        i--;
    }
    node->keys[i + 1] = key;
    node->children[i + 2] = right_child;
    node->num_keys++;
    return true;
}

BPTreeNode *find_leaf(BPTree *tree, int key)
{
    if (!tree || !tree->root)
        return NULL;
    BPTreeNode *node = tree->root;
    while (node && !node->is_leaf)
    {
        int i;
        for (i = 0; i < node->num_keys; i++)
        {
            if (key < node->keys[i])
                break;
        }
        node = node->children[i];
    }
    return node;
}

int find_key_in_leaf(BPTreeNode *leaf, int key)
{
    if (!leaf)
        return -1;
    for (int i = 0; i < leaf->num_keys; i++)
    {
        if (leaf->keys[i] == key)
            return i;
    }
    return -1;
}

bool insert_recursive(BPTree *tree, BPTreeNode *node, int key, void *data, size_t size, int *up_key, BPTreeNode **new_node)
{
    if (node->is_leaf)
    {
        if (find_key_in_leaf(node, key) != -1)
            return false; // Duplicate
        int i = node->num_keys - 1;
        while (i >= 0 && node->keys[i] > key)
        {
            node->keys[i + 1] = node->keys[i];
            node->data_ptrs[i + 1] = node->data_ptrs[i];
            node->data_sizes[i + 1] = node->data_sizes[i];
            i--;
        }
        node->keys[i + 1] = key;
        node->data_ptrs[i + 1] = data;
        node->data_sizes[i + 1] = size;
        node->num_keys++;
        if (node->num_keys >= BP_ORDER - 1)
        {
            *new_node = split_leaf(tree, node, up_key);
            return *new_node != NULL;
        }
        return true;
    }
    else
    {
        int i;
        for (i = 0; i < node->num_keys; i++)
        {
            if (key < node->keys[i])
                break;
        }
        BPTreeNode *child = node->children[i];
        BPTreeNode *new_child = NULL;
        int child_up_key;
        if (!insert_recursive(tree, child, key, data, size, &child_up_key, &new_child))
            return false;
        if (new_child == NULL)
            return true;
        if (node->num_keys < BP_ORDER - 1)
        {
            return insert_in_internal(tree, node, child_up_key, new_child);
        }
        else
        {
            insert_in_internal(tree, node, child_up_key, new_child);
            *new_node = split_internal(tree, node, up_key);
            return *new_node != NULL;
        }
    }
}

static bool merge_nodes(BPTreeNode *left, BPTreeNode *right, int parent_key_idx, BPTreeNode *parent)
{
    if (left->is_leaf)
    {
        // Merge leaf nodes
        for (int i = 0; i < right->num_keys; i++)
        {
            left->keys[left->num_keys + i] = right->keys[i];
            left->data_ptrs[left->num_keys + i] = right->data_ptrs[i];
            left->data_sizes[left->num_keys + i] = right->data_sizes[i];
        }

        left->num_keys += right->num_keys;
        left->next_leaf = right->next_leaf;
    }
    else
    {
        // Merge internal nodes
        left->keys[left->num_keys] = parent->keys[parent_key_idx];
        left->num_keys++;

        for (int i = 0; i < right->num_keys; i++)
        {
            left->keys[left->num_keys + i] = right->keys[i];
            left->children[left->num_keys + i] = right->children[i];
        }

        left->children[left->num_keys + right->num_keys] = right->children[right->num_keys];
        left->num_keys += right->num_keys;
    }

    // Remove parent key and adjust child pointers
    for (int i = parent_key_idx; i < parent->num_keys - 1; i++)
    {
        parent->keys[i] = parent->keys[i + 1];
    }

    for (int i = parent_key_idx + 1; i < parent->num_keys; i++)
    {
        parent->children[i] = parent->children[i + 1];
    }

    parent->num_keys--;

    // Free the right node
    free(right);

    return true;
}


static bool remove_recursive(BPTree *tree, BPTreeNode *node, int key, BPTreeNode *parent, int parent_idx)
{
    if (node->is_leaf)
    {
        // Case 1: Leaf node

        // Find position of key
        int pos = find_key_in_leaf(node, key);
        if (pos == -1)
        {
            // Key not found
            return false;
        }

        // Free NVRAM data
        free_memory(node->data_ptrs[pos], node->data_sizes[pos]);

        // Remove key and shift others
        for (int i = pos; i < node->num_keys - 1; i++)
        {
            node->keys[i] = node->keys[i + 1];
            node->data_ptrs[i] = node->data_ptrs[i + 1];
            node->data_sizes[i] = node->data_sizes[i + 1];
        }
        node->num_keys--;

        // Handle underflow (if not root)
        if (parent && node->num_keys < (BP_ORDER - 1) / 2)
        {
            // Get siblings
            BPTreeNode *left_sibling = NULL;
            BPTreeNode *right_sibling = NULL;
            int left_idx = -1, right_idx = -1;

            if (parent_idx > 0)
            {
                left_sibling = parent->children[parent_idx - 1];
                left_idx = parent_idx - 1;
            }

            if (parent_idx < parent->num_keys)
            {
                right_sibling = parent->children[parent_idx + 1];
                right_idx = parent_idx;
            }

            // Try to borrow from siblings or merge
            if (left_sibling && left_sibling->num_keys > (BP_ORDER - 1) / 2)
            {
                // Borrow from left sibling

                // Make space for the new key
                for (int i = node->num_keys; i > 0; i--)
                {
                    node->keys[i] = node->keys[i - 1];
                    node->data_ptrs[i] = node->data_ptrs[i - 1];
                    node->data_sizes[i] = node->data_sizes[i - 1];
                }

                // Copy the rightmost key from left sibling
                node->keys[0] = left_sibling->keys[left_sibling->num_keys - 1];
                node->data_ptrs[0] = left_sibling->data_ptrs[left_sibling->num_keys - 1];
                node->data_sizes[0] = left_sibling->data_sizes[left_sibling->num_keys - 1];
                node->num_keys++;

                // Update left sibling
                left_sibling->num_keys--;

                // Update parent key
                parent->keys[left_idx] = node->keys[0];
            }
            else if (right_sibling && right_sibling->num_keys > (BP_ORDER - 1) / 2)
            {
                // Borrow from right sibling

                // Copy the leftmost key from right sibling
                node->keys[node->num_keys] = right_sibling->keys[0];
                node->data_ptrs[node->num_keys] = right_sibling->data_ptrs[0];
                node->data_sizes[node->num_keys] = right_sibling->data_sizes[0];
                node->num_keys++;

                // Update right sibling
                for (int i = 0; i < right_sibling->num_keys - 1; i++)
                {
                    right_sibling->keys[i] = right_sibling->keys[i + 1];
                    right_sibling->data_ptrs[i] = right_sibling->data_ptrs[i + 1];
                    right_sibling->data_sizes[i] = right_sibling->data_sizes[i + 1];
                }
                right_sibling->num_keys--;

                // Update parent key
                parent->keys[right_idx] = right_sibling->keys[0];
            }
            else if (left_sibling)
            {
                // Merge with left sibling
                merge_nodes(left_sibling, node, left_idx, parent);

                // node is now merged into left_sibling
                return true;
            }
            else if (right_sibling)
            {
                // Merge with right sibling
                merge_nodes(node, right_sibling, right_idx, parent);
            }
        }

        return true;
    }
    else
    {
        // Case 2: Internal node

        // Find the appropriate child to traverse
        int i;
        for (i = 0; i < node->num_keys; i++)
        {
            if (key < node->keys[i])
                break;
        }

        BPTreeNode *child = node->children[i];

        // Recursive removal
        bool result = remove_recursive(tree, child, key, node, i);

        // Handle underflow in child (if not leaf and needs rebalancing)
        if (result && node->children[i]->num_keys < (BP_ORDER - 1) / 2 && !node->children[i]->is_leaf)
        {
            // Similar to leaf node case, handle borrowing or merging
            // For internal nodes, this is more complex
            // ...
        }

        // If parent has become empty (only happens when root becomes empty)
        if (node == tree->root && node->num_keys == 0)
        {
            tree->root = node->children[0];
            free(node);
            tree->height--;
            tree->node_count--;
        }

        return result;
    }
}


static void free_node(BPTreeNode *node)
{
    if (!node)
        return;
    if (!node->is_leaf)
    {
        for (int i = 0; i <= node->num_keys; i++)
        {
            free_node(node->children[i]);
        }
    }
    free(node);
}

static void free_tree(BPTree *tree)
{
    if (tree)
    {
        free_node(tree->root);
        free(tree);
    }
}


int db_get_next_row(Table *table, int current_key)
{
    if (!table || !table->is_open)
    {
        printf("Error: Invalid or closed table\n");
        return -1;
    }

    // Special case: if current_key is -1, return the first key
    if (current_key == -1)
    {
        BPTreeNode *node = table->index->root;

        // Navigate to leftmost leaf
        while (!node->is_leaf)
        {
            node = node->children[0];
        }

        if (node->num_keys > 0)
        {
            return node->keys[0];
        }
        else
        {
            return -1; // Empty tree
        }
    }
}
