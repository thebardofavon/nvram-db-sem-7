#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/free_space.h"
#include "../include/ram_bptree.h"
#include "../include/wal.h"
#include "../include/lock_manager.h"

// Maximum number of tables
#define MAX_TABLES 10
#define MAX_TABLE_NAME 64

// B+ Tree node structure (in RAM)
struct BPTreeNode
{
    bool is_leaf;           // Is this a leaf node?
    int num_keys;           // Number of keys currently stored
    int keys[BP_ORDER - 1]; // Array of keys (row IDs)

    union
    {
        BPTreeNode *children[BP_ORDER]; // Internal node: pointers to children
        struct
        {
            NVRAMPtr data_ptrs[BP_ORDER - 1]; // Leaf node: pointers to data in NVRAM
            size_t data_sizes[BP_ORDER - 1];  // Size of each data item
        };
    };

    BPTreeNode *next_leaf; // Pointer to next leaf (for range queries)
};

// B+ Tree structure (in RAM)
struct BPTree
{
    BPTreeNode *root; // Root node of the tree
    int height;       // Height of the tree
    int node_count;   // Number of nodes
    int record_count; // Number of records
};

// Table structure (in RAM)
struct Table
{
    char name[MAX_TABLE_NAME]; // Table name
    int table_id;              // Unique ID
    BPTree *index;             // B+ Tree index
    bool is_open;              // Is table open
};

// Global state
static Table *tables[MAX_TABLES] = {NULL};
static int next_table_id = 0;
static bool is_initialized = false;

// Global lock manager
LockManager g_lock_manager;

// Helper function to allocate a new node in RAM
static BPTreeNode *create_node(bool is_leaf)
{
    BPTreeNode *node = (BPTreeNode *)malloc(sizeof(BPTreeNode));
    if (!node)
        return NULL;

    // Initialize node
    node->is_leaf = is_leaf;
    node->num_keys = 0;
    node->next_leaf = NULL;

    // Clear memory
    memset(node->keys, 0, sizeof(node->keys));

    if (is_leaf)
    {
        // Clear data pointers and sizes
        memset(node->data_ptrs, 0, sizeof(node->data_ptrs));
        memset(node->data_sizes, 0, sizeof(node->data_sizes));
    }
    else
    {
        // Clear children pointers
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

    // Create root node (initially a leaf)
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

// Helper function to split a leaf node
static BPTreeNode *split_leaf(BPTree *tree, BPTreeNode *leaf, int *up_key)
{
    // Create a new leaf node
    BPTreeNode *new_leaf = create_node(true);
    if (!new_leaf)
        return NULL;

    // Find median position
    int mid = (BP_ORDER - 1) / 2;

    // Set the up key (key that will go to parent)
    *up_key = leaf->keys[mid];

    // Copy upper half of keys and data to new leaf
    for (int i = mid; i < leaf->num_keys; i++)
    {
        new_leaf->keys[i - mid] = leaf->keys[i];
        new_leaf->data_ptrs[i - mid] = leaf->data_ptrs[i];
        new_leaf->data_sizes[i - mid] = leaf->data_sizes[i];

        // Clear original entries (optional)
        leaf->keys[i] = 0;
        leaf->data_ptrs[i] = NULL;
        leaf->data_sizes[i] = 0;
    }

    // Update key counts
    new_leaf->num_keys = leaf->num_keys - mid;
    leaf->num_keys = mid;

    // Link leaves for sequential access
    new_leaf->next_leaf = leaf->next_leaf;
    leaf->next_leaf = new_leaf;

    // Update tree stats
    tree->node_count++;

    return new_leaf;
}

// Helper function to split an internal node
static BPTreeNode *split_internal(BPTree *tree, BPTreeNode *node, int *up_key)
{
    // Create a new internal node
    BPTreeNode *new_node = create_node(false);
    if (!new_node)
        return NULL;

    // Find median position
    int mid = (BP_ORDER - 1) / 2;

    // Set the up key (key that will go to parent)
    *up_key = node->keys[mid];

    // Copy upper half of keys to new node
    for (int i = mid + 1; i < node->num_keys; i++)
    {
        new_node->keys[i - (mid + 1)] = node->keys[i];
        node->keys[i] = 0; // Clear original entry
    }

    // Copy upper half of children to new node
    for (int i = mid + 1; i <= node->num_keys; i++)
    {
        new_node->children[i - (mid + 1)] = node->children[i];
        node->children[i] = NULL; // Clear original entry
    }

    // Update key counts
    new_node->num_keys = node->num_keys - (mid + 1);
    node->num_keys = mid;

    // Update tree stats
    tree->node_count++;

    return new_node;
}

// Helper function to insert a key into an internal node
static bool insert_in_internal(BPTree *tree, BPTreeNode *node, int key, BPTreeNode *right_child)
{
    // Find position to insert
    int i = node->num_keys - 1;
    while (i >= 0 && node->keys[i] > key)
    {
        node->keys[i + 1] = node->keys[i];
        node->children[i + 2] = node->children[i + 1];
        i--;
    }

    // Insert key and child
    node->keys[i + 1] = key;
    node->children[i + 2] = right_child;
    node->num_keys++;

    return true;
}

// Find the leaf node where a key should be located
static BPTreeNode *find_leaf(BPTree *tree, int key)
{
    if (!tree || !tree->root)
        return NULL;

    BPTreeNode *node = tree->root;
    while (!node->is_leaf)
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

// Find position of key in leaf node. Returns index if found, -1 if not found
static int find_key_in_leaf(BPTreeNode *leaf, int key)
{
    for (int i = 0; i < leaf->num_keys; i++)
    {
        if (leaf->keys[i] == key)
        {
            return i;
        }
    }
    return -1; // Key not found
}

// Helper function to insert key recursively
static bool insert_recursive(BPTree *tree, BPTreeNode *node, int key, void *data, size_t size, int *up_key, BPTreeNode **new_node)
{
    if (node->is_leaf)
    {
        // Case 1: Leaf node

        // Check if key already exists
        int pos = find_key_in_leaf(node, key);
        if (pos != -1)
        {
            // Update existing row
            // Free old data
            free_memory(node->data_ptrs[pos], node->data_sizes[pos]);

            // Update with new data
            node->data_ptrs[pos] = data;
            node->data_sizes[pos] = size;
            return true;
        }

        // Find position to insert
        int i = node->num_keys - 1;
        while (i >= 0 && node->keys[i] > key)
        {
            node->keys[i + 1] = node->keys[i];
            node->data_ptrs[i + 1] = node->data_ptrs[i];
            node->data_sizes[i + 1] = node->data_sizes[i];
            i--;
        }

        // Insert key and data
        node->keys[i + 1] = key;
        node->data_ptrs[i + 1] = data;
        node->data_sizes[i + 1] = size;
        node->num_keys++;

        // Check if node needs splitting
        if (node->num_keys >= BP_ORDER - 1)
        {
            *new_node = split_leaf(tree, node, up_key);
            return *new_node != NULL;
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
        BPTreeNode *new_child = NULL;
        int child_up_key;

        // Recursive insertion
        if (!insert_recursive(tree, child, key, data, size, &child_up_key, &new_child))
        {
            return false;
        }

        // If child did not split, we're done
        if (new_child == NULL)
        {
            return true;
        }

        // If child split, we need to insert the new key and child
        if (node->num_keys < BP_ORDER - 1)
        {
            // Node has space
            return insert_in_internal(tree, node, child_up_key, new_child);
        }
        else
        {
            // Node needs to split
            insert_in_internal(tree, node, child_up_key, new_child);
            *new_node = split_internal(tree, node, up_key);
            return *new_node != NULL;
        }
    }
}

// Helper function to find minimum key in a subtree
static int find_min_key(BPTreeNode *node)
{
    if (!node)
        return -1;

    // Navigate to leftmost leaf
    while (!node->is_leaf)
    {
        node = node->children[0];
    }

    if (node->num_keys > 0)
    {
        return node->keys[0];
    }

    return -1;
}

// Helper function to merge nodes
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

// Helper function to remove key recursively
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

// Helper function to free a B+ Tree node recursively
static void free_node(BPTreeNode *node)
{
    if (!node)
        return;

    if (!node->is_leaf)
    {
        // Free children recursively
        for (int i = 0; i <= node->num_keys; i++)
        {
            free_node(node->children[i]);
        }
    }

    free(node);
}

// Helper function to free a B+ Tree
static void free_tree(BPTree *tree)
{
    if (tree)
    {
        free_node(tree->root);
        free(tree);
    }
}

// Initialize database system
void db_init()
{
    if (is_initialized)
        return;

    // Initialize NVRAM free space manager
    init_free_space();

    // Initialize lock manager
    lock_manager_init(&g_lock_manager);

    // Initialize tables array
    for (int i = 0; i < MAX_TABLES; i++)
    {
        tables[i] = NULL;
    }

    is_initialized = true;
    printf("Database system initialized\n");
}

// Shutdown database system
void db_shutdown()
{
    if (!is_initialized)
        return;

    // Close and free all tables
    for (int i = 0; i < MAX_TABLES; i++)
    {
        if (tables[i])
        {
            // Free NVRAM data for all records
            if (tables[i]->index)
            {
                // We would need to traverse all leaves and free NVRAM data
                // For brevity, this code is omitted
                free_tree(tables[i]->index);
            }
            free(tables[i]);
            tables[i] = NULL;
        }
    }

    // Clean up NVRAM
    cleanup_free_space();

    // Clean up lock manager
    lock_manager_cleanup(&g_lock_manager);

    is_initialized = false;
    printf("Database system shut down\n");
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
        // Update WAL commit pointers for all tables
        // In a real implementation, you would track which tables were modified
        // by the transaction and only update those
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
    return transaction_abort(&g_lock_manager, txn_id);
}

// Create a new table
int db_create_table(const char *name)
{
    if (!is_initialized)
    {
        printf("Error: Database not initialized\n");
        return -1;
    }

    // Find a free slot in tables array
    int slot = -1;
    for (int i = 0; i < MAX_TABLES; i++)
    {
        if (tables[i] == NULL)
        {
            slot = i;
            break;
        }
    }

    if (slot == -1)
    {
        printf("Error: Maximum number of tables reached\n");
        return -1;
    }

    // Check if table with same name already exists
    for (int i = 0; i < MAX_TABLES; i++)
    {
        if (tables[i] && strcmp(tables[i]->name, name) == 0)
        {
            printf("Error: Table '%s' already exists\n", name);
            return -1;
        }
    }

    // Create table structure
    Table *table = (Table *)malloc(sizeof(Table));
    if (!table)
    {
        printf("Error: Failed to allocate memory for table\n");
        return -1;
    }

    // Create B+ Tree index
    BPTree *tree = create_tree();
    if (!tree)
    {
        printf("Error: Failed to create index for table\n");
        free(table);
        return -1;
    }

    // Initialize table
    strncpy(table->name, name, MAX_TABLE_NAME - 1);
    table->name[MAX_TABLE_NAME - 1] = '\0';
    table->table_id = next_table_id++;
    table->index = tree;
    table->is_open = true;

    // Create WAL table in NVRAM
    void *wal_table_ptr = allocate_memory(sizeof(WALTable));
    if (!wal_table_ptr)
    {
        printf("Error: Failed to allocate NVRAM for WAL table\n");
        free_tree(tree);
        free(table);
        return -1;
    }

    // Initialize WAL table
    if (!wal_create_table(table->table_id, wal_table_ptr))
    {
        printf("Error: Failed to create WAL table\n");
        free_memory(wal_table_ptr, sizeof(WALTable));
        free_tree(tree);
        free(table);
        return -1;
    }

    // Add to tables array
    tables[slot] = table;

    printf("Table '%s' created with ID %d\n", name, table->table_id);
    return table->table_id;
}

// Open an existing table
Table *db_open_table(const char *name)
{
    if (!is_initialized)
    {
        printf("Error: Database not initialized\n");
        return NULL;
    }

    for (int i = 0; i < MAX_TABLES; i++)
    {
        if (tables[i] && strcmp(tables[i]->name, name) == 0)
        {
            tables[i]->is_open = true;
            return tables[i];
        }
    }

    printf("Error: Table '%s' not found\n", name);
    return NULL;
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
    {
        printf("Error: Invalid or closed table\n");
        return NULL;
    }

    // Acquire locks
    if (!lock_acquire(&g_lock_manager, txn_id, table->table_id, true, LOCK_SHARED))
    {
        printf("Error: Could not acquire table lock\n");
        return NULL;
    }

    if (!lock_acquire(&g_lock_manager, txn_id, key, false, LOCK_SHARED))
    {
        printf("Error: Could not acquire row lock\n");
        lock_release(&g_lock_manager, txn_id, table->table_id, true);
        return NULL;
    }

    // Find leaf node containing key
    BPTreeNode *leaf = find_leaf(table->index, key);
    if (!leaf)
    {
        lock_release(&g_lock_manager, txn_id, key, false);
        lock_release(&g_lock_manager, txn_id, table->table_id, true);
        return NULL;
    }

    // Find key in leaf
    int pos = find_key_in_leaf(leaf, key);
    if (pos == -1)
    {
        // Key not found
        lock_release(&g_lock_manager, txn_id, key, false);
        lock_release(&g_lock_manager, txn_id, table->table_id, true);
        return NULL;
    }

    // Return data pointer and size
    if (size)
        *size = leaf->data_sizes[pos];

    // No need to release locks yet since the transaction is still ongoing
    // They will be released when the transaction commits or aborts
    return leaf->data_ptrs[pos];
}

// Insert or update a row
bool db_put_row(Table *table, int txn_id, int key, void *data, size_t size)
{
    if (!table || !table->is_open)
    {
        printf("Error: Invalid or closed table\n");
        return false;
    }

    // Acquire locks
    if (!lock_acquire(&g_lock_manager, txn_id, table->table_id, true, LOCK_SHARED))
    {
        printf("Error: Could not acquire table lock\n");
        return false;
    }

    if (!lock_acquire(&g_lock_manager, txn_id, key, false, LOCK_EXCLUSIVE))
    {
        printf("Error: Could not acquire row lock\n");
        lock_release(&g_lock_manager, txn_id, table->table_id, true);
        return false;
    }

    BPTreeNode *leaf = find_leaf(table->index, key);
    if (leaf)
    {
        // Check if key already exists
        int pos = find_key_in_leaf(leaf, key);
        if (pos != -1)
        {
            // Key already exists, do not insert
            lock_release(&g_lock_manager, txn_id, key, false);
            lock_release(&g_lock_manager, txn_id, table->table_id, true);
            return false; // Row already exists
        }
    }

    // CHANGED: Create WAL entry BEFORE allocating NVRAM memory
    // Add WAL entry for the insertion
    void *wal_entry_ptr = allocate_memory(sizeof(WALEntry));
    if (!wal_entry_ptr)
    {
        printf("Error: Failed to allocate NVRAM for WAL entry\n");
        lock_release(&g_lock_manager, txn_id, key, false);
        lock_release(&g_lock_manager, txn_id, table->table_id, true);
        return false;
    }

    // Allocate space in NVRAM for data
    NVRAMPtr nvram_data = allocate_memory(size);
    if (!nvram_data)
    {
        printf("Error: Failed to allocate NVRAM space for data\n");
        free_memory(wal_entry_ptr, sizeof(WALEntry));
        lock_release(&g_lock_manager, txn_id, key, false);
        lock_release(&g_lock_manager, txn_id, table->table_id, true);
        return false;
    }

    // Copy data to NVRAM
    memcpy(nvram_data, data, size);

    // Flush the data to NVRAM
    flush_range(nvram_data, size);

    // Add entry to WAL (1 for insertion)
    if (!wal_add_entry(table->table_id, key, nvram_data, 1, wal_entry_ptr, size))
    {
        printf("Error: Failed to add WAL entry\n");
        free_memory(wal_entry_ptr, sizeof(WALEntry));
        free_memory(nvram_data, size);
        lock_release(&g_lock_manager, txn_id, key, false);
        lock_release(&g_lock_manager, txn_id, table->table_id, true);
        return false;
    }

    // Handle empty tree case
    if (table->index->root == NULL)
    {
        table->index->root = create_node(true);
        if (!table->index->root)
        {
            printf("Error: Failed to create root node\n");
            free_memory(nvram_data, size);
            lock_release(&g_lock_manager, txn_id, key, false);
            lock_release(&g_lock_manager, txn_id, table->table_id, true);
            return false;
        }

        table->index->root->keys[0] = key;
        table->index->root->data_ptrs[0] = nvram_data;
        table->index->root->data_sizes[0] = size;
        table->index->root->num_keys = 1;
        table->index->record_count++;

        // No need to release locks yet since the transaction is still ongoing
        // They will be released when the transaction commits or aborts
        return true;
    }

    // Recursive insertion
    int up_key;
    BPTreeNode *new_node = NULL;

    if (!insert_recursive(table->index, table->index->root, key, nvram_data, size, &up_key, &new_node))
    {
        printf("Error: Failed to insert key\n");
        free_memory(nvram_data, size);
        lock_release(&g_lock_manager, txn_id, key, false);
        lock_release(&g_lock_manager, txn_id, table->table_id, true);
        return false;
    }

    // Root split case
    if (new_node != NULL)
    {
        // Create new root
        BPTreeNode *new_root = create_node(false);
        if (!new_root)
        {
            printf("Error: Failed to create new root\n");
            free_node(new_node);
            lock_release(&g_lock_manager, txn_id, key, false);
            lock_release(&g_lock_manager, txn_id, table->table_id, true);
            return false;
        }

        // Set up new root
        new_root->keys[0] = up_key;
        new_root->children[0] = table->index->root;
        new_root->children[1] = new_node;
        new_root->num_keys = 1;

        // Update tree
        table->index->root = new_root;
        table->index->height++;
        table->index->node_count++;
    }

    // Update record count
    table->index->record_count++;

    // No need to release locks yet since the transaction is still ongoing
    // They will be released when the transaction commits or aborts
    return true;
}

// Delete a row
bool db_delete_row(Table *table, int txn_id, int key)
{
    if (!table || !table->is_open)
    {
        printf("Error: Invalid or closed table\n");
        return false;
    }

    // Acquire locks
    if (!lock_acquire(&g_lock_manager, txn_id, table->table_id, true, LOCK_SHARED))
    {
        printf("Error: Could not acquire table lock\n");
        return false;
    }

    if (!lock_acquire(&g_lock_manager, txn_id, key, false, LOCK_EXCLUSIVE))
    {
        printf("Error: Could not acquire row lock\n");
        lock_release(&g_lock_manager, txn_id, table->table_id, true);
        return false;
    }

    // Find the data and its size before deleting
    size_t data_size = 0;
    void *data_ptr = NULL;

    // Find leaf node containing key
    BPTreeNode *leaf = find_leaf(table->index, key);
    if (leaf)
    {
        // Find key in leaf
        int pos = find_key_in_leaf(leaf, key);
        if (pos != -1)
        {
            data_ptr = leaf->data_ptrs[pos];
            data_size = leaf->data_sizes[pos];
        }
    }

    if (!data_ptr)
    {
        printf("Error: Row to delete not found\n");
        lock_release(&g_lock_manager, txn_id, key, false);
        lock_release(&g_lock_manager, txn_id, table->table_id, true);
        return false;
    }

    // CHANGED: Add WAL entry for deletion before actually deleting data
    void *wal_entry_ptr = allocate_memory(sizeof(WALEntry));
    if (!wal_entry_ptr)
    {
        printf("Error: Failed to allocate NVRAM for WAL entry\n");
        lock_release(&g_lock_manager, txn_id, key, false);
        lock_release(&g_lock_manager, txn_id, table->table_id, true);
        return false;
    }

    // Add entry to WAL (0 for deletion)
    if (!wal_add_entry(table->table_id, key, data_ptr, 0, wal_entry_ptr, data_size))
    {
        printf("Error: Failed to add WAL entry\n");
        free_memory(wal_entry_ptr, sizeof(WALEntry));
        lock_release(&g_lock_manager, txn_id, key, false);
        lock_release(&g_lock_manager, txn_id, table->table_id, true);
        return false;
    }

    // Handle empty tree case
    if (table->index->root == NULL)
    {
        lock_release(&g_lock_manager, txn_id, key, false);
        lock_release(&g_lock_manager, txn_id, table->table_id, true);
        return false;
    }

    // Recursive deletion
    bool result = remove_recursive(table->index, table->index->root, key, NULL, 0);

    if (result)
    {
        // Update record count
        table->index->record_count--;
    }

    // No need to release locks yet since the transaction is still ongoing
    // They will be released when the transaction commits or aborts
    return result;
}
// Get the next row for iteration
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

    // Find leaf containing current key
    BPTreeNode *leaf = find_leaf(table->index, current_key);
    if (!leaf)
        return -1;

    // Find position of current key
    int pos = find_key_in_leaf(leaf, current_key);
    if (pos == -1)
    {
        // Current key not found
        return -1;
    }

    // Check if there's a next key in the same leaf
    if (pos + 1 < leaf->num_keys)
    {
        return leaf->keys[pos + 1];
    }

    // Otherwise, move to next leaf
    if (leaf->next_leaf && leaf->next_leaf->num_keys > 0)
    {
        return leaf->next_leaf->keys[0];
    }

    // No more keys
    return -1;
}