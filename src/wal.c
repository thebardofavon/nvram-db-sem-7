#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <immintrin.h> // For Intel intrinsics (_mm_clwb, _mm_stream_si64, etc.)
#include "../include/wal.h"
#include "../include/ram_bptree.h"
#include "../include/free_space.h" // For nvram_map access

// Global array of RAM pointers to the NVRAM WALTable structures
WALTable *wal_tables[MAX_TABLES] = {NULL};

// External declaration from ram_bptree.c
extern BPTreeNode *find_leaf(BPTree *tree, int key);
extern int find_key_in_leaf(BPTreeNode *leaf, int key);
extern bool insert_recursive(BPTree *tree, BPTreeNode *node, int key, void *data, size_t size, int *up_key, BPTreeNode **new_node);
extern bool remove_recursive(BPTree *tree, BPTreeNode *node, int key, BPTreeNode *parent, int parent_idx);
extern BPTreeNode *create_node(bool is_leaf); // Need to access this for recovery
extern void *nvram_map; // Access to the NVRAM base address

// Helper macros to convert between pointers and offsets
#define PTR_TO_OFFSET(ptr) ((ptr) ? (size_t)((char*)(ptr) - (char*)nvram_map) : 0)
#define OFFSET_TO_PTR(offset, type) ((offset) ? (type*)((char*)nvram_map + (offset)) : NULL)

// NVRAM persistence functions
void flush_range(void *start, size_t size)
{
    char *ptr = (char *)start;
    // Align to cache line boundary
    ptr = (char *)((uintptr_t)ptr & ~(63));
    size += (char *)start - ptr;

    for (size_t i = 0; i < size; i += 64)
    {
        _mm_clwb(ptr + i);
    }
    _mm_sfence(); // Ensure all previous stores are visible
}

// Atomic 64-bit write using non-temporal store (movnti)
void atomic_write_64(void *dest, uint64_t val)
{
    _mm_stream_si64((long long *)dest, (long long)val);
    _mm_sfence(); // Ensure the write is committed
}

int wal_create_table(int table_id, void *memory_ptr)
{
    if (table_id < 0 || table_id >= MAX_TABLES)
    {
        printf("Error: Invalid table ID %d.\n", table_id);
        return 0;
    }

    if (wal_tables[table_id] != NULL)
    {
        printf("Error: WAL Table ID %d already exists.\n", table_id);
        return 0;
    }

    // Initialize the WAL table in allocated NVRAM space
    WALTable *new_table = (WALTable *)memory_ptr;
    new_table->table_id = table_id;
    new_table->entry_head_offset = 0; // 0 means NULL
    new_table->entry_tail_offset = 0;
    new_table->commit_offset = 0;

    // Initialize mutex
    pthread_mutex_init(&new_table->mutex, NULL);

    // Ensure WAL table data is persisted to NVRAM
    flush_range(new_table, sizeof(WALTable));

    wal_tables[table_id] = new_table;
    return 1;
}


void* wal_add_entry(int table_id, int key, void *data_ptr, WALOperation op, void *entry_ptr, size_t data_size)
{
    if (table_id < 0 || table_id >= MAX_TABLES || wal_tables[table_id] == NULL)
    {
        printf("Error: WAL Table %d not found.\n", table_id);
        return NULL; // Return NULL on failure
    }

    WALTable *table = wal_tables[table_id];
    pthread_mutex_lock(&table->mutex);

    WALEntry *entry = (WALEntry *)entry_ptr;
    entry->key = key;
    entry->data_offset = PTR_TO_OFFSET(data_ptr);
    entry->op_flag = op;
    entry->data_size = data_size;
    entry->next_offset = 0; // NULL
    flush_range(entry, sizeof(WALEntry));

    size_t entry_offset = PTR_TO_OFFSET(entry);

    if (table->entry_tail_offset == 0)
    {
        table->entry_head_offset = entry_offset;
        table->entry_tail_offset = entry_offset;
        flush_range(&table->entry_head_offset, sizeof(size_t) * 2);
    }
    else
    {
        WALEntry *old_tail = OFFSET_TO_PTR(table->entry_tail_offset, WALEntry);
        old_tail->next_offset = entry_offset;
        flush_range(&old_tail->next_offset, sizeof(size_t));
        table->entry_tail_offset = entry_offset;
        flush_range(&table->entry_tail_offset, sizeof(size_t));
    }

    pthread_mutex_unlock(&table->mutex);
    return entry; // Return the pointer to the new entry on success
}

void wal_advance_commit_ptr(int table_id, int txn_id)
{
    (void)txn_id; // Tell compiler we know this is unused for now
    if (table_id < 0 || table_id >= MAX_TABLES || wal_tables[table_id] == NULL)
    {
        return;
    }

    WALTable *table = wal_tables[table_id];
    pthread_mutex_lock(&table->mutex);
    atomic_write_64(&table->commit_offset, (uint64_t)table->entry_tail_offset);
    pthread_mutex_unlock(&table->mutex);
}

void wal_show_data()
{
    for (int i = 0; i < MAX_TABLES; i++)
    {
        if (wal_tables[i] == NULL)
            continue;

        WALTable *table = wal_tables[i];
        pthread_mutex_lock(&table->mutex);

        printf("\n--- WAL for Table ID: %d ---\n", table->table_id);
        printf("Head: %zu | Tail: %zu | Commit: %zu\n",
               table->entry_head_offset, table->entry_tail_offset, table->commit_offset);

        WALEntry *current = OFFSET_TO_PTR(table->entry_head_offset, WALEntry);
        size_t commit_offset = table->commit_offset;
        int entry_count = 0;
        while (current != NULL)
        {
            size_t current_offset = PTR_TO_OFFSET(current);
            printf("  Entry %d [%zu]: Key: %d | Op: %s | Data@: %zu (Size: %zu) | Next: %zu %s\n",
                   entry_count++,
                   current_offset,
                   current->key,
                   current->op_flag ? "Insert" : "Delete",
                   current->data_offset,
                   current->data_size,
                   current->next_offset,
                   (current_offset == commit_offset) ? "<-- COMMITTED" : "");

            if (current_offset == table->entry_tail_offset)
                break; // Safety break
            current = OFFSET_TO_PTR(current->next_offset, WALEntry);
        }
        pthread_mutex_unlock(&table->mutex);
    }
}

// Replays the log for a single table to rebuild its B+Tree index.
// This is the core of the REDO phase of crash recovery.
void wal_replay_log_for_table(Table *table)
{
    if (!table || table->table_id < 0 || table->table_id >= MAX_TABLES)
        return;

    WALTable *wal_table = wal_tables[table->table_id];
    if (!wal_table)
        return;

    printf("Replaying WAL for Table ID %d (%s)...\n", table->table_id, table->name);

    pthread_mutex_lock(&wal_table->mutex);

    WALEntry *current = OFFSET_TO_PTR(wal_table->entry_head_offset, WALEntry);
    size_t commit_offset = wal_table->commit_offset;

    if (commit_offset == 0)
    {
        printf("No committed entries for Table %d. Nothing to replay.\n", table->table_id);
        pthread_mutex_unlock(&wal_table->mutex);
        return;
    }

    // Replay all entries up to and including the commit point
    while (current != NULL)
    {
        void *data_ptr = OFFSET_TO_PTR(current->data_offset, void);
        
        if (current->op_flag == 1)
        { // Insert operation
            // This is a simplified insert, it doesn't handle splits correctly
            // in a recovery-only context, but it rebuilds the state.
            // A more robust implementation would reuse the full db_put_row logic.
            int up_key;
            BPTreeNode *new_node = NULL;
            bool inserted = insert_recursive(table->index, table->index->root, current->key, data_ptr, current->data_size, &up_key, &new_node);
            
            if (inserted) {
                // Handle root split if necessary
                if (new_node != NULL) {
                    BPTreeNode *new_root = create_node(false);
                    new_root->keys[0] = up_key;
                    new_root->children[0] = table->index->root;
                    new_root->children[1] = new_node;
                    new_root->num_keys = 1;
                    table->index->root = new_root;
                    table->index->height++;
                    table->index->node_count++;
                }
                table->index->record_count++;
            }
        }
        else
        { // Delete operation
            remove_recursive(table->index, table->index->root, current->key, NULL, 0);
        }

        size_t current_offset = PTR_TO_OFFSET(current);
        if (current_offset == commit_offset)
        {
            printf("Reached commit point for Table %d. Replay complete.\n", table->table_id);
            break;
        }
        current = OFFSET_TO_PTR(current->next_offset, WALEntry);
    }
    pthread_mutex_unlock(&wal_table->mutex);
}
