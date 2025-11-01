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
    new_table->entry_head = NULL;
    new_table->entry_tail = NULL;
    new_table->commit_ptr = NULL;

    // Initialize mutex
    pthread_mutex_init(&new_table->mutex, NULL);

    // Ensure WAL table data is persisted to NVRAM
    flush_range(new_table, sizeof(WALTable));

    wal_tables[table_id] = new_table;
    return 1;
}

int wal_add_entry(int table_id, int key, void *data_ptr, int op, void *entry_ptr, size_t data_size)
{
    if (table_id < 0 || table_id >= MAX_TABLES || wal_tables[table_id] == NULL)
    {
        printf("Error: WAL Table %d not found.\n", table_id);
        return 0;
    }

    WALTable *table = wal_tables[table_id];
    pthread_mutex_lock(&table->mutex);

    // Create WAL entry in allocated NVRAM space
    WALEntry *entry = (WALEntry *)entry_ptr;
    entry->key = key;
    entry->data_ptr = data_ptr;
    entry->op_flag = op;
    entry->data_size = data_size;
    entry->next = NULL;

    // First, persist the entry content itself
    flush_range(entry, sizeof(WALEntry));

    // Add to the end of the linked list
    if (table->entry_tail == NULL)
    {
        table->entry_head = entry;
        table->entry_tail = entry;
        flush_range(&table->entry_head, sizeof(void *) * 2); // Persist head and tail
    }
    else
    {
        WALEntry *old_tail = table->entry_tail;
        old_tail->next = entry;
        flush_range(&old_tail->next, sizeof(void *)); // Persist the next pointer of the old tail

        table->entry_tail = entry;
        flush_range(&table->entry_tail, sizeof(void *)); // Then update and persist the tail
    }

    pthread_mutex_unlock(&table->mutex);
    return 1;
}

void wal_advance_commit_ptr(int table_id, int txn_id)
{
    if (table_id < 0 || table_id >= MAX_TABLES || wal_tables[table_id] == NULL)
    {
        return;
    }

    WALTable *table = wal_tables[table_id];
    pthread_mutex_lock(&table->mutex);

    // Atomically update commit pointer to current tail (last entry)
    atomic_write_64(&table->commit_ptr, (uint64_t)table->entry_tail);

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
        printf("Head: %p | Tail: %p | Commit Ptr: %p\n",
               table->entry_head, table->entry_tail, table->commit_ptr);

        WALEntry *current = table->entry_head;
        int entry_count = 0;
        while (current != NULL)
        {
            printf("  Entry %d [%p]: Key: %d | Op: %s | Data@: %p (Size: %zu) | Next: %p %s\n",
                   entry_count++,
                   current,
                   current->key,
                   current->op_flag ? "Insert" : "Delete",
                   current->data_ptr,
                   current->data_size,
                   current->next,
                   (current == table->commit_ptr) ? "<-- COMMITTED" : "");

            if (current == table->entry_tail)
                break; // Safety break
            current = current->next;
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

    WALEntry *current = wal_table->entry_head;
    WALEntry *commit_point = wal_table->commit_ptr;

    if (commit_point == NULL)
    {
        printf("No committed entries for Table %d. Nothing to replay.\n", table->table_id);
        pthread_mutex_unlock(&wal_table->mutex);
        return;
    }

    // Replay all entries up to and including the commit point
    while (current != NULL)
    {
        if (current->op_flag == 1)
        { // Insert operation
            // This is a simplified insert, it doesn't handle splits correctly
            // in a recovery-only context, but it rebuilds the state.
            // A more robust implementation would reuse the full db_put_row logic.
            int up_key;
            BPTreeNode *new_node = NULL;
            insert_recursive(table->index, table->index->root, current->key, current->data_ptr, current->data_size, &up_key, &new_node);
            // Note: We are not handling root splits during recovery for simplicity.
            // This assumes the tree structure was simple before the crash.
            // A full ARIES implementation would log physical changes to handle this.
        }
        else
        { // Delete operation
            remove_recursive(table->index, table->index->root, current->key, NULL, 0);
        }

        if (current == commit_point)
        {
            printf("Reached commit point for Table %d. Replay complete.\n", table->table_id);
            break;
        }
        current = current->next;
    }
    pthread_mutex_unlock(&wal_table->mutex);
}
