#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/lock_manager.h"

// Initialize lock manager
void lock_manager_init(LockManager *lm)
{
    lm->lock_table = NULL;
    lm->transactions = NULL;
    pthread_mutex_init(&lm->mutex, NULL);
    lm->next_txn_id = 1;
}

// Start a new transaction
int transaction_begin(LockManager *lm)
{
    pthread_mutex_lock(&lm->mutex);

    // Create new transaction
    Transaction *txn = (Transaction *)malloc(sizeof(Transaction));
    if (!txn)
    {
        pthread_mutex_unlock(&lm->mutex);
        return -1;
    }

    txn->id = lm->next_txn_id++;
    txn->active = true;
    txn->held_locks = NULL;

    // Add to transaction list
    txn->next = lm->transactions;
    lm->transactions = txn;

    int txn_id = txn->id;
    pthread_mutex_unlock(&lm->mutex);

    return txn_id;
}

// Find a transaction by ID
static Transaction *find_transaction(LockManager *lm, int txn_id)
{
    Transaction *txn = lm->transactions;
    while (txn)
    {
        if (txn->id == txn_id)
        {
            return txn;
        }
        txn = txn->next;
    }
    return NULL;
}

// Find a lock entry
static LockEntry *find_lock_entry(LockManager *lm, int resource_id, bool is_table)
{
    LockEntry *entry = lm->lock_table;
    while (entry)
    {
        if (entry->resource_id == resource_id && entry->is_table == is_table)
        {
            return entry;
        }
        entry = entry->next;
    }
    return NULL;
}

// Add a lock request to transaction's held locks
static void add_lock_to_transaction(Transaction *txn, int resource_id, bool is_table, LockMode mode)
{
    LockRequest *req = (LockRequest *)malloc(sizeof(LockRequest));
    if (!req)
        return;

    req->transaction_id = txn->id;
    req->resource_id = resource_id;
    req->is_table = is_table;
    req->mode = mode;

    req->next = txn->held_locks;
    txn->held_locks = req;
}

// Can a lock be granted?
static bool can_grant_lock(LockEntry *entry, LockMode mode, int txn_id)
{
    if (mode == LOCK_SHARED)
    {
        // Shared lock can be granted if:
        // 1. No exclusive lock
        // 2. Exclusive lock is held by the same transaction
        return (entry->exclusive_owner == -1 || entry->exclusive_owner == txn_id);
    }
    else
    { // LOCK_EXCLUSIVE
        // Exclusive lock can be granted if:
        // 1. No exclusive lock and no shared locks
        // 2. The transaction already holds the exclusive lock
        return ((entry->exclusive_owner == -1 && entry->shared_count == 0) ||
                entry->exclusive_owner == txn_id);
    }
}

// Process waiting lock requests
static void process_waiting_requests(LockManager *lm, LockEntry *entry)
{
    LockRequest *prev = NULL;
    LockRequest *curr = entry->waiting_list;

    while (curr)
    {
        if (can_grant_lock(entry, curr->mode, curr->transaction_id))
        {
            // Grant the lock
            Transaction *txn = find_transaction(lm, curr->transaction_id);
            if (txn)
            {
                if (curr->mode == LOCK_SHARED)
                {
                    entry->shared_count++;
                }
                else
                { // LOCK_EXCLUSIVE
                    entry->exclusive_owner = txn->id;
                }

                add_lock_to_transaction(txn, curr->resource_id, curr->is_table, curr->mode);
            }

            // Remove from waiting list
            if (prev)
            {
                prev->next = curr->next;
            }
            else
            {
                entry->waiting_list = curr->next;
            }

            LockRequest *to_free = curr;
            curr = curr->next;
            free(to_free);
        }
        else
        {
            prev = curr;
            curr = curr->next;
        }
    }
}

// Acquire a lock
bool lock_acquire(LockManager *lm, int txn_id, int resource_id, bool is_table, LockMode mode)
{
    pthread_mutex_lock(&lm->mutex);

    // Find the transaction
    Transaction *txn = find_transaction(lm, txn_id);
    if (!txn || !txn->active)
    {
        pthread_mutex_unlock(&lm->mutex);
        return false;
    }

    // Find or create lock entry
    LockEntry *entry = find_lock_entry(lm, resource_id, is_table);
    if (!entry)
    {
        entry = (LockEntry *)malloc(sizeof(LockEntry));
        if (!entry)
        {
            pthread_mutex_unlock(&lm->mutex);
            return false;
        }

        entry->resource_id = resource_id;
        entry->is_table = is_table;
        entry->shared_count = 0;
        entry->exclusive_owner = -1;
        entry->waiting_list = NULL;

        entry->next = lm->lock_table;
        lm->lock_table = entry;
    }

    // Check if lock can be granted immediately
    if (can_grant_lock(entry, mode, txn_id))
    {
        if (mode == LOCK_SHARED)
        {
            entry->shared_count++;
        }
        else
        { // LOCK_EXCLUSIVE
            entry->exclusive_owner = txn_id;
        }

        add_lock_to_transaction(txn, resource_id, is_table, mode);
        pthread_mutex_unlock(&lm->mutex);
        return true;
    }

    // Lock cannot be granted immediately - add to waiting list
    // Note: This is a simplified version without deadlock detection
    LockRequest *req = (LockRequest *)malloc(sizeof(LockRequest));
    if (!req)
    {
        pthread_mutex_unlock(&lm->mutex);
        return false;
    }

    req->transaction_id = txn_id;
    req->resource_id = resource_id;
    req->is_table = is_table;
    req->mode = mode;
    req->next = NULL;

    // Add to end of waiting list
    if (entry->waiting_list == NULL)
    {
        entry->waiting_list = req;
    }
    else
    {
        LockRequest *last = entry->waiting_list;
        while (last->next)
        {
            last = last->next;
        }
        last->next = req;
    }

    pthread_mutex_unlock(&lm->mutex);

    // In a real implementation, we would wait here and return when the lock is granted
    // For simplicity, we just return false to indicate the lock couldn't be acquired immediately
    return false;
}

// Release a lock
bool lock_release(LockManager *lm, int txn_id, int resource_id, bool is_table)
{
    pthread_mutex_lock(&lm->mutex);

    // Find the transaction
    Transaction *txn = find_transaction(lm, txn_id);
    if (!txn)
    {
        pthread_mutex_unlock(&lm->mutex);
        return false;
    }

    // Find the lock entry
    LockEntry *entry = find_lock_entry(lm, resource_id, is_table);
    if (!entry)
    {
        pthread_mutex_unlock(&lm->mutex);
        return false;
    }

    // Remove lock from transaction's held locks
    LockRequest *prev = NULL;
    LockRequest *curr = txn->held_locks;
    bool found = false;

    while (curr)
    {
        if (curr->resource_id == resource_id && curr->is_table == is_table)
        {
            if (prev)
            {
                prev->next = curr->next;
            }
            else
            {
                txn->held_locks = curr->next;
            }

            LockMode mode = curr->mode;
            free(curr);

            // Update lock entry
            if (mode == LOCK_SHARED)
            {
                entry->shared_count--;
            }
            else
            { // LOCK_EXCLUSIVE
                entry->exclusive_owner = -1;
            }

            found = true;
            break;
        }

        prev = curr;
        curr = curr->next;
    }

    if (!found)
    {
        pthread_mutex_unlock(&lm->mutex);
        return false;
    }

    // Process waiting requests
    process_waiting_requests(lm, entry);

    pthread_mutex_unlock(&lm->mutex);
    return true;
}

// Release all locks held by a transaction
static void release_all_locks(LockManager *lm, Transaction *txn)
{
    while (txn->held_locks)
    {
        LockRequest *req = txn->held_locks;
        txn->held_locks = req->next;

        // Find the lock entry
        LockEntry *entry = find_lock_entry(lm, req->resource_id, req->is_table);
        if (entry)
        {
            if (req->mode == LOCK_SHARED)
            {
                entry->shared_count--;
            }
            else
            { // LOCK_EXCLUSIVE
                entry->exclusive_owner = -1;
            }

            // Process waiting requests
            process_waiting_requests(lm, entry);
        }

        free(req);
    }
}

// Commit a transaction
bool transaction_commit(LockManager *lm, int txn_id)
{
    pthread_mutex_lock(&lm->mutex);

    // Find the transaction
    Transaction *txn = find_transaction(lm, txn_id);
    if (!txn || !txn->active)
    {
        pthread_mutex_unlock(&lm->mutex);
        return false;
    }

    // Release all locks
    release_all_locks(lm, txn);

    // Mark transaction as inactive
    txn->active = false;

    pthread_mutex_unlock(&lm->mutex);
    return true;
}

// Abort a transaction
bool transaction_abort(LockManager *lm, int txn_id)
{
    // In a real implementation, we would also undo any changes made by the transaction

    return transaction_commit(lm, txn_id);
}

// Clean up lock manager
void lock_manager_cleanup(LockManager *lm)
{
    // Free all lock entries
    while (lm->lock_table)
    {
        LockEntry *entry = lm->lock_table;
        lm->lock_table = entry->next;

        // Free waiting list
        while (entry->waiting_list)
        {
            LockRequest *req = entry->waiting_list;
            entry->waiting_list = req->next;
            free(req);
        }

        free(entry);
    }

    // Free all transactions
    while (lm->transactions)
    {
        Transaction *txn = lm->transactions;
        lm->transactions = txn->next;

        // Free held locks
        while (txn->held_locks)
        {
            LockRequest *req = txn->held_locks;
            txn->held_locks = req->next;
            free(req);
        }

        free(txn);
    }

    pthread_mutex_destroy(&lm->mutex);
}