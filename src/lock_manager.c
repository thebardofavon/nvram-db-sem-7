#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "../include/lock_manager.h"
static int next_txn_idx = 0; // Internal index for waits-for graph
static int txn_id_map[MAX_CONCURRENT_TRANSACTIONS]; // Maps index to actual txn_id
// Helper to find a transaction by ID
static Transaction *find_transaction(LockManager *lm, int txn_id) {
    for (Transaction *txn = lm->transactions; txn; txn = txn->next) {
        if (txn->id == txn_id)
            return txn;
    }
    return NULL;
}
// Get the internal index for the waits-for graph from a txn_id
static int get_txn_idx(int txn_id) {
    for (int i = 0; i < MAX_CONCURRENT_TRANSACTIONS; i++) {
        if (txn_id_map[i] == txn_id)
            return i;
    }
    return -1;
}
void lock_manager_init(LockManager *lm) {
    lm->lock_table = NULL;
    lm->transactions = NULL;
    pthread_mutex_init(&lm->mutex, NULL);
    lm->next_txn_id = 1;
    memset(lm->waits_for, 0, sizeof(lm->waits_for));
    memset(txn_id_map, -1, sizeof(txn_id_map));
    next_txn_idx = 0;
}
int transaction_begin(LockManager *lm) {
    pthread_mutex_lock(&lm->mutex);
    if (next_txn_idx >= MAX_CONCURRENT_TRANSACTIONS) {
        pthread_mutex_unlock(&lm->mutex);
        fprintf(stderr, "Max concurrent transactions reached.\n");
        return -1;
    }

    Transaction *txn = (Transaction *)malloc(sizeof(Transaction));
    txn->id = lm->next_txn_id++;
    txn->active = true;
    txn->held_locks = NULL;
    txn->undo_log = NULL;
    txn->thread_id = pthread_self();

    txn->next = lm->transactions;
    lm->transactions = txn;

    txn_id_map[next_txn_idx++] = txn->id;

    pthread_mutex_unlock(&lm->mutex);
    return txn->id;
}
// Find or create a lock table entry
static LockEntry *find_or_create_lock_entry(LockManager *lm, int resource_id, bool is_table) {
    for (LockEntry *entry = lm->lock_table; entry; entry = entry->next) {
        if (entry->resource_id == resource_id && entry->is_table == is_table) {
            return entry;
        }
    }

    LockEntry *new_entry = (LockEntry *)malloc(sizeof(LockEntry));
    new_entry->resource_id = resource_id;
    new_entry->is_table = is_table;
    new_entry->shared_count = 0;
    new_entry->exclusive_owner = -1;
    new_entry->waiting_list = NULL;
    pthread_cond_init(&new_entry->condition, NULL);
    new_entry->next = lm->lock_table;
    lm->lock_table = new_entry;
    return new_entry;
}
// --- Deadlock Detection (DFS) ---
static bool is_cyclic_util(LockManager *lm, int u, bool *visited, bool *recursion_stack) {
    if (!visited[u]) {
        visited[u] = true;
        recursion_stack[u] = true;

        for (int v = 0; v < MAX_CONCURRENT_TRANSACTIONS; v++) {
            if (lm->waits_for[u][v]) { // u waits for v
                if (!visited[v] && is_cyclic_util(lm, v, visited, recursion_stack)) {
                    return true;
                } else if (recursion_stack[v]) {
                    return true; // Cycle detected
                }
            }
        }
    }

    recursion_stack[u] = false; // Remove from recursion stack
    return false;
}
static bool detect_deadlock(LockManager *lm) {
    bool visited[MAX_CONCURRENT_TRANSACTIONS] = {0};
    bool recursion_stack[MAX_CONCURRENT_TRANSACTIONS] = {0};

    for (int i = 0; i < MAX_CONCURRENT_TRANSACTIONS; i++) {
        if (txn_id_map[i] != -1) {
            if (is_cyclic_util(lm, i, visited, recursion_stack)) {
                return true;
            }
        }
    }
    return false;
}
bool lock_acquire(LockManager *lm, int txn_id, int resource_id, bool is_table, LockMode mode) {
    pthread_mutex_lock(&lm->mutex);

    Transaction *txn = find_transaction(lm, txn_id);
    if (!txn || !txn->active) {
        pthread_mutex_unlock(&lm->mutex);
        return false;
    }

    LockEntry *entry = find_or_create_lock_entry(lm, resource_id, is_table);

    while (true) { // Loop until lock is acquired or deadlock is detected
        // Check if lock can be granted
        bool can_grant = false;
        if (mode == LOCK_SHARED) {
            can_grant = (entry->exclusive_owner == -1 || entry->exclusive_owner == txn_id);
        } else { // LOCK_EXCLUSIVE
            can_grant = (entry->exclusive_owner == -1 && entry->shared_count == 0) ||
                        (entry->exclusive_owner == txn_id) ||
                        (entry->shared_count == 1 && find_transaction(lm, txn_id)->held_locks->mode == LOCK_SHARED); // Lock upgrade
        }

        if (can_grant) {
            // Grant the lock
            if (mode == LOCK_SHARED) {
                entry->shared_count++;
            } else {
                entry->exclusive_owner = txn_id;
            }
            LockRequest *req = (LockRequest *)malloc(sizeof(LockRequest));
            req->transaction_id = txn_id;
            req->resource_id = resource_id;
            req->is_table = is_table;
            req->mode = mode;
            req->next = txn->held_locks;
            txn->held_locks = req;

            pthread_mutex_unlock(&lm->mutex);
            return true;
        }

        // Lock cannot be granted, must wait.
        int waiter_idx = get_txn_idx(txn_id);
        if (entry->exclusive_owner != -1) {
            int holder_idx = get_txn_idx(entry->exclusive_owner);
            if (waiter_idx != -1 && holder_idx != -1) {
                lm->waits_for[waiter_idx][holder_idx] = true;
            }
        } else { // Waiting on shared locks
            // Simplified: wait on all shared holders
        }

        // Check for deadlock
        if (detect_deadlock(lm)) {
            // Deadlock detected, this transaction is the victim.
            printf("Deadlock detected! Aborting transaction %d.\n", txn_id);
            // Clean up waits-for edge
            if (entry->exclusive_owner != -1) {
                int holder_idx = get_txn_idx(entry->exclusive_owner);
                if (waiter_idx != -1 && holder_idx != -1) {
                    lm->waits_for[waiter_idx][holder_idx] = false;
                }
            }
            pthread_mutex_unlock(&lm->mutex);
            transaction_abort(lm, txn_id, true); // Perform undo
            return false;
        }

        // Wait on condition variable
        pthread_cond_wait(&entry->condition, &lm->mutex);

        // Woke up, clean up waits-for edge before re-checking
        if (entry->exclusive_owner != -1) {
            int holder_idx = get_txn_idx(entry->exclusive_owner);
            if (waiter_idx != -1 && holder_idx != -1) {
                lm->waits_for[waiter_idx][holder_idx] = false;
            }
        }
    }
}
static void release_all_locks(LockManager *lm, Transaction *txn) {
    while (txn->held_locks) {
        LockRequest *req = txn->held_locks;
        LockEntry *entry = find_or_create_lock_entry(lm, req->resource_id, req->is_table);
        if (req->mode == LOCK_SHARED) {
            entry->shared_count--;
        } else {
            if (entry->exclusive_owner == txn->id) {
                entry->exclusive_owner = -1;
            }
        }
        // Wake up all waiting threads for this resource
        pthread_cond_broadcast(&entry->condition);

        txn->held_locks = req->next;
        free(req);
    }
}
bool transaction_commit(LockManager *lm, int txn_id) {
    pthread_mutex_lock(&lm->mutex);
    Transaction *txn = find_transaction(lm, txn_id);
    if (!txn || !txn->active) {
        pthread_mutex_unlock(&lm->mutex);
        return false;
    }

    release_all_locks(lm, txn);
    txn->active = false; // Mark for cleanup

    // Free undo log
    while (txn->undo_log) {
        UndoLog *temp = txn->undo_log;
        txn->undo_log = temp->next;
        free(temp);
    }

    pthread_mutex_unlock(&lm->mutex);
    return true;
}
// perform_undo is a flag to prevent recursive aborts from deadlock detector
bool transaction_abort(LockManager *lm, int txn_id, bool perform_undo) {
    pthread_mutex_lock(&lm->mutex);
    Transaction *txn = find_transaction(lm, txn_id);
    if (!txn || !txn->active) {
        pthread_mutex_unlock(&lm->mutex);
        return false;
    }

    // The actual UNDO logic is in ram_bptree.c now.
    // This function just cleans up the lock manager state.

    release_all_locks(lm, txn);
    txn->active = false; // Mark for cleanup

    // Free undo log (it was hopefully just used by ram_bptree)
    while (txn->undo_log) {
        UndoLog *temp = txn->undo_log;
        txn->undo_log = temp->next;
        free(temp);
    }

    pthread_mutex_unlock(&lm->mutex);
    return true;
}
bool transaction_add_undo_action(LockManager *lm, int txn_id, int table_id, void *wal_entry_ptr) {
    pthread_mutex_lock(&lm->mutex);
    Transaction *txn = find_transaction(lm, txn_id);
    if (!txn) {
        pthread_mutex_unlock(&lm->mutex);
        return false;
    }

    UndoLog *undo_entry = (UndoLog *)malloc(sizeof(UndoLog));
    undo_entry->table_id = table_id;
    undo_entry->wal_entry_nvram_ptr = wal_entry_ptr;
    undo_entry->next = txn->undo_log; // Prepend to list
    txn->undo_log = undo_entry;

    pthread_mutex_unlock(&lm->mutex);
    return true;
}
Transaction* get_transaction(LockManager *lm, int txn_id) {
    // Note: No mutex lock here, assumes caller holds it or is in a safe context
    return find_transaction(lm, txn_id);
}
void lock_manager_cleanup(LockManager *lm) {
    // Free lock entries
    while (lm->lock_table) {
        LockEntry *entry = lm->lock_table;
        lm->lock_table = entry->next;
        pthread_cond_destroy(&entry->condition);
        // Free waiting list if any (should be empty on clean shutdown)
        free(entry);
    }
    // Free transactions
    while (lm->transactions) {
        Transaction *txn = lm->transactions;
        lm->transactions = txn->next;
        // Free held locks and undo logs (should be empty)
        free(txn);
    }
    pthread_mutex_destroy(&lm->mutex);
}
