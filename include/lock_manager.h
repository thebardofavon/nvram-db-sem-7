#ifndef LOCK_MANAGER_H
#define LOCK_MANAGER_H

#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>

// Lock modes
typedef enum {
    LOCK_SHARED,    // Read lock
    LOCK_EXCLUSIVE  // Write lock
} LockMode;

// Lock request structure
typedef struct LockRequest {
    int transaction_id;
    int resource_id;  // Table ID or row ID
    bool is_table;    // true if table lock, false if row lock
    LockMode mode;
    struct LockRequest *next;
} LockRequest;

// Lock table entry
typedef struct LockEntry {
    int resource_id;
    bool is_table;
    int shared_count;
    int exclusive_owner;  // -1 if no exclusive owner
    LockRequest *waiting_list;
    struct LockEntry *next;
} LockEntry;

// Transaction structure
typedef struct Transaction {
    int id;
    bool active;
    LockRequest *held_locks;
    struct Transaction *next;
} Transaction;

// Lock manager structure
typedef struct {
    LockEntry *lock_table;
    Transaction *transactions;
    pthread_mutex_t mutex;
    int next_txn_id;
} LockManager;

// Initialize lock manager
void lock_manager_init(LockManager *lm);

// Start a new transaction
int transaction_begin(LockManager *lm);

// Commit a transaction
bool transaction_commit(LockManager *lm, int txn_id);

// Abort a transaction
bool transaction_abort(LockManager *lm, int txn_id);

// Acquire a lock
bool lock_acquire(LockManager *lm, int txn_id, int resource_id, bool is_table, LockMode mode);

// Release a lock
bool lock_release(LockManager *lm, int txn_id, int resource_id, bool is_table);

// Clean up lock manager
void lock_manager_cleanup(LockManager *lm);

#endif // LOCK_MANAGER_H