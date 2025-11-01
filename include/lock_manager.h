#ifndef LOCK_MANAGER_H
#define LOCK_MANAGER_H

#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>

#define MAX_CONCURRENT_TRANSACTIONS 64 // Maximum active transactions

// Lock modes
typedef enum {
    LOCK_SHARED,    // Read lock
    LOCK_EXCLUSIVE  // Write lock
} LockMode;

// --- Forward Declarations ---
struct LockRequest;
struct LockEntry;
struct Transaction;
struct UndoLog;

// Lock request structure (for held locks list)
typedef struct LockRequest {
    int transaction_id;
    int resource_id;
    bool is_table;
    LockMode mode;
    struct LockRequest *next;
} LockRequest;

// Lock table entry
typedef struct LockEntry {
    int resource_id;
    bool is_table;
    int shared_count;
    int exclusive_owner; // -1 if no exclusive owner
    struct LockRequest *waiting_list;
    pthread_cond_t condition; // Condition variable for waiting transactions
    struct LockEntry *next;
} LockEntry;

// Structure to track a single undo action for a transaction
typedef struct UndoLog {
    int table_id;
    void* wal_entry_nvram_ptr; // Pointer to the WALEntry in NVRAM
    struct UndoLog* next;
} UndoLog;

// Transaction structure
typedef struct Transaction {
    int id;
    bool active;
    pthread_t thread_id;    // For deadlock detection
    LockRequest *held_locks;
    UndoLog *undo_log;      // Head of the linked list of undo actions
    struct Transaction *next;
} Transaction;

// Lock manager structure
typedef struct {
    LockEntry *lock_table;
    Transaction *transactions;
    pthread_mutex_t mutex;
    int next_txn_id;
    // For deadlock detection: waits_for[waiter_idx][holder_idx] = true
    bool waits_for[MAX_CONCURRENT_TRANSACTIONS];
} LockManager;

// --- Lock Manager Lifecycle ---
void lock_manager_init(LockManager *lm);
void lock_manager_cleanup(LockManager *lm);

// --- Transaction Management ---
int transaction_begin(LockManager *lm);
bool transaction_commit(LockManager *lm, int txn_id);
bool transaction_abort(LockManager *lm, int txn_id, bool perform_undo);

// --- Lock Operations ---
bool lock_acquire(LockManager *lm, int txn_id, int resource_id, bool is_table, LockMode mode);
// Release lock is now internal, as it's handled by commit/abort
// bool lock_release(LockManager *lm, int txn_id, int resource_id, bool is_table);

// --- Undo Log Management ---
bool transaction_add_undo_action(LockManager lm, int txn_id, int table_id, void wal_entry_ptr);
Transaction* get_transaction(LockManager *lm, int txn_id); // Expose for abort logic

#endif // LOCK_MANAGER_H
