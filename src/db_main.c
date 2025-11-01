#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <unistd.h>
#include "../include/ram_bptree.h"
#include "../include/free_space.h"
#include "../include/wal.h"
#define PORT 8080
#define BUFFER_SIZE 1024
#define CHECKPOINT_INTERVAL_S 30 // Checkpoint every 30 seconds

void *handle_client(void *arg)
{
    int client_socket = *(int *)arg;
    free(arg);
    Table *current_table = NULL;
    int current_txn_id = -1;
    char buffer[BUFFER_SIZE * 2];
    char *buffer_ptr = buffer;
    int bytes_in_buffer = 0;

    memset(buffer, 0, sizeof(buffer));

    while (1)
    {
        int n = recv(client_socket, buffer_ptr, BUFFER_SIZE, 0);
        if (n <= 0) break;
        bytes_in_buffer += n;
        buffer_ptr += n;

        char *command_start = buffer;
        char *newline;

        while ((newline = strchr(command_start, '\n')) != NULL)
        {
            *newline = '\0';

            if (strlen(command_start) > 0)
            {
                char command[32];
                sscanf(command_start, "%s", command);

                if (strcmp(command, "CREATE") == 0 && strstr(command_start, "TABLE"))
                {
                    char table_name[64];
                    sscanf(command_start, "CREATE TABLE %s", table_name);
                    int table_id = db_create_table(table_name);
                    if (table_id >= 0)
                    {
                        send(client_socket, "Table created\n", 14, 0);
                    }
                    else
                    {
                        send(client_socket, "Failed to create table\n", 23, 0);
                    }
                }
                else if (strcmp(command, "USE") == 0 && strstr(command_start, "TABLE"))
                {
                    char table_name[64];
                    sscanf(command_start, "USE TABLE %s", table_name);
                    current_table = db_open_table(table_name);
                    if (current_table)
                    {
                        send(client_socket, "Table opened\n", 13, 0);
                    }
                    else
                    {
                        send(client_socket, "Table not found\n", 16, 0);
                    }
                }
                else if (strcmp(command, "BEGIN") == 0 && strstr(command_start, "TRANSACTION"))
                {
                    current_txn_id = db_begin_transaction();
                    if (current_txn_id >= 0)
                    {
                        char msg[64];
                        snprintf(msg, sizeof(msg), "Transaction %d started\n", current_txn_id);
                        send(client_socket, msg, strlen(msg), 0);
                    }
                    else
                    {
                        send(client_socket, "Failed to start transaction\n", 28, 0);
                    }
                }
                else if (strcmp(command, "COMMIT") == 0)
                {
                    if (current_txn_id >= 0)
                    {
                        if (db_commit_transaction(current_txn_id))
                        {
                            send(client_socket, "Transaction committed\n", 22, 0);
                            current_txn_id = -1;
                        }
                        else
                        {
                            send(client_socket, "Failed to commit transaction\n", 29, 0);
                        }
                    }
                    else
                    {
                        send(client_socket, "No active transaction\n", 22, 0);
                    }
                }
                else if (strcmp(command, "ABORT") == 0)
                {
                    if (current_txn_id >= 0)
                    {
                        if (db_abort_transaction(current_txn_id))
                        {
                            send(client_socket, "Transaction aborted\n", 20, 0);
                            current_txn_id = -1;
                        }
                        else
                        {
                            send(client_socket, "Failed to abort transaction\n", 28, 0);
                        }
                    }
                    else
                    {
                        send(client_socket, "No active transaction\n", 22, 0);
                    }
                }
                else if (strcmp(command, "INSERT") == 0 && strstr(command_start, "ROW"))
                {
                    if (!current_table) send(client_socket, "No table selected\n", 18, 0);
                    else if (current_txn_id < 0) send(client_socket, "No active transaction\n", 22, 0);
                    else
                    {
                        int key;
                        char data[256];
                        char *ptr = strstr(command_start, "'");
                        sscanf(command_start, "INSERT ROW %d", &key);

                        if (ptr && sscanf(ptr, "'%[^']'", data) == 1)
                        {
                            if (db_put_row(current_table, current_txn_id, key, data, strlen(data) + 1))
                            {
                                send(client_socket, "Row inserted\n", 13, 0);
                            }
                            else
                            {
                                send(client_socket, "Row already exists or failed\n", 29, 0);
                            }
                        }
                        else
                        {
                            send(client_socket, "Invalid format\n", 15, 0);
                        }
                    }
                }
                else if (strcmp(command, "GET") == 0 && strstr(command_start, "ROW"))
                {
                    if (!current_table) send(client_socket, "No table selected\n", 18, 0);
                    else if (current_txn_id < 0) send(client_socket, "No active transaction\n", 22, 0);
                    else {
                        int key;
                        sscanf(command_start, "GET ROW %d", &key);
                        size_t size;
                        void *data = db_get_row(current_table, current_txn_id, key, &size);
                        if (data)
                        {
                            char response[512];
                            snprintf(response, sizeof(response), "Row %d: %s\n", key, (char *)data);
                            send(client_socket, response, strlen(response), 0);
                        }
                        else
                        {
                            send(client_socket, "Row not found\n", 14, 0);
                        }
                    }
                }
                else if (strcmp(command, "DELETE") == 0 && strstr(command_start, "ROW"))
                {
                    if (!current_table) send(client_socket, "No table selected\n", 18, 0);
                    else if (current_txn_id < 0) send(client_socket, "No active transaction\n", 22, 0);
                    else {
                        int key;
                        sscanf(command_start, "DELETE ROW %d", &key);
                        if (db_delete_row(current_table, current_txn_id, key))
                        {
                            send(client_socket, "Row deleted\n", 12, 0);
                        }
                        else
                        {
                            send(client_socket, "Row not found or failed to delete\n", 34, 0);
                        }
                    }
                }
                else if (strcmp(command, "SHOW") == 0 && strstr(command_start, "WAL"))
                {
                    wal_show_data();
                    send(client_socket, "WAL data displayed in server console\n", 37, 0);
                }
                else if (strcmp(command, "EXIT") == 0)
                {
                    send(client_socket, "Goodbye\n", 8, 0);
                    if (current_txn_id >= 0) db_abort_transaction(current_txn_id);
                    close(client_socket);
                    return NULL;
                }
                else
                {
                    send(client_socket, "Invalid command\n", 16, 0);
                }
            }
            command_start = newline + 1;
        }

        int remaining_bytes = bytes_in_buffer - (command_start - buffer);
        memmove(buffer, command_start, remaining_bytes);
        bytes_in_buffer = remaining_bytes;
        buffer_ptr = buffer + remaining_bytes;
    }

    if (current_txn_id >= 0) db_abort_transaction(current_txn_id);
    close(client_socket);
    return NULL;
}
// NEW: Background thread for periodic checkpointing
void *checkpoint_thread_func(void *arg) {
    while (1) {
        sleep(CHECKPOINT_INTERVAL_S);
        db_checkpoint();
    }
    return NULL;
}
int main()
{
    db_startup();
    // NEW: Start the checkpointing thread
    pthread_t checkpoint_thread;
    if (pthread_create(&checkpoint_thread, NULL, checkpoint_thread_func, NULL) != 0) {
        perror("pthread_create for checkpoint thread");
        // Non-fatal, server can still run without checkpointing
    } else {
        pthread_detach(checkpoint_thread);
        printf("Periodic checkpointing thread started.\n");
    }

    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) { perror("socket"); exit(1); }

    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        exit(1);
    }

    if (listen(server_socket, 10) < 0) { perror("listen"); exit(1); }
    printf("Server listening on port %d\n", PORT);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) { perror("accept"); continue; }

        pthread_t thread;
        int *sock_ptr = malloc(sizeof(int));
        *sock_ptr = client_socket;
        if (pthread_create(&thread, NULL, handle_client, sock_ptr) != 0) {
            perror("pthread_create for client thread");
            close(client_socket);
            free(sock_ptr);
        } else {
            pthread_detach(thread);
        }
    }

    close(server_socket);
    db_shutdown();
    return 0;
}

