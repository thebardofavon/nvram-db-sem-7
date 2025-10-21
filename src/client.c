#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main()
{
    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("socket");
        exit(1);
    }

    // Configure server address
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

    // Connect to server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("connect");
        exit(1);
    }

    char buffer[BUFFER_SIZE];
    while (1)
    {
        // Display menu
        printf("\nMenu:\n");
        printf("1. Create Table\n");
        printf("2. Use Table\n");
        printf("3. Begin Transaction\n");
        printf("4. Commit\n");
        printf("5. Abort\n");
        printf("6. Insert Row\n");
        printf("7. Get Row\n");
        printf("8. Delete Row\n");
        printf("9. Show WAL\n");
        printf("10. Exit\n");
        printf("Enter choice: ");

        int choice;
        scanf("%d", &choice);
        getchar(); // Consume newline

        switch (choice)
        {
        case 1:
        { // Create Table
            printf("Enter table name: ");
            char table_name[64];
            fgets(table_name, 64, stdin);
            table_name[strcspn(table_name, "\n")] = 0; // Remove newline
            snprintf(buffer, BUFFER_SIZE, "CREATE TABLE %s\n", table_name);
            break;
        }
        case 2:
        { // Use Table
            printf("Enter table name: ");
            char table_name[64];
            fgets(table_name, 64, stdin);
            table_name[strcspn(table_name, "\n")] = 0;
            snprintf(buffer, BUFFER_SIZE, "USE TABLE %s\n", table_name);
            break;
        }
        case 3:
        { // Begin Transaction
            snprintf(buffer, BUFFER_SIZE, "BEGIN TRANSACTION\n");
            break;
        }
        case 4:
        { // Commit
            snprintf(buffer, BUFFER_SIZE, "COMMIT\n");
            break;
        }
        case 5:
        { // Abort
            snprintf(buffer, BUFFER_SIZE, "ABORT\n");
            break;
        }
        case 6:
        { // Insert Row
            printf("Enter row ID (integer key): ");
            int key;
            scanf("%d", &key);
            getchar(); // Consume newline
            printf("Enter data: ");
            char data[256];
            fgets(data, 256, stdin);
            data[strcspn(data, "\n")] = 0;
            snprintf(buffer, BUFFER_SIZE, "INSERT ROW %d '%s'\n", key, data);
            send(sock, buffer, strlen(buffer), 0);

            // Receive and display response
            int n = recv(sock, buffer, BUFFER_SIZE - 1, 0);
            if (n > 0)
            {
                buffer[n] = '\0';
                if (strncmp(buffer, "Row already exists", 18) == 0)
                {
                    printf("Row already exists\n");
                }
                else
                {
                    printf("%s", buffer);
                }
            }
            else if (n == 0)
            {
                printf("Server disconnected\n");
                close(sock);
                return 0;
            }
            else
            {
                perror("recv");
            }
            break;
        }
        case 7:
        { // Get Row
            printf("Enter row ID: ");
            int key;
            scanf("%d", &key);
            getchar();
            snprintf(buffer, BUFFER_SIZE, "GET ROW %d\n", key);
            break;
        }
        case 8:
        { // Delete Row
            printf("Enter row ID: ");
            int key;
            scanf("%d", &key);
            getchar();
            snprintf(buffer, BUFFER_SIZE, "DELETE ROW %d\n", key);
            break;
        }
        case 9:
        { // Show WAL
            snprintf(buffer, BUFFER_SIZE, "SHOW WAL\n");
            break;
        }
        case 10:
        { // Exit
            snprintf(buffer, BUFFER_SIZE, "EXIT\n");
            send(sock, buffer, strlen(buffer), 0);
            int n = recv(sock, buffer, BUFFER_SIZE - 1, 0);
            if (n > 0)
            {
                buffer[n] = '\0';
                printf("%s", buffer);
            }
            close(sock);
            return 0;
        }
        default:
            printf("Invalid choice\n");
            continue;
        }

        // Send command to server
        send(sock, buffer, strlen(buffer), 0);

        // Receive and display response
        int n = recv(sock, buffer, BUFFER_SIZE - 1, 0);
        if (n > 0)
        {
            buffer[n] = '\0';
            printf("%s", buffer);
        }
        else if (n == 0)
        {
            printf("Server disconnected\n");
            close(sock);
            return 0;
        }
        else
        {
            perror("recv");
        }
    }

    close(sock);
    return 0;
}