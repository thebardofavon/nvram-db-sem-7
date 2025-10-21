CC = gcc
CFLAGS = -Wall -Wextra -g -I./include -pthread -march=native

# Define targets
SERVER_TARGET = nvram_db
CLIENT_TARGET = nvram_client

# Source files for server and client
SERVER_SRC = src/db_main.c src/free_space.c src/ram_bptree.c src/wal.c src/lock_manager.c
CLIENT_SRC = src/client.c

# Object files
SERVER_OBJ = $(SERVER_SRC:.c=.o)
CLIENT_OBJ = $(CLIENT_SRC:.c=.o)

# Default target to build both server and client
all: $(SERVER_TARGET) $(CLIENT_TARGET)

# Link object files to create server executable
$(SERVER_TARGET): $(SERVER_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

# Link object files to create client executable
$(CLIENT_TARGET): $(CLIENT_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

# Compile source files to object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up
clean:
	rm -f $(SERVER_OBJ) $(CLIENT_OBJ) $(SERVER_TARGET) $(CLIENT_TARGET)

# Run the server with sudo
server: $(SERVER_TARGET)
	sudo ./$(SERVER_TARGET)

# Run the client
client: $(CLIENT_TARGET)
	./$(CLIENT_TARGET)

.PHONY: all clean run_server run_client