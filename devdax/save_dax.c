#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEVDAX_PATH "/dev/dax0.0"
#define DEVDAX_SIZE (2L * 1024 * 1024 * 1024) // 2GB
#define BACKUP_PATH "/home/master/dax_backup.bin"

int main()
{
    // Open devdax device
    int fd = open(DEVDAX_PATH, O_RDWR);
    if (fd < 0)
    {
        perror("Failed to open devdax device");
        return 1;
    }

    // Map the device
    void *dax_addr = mmap(NULL, DEVDAX_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (dax_addr == MAP_FAILED)
    {
        perror("Failed to map devdax device");
        close(fd);
        return 1;
    }

    // Write example data
    char *data = (char *)dax_addr;
    strcpy(data, "Example data saved to devdax on 2025-04-03");

    // Open backup file
    int backup_fd = open(BACKUP_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (backup_fd < 0)
    {
        perror("Failed to open backup file");
        munmap(dax_addr, DEVDAX_SIZE);
        close(fd);
        return 1;
    }

    // Save devdax contents to disk
    if (write(backup_fd, dax_addr, DEVDAX_SIZE) != DEVDAX_SIZE)
    {
        perror("Failed to write to backup file");
        close(backup_fd);
        munmap(dax_addr, DEVDAX_SIZE);
        close(fd);
        return 1;
    }

    printf("Data saved to %s\n", BACKUP_PATH);

    // Cleanup
    close(backup_fd);
    munmap(dax_addr, DEVDAX_SIZE);
    close(fd);
    return 0;
}