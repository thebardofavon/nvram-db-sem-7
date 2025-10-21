#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

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

    // Open backup file
    int backup_fd = open(BACKUP_PATH, O_RDONLY);
    if (backup_fd < 0)
    {
        perror("No backup file found, leaving devdax unchanged");
        munmap(dax_addr, DEVDAX_SIZE);
        close(fd);
        return 1;
    }

    // Restore from backup to devdax
    if (read(backup_fd, dax_addr, DEVDAX_SIZE) != DEVDAX_SIZE)
    {
        perror("Failed to read from backup file");
        close(backup_fd);
        munmap(dax_addr, DEVDAX_SIZE);
        close(fd);
        return 1;
    }

    printf("Data restored from %s to devdax\n", BACKUP_PATH);

    // Cleanup
    close(backup_fd);
    munmap(dax_addr, DEVDAX_SIZE);
    close(fd);
    return 0;
}