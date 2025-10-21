CC = gcc
CFLAGS = -Wall

all: save_dax restore_dax

save_dax: save_dax.c
	$(CC) $(CFLAGS) -o save_dax save_dax.c

restore_dax: restore_dax.c
	$(CC) $(CFLAGS) -o restore_dax restore_dax.c

save: save_dax
	sudo ./save_dax

restore: restore_dax
	sudo ./restore_dax

clean:
	rm -f save_dax restore_dax