COMPILER = gcc
FILESYSTEM_FILES = file_system.c

build: $(FILESYSTEM_FILES)
	$(COMPILER) $(FILESYSTEM_FILES) -o file_system `pkg-config fuse --cflags --libs` -lcrypto
	echo 'To Mount: ./file_system -f [mount point]'

clean:
	rm ssfs