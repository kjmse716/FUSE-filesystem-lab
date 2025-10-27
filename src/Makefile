COMPILER = gcc
FILESYSTEM_FILES = file_system aes256_encrypt.o

all:$(FILESYSTEM_FILES)


aes256_encrypt.o:aes256_encrypt.c
	$(COMPILER) -c $< -o $@


file_system:file_system.c aes256_encrypt.o
	$(COMPILER) -o file_system file_system.c aes256_encrypt.o `pkg-config fuse --cflags --libs` -lcrypto -luuid
	echo 'To Mount: ./file_system -f [mount point]'
	

clean:
	rm $(FILESYSTEM_FILES)