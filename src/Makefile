COMPILER = gcc
FILESYSTEM_FILES = file_system aes256_encrypt

all:$(FILESYSTEM_FILES)




aes256_encrypt:aes256_encrypt.c
	$(COMPILER) -o $@ -c $<


file_system:file_system.c aes256_encrypt
	$(COMPILER) -o file_system.c aes256_encrypt.o `pkg-config fuse --cflags --libs` -lcrypto
	echo 'To Mount: ./file_system -f [mount point]'
	

clean:
	rm $(FILESYSTEM_FILES)