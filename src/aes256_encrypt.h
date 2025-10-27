#ifndef AES256_ENCRYPT_H
#define AES256_ENCRYPT_H

#include <uuid/uuid.h>

#define DEBUG

//struct used for file content.
typedef struct {
    unsigned char key[32];
    unsigned char iv[12];
    uuid_t uuid;
    size_t size; // file size

}file_metadata;


int print_data(const char *start_ptr,int data_len,char*data_name);

file_metadata* file_metadata_init();

int file_metadata_free(file_metadata* data);

size_t aes_gcm_encrypt(const char *input, size_t input_length ,file_metadata* data, char ** encrypted_output);

size_t aes_gcm_decrypt(const char* encrypted_input, size_t size, file_metadata * data,char** output);




#endif