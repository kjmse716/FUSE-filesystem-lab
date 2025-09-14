#ifndef AES256_ENCRYPT_H
#define AES256_ENCRYPT_H


#define BUFFER_SIZE 1000
#define DEBUG

//struct used for file content.
typedef struct {
    char *content;
    int size;
    unsigned char key[32];
    unsigned char iv[12];

}file_metadata;


int print_data(const char *start_ptr,int data_len,char*data_name);

file_metadata* file_metadata_init();

int file_metadata_free(file_metadata* data);

file_metadata* aes_gcm_encrypt(const char *input,file_metadata* data);

void aes_gcm_decrypt(file_metadata * data,char** output);




#endif