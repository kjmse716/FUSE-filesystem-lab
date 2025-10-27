#include <stdio.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <time.h>
#include <string.h>
#include "aes256_encrypt.h"
#include <openssl/rand.h>




//print hex data stored in char data type.
int print_data(const char *start_ptr,int data_len,char*data_name){
    #ifdef DEBUG
        printf("\n%s\n",data_name);
        for(int i = 0;i<data_len;i++){
            printf("%x ",(unsigned char)start_ptr[i]);
        }
        printf("\n");
    #endif
}

int random_key_gen(unsigned char* random256key,int byte_num){
    if(RAND_bytes(random256key, byte_num) != 1){
        fprintf(stderr, "Error: RAND_bytes failed to generate random data.\n");
        return -1;
    }
    #ifdef DEBUG
    printf("New file key generated.\n");
    #endif
}


file_metadata* file_metadata_init(){
    file_metadata *data = (file_metadata*)malloc(sizeof(file_metadata));
    random_key_gen(data->key, 32);
    random_key_gen(data->iv,12); 
    uuid_generate(data->uuid);
    data->size = 0;
    print_data((char*)data->uuid, sizeof(uuid_t), "New file UUID:");
    print_data(data->key,32,"New file key:");
    return data;
}


int file_metadata_free(file_metadata* data){
    free(data);
}

#ifdef AES_FUNCTION_TEST
/* Example plaintext to encrypt 64 */ 
static unsigned char gcm_pt[] = {
    0xf5, 0x6e, 0x87, 0x05, 0x5b, 0xc3, 0x2d, 0x0e, 0xeb, 0x31, 0xb2, 0xea,
    0xcc, 0x2b, 0xf2, 0xa5,'\0'
};
#endif


size_t aes_gcm_encrypt(const char *input, size_t input_len,file_metadata* data, char ** encrypted_output){
    if(input_len!=0){
        //initial setting reference from openssl aes demo
        EVP_CIPHER_CTX *ctx;
        EVP_CIPHER *cipher = NULL;
        int outlen,tmplen;

        // unsigned char outbuf[BUFFER_SIZE];
        unsigned char* outbuf = (char*)calloc(input_len,sizeof(char));
        OSSL_PARAM params[2] = {
            OSSL_PARAM_END, OSSL_PARAM_END
        };

        size_t gcm_ivlen = sizeof(data->iv);

        print_data(input,input_len,"Write content unencrypt(Hex):");
        /* Set IV length if default 96 bits is not appropriate */
        params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
                                                &gcm_ivlen);
        cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
        ctx = EVP_CIPHER_CTX_new();

        // aes encryption
        EVP_EncryptInit_ex2(ctx, cipher, data->key, data->iv, params);
        EVP_EncryptUpdate(ctx, outbuf, &outlen, input, input_len);
        EVP_EncryptFinal_ex(ctx, outbuf, &tmplen);
        outlen+=tmplen;

        //saving encrypted content and size.
        *encrypted_output = (char*)outbuf;
        
        print_data(*encrypted_output,(int)outlen,"Write content encrypted(Hex)");

        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(ctx);
        return (int)outlen;
    }
    return 0;
}


//unsigned char* gcm_ct
size_t aes_gcm_decrypt(const char* encrypted_input, size_t size, file_metadata * data,char** output){
    if(size!= 0){

        //initial setting reference from openssl aes demo
        EVP_CIPHER_CTX *ctx;
        EVP_CIPHER *cipher = NULL;
        int outlen;
        int total_outlen;
        size_t gcm_ivlen = sizeof(data->iv);
        // unsigned char outbuf[BUFFER_SIZE];
        unsigned char* outbuf = (char*)calloc(size,sizeof(char));
        OSSL_PARAM params[2] = {
            OSSL_PARAM_END, OSSL_PARAM_END
        };
        #ifdef USE_INCORRECT_KEY
        *(data->key) = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";
        #endif
        print_data(encrypted_input,size,"File content undecrypt(Hex):");
        /* Set IV length if default 96 bits is not appropriate */
        params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
                                                &gcm_ivlen);
        cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
        ctx = EVP_CIPHER_CTX_new();
        // aes decryption
        EVP_DecryptInit_ex2(ctx, cipher, data->key, data->iv, params);
        EVP_DecryptUpdate(ctx, outbuf, &outlen, encrypted_input, size);
        total_outlen = outlen;

        EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
        total_outlen += outlen;
        print_data(outbuf,total_outlen,"File content decyrpted(Hex):");
        *output = (char*)calloc(((total_outlen+1)/4096+1)*4096,sizeof(char));
        memcpy(*output,outbuf,total_outlen);
        free(outbuf);

        (*output) [total_outlen] = '\0';   

        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(ctx);

        return total_outlen;
    }else{
        *output = (char*)calloc(1,sizeof(char));
        *output[0] = '\0';
        return 0;
    }

}


#ifdef AES_FUNCTION_TEST
int main(){
    char size_test[] ="";
    printf("size of \"\" = %d\n",(int)sizeof(size_test));
    char *decryped_data;
    srand(time(NULL));
    //char random256key[32];
    char *test_data = "t";
    char *test_data2 = "test enc_final";

    printf("\n strlen of \"\":%d\n",(int)strlen(test_data));

    //create new file_metadata
    file_metadata *data = file_metadata_init();
    aes_gcm_encrypt(test_data,data);

    print_data(data->content,data->size,"main_check cipher_text:");

    printf("\ncypher strlen:%d\n",(int)strlen(data->content));
    char *output;
    aes_gcm_decrypt(data,&output);

    printf("\ndescrypt strlen:%d\n",(int)strlen(output));

    print_data(output,strlen(output),"output_test");
    // print_data(plain_text->content,plain_text->size,"main_check plain text");
    //printf("\n main_check decrypted data%s",decryped_data);
    printf("\nstring test:%s\n",output[1]);
    // file_metadata_free(cipher_data);
    printf("\nsize of test = %d\n",sizeof(*output));
    free(output);
}
#endif