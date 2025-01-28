NCU Memory 2024 Lab2

[於HackMD中閱讀](https://hackmd.io/@kjmse716/B1B8T9CX1e)
# 程式介紹
## file_system.c
:::spoiler file_system.c
```c=1
#define FUSE_USE_VERSION 30
#include <fuse.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "aes256_encrypt.c"

// ... //

char dir_list[ 256 ][ 256 ];
int curr_dir_idx = -1;

char files_list[ 256 ][ 256 ];
int curr_file_idx = -1;

file_metadata* files_content[ 256 ];

void add_dir( const char *dir_name )
{
	curr_dir_idx++;
	strcpy( dir_list[ curr_dir_idx ], dir_name );
}

int is_dir( const char *path )
{
	path++; // Eliminating "/" in the path
	
	for ( int curr_idx = 0; curr_idx <= curr_dir_idx; curr_idx++ )
		if ( strcmp( path, dir_list[ curr_idx ] ) == 0 )
			return 1;
	
	return 0;
}

void add_file( const char *filename )
{	
	printf("add_file start\n");
	curr_file_idx++;
	strcpy( files_list[ curr_file_idx ], filename );

	files_content[curr_file_idx] = file_metadata_init();
	printf("metadata_init\n");
	aes_gcm_encrypt("",files_content[curr_file_idx]);
	printf("encrypt complete\n");
	// strcpy( files_content[ curr_file_idx ], "" );
}

int is_file( const char *path )
{
	path++; // Eliminating "/" in the path
	
	for ( int curr_idx = 0; curr_idx <= curr_file_idx; curr_idx++ )
		if ( strcmp( path, files_list[ curr_idx ] ) == 0 )
			return 1;
	
	return 0;
}

int get_file_index( const char *path )
{
	path++; // Eliminating "/" in the path
	
	for ( int curr_idx = 0; curr_idx <= curr_file_idx; curr_idx++ )
		if ( strcmp( path, files_list[ curr_idx ] ) == 0 )
			return curr_idx;
	
	return -1;
}

int get_dir_index( const char *path )
{
	path++; // Eliminating "/" in the path

	for ( int curr_idx = 0; curr_idx <= curr_dir_idx; curr_idx++ )
		if ( strcmp( path, dir_list[ curr_idx ] ) == 0 ){
			printf("\n\n\ntest find fir id:%d\n\n\n",curr_idx);
			return curr_idx;
		}
		printf("\n\n\ntest find fir id:%d\n\n\n",-1);
	
	return -1;
}


void write_to_file( const char *path, const char *new_content )
{
	int file_idx = get_file_index( path );
	
	if ( file_idx == -1 ) // No such file
		return;

	printf("Write content unencrypt:\n%s\n",new_content);
	aes_gcm_encrypt(new_content,files_content[ file_idx ]);
	//strcpy( files_content[ file_idx ], new_content ); 
}

// ... //

static int do_getattr( const char *path, struct stat *st )
{
	st->st_uid = getuid(); // The owner of the file/directory is the user who mounted the filesystem
	st->st_gid = getgid(); // The group of the file/directory is the same as the group of the user who mounted the filesystem
	st->st_atime = time( NULL ); // The last "a"ccess of the file/directory is right now
	st->st_mtime = time( NULL ); // The last "m"odification of the file/directory is right now
	
	if ( strcmp( path, "/" ) == 0 || is_dir( path ) == 1 )
	{
		st->st_mode = S_IFDIR | 0755;
		st->st_nlink = 2; // Why "two" hardlinks instead of "one"? The answer is here: http://unix.stackexchange.com/a/101536
	}
	else if ( is_file( path ) == 1 )
	{
		st->st_mode = S_IFREG | 0644;
		st->st_nlink = 1;
		st->st_size = 1024;
	}
	else
	{
		return -ENOENT;
	}
	
	return 0;
}

static int do_readdir( const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi )
{
	filler( buffer, ".", NULL, 0 ); // Current Directory
	filler( buffer, "..", NULL, 0 ); // Parent Directory
	if ( strcmp( path, "/" ) == 0 ) // If the user is trying to show the files/directories of the root directory show the following
	{
		for ( int curr_idx = 0; curr_idx <= curr_dir_idx; curr_idx++ )
			filler( buffer, dir_list[ curr_idx ], NULL, 0 );
	
		for ( int curr_idx = 0; curr_idx <= curr_file_idx; curr_idx++ )
			filler( buffer, files_list[ curr_idx ], NULL, 0 );
	}
	
	return 0;
}

static int do_read( const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi )
{
	int file_idx = get_file_index( path );
	
	if ( file_idx == -1 )
		return -1;
	
	char * content;
	aes_gcm_decrypt(files_content[ file_idx ],&content);
	printf("\noffset = %d,   size  = %d\n",(int)offset,(int)size);
	memcpy( buffer, content + offset, size );
	size_t return_value = strlen( content ) - offset;
	free(content);
	return return_value;
}

static int do_mkdir( const char *path, mode_t mode )
{
	path++;
	add_dir( path );
	
	return 0;
}

static int do_mknod( const char *path, mode_t mode, dev_t rdev )
{
	path++;
	add_file( path );
	
	return 0;
}

static int do_write( const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *info )
{
	write_to_file( path, buffer );
	return size;
}
static int do_open(const char* path,struct fuse_file_info* fi)
{
	int file_index = get_file_index(path);
	if(file_index!=-1){
		char* key = files_content[file_index]->key;
		print_data(key,32,"file key obtained. file key : ");
	}

	return 0;
}

static int do_release(const char*,struct fuse_file_info* fi){
	printf("file closed");
	return 0;
}

static int do_rmdir(const char* path){
	int dir_index = get_dir_index(path);
	memcpy(dir_list[dir_index],dir_list[curr_dir_idx],sizeof(dir_list[0]));
	curr_dir_idx = curr_dir_idx-1;
	return 0;
}

static struct fuse_operations operations = {
    .getattr	= do_getattr,
    .readdir	= do_readdir,
    .read		= do_read,
    .mkdir		= do_mkdir,
    .mknod		= do_mknod,
    .write		= do_write,
	.open		= do_open,
	.release	= do_release,
	.rmdir		= do_rmdir
};

int main( int argc, char *argv[] )
{
	return fuse_main( argc, argv, &operations, NULL );
}

```
:::
修改自[Less Simple, Yet Stupid Filesystem (Using FUSE)](https://github.com/MaaSTaaR/LSYSFS)
`20：`宣告一個`file_metadata* files_content[ 256 ];`的陣列，此struct會於aes256_encrypt.c中進行宣告。
### add_file()
```c=39
void add_file( const char *filename )
{	
	printf("add_file start\n");
	curr_file_idx++;
	strcpy( files_list[ curr_file_idx ], filename );

	files_content[curr_file_idx] = file_metadata_init();
	printf("metadata_init\n");
	aes_gcm_encrypt("",files_content[curr_file_idx]);
	printf("encrypt complete\n");
	// strcpy( files_content[ curr_file_idx ], "" );
}
```

在新增檔案時會執於`aes256_encrypt.c`中實作的file_metadata_init()，來產生專屬於此檔案的aes256 key與加密初始化向量。

### write_to_file()

```c=89
void write_to_file( const char *path, const char *new_content )
{
	int file_idx = get_file_index( path );
	
	if ( file_idx == -1 ) // No such file
		return;

	printf("Write content unencrypt:\n%s\n",new_content);
	aes_gcm_encrypt(new_content,files_content[ file_idx ]);
	//strcpy( files_content[ file_idx ], new_content ); 
}
```
在寫入前會先print出未加密的寫入內容，呼叫於`aes256_encrypt.c`中進行實作的`aes_gcm_encrypt()`進行檔案的加密後儲存。

### do_read()
```c=145
static int do_read( const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi )
{
	int file_idx = get_file_index( path );
	
	if ( file_idx == -1 )
		return -1;
	
	char * content;
	aes_gcm_decrypt(files_content[ file_idx ],&content);
	printf("\noffset = %d,   size  = %d\n",(int)offset,(int)size);
	memcpy( buffer, content + offset, size );
	size_t return_value = strlen( content ) - offset;
	free(content);
	return return_value;
}
```
透過先找出file於儲存陣列中的index後，呼叫於`aes256_encrypt.c`中進行實作的`aes_gcm_decrypt()`對儲存的資料記進行解密後，將解密得到的content copy至目標buffer中。

### static int do_rmdir()

```c=198
static int do_rmdir(const char* path){
	int dir_index = get_dir_index(path);
	memcpy(dir_list[dir_index],dir_list[curr_dir_idx],sizeof(dir_list[0]));
	curr_dir_idx = curr_dir_idx-1;
	return 0;
}
```
在進行刪除dir時，將list最末的dir資料copy至預刪除的index位置，並將當前dir總數量減一來達成刪除的效果。



## aes256_encrypt.c
:::spoiler aes256_encrypt.c

```c=1
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <time.h>
#include <string.h>
#define BUFFER_SIZE 1000
#define DEBUG

//struct used for file content.
typedef struct {
    char *content;
    int size;
    unsigned char key[32];
    unsigned char iv[12];

}file_metadata;

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
    for(int i = 0;i<byte_num;i++){
        random256key[i] = rand()&0xFF;
    }
    #ifdef DEBUG
    printf("New file key generated.\n");
    #endif
}


file_metadata* file_metadata_init(){
    file_metadata *data = (file_metadata*)malloc(sizeof(file_metadata));
    random_key_gen(data->key, 32);
    random_key_gen(data->iv,12); 
    data ->content = NULL;
    data->size = 0;
    print_data(data->key,32,"New file key:");
    return data;
}


int file_metadata_free(file_metadata* data){
    free(data->content);
    free(data);
}

#ifdef AES_FUNCTION_TEST
/* Example plaintext to encrypt 64 */ 
static unsigned char gcm_pt[] = {
    0xf5, 0x6e, 0x87, 0x05, 0x5b, 0xc3, 0x2d, 0x0e, 0xeb, 0x31, 0xb2, 0xea,
    0xcc, 0x2b, 0xf2, 0xa5,'\0'
};
#endif


file_metadata* aes_gcm_encrypt(const char *input,file_metadata* data){
    if(strlen(input)!=0){
        //initial setting reference from openssl aes demo
        EVP_CIPHER_CTX *ctx;
        EVP_CIPHER *cipher = NULL;
        int outlen,tmplen;

        // unsigned char outbuf[BUFFER_SIZE];
        unsigned char* outbuf = (char*)calloc(strlen(input),sizeof(char));
        OSSL_PARAM params[2] = {
            OSSL_PARAM_END, OSSL_PARAM_END
        };

        size_t gcm_ivlen = sizeof(data->iv);

        print_data(input,strlen(input),"Write content unencrypt(Hex):");
        /* Set IV length if default 96 bits is not appropriate */
        params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
                                                &gcm_ivlen);
        cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
        ctx = EVP_CIPHER_CTX_new();

        // aes encryption
        EVP_EncryptInit_ex2(ctx, cipher, data->key, data->iv, params);
        EVP_EncryptUpdate(ctx, outbuf, &outlen, input, strlen(input));
        EVP_EncryptFinal_ex(ctx, outbuf, &tmplen);
        outlen+=tmplen;

        //saving encrypted content and size.
        if(data->content != NULL){
            free(data->content);
            data->content = NULL;
        }
        data->content = (char*)calloc(outlen,sizeof(char));
        memcpy(data->content,outbuf,(int)outlen);
        free(outbuf);
        data->size = (int)outlen;

        print_data(data->content,data->size,"Write content encrypted(Hex)");

        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(ctx);
    }
    return data;
}


//unsigned char* gcm_ct
void aes_gcm_decrypt(file_metadata * data,char** output){
    if(data->size!= 0){

        //initial setting reference from openssl aes demo
        EVP_CIPHER_CTX *ctx;
        EVP_CIPHER *cipher = NULL;
        int outlen;
        int total_outlen;
        size_t gcm_ivlen = sizeof(data->iv);
        // unsigned char outbuf[BUFFER_SIZE];
        unsigned char* outbuf = (char*)calloc(data->size,sizeof(char));
        OSSL_PARAM params[2] = {
            OSSL_PARAM_END, OSSL_PARAM_END
        };
        print_data(data->content,strlen(data->content),"File content undecrypt(Hex):");
        /* Set IV length if default 96 bits is not appropriate */
        params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
                                                &gcm_ivlen);
        cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
        ctx = EVP_CIPHER_CTX_new();
        // aes decryption
        EVP_DecryptInit_ex2(ctx, cipher, data->key, data->iv, params);
        EVP_DecryptUpdate(ctx, outbuf, &outlen, data->content, data->size);
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
    }else{
        *output = (char*)calloc(1,sizeof(char));
        *output[0] = '\0';
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
```

:::

### sturct file_metadata
```c=11
//struct used for file content.
typedef struct {
    char *content;
    int size;
    unsigned char key[32];
    unsigned char iv[12];

}file_metadata;
```

每個`file_metadata struct` instance會對應一個file，`file_metadata struct`包含五個元素，分別紀錄指向content的pointer、content size、專屬於這個file的aes256 key(32 Byte = 256bit)、專屬於這個檔案的加密初始化向量iv。


### int random_key_gen(unsigned char* random256key,int byte_num)

```c=31
int random_key_gen(unsigned char* random256key,int byte_num){
    for(int i = 0;i<byte_num;i++){
        random256key[i] = rand()&0xFF;
    }
    #ifdef DEBUG
    printf("New file key generated.\n");
    #endif
}
```
在初始化file metadata(create新file)時，會為這個檔案產生一個新的aes256key(另外也用於產生16 Byte的初始化向量)，使用者可以指定要產生的Byte長度，function中透過`rand()&0xFF`來每次產生一個Byte長度的隨機bit串。


### file_metadata* file_metadata_init()
```c=41
file_metadata* file_metadata_init(){
    file_metadata *data = (file_metadata*)malloc(sizeof(file_metadata));
    random_key_gen(data->key, 32);
    random_key_gen(data->iv,12); 
    data ->content = NULL;
    data->size = 0;
    print_data(data->key,32,"New file key:");
    return data;
}
```
在每一次create新檔案時都會對應新建一個`file_metadata`實例，並對該`file_metadata`實例中的4個元素分別進行初始化(ex:生成專屬於這個新檔案用於aes256加密的key、初始vector)。


### file_metadata* aes_gcm_encrypt(const char *input,file_metadata* data)

```c=66
file_metadata* aes_gcm_encrypt(const char *input,file_metadata* data){
    if(strlen(input)!=0){
        //initial setting reference from openssl aes demo
        EVP_CIPHER_CTX *ctx;
        EVP_CIPHER *cipher = NULL;
        int outlen,tmplen;

        // unsigned char outbuf[BUFFER_SIZE];
        unsigned char* outbuf = (char*)calloc(strlen(input),sizeof(char));
        OSSL_PARAM params[2] = {
            OSSL_PARAM_END, OSSL_PARAM_END
        };

        size_t gcm_ivlen = sizeof(data->iv);

        print_data(input,strlen(input),"Write content unencrypt(Hex):");
        /* Set IV length if default 96 bits is not appropriate */
        params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
                                                &gcm_ivlen);
        cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
        ctx = EVP_CIPHER_CTX_new();

        // aes encryption
        EVP_EncryptInit_ex2(ctx, cipher, data->key, data->iv, params);
        EVP_EncryptUpdate(ctx, outbuf, &outlen, input, strlen(input));
        EVP_EncryptFinal_ex(ctx, outbuf, &tmplen);
        outlen+=tmplen;

        //saving encrypted content and size.
        if(data->content != NULL){
            free(data->content);
            data->content = NULL;
        }
        data->content = (char*)calloc(outlen,sizeof(char));
        memcpy(data->content,outbuf,(int)outlen);
        free(outbuf);
        data->size = (int)outlen;

        print_data(data->content,data->size,"Write content encrypted(Hex)");

        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(ctx);
    }
    return data;
}
```
此function會透過傳入的`file_metadata` instance `data`中的`key`與`iv`來對傳入的`char* input`內容進行aes256加密，並將加密後的資料存入傳入的`file_metatdata`instant(pointer) `data`的`content`欄位(pointer)中。

首先檢查若input長度為0，那就跳過加密，
`68~86`：初始化openssl的aes加密功能。
`89~91`：進行Aes加密
`94~104`：將加密後content存入`file metadata data`中。


### void aes_gcm_decrypt(file_metadata * data,char** output)
```c=114
void aes_gcm_decrypt(file_metadata * data,char** output){
    if(data->size!= 0){

        //initial setting reference from openssl aes demo
        EVP_CIPHER_CTX *ctx;
        EVP_CIPHER *cipher = NULL;
        int outlen;
        int total_outlen;
        size_t gcm_ivlen = sizeof(data->iv);
        // unsigned char outbuf[BUFFER_SIZE];
        unsigned char* outbuf = (char*)calloc(data->size,sizeof(char));
        OSSL_PARAM params[2] = {
            OSSL_PARAM_END, OSSL_PARAM_END
        };
        print_data(data->content,strlen(data->content),"File content undecrypt(Hex):");
        /* Set IV length if default 96 bits is not appropriate */
        params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
                                                &gcm_ivlen);
        cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
        ctx = EVP_CIPHER_CTX_new();
        // aes decryption
        EVP_DecryptInit_ex2(ctx, cipher, data->key, data->iv, params);
        EVP_DecryptUpdate(ctx, outbuf, &outlen, data->content, data->size);
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
    }else{
        *output = (char*)calloc(1,sizeof(char));
        *output[0] = '\0';
    }
}
```
此function會透過傳入的`file_metadata` instance `data`中的`key`與`iv`來對`content`進行AES-256解密。
`115`、`150~153`：`aes_gcm_decrypt`會先檢查傳入的`file_metadata` instance `data`長度不為空，若為空則回傳1 Byte 的 `\0` char 代表檔案結尾。
`117~133`初始化openssl的AES-256 decrypt功能。
`134~140`進行AES-256 decryption。
`141~146`將解密後的內容存入output buffer中。

# 基本操作
## 編譯及掛載
![image](https://hackmd.io/_uploads/Sk_0IxOryg.png)


## Create, read, and write files.
### Create file
![image](https://hackmd.io/_uploads/B1qNDgdHJe.png)
![image](https://hackmd.io/_uploads/H1OV9edBye.png)


### write file
![image](https://hackmd.io/_uploads/BJ3odgdSke.png)
![image](https://hackmd.io/_uploads/SJLv9xdrkg.png)



### read file
![image](https://hackmd.io/_uploads/H11oYe_ryx.png)
![image](https://hackmd.io/_uploads/SJvsceOrkl.png)


## Open and close files.
### Open 
![image](https://hackmd.io/_uploads/BkLpilOSyg.png)
### Close(Release)
![image](https://hackmd.io/_uploads/SJjQaxOrJe.png)

## Create and remove directories.
### Create dir
![image](https://hackmd.io/_uploads/S1KLnxdByx.png)
### Remove dir
![image](https://hackmd.io/_uploads/rkOY2x_rJg.png)

## List directory contents.
![image](https://hackmd.io/_uploads/r1m36edBkl.png)

# Part 3,4,5,6 AES加解密:
## 每個檔案使用不同的Key加密與解密、能於OPEN時正確獲得對應KEY，並且在所有基礎操作中都能正確進行加密與解密:
![image](https://hackmd.io/_uploads/B1nG49RBye.png)

![image](https://hackmd.io/_uploads/HyacV5AS1l.png)
![image](https://hackmd.io/_uploads/BktsvqABJl.png)
![image](https://hackmd.io/_uploads/rJHXSc0HJg.png)
![image](https://hackmd.io/_uploads/BkdnHq0S1x.png)
![image](https://hackmd.io/_uploads/BJIIuqCHJe.png)


## 驗證沒有正確的Key，檔案的內容unreadable:
透過新增的程式碼片段，強制將解密金鑰改為錯誤的金鑰:
![image](https://hackmd.io/_uploads/HyqqYoCHJl.png)

可以看到測試Read到的資料為亂碼:
![image](https://hackmd.io/_uploads/r1oSqjRrJl.png)
將`#define USE_INCORRECT_KEY`移除後，可以看到如下圖，解密回復正常。
![image](https://hackmd.io/_uploads/SJ3R5jAHJl.png)








# 碰到問題

在讀取檔案時出現segemtation fault,
core dumped.


後來發現是測試檔案的大小太大，超出了設定的]

fuse_operations中operations中的.read(do_read函數的傳入參數中)
![image](https://hackmd.io/_uploads/BJwIujIN1g.png)
![image](https://hackmd.io/_uploads/HyTj_sLN1x.png)
![image](https://hackmd.io/_uploads/BytNtoUVke.png)


一次讀取的size最小為4096，因此若使用malloc或calloc分配記憶體來佔存輸出的資料時，若只分配剛好與檔案內容大小相等的記憶體(不足4096Byte)，在memcopy容易會觸發segmentation error.


![image](https://hackmd.io/_uploads/HyAuF6LEyx.png)


