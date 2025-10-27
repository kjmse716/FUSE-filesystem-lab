
FUSE Virtual Filesystem
[於HackMD中閱讀](https://hackmd.io/@kjmse716/B1B8T9CX1e)





# FUSE (Filesystem in Userspace)
## 甚麼是 FUSE(Filesystem in Userspace)?
在開始 FUSE 實驗之前，我認為有必要先釐清一個核心問題：我們為什麼要選擇在「使用者空間」而不是傳統的「核心空間」來實作一個檔案系統？

* 傳統上，檔案系統是作業系統核心的一部分，直接在核心層開發雖然能帶來最高的執行效能，但這條路充滿了挑戰。開發者不僅需要面對複雜的同步問題和核心崩潰的風險，還得在一個受限的環境中（通常只能用 C 語言、無法使用標準函式庫）進行開發與除錯，整個過程極為困難且耗時。


FUSE (Filesystem in Userspace) 框架的出現，正是為了解決這些痛點。它讓我們可以像開發一般應用程式一樣，在熟悉的環境中使用豐富的函式庫、方便的除錯工具來建構檔案系統。雖然這犧牲了部分效能（因為操作需要在核心與使用者空間之間切換），但換來了無與倫比的開發彈性與速度。因此，本次實驗選擇 FUSE，主要考量便是優先享受其快速開發與高度彈性的優點，而非追求極致的 I/O 效能。


ClamFS (a FUSE-based user-space file system) VS Filesystem in kernel
![image](https://hackmd.io/_uploads/Hk3LXjGigx.png)
* 上圖展示了 ClamFS 的檔案存取運作流程與傳統核心中 filesystem 的差異。
[ClamFS Github](https://github.com/burghardt/clamfs)

## **FUSE 核心運作流程**

* What is inside FUSE
![image](https://hackmd.io/_uploads/r1FyVozieg.png)

上圖展示了`open()`檔案存取請求，是如何從使用者空間的應用程式，一路傳遞到我們撰寫的 FUSE filesystem 程式。


1. 第一步：來自應用程式的請求 
一切都始於一個普通的使用者空間應用程式。當它需要存取掛載在 `/mnt/foo/` 下的檔案時，它會像存取任何其他檔案一樣，發起一個標準的系統呼叫，例如 `open("/mnt/foo/bar")`。在這個階段，應用程式本身並不知道、也不需要知道它正在跟一個 FUSE 檔案系統互動。

2. 第二步：核心 VFS 的分派
這個請求透過系統呼叫進入了核心空間 (Kernel Space)，首先由**虛擬檔案系統 (VFS)** 層接收。VFS 是 Linux 檔案系統的抽象層，它扮演著「總機」的角色。當 VFS 解析路徑 `/mnt/foo/bar` 後，它會發現這個掛載點 (`/mnt/foo`) 的類型是 FUSE，於是它不會將請求交給硬碟的驅動程式 (如 EXT4)，而是轉交給核心內的 **FUSE Driver**。

3. 第三步 & 第四步：Filesystem in userspace 的關鍵
由於核心中的 FUSE Driver 本身並不包含任何檔案系統的邏輯（例如如何建立檔案、如何列出目錄），它只是一個「橋樑」，因此我們需要將使用者檔案存取的請求轉發給 User space 中我們寫的 FUSE 程式。
    * **第三步** FUSE Driver 接收到 VFS 的請求後（例如 `lookup("foo")`），會將這個操作打包成一個請求訊息，放入一個佇列 (QUEUE) 中，然後執行一次**上下文切換 (Context Switch)**，從核心空間跳回使用者空間。
    * **第四步** 這個切換會喚醒我們一直在背景等待的 **FUSE Daemon** (也就是我們自己寫的 FUSE 程式)。我們的程式透過 **LIB FUSE** 函式庫，從 FUSE Driver 中讀取到這個請求訊息。

4. **第五步 & 第六步：執行自訂邏輯**
我們的 FUSE Daemon 被喚醒並收到請求後，就**開始執行我們自己寫的檔案系統邏輯**。
圖中的 `lookup()`、`getattr()`、`read()`、`write()` 等，就是我們在程式中實作的那些函式 (callbacks)。FUSE Daemon 會根據收到的請求類型，去呼叫對應的函式。
    * 圖中的 **第五步和第六步** ：如果我們的 FUSE Daemon 在設計上有需要去存取放在其他檔案系統中的資料，FUSE 框架支援去存取底層的其他檔案系統 (Lower FS) 例如 EXT4。這種檔案系統被稱為「堆疊式檔案系統 (Stackable File System)」。
    ex: 我們可以實作一個加密檔案系統，當 `read()` 請求進來時，我們的 FUSE 程式就去底層的 EXT4 硬碟上讀取真正的加密檔案，解密後再把內容回傳。

5. **返回路徑**
在我們的 FUSE Daemon 處理完請求後（例如找到了檔案、讀取了內容），會將結果傳遞給 **LIB FUSE** ，並透過 write() system call 將資料寫回給核心的 FUSE Driver(透過 copy_from_user())。
最後，FUSE Driver 將結果循原路返回給 VFS，VFS 再將結果交給最初發起請求的應用程式。

FUSE 透過兩次「核心 <-> 使用者空間」的上下文切換，將傳統上屬於核心的複雜檔案系統邏輯，「外包」給了一個在使用者空間執行的、更安全、更易於開發和除錯的普通行程。



## FUSE 的核心組件

![FUSE_structure](https://hackmd.io/_uploads/Hy8h4jzogx.svg)

FUSE 系統本身的核心組件只有兩個：

* Kernel space
fuse.ko：唯一的 FUSE 核心模組，掛載在 VFS 下，並建立 /dev/fuse 這個字元裝置作為與使用者空間溝通的管道。
* User-space
libfuse.so：FUSE 使用者空間函式庫，提供 API 並負責與 /dev/fuse 溝通。

其中，fuse.ko 在實作方法上更像是一個特殊的字元裝置驅動：它的任務是把 VFS 的檔案操作請求搬到使用者空間，並把結果搬回來，同時也向 VFS 註冊 "fuse" 檔案系統型別，讓系統能識別並掛載 FUSE 檔案系統。









# 實作目標：加密檔案系統
## 什麼是加密檔案系統
在現代資訊環境中，資料不只在傳輸過程中需要保護，儲存在硬碟、SSD、雲端儲存等媒介上的靜態資料（data-at-rest）同樣面臨風險。這些資料可能因為設備遺失、被竊取、硬體報廢或遭到未授權存取而外洩。一旦攻擊者直接取得儲存裝置，如果沒有任何防護措施，檔案內容往往能被輕易讀取。而加密檔案系統（Encrypted File System, EFS）便是為此而生的核心技術之一。

在加密檔案系統中，檔案的內容在寫入儲存媒介之前，會先經過加密處理；而在讀取時，則會即時解密還原。這種設計的目的，是確保即使儲存裝置遺失、被竊取或遭到未授權存取，檔案內容依然無法被直接讀取。通常在加密檔案系統中，**每個檔案都有自己獨立的金鑰**。
* 這把金鑰在密碼學上通常稱為檔案加密金鑰 (File Encryption Key, FEK)。
* 每個檔案會生成一個獨立的、高強度的隨機金鑰（例如 AES-256）來加密該檔案的內容。

優點：隔離風險。即使攻擊者設法獲取了其中一個檔案的 FEK，其他所有檔案依然是安全的。
:::info
每個檔案的獨立加密金鑰存放於哪裡?
---
系統需要一個地方來存放所有加密過的 FEK。在實際的系統中，不是一個「單獨的檔案」去儲存所有的金鑰。常見的做法是，將加密後的 FEK 存放在對應檔案的元數據 (metadata) 或標頭 (header) 中。也就是說，加密後的金鑰跟著加密後的檔案內容一起存放。
這樣做的好處是管理方便，當使用者複製或移動檔案時，它的加密金鑰（的加密版本）也跟著一起移動了。

* 這個儲存金鑰的「檔案」需要透過一個使用者的主金鑰才能存取
這把主金鑰通常被稱為金鑰加密金鑰 (Key Encryption Key, KEK) 或主金鑰 (Master Key)。
系統會使用這把 KEK 去加密（或稱「封裝」）所有單獨的 FEK。因此，儲存在硬碟上的 FEK 都是密文狀態。

:::



## 當使用者需要讀取一個檔案時，系統的運作流程

1. 使用者提供密碼 (Password)。
2. 系統使用一個稱為金鑰派生函式 (KDF) 的演算法（例如 PBKDF2, scrypt, Argon2）從使用者的密碼中運算產生出主金鑰 (KEK)。這個步驟非常重要，可以抵抗暴力破解。
3. 系統讀取檔案標頭，取得加密過的 FEK。
4. 使用主金鑰 (KEK) 將 FEK 解密出來，得到明文的檔案金鑰。
5. 最後，使用明文的 FEK 來解密檔案的實際內容。

::: info
為什麼要用這樣兩層式（或多層式）金鑰架構?
---
* 方便更換密碼：當使用者想更換密碼時，系統不需要將硬碟上所有的資料全部重新加密。只需要用新密碼產生一把新的主金鑰 (KEK)，然後用這把新的主金鑰去把所有被加密的 FEK 重新加密一遍即可。這個過程非常快，因為需要重新加密的只有幾百或幾千個檔案金鑰，而不是海量的檔案內容。
* 更高的安全性：使用者的密碼通常強度不足（例如 password123），不適合直接用於檔案加密。透過 KDF 函式，可以將一個相對較弱的密碼「拉伸」成一個密碼學上強度非常高的主金鑰，大大增加了安全性。
* 支援細粒度的存取控制與撤銷
如果要撤銷某個使用者對某檔案的存取權，只要刪掉該檔案 metadata 中用該使用者公鑰加密的 FEK 副本即可。
單一主金鑰模式下，撤銷權限幾乎等於要換掉整個主金鑰並重新加密所有檔案。

但是這樣不是只要有了主金鑰就可以打開所有的檔案(即使每個檔案的加密金鑰不同)，這與只有一個主金鑰加密所有的檔案，沒有每個檔案專屬的加密金鑰有什麼不同?
* 在某些加密模式下，如果攻擊者能同時獲取某個加密塊的明文和密文（這被稱為 Known-Plaintext Attack），他們可能可以推斷出關於金鑰的資訊。如果所有檔案都用同一把金鑰，攻擊者可以分析的資料就非常多，破解金鑰的風險隨之增加。
* 更換密碼變得可行
* 在多使用者系統中，可以為同一個檔案的 FEK 建立多份加密副本（每份用不同使用者的公鑰加密），存放在檔案 metadata。
:::








# FUSE filesystem lab



## FUSE installation
Install FUSE and all the dependencies:
```bash
$ sudo apt-get update 
$ sudo apt install pkg-config
$ sudo apt-get install gcc fuse libfuse-dev make cmake
```

 To check the FUSE version:
 ```bash
 $ fusermount-V
 ```
## Open SSL instalation
```bash
sudo apt install libssl-dev
```



## 實作(outdated, waiting for update)
### file_system.c

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

