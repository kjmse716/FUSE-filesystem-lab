#define _XOPEN_SOURCE 700 // for S_IFDIR and S_IFREG macro
#define FUSE_USE_VERSION 30
#define _FILE_OFFSET_BITS_64
#include <fuse.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h> // for S_IFDIR and S_IFREG macro
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "aes256_encrypt.h"
#include "uthash.h"

/* –- Custom inode struct for dirs and files –- */

#define MAX_FILENAME_LENGTH 256
#define DATA_DIR ".data"
#define METADATA_FILE ".metadata.dat"

typedef struct inode_struct inode_struct;

struct inode_struct
{
	char file_name [MAX_FILENAME_LENGTH];
	int is_file; // 0 for dir, 1 for file.
	inode_struct* files_under; // hash table for files under this dir.
	file_metadata* file_metadata;
	UT_hash_handle hh; // makes this structure hashable
	time_t mtime;
};

static inode_struct* root = NULL; // Root hash table

/* --- Persistence data storage ---*/
void serialize_inode(FILE* f, inode_struct* inode, int depth) {
    if (!inode) return;

    // Store metadata
    fprintf(f, "%d,%d,%s\n", depth, inode->is_file, inode->file_name);
    
    // file metadata (uuid, key, iv)
    if (inode->is_file && inode->file_metadata) {
        char uuid_str[37];
        uuid_unparse(inode->file_metadata->uuid, uuid_str);
        fprintf(f, "META,%s,%ld,", uuid_str, inode->file_metadata->size);
        for(int i=0; i<32; i++) fprintf(f, "%02x", inode->file_metadata->key[i]);
        fprintf(f, ",");
        for(int i=0; i<12; i++) fprintf(f, "%02x", inode->file_metadata->iv[i]);
        fprintf(f, "\n");
    }

    // Recursive 
    if (!inode->is_file && inode->files_under) {
        inode_struct *s, *tmp;
        HASH_ITER(hh, inode->files_under, s, tmp) {
            serialize_inode(f, s, depth + 1);
        }
    }
}

// Save all metadata records into METADATA_FILE
int serialize_metadata() {
    FILE* f = fopen(METADATA_FILE, "w");
    if (!f) {
        perror("Failed to open metadata file for writing");
        return -1;
    }
    serialize_inode(f, root, 0);
    fclose(f);
    return 0;
}

// Restore all metadata records from METADATA_FILE
void deserialize_metadata() {
    FILE* f = fopen(METADATA_FILE, "r");
    if (!f) return; // No existing METADATA_FILE

    char line[1024];
    inode_struct* path_stack[256]; // Use a stack to track parent nodes
    path_stack[0] = root;
    int last_depth = 0;

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "META,", 5) == 0) {
            // Restore metadata
            char uuid_str[37];
            char key_str[65];
            char iv_str[25];
			size_t size;
            sscanf(line, "META,%36[^,],%ld,%64[^,],%24s", uuid_str, &size, key_str, iv_str);
            
            inode_struct* file_node = path_stack[last_depth];
            file_node->file_metadata = malloc(sizeof(file_metadata));
			file_node->file_metadata->size = size;
            uuid_parse(uuid_str, file_node->file_metadata->uuid);
            for(int i=0; i<32; i++) sscanf(&key_str[i*2], "%2hhx", &file_node->file_metadata->key[i]);
            for(int i=0; i<12; i++) sscanf(&iv_str[i*2], "%2hhx", &file_node->file_metadata->iv[i]);

        } else {
            // Restore inode
            int depth, is_file;
            char name[MAX_FILENAME_LENGTH];
            sscanf(line, "%d,%d,%[^\n]", &depth, &is_file, name);

			if(depth == 0)continue;

            inode_struct* parent = path_stack[depth - 1];
            inode_struct* new_node = malloc(sizeof(inode_struct));
            strcpy(new_node->file_name, name);
            new_node->is_file = is_file;
            new_node->files_under = NULL;
            new_node->file_metadata = NULL;
            new_node->mtime = time(NULL);

            HASH_ADD_STR(parent->files_under, file_name, new_node);
            path_stack[depth] = new_node;
            last_depth = depth;
        }
    }
    fclose(f);
}




/* --- Hash util funcitons --- */
static inode_struct* hash_add_inode(inode_struct** target_hash_table, char *file_name,int is_file) {
	inode_struct *s;

	s = malloc(sizeof(inode_struct));
	strcpy(s->file_name, file_name);
	s->is_file = is_file;
	s->files_under = NULL;
	s->mtime = time(NULL);
	HASH_ADD_STR(*target_hash_table, file_name, s);  // file system usualy use inode number as key, here use file_name just for ease.
	return s;

}


static void hash_join_inode(inode_struct** target_hash_table, inode_struct* target_inode) {

	HASH_ADD_STR(*target_hash_table, file_name, target_inode);  // file system usualy use inode number as key, here use file_name just for ease.
}

static inode_struct* hash_find_inode(inode_struct* target_hash_table, char *file_name) {
	inode_struct *s;

	HASH_FIND_STR(target_hash_table, file_name, s);  /* s: output pointer */
	return s;

}


void hash_delete_inode(inode_struct** target_hash_table, inode_struct* target_file) {
	if (target_file->is_file && target_file->file_metadata) {
        char uuid_str[37];
        char file_path[512];
        uuid_unparse(target_file->file_metadata->uuid, uuid_str);
        snprintf(file_path, sizeof(file_path), "%s/%s", DATA_DIR, uuid_str);
        remove(file_path);
        free(target_file->file_metadata);
    }
    
	HASH_DEL(*target_hash_table, target_file);

	if(target_file->files_under){
		inode_struct *s, *tmp;
		HASH_ITER(hh, target_file->files_under, s, tmp) {
			hash_delete_inode(&target_file->files_under, s);
		}
	}
	free(target_file);

}



// Deleting all inode
void hash_delete_all_inode(inode_struct** target_hash_table) {
	inode_struct *s, *tmp;

	HASH_ITER(hh, *target_hash_table, s, tmp) {
		hash_delete_inode(target_hash_table, s);
		
	}

}

/* –- Custom operations –- */

inode_struct** get_hash_table_from_path(const char* path, char* child_name_out)
{
	if(strcmp(path, "/") == 0)
	{
		strncpy(child_name_out, "\0", MAX_FILENAME_LENGTH);
		return &root->files_under;
	}



	path++; // Eliminating "/" in the path

	char path_copy[MAX_FILENAME_LENGTH];
	strncpy(path_copy, path, sizeof(path_copy));
	path_copy[sizeof(path_copy) - 1] = '\0';


	inode_struct* parent = root;
	char* parent_name = NULL, *child_name;
	char* saveptr;

	child_name = strtok_r(path_copy, "/", &saveptr);
	while (child_name != NULL) 
	{
		if(parent_name != NULL)
		{
			parent = hash_find_inode(parent->files_under, parent_name);
			if(parent==NULL)
				return NULL;
		}
		
		parent_name = child_name;
		child_name = strtok_r(NULL, "/", &saveptr);
	}
	if(parent_name){
		strncpy(child_name_out, parent_name, MAX_FILENAME_LENGTH);
	}

	return &parent->files_under;

}

void add_dir( const char* path )
{
	char new_dir_name [MAX_FILENAME_LENGTH];
	inode_struct** hash_table = get_hash_table_from_path(path, new_dir_name);

	hash_add_inode(hash_table, new_dir_name, 0);

}

int is_dir( const char* path )
{
	char target_name [MAX_FILENAME_LENGTH];
	inode_struct** hash_table = get_hash_table_from_path(path, target_name);
	inode_struct* target = hash_find_inode(*hash_table, target_name);
	
	if(!target) return 0;
	return target->is_file==0?1:0;
}

void add_file( const char* path )
{
	char new_file_name [MAX_FILENAME_LENGTH];
	inode_struct**hash_table = get_hash_table_from_path(path, new_file_name);
	inode_struct* new_file;

	HASH_FIND_STR(*hash_table, new_file_name, new_file);
	if(new_file != NULL) return;

	new_file = hash_add_inode(hash_table, new_file_name, 1);

	new_file->file_metadata = file_metadata_init();
	printf("metadata_init\n");

	// Create an empty file
	char uuid_str[37];
    char file_path[512];
    uuid_unparse(new_file->file_metadata->uuid, uuid_str);
    snprintf(file_path, sizeof(file_path), "%s/%s", DATA_DIR, uuid_str);
    FILE* f = fopen(file_path, "w");
    if (f) fclose(f);

}

int is_file( const char* path )
{
	char target_name [MAX_FILENAME_LENGTH];
	inode_struct**hash_table = get_hash_table_from_path(path, target_name);
	inode_struct* target = hash_find_inode(*hash_table, target_name);


	if(!target) return 0;
	return target->is_file;

}


static int do_getattr( const char *path, struct stat *st )
{
	char target_name [MAX_FILENAME_LENGTH];
	inode_struct** hash_table = get_hash_table_from_path(path, target_name);
	inode_struct* target = hash_find_inode(*hash_table, target_name);

	st->st_uid = getuid(); // The owner of the file/directory is the user who mounted the filesystem
	st->st_gid = getgid(); // The group of the file/directory is the same as the group of the user who mounted the filesystem
	st->st_atime = time( NULL ); // The last "a"ccess of the file/directory is right now
	if(target)
		st->st_mtime = target->mtime; // The last "m"odification of the file/directory is right now

	if ( strcmp( path, "/" ) == 0 || is_dir( path ) == 1 )
	{
		st->st_mode = S_IFDIR | 0755;
		st->st_nlink = 2; // Why "two" hardlinks instead of "one"? The answer is here: http://unix.stackexchange.com/a/101536
	}
	else if ( is_file( path ) == 1 )
	{
		st->st_mode = S_IFREG | 0644;
		st->st_nlink = 1;
		st->st_size = (target && target->file_metadata)? target->file_metadata->size:0;
	}
	else
	{
		return -ENOENT;
	}

	return 0;

}

static int do_readdir( const char *path, void* buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* fi )
{
	filler( buffer, ".", NULL, 0 ); // Current Directory
	filler( buffer, "..", NULL, 0 ); // Parent Directory


	inode_struct *s;
	if(strcmp(path, "/") == 0)
	{
		for (s = root->files_under; s != NULL; s = s->hh.next) {
			filler(buffer, s->file_name, NULL, 0);
		}

		return 0;
	}

	char target_name [MAX_FILENAME_LENGTH];
	inode_struct** hash_table = get_hash_table_from_path(path, target_name);
	inode_struct* target = hash_find_inode(*hash_table, target_name);

	
	if(!target)
		return 0;

	for (s = target->files_under; s != NULL; s = s->hh.next) {
		filler(buffer, s->file_name, NULL, 0);
	}

	return 0;

}

static int do_read( const char *path, char* buffer, size_t size, off_t offset, struct fuse_file_info* fi )
{
	char target_name [MAX_FILENAME_LENGTH];
	inode_struct** hash_table = get_hash_table_from_path(path, target_name);
	inode_struct* target = hash_find_inode(*hash_table, target_name);

	if (target==NULL)
		return -1;

	// Build file path from UUID
	char uuid_str[37];
    char file_path[512];
    uuid_unparse(target->file_metadata->uuid, uuid_str);
    snprintf(file_path, sizeof(file_path), "%s/%s", DATA_DIR, uuid_str);


	// Read encrypted file content

	FILE* f = fopen(file_path, "rb");
	if(!f) return -1;

	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	char * encrypted_content = malloc(fsize);
	fread(encrypted_content, fsize, 1, f);
	fclose(f);
	

	// Decrypt file content

	char * decrypted_content;
	size_t len;

	len = aes_gcm_decrypt(encrypted_content, fsize, target->file_metadata ,&decrypted_content);
	printf("\noffset = %ld,   size  = %ld, decrypted_len = %ld\n", offset, size, len);

	if(offset >= len) return 0;
	if(size > len - offset) size = len - offset;

	memcpy( buffer, decrypted_content + offset, size );
	free(decrypted_content);
	return size;

}

static int do_mkdir( const char *path, mode_t mode )
{
	add_dir( path );
	serialize_metadata();

	return 0;

}

static int do_mknod( const char *path, mode_t mode, dev_t rdev )
{
	add_file( path );
	serialize_metadata();
	return 0;

}

static int do_write( const char* path, const char* buffer, size_t size, off_t offset, struct fuse_file_info* info ) {
	char target_name [MAX_FILENAME_LENGTH];
	inode_struct** hash_table = get_hash_table_from_path(path, target_name);
	inode_struct* target = hash_find_inode(*hash_table, target_name);
    
    if (target == NULL || !target->is_file) return -ENOENT;

    // --- Read old content ---
    char uuid_str[37];
    char file_path[512];
    uuid_unparse(target->file_metadata->uuid, uuid_str);
    snprintf(file_path, sizeof(file_path), "%s/%s", DATA_DIR, uuid_str);

    char* old_decrypted_content = NULL;
    FILE* f = fopen(file_path, "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (fsize > 0) {
            char* old_encrypted_content = malloc(fsize);
            fread(old_encrypted_content, fsize, 1, f);
            aes_gcm_decrypt(old_encrypted_content, fsize, target->file_metadata, &old_decrypted_content);
            free(old_encrypted_content);
        }
        fclose(f);
    }
    
    if (old_decrypted_content == NULL) {
        old_decrypted_content = calloc(1, 1);
    }
    
    // --- Combine old and new data (for encription) ---
    size_t old_len = target->file_metadata->size;
    size_t new_len = offset + size;
    char* new_decrypted_content = (char*)malloc(new_len + 1);
    memcpy(new_decrypted_content, old_decrypted_content, offset > old_len ? old_len : offset);
    if (offset > old_len) {
        // Fill the gap with zeros
        memset(new_decrypted_content + old_len, 0, offset - old_len);
    }
    memcpy(new_decrypted_content + offset, buffer, size);
    new_decrypted_content[new_len] = '\0';
    free(old_decrypted_content);

	// --- Encrypt & Write back ---
    char* encrypted_output = NULL;
    int encrypted_size = aes_gcm_encrypt(new_decrypted_content, target->file_metadata, &encrypted_output);
    free(new_decrypted_content);

    f = fopen(file_path, "wb");
    if (!f) {
        if(encrypted_output) free(encrypted_output);
        return -EIO;
    }
    if (encrypted_output) {
        fwrite(encrypted_output, encrypted_size, 1, f);
        free(encrypted_output);
    }
    fclose(f);

    target->mtime = time(NULL);
	target->file_metadata->size = new_len;
    serialize_metadata(); // Store changes to disk every time.
	return size;
}

static int do_open(const char* path,struct fuse_file_info* fi)
{
	char target_name [MAX_FILENAME_LENGTH];
	inode_struct** hash_table = get_hash_table_from_path(path, target_name);
	inode_struct* target = hash_find_inode(*hash_table, target_name);

	if(target){
		char* key = target->file_metadata->key;
		print_data(key,32,"file key obtained. file key : ");
	}

	return 0;

}

static int do_release(const char* path,struct fuse_file_info* fi){
	printf("file closed");
	return 0;
}

static int do_rmdir(const char* path){
	char target_name [MAX_FILENAME_LENGTH];
	inode_struct** hash_table = get_hash_table_from_path(path, target_name);
	inode_struct* target = hash_find_inode(*hash_table, target_name);

	if(!target || target->is_file) return -ENOENT;
	if(target->files_under != NULL) return -ENOTEMPTY;

	hash_delete_inode(hash_table, target);
	serialize_metadata();

	return 0;

}

static int do_unlink(const char* path){
	char target_name [MAX_FILENAME_LENGTH];
	inode_struct** hash_table = get_hash_table_from_path(path, target_name);
	inode_struct* target = hash_find_inode(*hash_table, target_name);

	hash_delete_inode(hash_table, target);
	serialize_metadata();
	
	return 0;
}

static int do_rename(const char *oldpath, const char *newpath){
	char target_name [MAX_FILENAME_LENGTH];
	inode_struct** hash_table = get_hash_table_from_path(oldpath, target_name);
	inode_struct* target = hash_find_inode(*hash_table, target_name);

	if(!target)
		return 0;

	HASH_DEL(*hash_table, target); 
	
	hash_table = get_hash_table_from_path(newpath, target_name);
	strncpy(target->file_name, target_name, MAX_FILENAME_LENGTH);
	
	inode_struct* exist = hash_find_inode(*hash_table, target_name);
	if(exist)
		hash_delete_inode(hash_table, exist);

	hash_join_inode(hash_table, target);
	serialize_metadata();
	return 0;
}


static struct fuse_operations operations = {
	.getattr = do_getattr,
	.readdir = do_readdir,
	.read = do_read,
	.mkdir = do_mkdir,
	.mknod = do_mknod,
	.write = do_write,
	.open = do_open,
	.release = do_release,
	.rmdir = do_rmdir,
	.unlink = do_unlink,
	.rename = do_rename
};

int main( int argc, char *argv[] )
{
	mkdir(DATA_DIR, 0755);

	root = malloc(sizeof(inode_struct));
	strcpy(root->file_name, "/");
	root->is_file = 0;
	root->files_under = NULL;
	root->file_metadata = NULL;

	deserialize_metadata();

	return fuse_main( argc, argv, &operations, NULL );
}
