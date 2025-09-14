#define _XOPEN_SOURCE 700 // for S_IFDIR and S_IFREG macro
#define FUSE_USE_VERSION 30
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

typedef struct inode_struct inode_struct;

struct inode_struct
{
	char file_name [MAX_FILENAME_LENGTH];
	char content [256]; // content or pointer to file that store data.
	int is_file; // 0 for dir, 1 for file.
	inode_struct* files_under; // hash table for files under this dir.
	file_metadata* file_metadata;
	UT_hash_handle hh; // makes this structure hashable

};

/* --- Hash util funcitons --- */
static inode_struct* hash_add_inode(inode_struct** target_hash_table, char *file_name,int is_file) {
	inode_struct *s;

	s = malloc(sizeof(inode_struct));
	strcpy(s->file_name, file_name);
	s->is_file = is_file;
	s->files_under = NULL;
	HASH_ADD_STR(*target_hash_table, file_name, s);  // file system usualy use inode number as key, here use file_name just for ease.
	return s;

}

static inode_struct* hash_find_inode(inode_struct** target_hash_table, char *file_name) {
	inode_struct *s;

	HASH_FIND_STR(*target_hash_table, file_name, s);  /* s: output pointer */
	return s;

}

void hash_delete_inode(inode_struct** target_hash_table, inode_struct* target_file) {
	HASH_DEL(*target_hash_table, target_file);  /*user: pointer to delete */ 

	if(target_file->files_under){
		inode_struct *s, *tmp;
		HASH_ITER(hh, target_file->files_under, s, tmp) {
			hash_delete_inode(&target_file->files_under, s);

		}
	}
	if(target_file->file_metadata)
		free(target_file->file_metadata);
	free(target_file);             /* optional; it's up to you! */

}



// Deleting all inode
void hash_delete_all_inode(inode_struct** target_hash_table) {
	inode_struct *s, *tmp;

	HASH_ITER(hh, *target_hash_table, s, tmp) {
		hash_delete_inode(target_hash_table, s);
		
	}

}

/* –- Custom operations –- */

static inode_struct* root = NULL; // Root hash table

inode_struct** get_hash_table_from_path(const char* path, char* child_name_out)
{
	if(strcmp(path, "/") == 0)
	{
		strncpy(child_name_out, "/", MAX_FILENAME_LENGTH);
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
			parent = hash_find_inode(&parent->files_under, parent_name);
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
	inode_struct* target = hash_find_inode(hash_table, target_name);
	
	if(!target) return 0;
	return target->is_file==0?1:0;
}

void add_file( const char* path )
{
	char new_file_name [MAX_FILENAME_LENGTH];
	inode_struct**hash_table = get_hash_table_from_path(path, new_file_name);
	inode_struct* new_file;
	new_file = hash_add_inode(hash_table, new_file_name, 1);

	new_file->file_metadata = file_metadata_init();
	printf("metadata_init\n");

	aes_gcm_encrypt("",new_file->file_metadata);
	printf("encrypt complete\n");
	// strcpy( files_content[ curr_file_idx ], "" );

}

int is_file( const char* path )
{
	char target_name [MAX_FILENAME_LENGTH];
	inode_struct**hash_table = get_hash_table_from_path(path, target_name);
	inode_struct* target = hash_find_inode(hash_table, target_name);


	if(!target) return 0;
	return target->is_file;

}

void write_to_file( const char* path, const char* new_content )
{
	char target_name [MAX_FILENAME_LENGTH];
	inode_struct** hash_table = get_hash_table_from_path(path, target_name);
	inode_struct* target = hash_find_inode(hash_table, target_name);

	printf("Write content unencrypt:\n%s\n",new_content);
	aes_gcm_encrypt(new_content,target->file_metadata);
	//strcpy( files_content[ file_idx ], new_content ); 

}

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
	inode_struct* target = hash_find_inode(hash_table, target_name);

	
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
	inode_struct* target = hash_find_inode(hash_table, target_name);

	if (target==NULL)
		return -1;

	char * content;
	aes_gcm_decrypt(target->file_metadata,&content);
	printf("\noffset = %d,   size  = %d\n",(int)offset,(int)size);

	size_t len = strlen(content);
	if(offset >= len) return 0;
	if(size > len - offset) size = len - offset;

	memcpy( buffer, content + offset, size );
	size_t return_value = strlen( content ) - offset;
	free(content);
	return return_value;

}

static int do_mkdir( const char *path, mode_t mode )
{
	add_dir( path );

	return 0;

}

static int do_mknod( const char *path, mode_t mode, dev_t rdev )
{
	add_file( path );

	return 0;

}

static int do_write( const char* path, const char* buffer, size_t size, off_t offset, struct fuse_file_info* info )
{
	write_to_file( path, buffer );
	return size;
}
static int do_open(const char* path,struct fuse_file_info* fi)
{
	char target_name [MAX_FILENAME_LENGTH];
	inode_struct** hash_table = get_hash_table_from_path(path, target_name);
	inode_struct* target = hash_find_inode(hash_table, target_name);

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
	inode_struct* target = hash_find_inode(hash_table, target_name);

	hash_delete_inode(hash_table, target);

	return 0;

}

static int do_unlink(const char* path){
	char target_name [MAX_FILENAME_LENGTH];
	inode_struct** hash_table = get_hash_table_from_path(path, target_name);
	inode_struct* target = hash_find_inode(hash_table, target_name);

	hash_delete_inode(hash_table, target);
	
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
	.unlink = do_unlink
};

int main( int argc, char *argv[] )
{
	root = malloc(sizeof(inode_struct));
	strcpy(root->file_name, "/");
	root->is_file = 0;
	root->files_under = NULL;
	root->file_metadata = NULL;

	return fuse_main( argc, argv, &operations, NULL );
}
