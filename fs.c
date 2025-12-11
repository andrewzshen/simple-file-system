#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "fs.h"
#include "disk.h"

#define MAX_FD_COUNT 32
#define MAX_FILE_COUNT 64
#define MAX_FILE_NAME_LENGTH 64

#define FAT_FREE -1
#define FAT_EOC 0

struct superblock {
    size_t dir_start; 
    size_t dir_blocks; 
    
    size_t fat_start; 
    size_t fat_blocks;
    
    size_t data_start;
    size_t data_blocks;
};

struct directory {
    int used;
    char name[MAX_FILE_NAME_LENGTH];
    int size;
    int head;
    int ref_count;
};

struct file_desc {
    int used;
    int file;
    int offset;
};

static struct superblock sb;
static int *fat;
static struct directory *directories;
static struct file_desc fd_table[MAX_FD_COUNT];

/* File system API */
int make_fs(char *disk_name) {
    if (!disk_name) return -1;
    if (make_disk(disk_name) == -1) return -1;
    if (open_disk(disk_name) == -1) return -1;

    struct superblock temp = {0};
    temp.dir_start = 1;
    temp.dir_blocks = 1; 

    temp.fat_start = 2; 
    temp.fat_blocks = 4; 

    temp.data_start = 6;
    temp.data_blocks = DISK_BLOCKS - temp.data_start;

    char buffer[BLOCK_SIZE];
    memset(buffer, 0, BLOCK_SIZE);
    memcpy(buffer, &temp, sizeof(struct superblock));

    if (block_write(0, buffer) == -1) return -1;
    if (close_disk() == -1) return -1;
    
    return 0;
}

int mount_fs(char *disk_name) {
    if (!disk_name) return -1;
    if (open_disk(disk_name) == -1) return -1; 

    char buffer[BLOCK_SIZE];
    memset(buffer, 0, BLOCK_SIZE);

    if (block_read(0, buffer) != 0) return -1;

    memcpy(&sb, buffer, sizeof(struct superblock));
    
    directories = (struct directory*)malloc(sb.dir_blocks * BLOCK_SIZE);
    
    if (directories == NULL) {
        return -1;
    }

    for (size_t i = 0; i < sb.dir_blocks; i++) {
        if (block_read(sb.dir_start + i, buffer) != 0) {
            free(fat);
            free(directories);
            return -1;
        }
        
        memcpy((char*)directories + (i * BLOCK_SIZE), buffer, BLOCK_SIZE);
    }

    fat = (int*)malloc(sb.fat_blocks * BLOCK_SIZE);

    if (fat == NULL) {
        free(directories);
        return -1;
    }
    
    for (size_t i = 0; i < sb.fat_blocks; i++) {
        if (block_read(sb.fat_start + i, buffer) != 0) {
            free(fat);
            return -1;
        }
        
        memcpy(fat + (i * (BLOCK_SIZE / sizeof(int))), buffer, BLOCK_SIZE);
    }

    memset(fd_table, 0, sizeof(fd_table));

    return 0;
}

int umount_fs(char *disk_name) {
    char buffer[BLOCK_SIZE];
    memset(buffer, 0, BLOCK_SIZE);
    
    if (fat != NULL) {
        for (size_t i = 0; i < sb.fat_blocks; i++) {
            memcpy(buffer, fat + (i * (BLOCK_SIZE / sizeof(int))), BLOCK_SIZE);
            if (block_write(sb.fat_start + i, buffer) != 0) return -1;
        }
        
        free(fat);
        fat = NULL;
    }

    if (directories != NULL) {
        for (size_t i = 0; i < sb.dir_blocks; i++) {
            memcpy(buffer, (char*)directories + (i * BLOCK_SIZE), BLOCK_SIZE);   
            if (block_write(sb.dir_start + i, buffer) != 0) return -1;
        }

        free(directories);
        directories = NULL;
    }

    for (size_t i = 0; i < MAX_FD_COUNT; i++) {
        fs_close(i);
    }

    if (close_disk() == -1) return -1;

    return 0;
}

int fs_open(char *name) {
    int file_index = -1;
    
    for (size_t i = 0; i < MAX_FILE_COUNT; i++) {
        int used = directories[i].used;
        int same_name = strcmp(directories[i].name, name) == 0;

        if (used && same_name) {
            file_index = i;
            break;
        }
    }
    
    if (file_index == -1) return -1;

    int fildes = -1;
    
    for (size_t i = 0; i < MAX_FD_COUNT; i++) {
        if (!fd_table[i].used) {
            fildes = i;
            fd_table[i].used = 1;
            fd_table[i].file = file_index;
            fd_table[i].offset = 0;
            break;
        }
    }
    
    if (fildes == -1) return -1;

    directories[file_index].ref_count++;
    
    return fildes;
}

int fs_close(int fildes) {
    if (fildes < 0 || fildes >= MAX_FD_COUNT) return -1; 
    if (!fd_table[fildes].used) return -1;

    int file_index = fd_table[fildes].file;

    if (directories[file_index].used) {
        directories[file_index].ref_count--;
    }

    fd_table[fildes].used = 0;
    fd_table[fildes].file = -1;
    fd_table[fildes].offset = 0;

    return 0;
}

int fs_create(char *name) {
    if (strlen(name) > MAX_FILE_NAME_LENGTH) return -1;

    for (size_t i = 0; i < MAX_FILE_COUNT; i++) {
        if (memcmp(directories[i].name, name, strlen(name)) == 0) return -1;
    }

    int free_index = -1;
    
    for (size_t i = 0; i < MAX_FILE_COUNT; i++) {
        if (directories[i].used == 0) {
            free_index = i;
            break;
        }
    }
    
    if (free_index == -1) return -1;

    directories[free_index].used = 1;
    directories[free_index].size = 0;
    directories[free_index].head = -1;
    directories[free_index].ref_count = 0;
    memcpy(directories[free_index].name, name, strlen(name));
    
    return 0;
}

int fs_delete(char *name) {
    for (size_t i = 0; i < MAX_FILE_COUNT; i++) {
        struct directory *dir = &directories[i];

        int used = dir->used;
        int diff_name = strcmp(dir->name, name) != 0;

        if (!used || diff_name) continue;
        
        if (dir->ref_count > 0) return -1;

        int curr_block = dir->head;
        int next_block = fat[curr_block];
        
        while (curr_block != -1) {
            next_block = fat[curr_block];
            fat[curr_block] = 0;
            curr_block = next_block;
        }

        dir->used = 0;
        dir->size = 0;
        dir->head = -1;
        dir->ref_count = 0;
        memset(dir->name, 0, strlen(name));

        return 0;
    }
    
    return -1;
}

int fs_read(int fildes, void *buf, size_t nbyte) {
    if (fildes < 0 || fildes >= MAX_FD_COUNT) return -1;
    if (!fd_table[fildes].used) return -1;
    
    struct file_desc *fd = &fd_table[fildes];
    struct directory *file = &directories[fd->file];

    if (fd->offset >= file->size) return 0;

    size_t totalbytes = nbyte;
    
    if (fd->offset + nbyte > file->size) {
        totalbytes = file->size - fd->offset;
    }

    int curr_block = file->head;
    size_t offset_in_block = fd->offset % BLOCK_SIZE;
    size_t block_offset = fd->offset / BLOCK_SIZE;

    while (block_offset >= BLOCK_SIZE && curr_block != -1) {
        curr_block = fat[curr_block];
        block_offset--;
    }

    size_t bytes_read = 0;

    while (totalbytes > 0 && curr_block != -1) {
        char block_data[BLOCK_SIZE];
        if (block_read(sb.data_start + curr_block, block_data) == -1) return -1;
        
        size_t bytes_from_block = BLOCK_SIZE - offset_in_block;
        
        if (bytes_from_block > totalbytes) {
            bytes_from_block = totalbytes;
        }

        memcpy((char*)buf + bytes_read, block_data + offset_in_block, bytes_from_block);
        totalbytes -= bytes_from_block;
        bytes_read += bytes_from_block;
        offset_in_block = 0;

        curr_block = fat[curr_block];
    }

    fd->offset += bytes_read;

    return bytes_read;
}

int fs_write(int fildes, void *buf, size_t nbyte) {
    if (fildes < 0 || fildes >= MAX_FD_COUNT) return -1;
    if (!fd_table[fildes].used) return -1;

    struct file_desc *fd = &fd_table[fildes];
    struct directory *file = &directories[fd->file];

    size_t bytes_written = 0;
    size_t remaining_bytes = nbyte;
    size_t offset_in_block = fd->offset % BLOCK_SIZE;

    int curr_block = file->head;
    size_t block_index = fd->offset / BLOCK_SIZE;

    while (block_index > 0 && curr_block != -1) {
        curr_block = fat[curr_block];
        block_index--;
    }

    while (remaining_bytes > 0) {
        if (curr_block == -1) {
            int new_block = -1;

            for (int i = 0; i < sb.data_blocks; i++) {
                if (fat[i] == FAT_FREE) {
                    new_block = i;
                    fat[i] = FAT_EOC;
                    break;
                }
            }
            
            if (new_block == -1) {
                return bytes_written;
            }

            if (file->head == -1) {
                file->head = new_block;
            } else {
                int last = file->head;
                while (fat[last] != -1) last = fat[last];
                fat[last] = new_block;
            }

            curr_block = new_block;
        }

        char block_data[BLOCK_SIZE];
        
        if (block_read(sb.data_start + curr_block, block_data) == -1) {
            memset(block_data, 0, BLOCK_SIZE);
        }    

        size_t bytes_in_block = BLOCK_SIZE - offset_in_block;

        if (bytes_in_block > remaining_bytes) {
            bytes_in_block = remaining_bytes;
        }

        memcpy(block_data + offset_in_block, (char *)buf + bytes_written, bytes_in_block);

        if (block_write(sb.data_start + curr_block, block_data) == -1) return -1;

        bytes_written += bytes_in_block;
        remaining_bytes -= bytes_in_block;
        offset_in_block = 0;

        if (remaining_bytes > 0) {
            if (fat[curr_block] == -1) {
                curr_block = -1;
            } else {
                curr_block = fat[curr_block];
            }
        }
    }

    fd->offset += bytes_written;
    
    if (fd->offset > file->size) {
        file->size = fd->offset;
    }

    return bytes_written;
}

int fs_get_filesize(int fildes) {
    if (fildes < 0 || fildes >= MAX_FD_COUNT) return -1;
    if (!fd_table[fildes].used) return -1;
    
    struct file_desc *fd = &fd_table[fildes];
    struct directory *file = &directories[fd->file];

    return file->size;
}

int fs_lseek(int fildes, off_t offset) {
    if (fildes < 0 || fildes >= MAX_FD_COUNT) return -1;
    if (!fd_table[fildes].used) return -1;
    
    struct file_desc *fd = &fd_table[fildes];
    struct directory *file = &directories[fd->file];
    
    if (offset < 0 || offset > file->size) return -1;
    
    fd->offset = offset;

    return 0;
}

int fs_truncate(int fildes, off_t length) {
    if (fildes < 0 || fildes >= MAX_FD_COUNT) return -1;
    if (!fd_table[fildes].used) return -1;
    
    struct file_desc *fd = &fd_table[fildes];
    struct directory *file = &directories[fd->file];
    
    if (length > file->size) return -1;

    if (fd->offset > length) {
        fd->offset = length;
    }

    int curr_block = file->head;
    size_t offset_in_block = length;

    while (offset_in_block >= BLOCK_SIZE && curr_block != -1) {
        curr_block = fat[curr_block];
        offset_in_block -= BLOCK_SIZE;
    }

    if (curr_block != -1) {
        int next_block = fat[curr_block];
        fat[curr_block] = -1;

        while (next_block != -1) {
            int temp_block = next_block;
            next_block = fat[next_block];
            fat[temp_block] = 0;
        }
    }

    file->size = length;

    return 0;
}
