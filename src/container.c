#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <sys/vfs.h>
#include <sys/ioctl.h>
#include <asm-generic/ioctl.h>
#include <assert.h>
#include <errno.h>

#include "e2crypt.h"

// Check if the given file path is on an ext4 filesystem
static
bool is_ext4_filesystem(const char *path)
{
    struct statfs fs;

    if ( statfs(path, &fs) != 0 ) {
        fprintf(stderr, "Cannot get filesystem information for %s: %s\n", path, strerror(errno));
        return false;
    }

    return (fs.f_type == EXT4_SUPER_MAGIC);
}

// Open an existing file on an ext4 filesystem
// Return a read-only file descriptor
static
int open_ext4_path(const char *path, int flags)
{
    if ( !is_ext4_filesystem(path) ) {
        fprintf(stderr, "Error: %s not found on ext4 filesystem\n", path);
        return -1;
    }

    int open_flags = O_RDONLY | O_NONBLOCK | flags;
    int fd = open(path, open_flags);
    if ( fd == -1 ) {
        if ( errno == ENOTDIR )
            fprintf(stderr, "Invalid argument: %s not a directory\n", path);
        else
            fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno));

        return -1;
    }

    return fd;
}

// Open an existing directory on an ext4 filesystem
// Return a file descriptor of the directory
static
int open_ext4_directory(const char *dir_path)
{
    return open_ext4_path(dir_path, O_DIRECTORY);
}

// Query the kernel for inode encryption policy
static
int get_ext4_encryption_policy(int dirfd, struct ext4_encryption_policy *policy, bool *has_policy)
{
    if ( ioctl(dirfd, EXT4_IOC_GET_ENCRYPTION_POLICY, policy) < 0 ) {
        switch ( errno ) {
            case ENOENT:
                *has_policy = false;
                return 0;

            case ENOTSUP:
                fprintf(stderr, "This filesystem does not support encryption\n");
                fprintf(stderr, "Make sure the kernel supports CONFIG_EXT4_ENCRYPTION\n");
                return -1;

            default:
                fprintf(stderr, "Cannot access ext4 encryption policy: %s\n", strerror(errno));
                return -1;
        }
    }

    *has_policy = true;
    return 0;
}

// Apply the specified ext4 encryption policy to directory
static
int set_ext4_encryption_policy(int dirfd, struct ext4_encryption_policy *policy)
{
    if ( ioctl(dirfd, EXT4_IOC_SET_ENCRYPTION_POLICY, policy) < 0 ) {
        switch ( errno ) {
            case ENOTSUP:
                fprintf(stderr, "This filesystem does not support encryption\n");
                fprintf(stderr, "Make sure rhe kernel supports CONFIG_EXT4_ENCRYPTION\n");
                return -1;

            case EINVAL:
                fprintf(stderr, "Encryption parameters do not match the ones already set\n");
                return -1;

            case ENOTEMPTY:
                fprintf(stderr, "Cannot setup encrypted directory: not empty\n");
                return -1;

            default:
                fprintf(stderr, "Cannot set ext4 encryption policy: %s\n", strerror(errno));
                return -1;
        }
    }

    return 0;
}

// Setup a new encryption policy for the specified directory
static
int setup_ext4_encryption(const char *dir_path, int dirfd, struct ext4_crypt_options opts) 
{
    struct ext4_encryption_policy policy;    

    // Current policy version
    policy.version = 0;

    policy.contents_encryption_mode = cipher_string_to_mode(opts.contents_cipher);
    policy.filenames_encryption_mode = cipher_string_to_mode(opts.filename_cipher);
    policy.flags = padding_length_to_flags(opts.filename_padding);

    generate_random_name(opts.key_descriptor, sizeof(opts.key_descriptor), 0);

    memcpy(policy.master_key_descriptor, opts.key_descriptor, sizeof(policy.master_key_descriptor));

    int ret = set_ext4_encryption_policy(dirfd, &policy);
    container_status(dir_path);
		return ret;
}

// Print information about directory container
int container_status(const char *dir_path)
{
    int dirfd = open_ext4_directory(dir_path);
    if ( dirfd == -1 ) {
        printf("Cannot open %s\n", dir_path);
        return -1;
    }

    struct ext4_encryption_policy policy;
    bool has_policy;

    if ( get_ext4_encryption_policy(dirfd, &policy, &has_policy) < 0 ) {
        printf("Cannot access directory properties of %s\n", dir_path);
        return -1;
    }

    if ( !has_policy ) {
        printf("Regular directory:    %s\n", dir_path);
        return 1;
    }

    printf("Encrypted directory:  %s\n", dir_path);
    printf("Policy version:       %d\n", policy.version);
    printf("Filename cipher:      %s\n", cipher_mode_to_string(policy.filenames_encryption_mode));
    printf("Contents cipher:      %s\n", cipher_mode_to_string(policy.contents_encryption_mode));
    printf("Filename padding:     %d\n", flags_to_padding_length(policy.flags));
    printf("Key descriptor:       0x");
    for (int i=0; i<EXT4_KEY_DESCRIPTOR_SIZE; ++i)
        printf("%02X", policy.master_key_descriptor[i] & 0xff);
    printf("\n");

    key_serial_t key_serial;
    if ( find_key_by_descriptor(&policy.master_key_descriptor, &key_serial) == -1 )
        printf("Key serial:           not found\n");
    else printf("Key serial:           %d\n", key_serial);

    return 0;
}

// BUG? when the block is unmounted but no encrypted inode was created
// Create dummy inode file here and unlink it immediately
static
int create_dummy_inode(int dirfd)
{
    char dummy_name[EXT4_KEY_DERIVATION_NONCE_SIZE+1];
    generate_random_name(dummy_name, EXT4_KEY_DERIVATION_NONCE_SIZE, 1);

    int fd = openat(dirfd, dummy_name, O_NONBLOCK|O_CREAT|O_TRUNC|O_RDWR, S_IRUSR|S_IWUSR);
    if ( fd == -1 ) {
        fprintf(stderr, "Cannot create dummy inode in directory: %s\n", strerror(errno));
        return -1;
    }

    if ( unlinkat(dirfd, dummy_name, 0) != 0 ) {
        fprintf(stderr, "Cannot unlink dummy inode in directory: %s\n", strerror(errno));
        return -1;
    }

    close(fd);
    return 0;
}

// Setup an encrypted directory at dir_path
int container_create(const char *dir_path, struct ext4_crypt_options opts)
{
    if ( crypto_init() == -1 )
        return -1;

    int dirfd = open_ext4_directory(dir_path);
    if ( dirfd == -1 )
        return -1;

    struct ext4_encryption_policy policy;
    bool has_policy;

    // First check if the directory is not already encrypted
    if ( get_ext4_encryption_policy(dirfd, &policy, &has_policy) < 0 ) {
        fprintf(stderr, "Cannot access directory properties of %s", dir_path);
        return -1;
    }

    if ( has_policy ) {
        fprintf(stderr, "Cannot setup encrypted directory %s: already encrypted\n", dir_path);
        return -1;
    }

    // Sets up the encryption policy
    if ( setup_ext4_encryption(dir_path, dirfd, opts) < 0 ) {
        fprintf(stderr, "Error in seting up encrypted directory %s\n", dir_path);
        return -1;
    }

    // Check if the encryption policy was successfully created
    if ( get_ext4_encryption_policy(dirfd, &policy, &has_policy) < 0 ) {
        fprintf(stderr, "Cannot access directory properties of %s\n", dir_path);
        return -1;
    }

    if ( !has_policy ) {
        fprintf(stderr, "Seting up encrypted directory %s failed\n", dir_path);
        return -1;
    }

    // Attach a key to the directory
    if ( request_key_for_descriptor(&policy.master_key_descriptor, opts, true) < 0 ) {
        fprintf(stderr, "Error in seting password for encrypted directory %s\n", dir_path);
        return -1;
    }

    // The directory is left in an inconsistent state if the superblock is unmounted before any inode is created
    if ( create_dummy_inode(dirfd) < 0 ) return -1;

    printf("Encryption directory %s now set up\n", dir_path);
    close(dirfd);
    return 0;
}

// Use a password on the encrypted directory
int container_attach(const char *dir_path, struct ext4_crypt_options opts)
{
    if ( crypto_init() == -1 ) {
        fprintf(stderr, "Cannot access cryptography system\n");
        return -1;
    }

    int dirfd = open_ext4_directory(dir_path);
    if ( dirfd == -1 ) {
        fprintf(stderr, "Cannot open directory %s\n", dir_path);
        return -1;
    }

    struct ext4_encryption_policy policy;    
    bool has_policy;

    // Check that this directory has already been set up for encryption
    if ( get_ext4_encryption_policy(dirfd, &policy, &has_policy) < 0 ) {
        fprintf(stderr, "Not an encrypted directory: %s\n", dir_path);
        return -1;
    }

    if ( !has_policy ) {
        fprintf(stderr, "Cannot use password: %s not an encrypted directory\n", dir_path);
        return -1;
    }

    if ( request_key_for_descriptor(&policy.master_key_descriptor, opts, false) < 0 ) {
        fprintf(stderr, "Error in using password on %s\n", dir_path);
        return -1;
    }

    close(dirfd);
    printf("Encryption directory %s now decrypted\n", dir_path);
    return 0;
}

// Recrypt the encrypted directory
int container_detach(const char *dir_path, struct ext4_crypt_options UNUSED opts)
{
    int dirfd = open_ext4_directory(dir_path);
    if ( dirfd == -1 ) {
        fprintf(stderr, "Can't open directory %s\n", dir_path);
        return -1;
    }

    struct ext4_encryption_policy policy;
    bool has_policy;

    // Check that this directory is setup for encryption
    if ( get_ext4_encryption_policy(dirfd, &policy, &has_policy) < 0 ) {
        fprintf(stderr, "Cannot access directory properties of %s\n", dir_path);
        return -1;
    }

    if ( !has_policy ) {
        fprintf(stderr, "Directory %s not setup for encryption\n", dir_path);
        return -1;
    }

    if ( remove_key_for_descriptor(&policy.master_key_descriptor) < 0 ) {
        fprintf(stderr, "Directory %s already encrypted\n", dir_path);
        return -1;
    }

    close(dirfd);
    printf("Encryption directory %s now encrypted\n", dir_path);
    system("echo 2 |sudo tee /proc/sys/vm/drop_caches >/dev/null");
    return 0;
}
