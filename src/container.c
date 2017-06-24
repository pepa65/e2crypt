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

    if (statfs(path, &fs) != 0) {
        error(0, "Cannot get filesystem information for %s: %s", path, strerror(errno));
        return false;
    }

    return (fs.f_type == EXT4_SUPER_MAGIC);
}

// Open an existing file on an ext4 filesystem
// Return a read-only file descriptor
static
int open_ext4_path(const char *path, int flags)
{
    if (!is_ext4_filesystem(path)) {
        error(0, "Error: %s not found on ext4 filesystem", path);
        return -1;
    }

    int open_flags = O_RDONLY | O_NONBLOCK | flags;
    int fd = open(path, open_flags);
    if (fd == -1) {
        if (errno == ENOTDIR)
            error(0, "Invalid argument: %s not a directory", path);
        else
            error(0, "Cannot open %s: %s", path, strerror(errno));

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
    if (ioctl(dirfd, EXT4_IOC_GET_ENCRYPTION_POLICY, policy) < 0) {
        switch (errno) {
            case ENOENT:
                *has_policy = false;
                return 0;

            case ENOTSUP:
                error(0, "This filesystem does not support encryption");
                error(0, "Make sure the kernel supports CONFIG_EXT4_ENCRYPTION");
                return -1;

            default:
                error(0, "Cannot access ext4 encryption policy: %s", strerror(errno));
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
    if (ioctl(dirfd, EXT4_IOC_SET_ENCRYPTION_POLICY, policy) < 0) {
        switch (errno) {
            case ENOTSUP:
                error(0, "This filesystem does not support encryption");
                error(0, "Make sure rhe kernel supports CONFIG_EXT4_ENCRYPTION");
                return -1;

            case EINVAL:
                error(0, "Encryption parameters do not match the ones already set");
                return -1;

            case ENOTEMPTY:
                error(0, "Cannot setup encrypted directory: not empty");
                return -1;

            default:
                error(0, "Cannot set ext4 encryption policy: %s", strerror(errno));
                return -1;
        }
    }

    return 0;
}

// Setup a new encryption policy for the specified directory
static
int setup_ext4_encryption(const char *dir_path, int dirfd)
{
    struct ext4_encryption_policy policy;    

    // Current policy version
    policy.version = 0;

    policy.contents_encryption_mode = cipher_string_to_mode(contents_cipher);
    policy.filenames_encryption_mode = cipher_string_to_mode(filename_cipher);
    policy.flags = padding_length_to_flags(padding);

    generate_random_name(policy.master_key_descriptor, EXT4_KEY_DESCRIPTOR_SIZE, 0);

    int ret = set_ext4_encryption_policy(dirfd, &policy);
    container_status(dir_path);
		return ret;
}

// Print information about directory container
int container_status(const char *dir_path)
{
    int dirfd = open_ext4_directory(dir_path);
    if (dirfd == -1) {
        error(0, "Cannot open %s", dir_path);
        return -1;
    }

    struct ext4_encryption_policy policy;
    bool has_policy;

    if (get_ext4_encryption_policy(dirfd, &policy, &has_policy) < 0) {
        error(0, "Cannot access directory properties of %s", dir_path);
        return -1;
    }

    if (!has_policy) {
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
    if (find_key_by_descriptor(&policy.master_key_descriptor, &key_serial) == -1)
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
    if (fd == -1) {
        error(0, "Cannot create nonce in directory: %s", strerror(errno));
        return -1;
    }

    if (unlinkat(dirfd, dummy_name, 0) != 0) {
        error(0, "Cannot unlink nonce in directory: %s", strerror(errno));
        return -1;
    }

    close(fd);
    return 0;
}

// Setup an encrypted directory at dir_path
int container_create(const char *dir_path)
{
    if (crypto_init() == -1)
        return -1;

    int dirfd = open_ext4_directory(dir_path);
    if (dirfd == -1)
        return -1;

    struct ext4_encryption_policy policy;
    bool has_policy;

    // First check if the directory is not already encrypted
    if (get_ext4_encryption_policy(dirfd, &policy, &has_policy) < 0) {
        error(0, "Cannot access directory properties of %s", dir_path);
        return -1;
    }

    if (has_policy) {
        error(0, "Cannot encrypt directory %s: already encrypted", dir_path);
        return -1;
    }

    // Sets up the encryption policy
    if (setup_ext4_encryption(dir_path, dirfd) < 0) {
        error(0, "Error in encrypting directory %s", dir_path);
        return -1;
    }

    // Check if the encryption policy was successfully created
    if (get_ext4_encryption_policy(dirfd, &policy, &has_policy) < 0) {
        error(0, "Cannot access directory properties of %s", dir_path);
        return -1;
    }

    if (!has_policy) {
        error(0, "Encrypting directory %s failed", dir_path);
        return -1;
    }

    // Attach a key to the directory
    if (request_key_for_descriptor(&policy.master_key_descriptor, true) < 0) {
        error(0, "Error seting password for encrypted directory %s", dir_path);
        return -1;
    }

    // The directory is left in an inconsistent state if the superblock is unmounted before any inode is created
    if (create_dummy_inode(dirfd) < 0) return -1;

    printf("Directory %s now encrypted\n", dir_path);
    close(dirfd);
    return 0;
}

// Use a password on the encrypted directory
int container_attach(const char *dir_path)
{
    if (crypto_init() == -1) {
        error(0, "Cannot access cryptography system");
        return -1;
    }

    int dirfd = open_ext4_directory(dir_path);
    if (dirfd == -1) {
        error(0, "Cannot open directory %s", dir_path);
        return -1;
    }

    struct ext4_encryption_policy policy;    
    bool has_policy;

    // Check that this directory has already been set up for encryption
    if (get_ext4_encryption_policy(dirfd, &policy, &has_policy) < 0) {
        error(0, "Not an encrypted directory: %s", dir_path);
        return -1;
    }

    if (!has_policy) {
        error(0, "Cannot decrypt: %s not an encrypted directory", dir_path);
        return -1;
    }

    if (request_key_for_descriptor(&policy.master_key_descriptor, false) < 0) {
        error(0, "Error in decrypting directory %s", dir_path);
        return -1;
    }

    close(dirfd);
    printf("Directory %s now decrypted\n", dir_path);
    return 0;
}

// Recrypt the encrypted directory
int container_detach(const char *dir_path)
{
    int dirfd = open_ext4_directory(dir_path);
    if (dirfd == -1) {
        error(0, "Cannot open directory %s", dir_path);
        return -1;
    }

    struct ext4_encryption_policy policy;
    bool has_policy;

    // Check that this directory is setup for encryption
    if (get_ext4_encryption_policy(dirfd, &policy, &has_policy) < 0) {
        error(0, "Cannot access directory properties of %s", dir_path);
        return -1;
    }

    if (!has_policy) {
        error(0, "Cannot recrypt, directory %s not set up for encryption", dir_path);
        return -1;
    }

    if (remove_key_for_descriptor(&policy.master_key_descriptor) < 0) {
        error(0, "Cannot recrypt, directory %s not decrypted", dir_path);
        return -1;
    }

    close(dirfd);
    printf("Directory %s now recrypted\n", dir_path);
    system("echo 2 |sudo tee /proc/sys/vm/drop_caches >/dev/null");
    return 0;
}
