#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <linux/random.h>
#include <time.h>
#include <keyutils.h>
#include <sodium.h>
#include <termios.h>
#include <errno.h>

#include "e2crypt.h"

// Derive ext4 encryption key from passphrase
static
int derive_passphrase_to_key(char *pass, size_t pass_sz, struct ext4_encryption_key *key)
{
    const unsigned char salt[] = "ext4";

    int ret = crypto_pwhash_scryptsalsa208sha256_ll(
            (uint8_t *) pass, pass_sz, salt, sizeof(salt) - 1,
            (1 << 14), 8, 16, // N, r, p
            key->raw, key->size);

    if ( ret != 0 ) {
        fprintf(stderr, "Failed to derive key from passphrase\n");
        return -1;
    }

    return 0;
}

// Convert ext4 key descriptor to a keyring descriptor
static
void build_full_key_descriptor(key_desc_t *key_desc, full_key_desc_t *full_key_desc)
{
    char tmp[sizeof(*full_key_desc) + 1]; // one extra space for terminating zero
    strcpy(tmp, EXT4_KEY_DESC_PREFIX);

    for ( size_t i = 0; i < sizeof(*key_desc); i++ ) {
        snprintf(tmp + EXT4_KEY_DESC_PREFIX_SIZE + i * 2, 3, "%02x", (*key_desc)[i] & 0xff);
    }

    memcpy(*full_key_desc, tmp, sizeof(*full_key_desc));
}

// Fill key buffer with zeros
static
void zero_key(void *key, size_t key_sz)
{
    sodium_memzero(key, key_sz);
}

// Read passphrase from standard input
static
ssize_t read_passphrase(const char *prompt, char *key, size_t n)
{
    int stdin_fd = fileno(stdin);
    const bool tty_input = isatty(stdin_fd);
    struct termios old, new;
    size_t key_sz = 0;

    // Show prompt, disable echo
    if ( tty_input ) {
        fprintf(stderr, "%s", prompt);
        fflush(stderr);

        if ( tcgetattr(stdin_fd, &old) != 0 ) {
            perror("tcgetattr");
            return -1;
        }

        new = old;
        new.c_lflag &= ~ECHO;
        if ( tcsetattr(stdin_fd, TCSAFLUSH, &new) != 0 ) {
            perror("tcsetattr");
            return -1;
        }
    }

    if ( fgets(key, n, stdin) ) key_sz = strlen(key);
    if ( key_sz > 0 && key[key_sz - 1] == '\n' ) key[--key_sz] = '\0';

    // Restore echo
    if ( tty_input ) {
        tcsetattr(stdin_fd, TCSAFLUSH, &old);
        fprintf(stderr, "\n");
    }

    return key_sz;
}

// Initialize libc PRNG
static
void random_init()
{
    unsigned int seed = randombytes_random();
    srandom(seed);
}

// Initialize the cryptographic library
int crypto_init()
{
    if ( sodium_init() == -1 ) {
        fprintf(stderr, "Cannot initialize libsodium\n");
        return -1;
    }

    // Make sure ptace cannot attach and disable core dumps
    if ( prctl(PR_SET_DUMPABLE, 0) != 0 ) {
        perror("prctl");
        return -1;
    }

    random_init();
    return 0;
}

// Generate random name identifier out of a predefined charset
void generate_random_name(char *name, size_t length, bool filename)
{
    int byte;
    for ( size_t i = 0; i < length; i++ ) {
again:  byte = random() % 256;
        if (filename && (byte == '/' || byte == 0)) goto again;
        name[i] = byte;
    }
    if (filename) name[length] = 0;
}

// Look up key in the user session keyring from an ext4 key descriptor
// Return the key's serial number in serial
int find_key_by_descriptor(key_desc_t *key_desc, key_serial_t *serial)
{
    full_key_desc_t full_key_descriptor;
    build_full_key_descriptor(key_desc, &full_key_descriptor);

    long key_serial = keyctl_search(KEY_SPEC_USER_SESSION_KEYRING,
            EXT4_ENCRYPTION_KEY_TYPE, full_key_descriptor, 0);
    if ( key_serial != -1 ) {
        *serial = key_serial;
        return 0;
    }

    return -1;
}

// Remove a key given its serial number and its keyring
int remove_key_for_descriptor(key_desc_t *key_desc)
{
    key_serial_t key_serial;
    if ( find_key_by_descriptor(key_desc, &key_serial) < 0 ) {
        fprintf(stderr, "No encryption key found: %s\n", strerror(errno));
        return -1;
    }

    if ( keyctl_unlink(key_serial, KEY_SPEC_USER_SESSION_KEYRING) == -1 ) {
        fprintf(stderr, "Cannot remove encryption key: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

// Request a key to be attached to the specified descriptor
int request_key_for_descriptor(key_desc_t *key_desc, struct ext4_crypt_options opts, bool confirm)
{
    int retries = 5;
    char passphrase[EXT4_MAX_PASSPHRASE_SZ];
    char confirm_passphrase[sizeof(passphrase)];
    ssize_t pass_sz;
    full_key_desc_t full_key_descriptor;
    build_full_key_descriptor(key_desc, &full_key_descriptor);

    while ( --retries >= 0 ) {
        pass_sz = read_passphrase("Enter passphrase: ", passphrase, sizeof(passphrase));
        if ( pass_sz < 0 )
            return -1;

        if ( pass_sz == 0 ) {
            fprintf(stderr, "Passphrase cannot be empty\n");
            continue;
        }

        if ( !confirm )
            break;

        read_passphrase("Confirm passphrase: ", confirm_passphrase, sizeof(confirm_passphrase));
        if ( strcmp(passphrase, confirm_passphrase) == 0 )
            break;

        fprintf(stderr, "Password mismatch\n");
    }

    if ( retries < 0 ) {
        fprintf(stderr, "Cannot read passphrase\n");
        return -1;
    }

    struct ext4_encryption_key master_key = {
        .mode = 0,
        .raw = { 0 },
        .size = cipher_key_size(opts.contents_cipher),
    };
    if ( derive_passphrase_to_key(passphrase, pass_sz, &master_key) < 0 )
        return -1;

    key_serial_t serial = add_key(EXT4_ENCRYPTION_KEY_TYPE,
            full_key_descriptor, &master_key, sizeof(master_key),
            KEY_SPEC_USER_SESSION_KEYRING);

    if ( serial == -1 ) {
        fprintf(stderr, "Cannot add key to keyring: %s\n", strerror(errno));
        return -1;
    }

    zero_key(passphrase, sizeof(passphrase));
    zero_key(confirm_passphrase, sizeof(confirm_passphrase));
    zero_key(&master_key, sizeof(master_key));
    return 0;
}
