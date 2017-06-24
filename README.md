# e2crypt

**Userspace tool to manage encrypted directories on ext4 filesystems**

Linux kernel 4.1.3 introduced native encryption for the ext4 filesystem.
This tool, *e2crypt*, is a userspace tool to manage encrypted ext4 directories.
Its options are intended to make it ease to use for an enduser. The code has
largely been copied from [ext4-crypt](https://github.com/gdelugre/ext4-crypt),
but the options have been simplified, the messages easier to understand, but
the security greatly improved by a greater key range.

From `e2fsprogs` version 1.43 onwards, a new tool called `e4crypt` is bundled
to work with the ext4 encryption facilities, but its semantics make it harder
to use.

## Usage
```console
e2crypt [ [-p|--padding <len>] -s|--setup | -d|--decrypt | -e|--encrypt ] <dir>
    -p|--padding <len>:   Padding of filename (4, 8, 16 or 32, default 4)
    -s|--setup <dir>:     Setup directory <dir> for encryption
    -d|--decrypt <dir>:   Decrypt directory <dir>
    -e|--encrypt <dir>:   Encrypt directory <dir>
  If just <dir> is specified, information on directory <dir> is displayed.
```

### Example: encrypting a directory (setting up)
The target directory must exist on an ext4 filesystem and be empty.

```console
$ mkdir vault
$ e2crypt -e vault
Encrypted directory:  vault
Policy version:       0
Filename cipher:      aes-256-cts
Contents cipher:      aes-256-xts
Filename padding:     4
Key descriptor:       0xB0679636D1282A4C
Key serial:           not found
Enter passphrase:
Confirm passphrase:
Directory vault now encrypted
```

### Example: decrypting an encrypted directory

```console
$ ls vault
FTRsD7y2dUyXl6e8omKYbB  IdLqPffZBKSebTeh6hZI7C  tReYAc2tKyIOHSIcaSV2DB

$ e2crypt -d vault
Enter passphrase: 
Directory vault now decrypted

$ ls vault
fstab  passwd  services
```

### Example: recrypting an encrypted directory
Enhanced permissions are needed to flush the file cache, so the contents
of the encrypted directory can be displayed properly.

```console
$ ls vault
fstab  passwd  services

$ e2crypt -r vault
Directory vault now recrypted
[sudo] password for user:

$ ls vault
FTRsD7y2dUyXl6e8omKYbB  IdLqPffZBKSebTeh6hZI7C  tReYAc2tKyIOHSIcaSV2DB
```

### Example: checking the encryption status of a directory

```console
$ e2crypt vault
Encrypted directory:  vault
Policy version:       0
Filename cipher:      aes-256-cts
Contents cipher:      aes-256-xts
Filename padding:     4
Key descriptor:       0xB0679636D1282A4C
Key serial:           186749517
```

## Install

```sh
git clone https://github.com/pepa65/e2crypt
cd e2crypt
cmake .
make
sudo make install
```

### Requirements

Linux kernel 4.1.3 or newer with support for `CONFIG_EXT4_ENCRYPTION`.

### Built-time dependencies

- git
- cmake
- [libkeyutils-dev](http://people.redhat.com/~dhowells/keyutils/)
- [libsodium-dev](http://download.libsodium.org/doc/)

## Limitations of the kernel ext4 crypt implementation

### There is no key verification

Any passphrase will be accepted, but when a wrong one is used,
it will result in junk. Only when the right passphrase is used will the
directory contents be decrypt properly.

### Ciphers cannot be selected

The cipher is hardcoded, AES-256-XTS for data and AES-256-CTS for filenames.
More ciphers will probably be available in future kernel versions.

### Once encrypted, a directory cannot be permanently decrypted

The encryption policy is stored at the inode level of the directory and
cannot be removed by userspace utilities. To remove the encrypted directory,
it needs to be deleted (after the decrypted content is moved elsewhere).

