# e2crypt

**Userspace tool to manage encrypted directories on ext4 filesystems**

Linux kernel 4.1.3 introduced native encryption for the ext4 filesystem.
This tool, *e2crypt*, is a userspace tool to manage encrypted ext4 directories.
Its options are intended to make it ease to use for an enduser. The code has
largely been copied from [ext4-crypt](https://github.com/gdelugre/ext4-crypt),
but with adapted options and messages semantics and greatly increased key range.

From `e2fsprogs` version 1.43 onwards, a new tool called `e4crypt` is bundled to
work with the ext4 encryption facilities, but its semantics are more obscure.

## Usage
```console
e2crypt [-v] [-p <len>] [-k <desc>] setup | open | close | status <dir>
  -v|--verbose:         Verbose output of setup
  -p|--padding <len>:   Padding of filename (4, 8, 16 or 32, default 4)
  -k|--key <desc>:      Key descriptor (1 to 8 characters long)
  <dir>:                Directory that is setup for encryption
```

### Example: preparing a directory for encryption
The target directory must exist on an ext4 filesystem and be empty.

```console
$ mkdir vault
$ e2crypt setup vault
Enter passphrase:
Confirm passphrase:
Encryption directory vault now set up
```

### Example: checking the encryption status of a directory
This is also displayed when using the -v option on setup.

```console
$ e2crypt status vault
Encrypted directory:  vault
Policy version:       0
Filename cipher:      aes-256-cts
Contents cipher:      aes-256-xts
Filename padding:     4
Key descriptor:       0xB0679636D1282A4C
Key serial:           186749517
```

### Example: unlocking an encrypted directory

```console
$ ls vault
FTRsD7y2dUyXl6e8omKYbB  IdLqPffZBKSebTeh6hZI7C  tReYAc2tKyIOHSIcaSV2DB

$ e2crypt open vault
Enter passphrase: 
Encryption directory vault now decrypted

$ ls vault
fstab  passwd  services
```

### Example: locking an encrypted directory
Enhanced permissions are needed to flush the file cache, so the contents
of the encrypted directory can be displayed properly.

```console
$ ls vault
fstab  passwd  services

$ e2crypt close vault
[sudo] password for user:
Encryption directory vault now encrypted

$ ls vault
FTRsD7y2dUyXl6e8omKYbB  IdLqPffZBKSebTeh6hZI7C  tReYAc2tKyIOHSIcaSV2DB
```

## Install

```sh
git clone https://github.com/pepa65/e2crypt
cd e2crypt
git checkout e2crypt
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

