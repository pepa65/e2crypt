# e2crypt

**Userspace tool to manage encrypted directories on ext4 filesystems**

This tool, *e2crypt*, is a userspace tool to encrypt, decrypt and recrypt
directories on ext4 filesystems. Its commandline options are intended to make
these ext4 encryption features accessible in a user-friendly way.

The codebase was forked from [ext4-crypt](https://github.com/gdelugre/ext4-crypt)
and then made easier to use and understand without losing any significant
features, while increasing the security by enlarging the key range.

Linux kernel 4.1.3 introduced native encryption for directories on
ext4 filesystems. From `e2fsprogs` version 1.43 (released May 2016) onwards,
a new tool called `e4crypt` is added to make use of the ext4 encryption
facilities, but its semantics make it hard to use and it is not user-friendly.
(GRUB cannot read an ext4 filesystem that has the `encrypt` option set. But
in general this option doesn't seem necessary to be set for *e2crypt*.)

## Usage
```console
e2crypt [ [-p|--padding <len>] -e|--encrypt | -d|--decrypt | -r|--recrypt ] <dir>
    -p|--padding <len>:   Padding of filename (4, 8, 16 or 32, default 4)
    -e|--encrypt <dir>:   Encrypt directory <dir> (initialize)
    -d|--decrypt <dir>:   Decrypt directory <dir>
    -r|--recrypt <dir>:   Recrypt directory <dir>
  No options: display encryption information on directory <dir>
```

### Example: encrypting a directory (setting up)
The target directory must exist on an ext4 filesystem and be empty.
The password can never be changed!

```console
$ mkdir vault
$ e2crypt -e vault
Encrypted directory:  vault
Policy version:       0
Filename cipher:      aes-256-cts
Contents cipher:      aes-256-xts
Filename padding:     4
Key descriptor:       b0679636d1282a4c
Key serial:           [not found]
Enter passphrase:
Confirm passphrase:
Directory vault now encrypted
```

### Example: decrypting an encrypted directory
A wrong password will be accepted, but only once the right password has been
entered is the directory decrypted.

```console
$ ls vault
FTRsD7y2dUyXl6e8omKYbB  IdLqPffZBKSebTeh6hZI7C  tReYAc2tKyIOHSIcaSV2DB

$ e2crypt -d vault
Enter passphrase: 
Directory vault now decrypted
Updating filesystem cache
[sudo] password for user:

$ ls vault
fstab  passwd  services
```

Enhanced permissions are needed to flush the file cache, so the contents
of the decrypted directory can be displayed properly. This basically executes
as root: `echo 2 >/proc/sys/vm/drop_caches` (but using sudo).

### Example: recrypting an encrypted directory
The recrypting does not require a password, because the immutable password has
been set on the encryption setup.

```console
$ ls vault
fstab  passwd  services

$ e2crypt -r vault
Directory vault now recrypted
Updating filesystem cache
[sudo] password for user:

$ ls vault
FTRsD7y2dUyXl6e8omKYbB  IdLqPffZBKSebTeh6hZI7C  tReYAc2tKyIOHSIcaSV2DB
```
Again, enhanced permissions needed to flush the file cache, so the contents
of the recrypted directory can be displayed properly.

### Example: checking the encryption status of a directory
The returncode is 0 when the directory is setup for encryption, 1 otherwise.

```console
$ e2crypt vault
Encrypted directory:  vault
Policy version:       0
Filename cipher:      aes-256-cts
Contents cipher:      aes-256-xts
Filename padding:     4
Key descriptor:       b0679636d1282a4c
Key serial:           2661eacd
```

## Install

### Requirements

Linux kernel 4.1.3 or newer with support for `CONFIG_EXT4_ENCRYPTION` (which
is available by default).

### Build dependencies

- git
- cmake
- [libkeyutils-dev](http://people.redhat.com/~dhowells/keyutils/)
- [libsodium-dev](http://download.libsodium.org/doc/)

### Run-time dependencies

- libkeyutils
- libsodium
- libc6
- sudo (for the system call to drop file caches which requires privileges)

### Installing
The following will download, build and install *e2crypt*:

```sh
git clone https://gitlab.com/pepa65/e2crypt
cd e2crypt
cmake .
make
sudo make install
```

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

## Licence

Original licence MIT, adapted code relicenced as GPLv3.
