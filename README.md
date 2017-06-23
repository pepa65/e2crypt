# e2crypt

**Userspace tool to manage encrypted directories on ext4 filesystems**

Linux kernel 4.1.3 introduced native encryption for the ext4 filesystem.
This tool, *e2crypt*, is a userspace tool to manage encrypted ext4 directories.
Its options are intended to make it ease to use for an enduser. The code has
largely been copied from [ext4-crypt](https://github.com/gdelugre/ext4-crypt),
but with adapted options and messages semantics.

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
vault: Encryption policy is now set.
```

### Example: checking the encryption status of a directory

```console
$ e2crypt status vault
Policy version:   0
Filename cipher:  aes-256-cts
Contents cipher:  aes-256-xts
Filename padding: 4
Key descriptor:   qC6PCZsF
Key serial:       351198062
```

### Example: unlocking an encrypted directory

```console
$ ls vault
FTRsD7y2dUyXl6e8omKYbB  IdLqPffZBKSebTeh6hZI7C  tReYAc2tKyIOHSIcaSV2DB

$ e2crypt attach vault
Enter passphrase: 

$ ls vault
fstab  passwd  services
```

## Install

```sh
git clone https://github.com/pepa65/ext4-crypt
cd ext4-crypt
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

## Limitations

### There is no key verification

Any passphrase will be accepted, but when a wrong key gets attached,
it will result in junk. Only when the right key gets attached will the
directory contents be decrypt properly.
This is a (current) limitation of the kernel implementation.

### Cyphers cannot be selected

The cipher is hardcoded, AES-256-XTS for data and AES-256-CTS for filenames.
More ciphers will probably be available in future kernel versions.

### Once encrypted, a directory cannot be permanently decrypted

The encryption policy is stored at the inode level of the directory and
cannot be removed by userspace utilities. To remove the encrypted directory,
it needs to be deleted. The decrypted content can be moved elsewhere.

