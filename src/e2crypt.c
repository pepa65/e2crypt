#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>

#include "e2crypt.h"

static
void usage(FILE *std, const char *program)
{
    fprintf(std, "%s - userspace tool to manage encrypted directories on ext4 filesystems\n\n", program);
    fprintf(std, "USAGE: %s [-v] [-p <len>] [-k <desc>] setup | open | close | status <dir>\n", program);
    fprintf(std, "  -v|--verbose:        Verbose output of setup\n");
    fprintf(std, "  -p|--padding <len>:  Padding of filename (4, 8, 16 or 32, default 4)\n");
    fprintf(std, "  -k|--key <desc>:     Key descriptor (1 to %d characters long)\n", EXT4_KEY_DESCRIPTOR_SIZE);
    fprintf(std, "  <dir>:               Directory that is setup for encryption\n\n");
}

static
bool is_valid_padding(unsigned padding)
{
    return ( padding == 4 || padding == 8 || padding == 16 || padding == 32 );
}

int main(int argc, char *argv[])
{
    const char *program = basename(argv[0]);
    int c, opt_index;
    size_t desc_len;
    struct ext4_crypt_options opts = {
        .verbose = false,
        .contents_cipher = "aes-256-xts",
        .filename_cipher = "aes-256-cts",
        .filename_padding = 0,
        .key_descriptor = { 0 },
        .requires_descriptor = true,
    };

    while ( true ) {
        static struct option long_options[] = {
            { "help", no_argument, 0, 'h' },
            { "verbose", no_argument, 0, 'v' },
            { "padding", required_argument, 0, 'p' },
            { "key", required_argument, 0, 'k' },
            { 0, 0, 0, 0 },
        };

        c = getopt_long(argc, argv, "hvp:k:", long_options, &opt_index);
        if ( c == -1 )
            break;

        switch ( c ) {
            case 'h':
                usage(stdout, program);
                return EXIT_SUCCESS;

            case 'v':
                opts.verbose = true;
                break;

            case 'p':
                opts.filename_padding = atoi(optarg); 
                if ( !is_valid_padding(opts.filename_padding) ) {
                    fprintf(stderr, "Invalid filename padding length: must be 4, 8, 16 or 32\n");
                    return EXIT_FAILURE;
                }
                break;

            case 'k':
                desc_len = strlen(optarg);
                if ( desc_len == 0 || desc_len > EXT4_KEY_DESCRIPTOR_SIZE ) {
                    fprintf(stderr, "Invalid key descriptor %s: must be between 1 and %d characters",
                            optarg, EXT4_KEY_DESCRIPTOR_SIZE);
                    return EXIT_FAILURE;
                }

                memcpy(opts.key_descriptor, optarg, desc_len);
                opts.requires_descriptor = false;
                break;

            default:
                usage(stderr, program);
                fprintf(stderr, "Invalid command option\n");
                return EXIT_FAILURE;
        }
    }

    if ( optind + 1 >= argc ) {
        usage(stderr, program);
        fprintf(stderr, "Invalid command invocation\n");
        return EXIT_FAILURE;
    }

    int status = 0;
    const char *command = argv[optind];
    const char *dir_path = argv[optind + 1];

    if ( strcmp(command, "setup") == 0 ) {
        if (opts.filename_padding == 0) opts.filename_padding = 4;
        status = container_create(dir_path, opts);
    }
    else if ( opts.key_descriptor[0] != 0 || opts.filename_padding != 0 || opts.verbose ) {
        usage(stderr, program);
        fprintf(stderr, "Error: options -v, -p and -k can only be used with setup\n");
        status = -1;
    }
    else if ( strcmp(command, "status") == 0 ) status = container_status(dir_path);
    else if ( strcmp(command, "open") == 0 ) status = container_attach(dir_path, opts);
    else if ( strcmp(command, "close") == 0 ) status = container_detach(dir_path, opts);
    else {
        usage(stderr, program);
        fprintf(stderr, "Error: unrecognized command %s\n", command);
        status = -1;
    }

    return (status == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
