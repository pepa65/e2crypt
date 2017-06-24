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
    fprintf(std, "USAGE: %s [ [-p <len>] -s|--setup | -d|--decrypt | -e|--encrypt ] <dir>\n", program);
    fprintf(std, "    -p|--padding <len>:  Padding of filename (4, 8, 16 or 32, default 4)\n");
    fprintf(std, "    -e|--encrypt <dir>:  Setup directory <dir> for encryption\n");
    fprintf(std, "    -d|--decrypt <dir>:  Decrypt directory <dir>\n");
    fprintf(std, "    -r|--recrypt <dir>:  Recrypt directory <dir>\n");
    fprintf(std, "  If just <dir> is specified, information on directory <dir> is displayed\n");
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
        .contents_cipher = "aes-256-xts",
        .filename_cipher = "aes-256-cts",
        .filename_padding = 0,
        .key_descriptor,
    };

    while ( true ) {
        static struct option long_options[] = {
            { "help", no_argument, 0, 'h' },
            { "padding", required_argument, 0, 'p' },
            { "encrypt", required_argument, 0, 'e' },
            { "decrypt", required_argument, 0, 'd' },
            { "recrypt", required_argument, 0, 'r' },
            { 0, 0, 0, 0 },
        };

        c = getopt_long(argc, argv, "hp:e:d:r:", long_options, &opt_index);
        if ( c == -1 )
            break;

        switch ( c ) {
            case 'h':
                usage(stdout, program);
                return EXIT_SUCCESS;

            case 'p':
                opts.filename_padding = atoi(optarg); 
                if ( !is_valid_padding(opts.filename_padding) ) {
                    fprintf(stderr, "Invalid filename padding length: must be 4, 8, 16 or 32\n");
                    return EXIT_FAILURE;
                }
                break;

            case 'e':
                len = strlen(optarg);
/*                if ( desc_len == 0 ) {
                    fprintf(stderr, "Directory must be specified");
                    return EXIT_FAILURE;
                }
*/
                memcpy(opts.key_descriptor, optarg, len);
                break;

            default:
                usage(stderr, program);
                fprintf(stderr, "Invalid command option -%c\n", c);
                return EXIT_FAILURE;
        }
    }

    if ( optind >= argc ) {
        usage(stderr, program);
        fprintf(stderr, "Invalid command invocation\n");
        return EXIT_FAILURE;
    }

    int status = 0;
    const char *dir = argv[optind]; // only for status

    if ( strcmp(dirnd, "setup") == 0 ) {
        if (opts.filename_padding == 0) opts.filename_padding = 4;
        status = container_create(dir_path, opts);
    }
    else if ( opts.key_descripopts.filename_padding != 0 || opts.verbose ) {
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
