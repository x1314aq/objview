//
// Created by x1314aq on 2019/03/31.
//


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>

#include "common.h"
#include "detect.h"


#define FILENAMELEN    128

struct global_args {
    int arch;
    int show_header;
    int show_ph;
    int show_sh;
    int show_sym;
    int show_dyn;
} gargs;

static void usage(int code)
{
    printf("objview OPTIONS FILE\n");
    exit(code);
}

int main(int argc, char *argv[])
{
    int c;
    char file_name[FILENAMELEN] = "a.out";
    const char *options = "adhlm:Ss";

    opterr = 0;
    while((c = getopt(argc, argv, options)) != -1) {
        switch(c) {
            case 'a':
                gargs.show_header = 1;
                gargs.show_ph = 1;
                gargs.show_sh = 1;
                break;
            case 'h':
                gargs.show_header = 1;
                break;
            case 'l':
                gargs.show_ph = 1;
                break;
            case 'm':
                gargs.arch = (int) strtol(optarg, NULL, 10);
                break;
            case 's':
                gargs.show_sym = 1;
                break;
            case 'd':
                gargs.show_dyn = 1;
                break;
            case 'S':
                gargs.show_sh = 1;
                break;
            case '?':
                usage(0);
            default:
                usage(1);
        }
    }
    if(optind < argc)
        strncpy(file_name, argv[optind], FILENAMELEN);

    int inp_fd = open(file_name, O_RDONLY);
    if(inp_fd == -1) {
        fprintf(stderr, "cannot open file %s, because %s\n", file_name, strerror(errno));
        exit(1);
    }

    struct stat inp_stat = {0};
    if(fstat(inp_fd, &inp_stat)) {
        fprintf(stderr, "cannot get file status %s, because %s\n", file_name, strerror(errno));
        close(inp_fd);
        exit(1);
    }

    printf("file size of %s is %lld bytes\n", file_name, inp_stat.st_size);
    void *fstart = mmap(NULL, inp_stat.st_size, PROT_READ, MAP_SHARED, inp_fd, 0);
    if(fstart == MAP_FAILED) {
        fprintf(stderr, "cannot mmap file %s, because %s\n", file_name, strerror(errno));
        close(inp_fd);
        exit(1);
    }

    if(elf_detect(fstart)) {
        struct elf_struct e = {
            .sh_basic = NULL,
        };
        elf_parse_header(fstart, &e, gargs.show_header);
        elf_print_sht(fstart, &e, gargs.show_sh);
        elf_print_pht(fstart, &e, gargs.show_ph);
        if(gargs.show_sym)
            elf_print_symtab(fstart, &e);
        if(gargs.show_dyn)
            elf_print_dyn(fstart, &e);
        free(e.sh_basic);
    }
    else if(macho_detect(fstart)) {
        macho_print_header(fstart);
    }
    else {
        fprintf(stderr, "unknown object file type!\n");
        exit(1);
    }

    munmap(fstart, inp_stat.st_size);
    close(inp_fd);
    return 0;
}
