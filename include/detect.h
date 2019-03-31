//
// Created by x1314aq on 2019/04/01.
//


#include <stdint.h>

struct elf_sh {
    char name[64];
    uint32_t type;
    uint64_t offset;
    uint64_t size;
};

struct elf_struct {
    uint64_t phoff;
    uint64_t shoff;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
    struct elf_sh *sh_basic;
};

int elf_detect(void *);
void elf_parse_header(void *, struct elf_struct *, int);
void elf_print_pht(void *, struct elf_struct *, int);
void elf_print_sht(void *, struct elf_struct *, int);
void elf_print_symtab(void *, struct elf_struct *);
void elf_print_dyn(void *, struct elf_struct *);


int macho_detect(void *);
void macho_print_header(void *);
