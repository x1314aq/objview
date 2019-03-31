//
// Created by x1314aq on 2019/04/01.
//


#include "common.h"
#include "detect.h"
#include "elf.h"
#include <unistd.h>

int elf_detect(void *buf)
{
    return *(uint32_t *) buf == 0x464c457f;
}

void elf_parse_header(void *buf, struct elf_struct *e, int show)
{
    Elf64_Ehdr *elf_hdr = (Elf64_Ehdr *) buf;
    e->phoff = elf_hdr->e_phoff;
    e->shoff = elf_hdr->e_shoff;
    e->phentsize = elf_hdr->e_phentsize;
    e->phnum = elf_hdr->e_phnum;
    e->shentsize = elf_hdr->e_shentsize;
    e->shnum = elf_hdr->e_shnum;
    e->shstrndx = elf_hdr->e_shstrndx;

    if(show == 0)
        return;
    printf("ELF Header\n"
           "  Magic:  %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
              elf_hdr->e_ident[0], elf_hdr->e_ident[1], elf_hdr->e_ident[2], elf_hdr->e_ident[3],
              elf_hdr->e_ident[4], elf_hdr->e_ident[5], elf_hdr->e_ident[6], elf_hdr->e_ident[7],
              elf_hdr->e_ident[8], elf_hdr->e_ident[9], elf_hdr->e_ident[10], elf_hdr->e_ident[11],
              elf_hdr->e_ident[12], elf_hdr->e_ident[13], elf_hdr->e_ident[14], elf_hdr->e_ident[15]);
    printf("  %-40s: ELF%d\n", "Class", elf_hdr->e_ident[4] == 1 ? 32 : 64);
    printf("  %-40s: %s\n", "Data", elf_hdr->e_ident[5] == 1 ? "little endian" : "big endian");
    printf("  %-40s: %s\n", "Version", elf_hdr->e_ident[6] == EV_CURRENT ? "Current version" : "Invalid version");
    printf("  %-40s: %s\n", "OS/ABI", elf_hdr->e_ident[7] == 0 ? "UNIX - System V" : "Unknown");
    printf("  %-40s: %hhu\n", "ABI Version", elf_hdr->e_ident[8]);
    printf("  %-40s: ", "Type");
    switch(elf_hdr->e_type) {
        case ET_NONE:
            printf("No file type\n");
            break;
        case ET_REL:
            printf("Relocatable file\n");
            break;
        case ET_EXEC:
            printf("Executable file\n");
            break;
        case ET_DYN:
            printf("Shared object file\n");
            break;
        case ET_CORE:
            printf("Core file\n");
            break;
        default:
            printf("unknown file type\n");
            break;
    }
    printf("  %-40s: ", "Machine");
    switch(elf_hdr->e_machine) {
        case EM_386:
            printf("Intel 80386\n");
            break;
        case EM_X86_64:
            printf("AMD x86-64 architecture\n");
            break;
        default:
            printf("unknown machine\n");
            break;
    }
    printf("  %-40s: %u\n", "Version", elf_hdr->e_version);
    printf("  %-40s: %#llx\n", "Entry point address", elf_hdr->e_entry);
    printf("  %-40s: %#llx\n", "Start of program headers", elf_hdr->e_phoff);
    printf("  %-40s: %#llx\n", "Start of section headers", elf_hdr->e_shoff);
    printf("  %-40s: %x\n", "Flags", elf_hdr->e_flags);
    printf("  %-40s: %hu (bytes)\n", "Size of this header", elf_hdr->e_ehsize);
    printf("  %-40s: %hu (bytes)\n", "Size of program header entry", elf_hdr->e_phentsize);
    printf("  %-40s: %hu\n", "Number of program headers", elf_hdr->e_phnum);
    printf("  %-40s: %hu (bytes)\n", "Size of section header entry", elf_hdr->e_shentsize);
    printf("  %-40s: %hu\n", "Number of section headers", elf_hdr->e_shnum);
    printf("  %-40s: %hu\n", "Section header string table index", elf_hdr->e_shstrndx);
}

static char *_get_sh_type(uint32_t type)
{
    switch(type) {
        case SHT_NULL:
            return "NULL";
        case SHT_PROGBITS:
            return "PROGBITS";
        case SHT_SYMTAB:
            return "SYMTAB";
        case SHT_STRTAB:
            return "STRTAB";
        case SHT_RELA:
            return "RELA";
        case SHT_HASH:
            return "HASH";
        case SHT_DYNAMIC:
            return "DYNAMIC";
        case SHT_NOTE:
            return "NOTE";
        case SHT_NOBITS:
            return "NOBITS";
        case SHT_REL:
            return "REL";
        case SHT_SHLIB:
            return "SHLIB";
        case SHT_DYNSYM:
            return "DYNSYM";
        case SHT_INIT_ARRAY:
            return "INIT_ARRAY";
        case SHT_FINI_ARRAY:
            return "FINI_ARRAY";
        case SHT_PREINIT_ARRAY:
            return "PREINIT_ARRAY";
        case SHT_GROUP:
            return "GROUP";
        case SHT_SYMTAB_SHNDX:
            return "SYMTAB_SHNDX";
        case SHT_GNU_ATTRIBUTES:
            return "GNU_ATTRIBUTES";
        case SHT_GNU_HASH:
            return "GNU_HASH";
        case SHT_GNU_LIBLIST:
            return "GNU_LIBLIST";
        case SHT_GNU_verdef:
            return "GNU_verdef";
        case SHT_GNU_verneed:
            return "GNU_verneed";
        case SHT_GNU_versym:
            return "GNU_versym";
        default:
            return "Unknown";
    }
    return NULL;
}

void elf_print_sht(void *buf, struct elf_struct *e, int show)
{
    Elf64_Shdr *sh_start = (Elf64_Shdr *)((char *) buf + e->shoff);
    Elf64_Shdr *str_sh, *sh;
    char *str_buf;

    str_sh = sh_start + e->shstrndx;
    if(str_sh->sh_type != SHT_STRTAB) {
        fprintf(stderr, "error!\n");
        return;
    }
    str_buf = (char *)((char *) buf + str_sh->sh_offset);
    e->sh_basic = (struct elf_sh *) malloc(e->shnum * sizeof(struct elf_sh));

    e->sh_basic[0].name[0] = 0;
    e->sh_basic[0].type = SHT_NULL;
    e->sh_basic[0].offset = 0;
    e->sh_basic[0].size = 0;
    for(uint16_t i = 1; i < e->shnum; i++) {
        sh = sh_start + i;
        strncpy(e->sh_basic[i].name, &str_buf[sh->sh_name], 63);
        e->sh_basic[i].name[63] = 0;
        e->sh_basic[i].type = sh->sh_type;
        e->sh_basic[i].offset = sh->sh_offset;
        e->sh_basic[i].size = sh->sh_size;
    }
    if(show == 0)
        return;
    printf("\nThere are %hu section headers, starting at offset %#llx\n", e->shnum, e->shoff);
    printf("\nSection headers:\n");
    printf(" [Nr]  Name                  Type                  Address             Offset\n");
    printf("       Size                  EntrySize             Flags   Link  Info  Align\n");
    for(uint16_t i = 1; i < e->shnum; i++) {
        sh = sh_start + i;
        printf(" [%02hu]  %-21s %-21s %#018llx  %#llx\n", i, &str_buf[sh->sh_name], _get_sh_type(sh->sh_type), sh->sh_addr, sh->sh_offset);
        printf("       %#018llx    %#018llx    %#06llx  %-4u  %-4u  %-llu\n", sh->sh_size, sh->sh_entsize, sh->sh_flags, sh->sh_link, sh->sh_info, sh->sh_addralign);
    }
}

static char *_get_ph_type(uint32_t type)
{
    switch(type) {
        case PT_NULL:
            return "NULL";
        case PT_LOAD:
            return "LOAD";
        case PT_DYNAMIC:
            return "DYNAMIC";
        case PT_INTERP:
            return "INTERP";
        case PT_NOTE:
            return "NOTE";
        case PT_SHLIB:
            return "SHLIB";
        case PT_PHDR:
            return "PHDR";
        case PT_TLS:
            return "TLS";
        case PT_NUM:
            return "NUM";
        case PT_LOOS:
            return "LOOS";
        case PT_GNU_EH_FRAME:
            return "GNU_EH_FRAME";
        case PT_GNU_STACK:
            return "GNU_STACK";
        case PT_GNU_RELRO:
            return "GNU_RELRO";
        case PT_LOPROC:
            return "LOPROC";
        case PT_HIPROC:
            return "HIPROC";
        default:
            return "Unknown";
    }
    return NULL;
}

void elf_print_pht(void *buf, struct elf_struct *e, int show)
{
    Elf64_Phdr *ph_start = (Elf64_Phdr *)((char *) buf + e->phoff);
    Elf64_Phdr *ph = NULL;

    if(show == 0)
        return;
    printf("\nThere are %hu program headers, starting at offset %#llx\n", e->phnum, e->phoff);
    printf("\nProgram headers:\n");
    printf("  %-15s%-20s%-20s%-20s\n", "Type", "Offset", "VirtAddr", "PhysAddr");
    printf("%-17s%-20s%-20s%-10s%-10s\n", " ", "FileSize", "MemSize", "Flags", "Align");
    for(uint16_t i = 0; i < e->phnum; i++) {
        ph = ph_start + i;
        char flags[4] = {' ', ' ', ' ', 0};
        printf("  %-15s%#018llx  %#018llx  %#018llx\n", _get_ph_type(ph->p_type), ph->p_offset, ph->p_vaddr, ph->p_paddr);
        if(ph->p_flags & PF_R)
            flags[0] = 'R';
        if(ph->p_flags & PF_W)
            flags[1] = 'W';
        if(ph->p_flags & PF_X)
            flags[2] = 'X';
        printf("%-17s%#018llx  %#018llx  %-10s%#llx\n", " ", ph->p_filesz, ph->p_memsz, flags, ph->p_align);
    }
    printf("\nSection to Segment mapping:\n");
    uint16_t j = 0, k = 0;
    uint64_t temp;
    for(uint16_t i = 0; i < e->phnum; i++) {
        ph = ph_start + i;
        temp = ph->p_filesz + ph->p_offset;
        printf("  [%02hu]    ", i);
        for(j = 0; j < e->shnum; j++) {
            if(ph->p_offset == e->sh_basic[j].offset)
                break;
        }
        for(k = j; k < e->shnum; k++) {
            if(temp == e->sh_basic[k].offset + e->sh_basic[k].size) {
                while(k < e->shnum - 1 && e->sh_basic[k + 1].type == SHT_NOBITS)
                    k++;
                break;
            }
        }
        if(j == e->shnum) {
            printf("\n");
            continue;
        }
        if(j == 0)
            j = 1;
        while(j <= k) {
            printf("%s ", e->sh_basic[j].name);
            j++;
        }
        printf("\n");
    }
}

static char *_get_symtab_bind(unsigned char val)
{
    switch(ELF64_ST_BIND(val)) {
        case STB_LOCAL:
            return "LOCAL";
        case STB_GLOBAL:
            return "GLOBAL";
        case STB_WEAK:
            return "WEAK";
        case STB_GNU_UNIQUE:
            return "GNU_UNIQUE";
        default:
            return "Unknown";
    }
    return NULL;
}

static char *_get_symtab_type(unsigned char val)
{
    switch(ELF64_ST_TYPE(val)) {
        case STT_NOTYPE:
            return "NOTYPE";
        case STT_OBJECT:
            return "OBJECT";
        case STT_FUNC:
            return "FUNC";
        case STT_SECTION:
            return "SECTION";
        case STT_FILE:
            return "FILE";
        case STT_COMMON:
            return "COMMON";
        case STT_TLS:
            return "TLS";
        default:
            return "Unknown";
    }
    return NULL;
}

static char *_get_symtab_vis(unsigned char val)
{
    switch(ELF64_ST_VISIBILITY(val)) {
        case STV_DEFAULT:
            return "DEFAULT";
        case STV_INTERNAL:
            return "INTERNAL";
        case STV_HIDDEN:
            return "HIDDEN";
        case STV_PROTECTED:
            return "PROTECTED";
        default:
            return "Unknown";
    }
    return NULL;
}

static char *_get_symtab_index(uint16_t val)
{
    static char buf[8] = {0};
    switch(val) {
        case SHN_ABS:
            return "ABS";
        case SHN_COMMON:
            return "COM";
        case SHN_UNDEF:
            return "UND";
        default:
            sprintf(buf, "%hu", val);
            return buf;
    }
    return NULL;
}

void elf_print_symtab(void *buf, struct elf_struct *e)
{
    uint16_t symtab_index = 0, dynsym_index = 0, strtab_index = 0, dynstr_index = 0;
    for(uint16_t i = 0; i < e->shnum; i++) {
        if(strcmp(".symtab", e->sh_basic[i].name) == 0)
            symtab_index = i;
        else if(strcmp(".dynsym", e->sh_basic[i].name) == 0)
            dynsym_index = i;
        else if(strcmp(".strtab", e->sh_basic[i].name) == 0)
            strtab_index = i;
        else if(strcmp(".dynstr", e->sh_basic[i].name) == 0)
            dynstr_index = i;
    }

    char *str_buf = (char *) ((char *) buf + e->sh_basic[strtab_index].offset);
    if(symtab_index == 0)
        fprintf(stderr, "\ncannot find symbol table '.symtab'!\n");
    else {
        Elf64_Sym *symtab = (Elf64_Sym *) ((char *) buf + e->sh_basic[symtab_index].offset);
        uint16_t n = e->sh_basic[symtab_index].size / sizeof(Elf64_Sym);
        printf("\nThere are %hu entries in symbol table '.symtab'\n", n);
        printf("  %-5s%-20s%-10s%-10s%-10s%-14s%-8s%-10s\n", "Num:", "Value", "Size", "Type", "Bind", "Visibility", "Index", "Name");
        for(uint16_t i = 0; i < n; i++) {
            Elf64_Sym *sym = symtab + i;
            printf(" %4hu: %#018llx  %#08llx  %-10s%-10s%-14s%-8s%s\n", i, sym->st_value, sym->st_size, _get_symtab_type(sym->st_info), _get_symtab_bind(sym->st_info), _get_symtab_vis(sym->st_other), _get_symtab_index(sym->st_shndx), &str_buf[sym->st_name]);
        }
    }
    if(dynsym_index == 0)
        fprintf(stderr, "\ncannot find dynamic symbol table '.dynsym'!\n");
    else {
        Elf64_Sym *dynsym = (Elf64_Sym *) ((char *) buf + e->sh_basic[dynsym_index].offset);
        char *dynstr_buf = (char *) ((char *) buf + e->sh_basic[dynstr_index].offset);
        uint16_t n = e->sh_basic[dynsym_index].size / sizeof(Elf64_Sym);
        printf("\nThere are %hu entries in dynamic symbol table '.dynsym'\n", n);
        printf("  %-5s%-20s%-10s%-10s%-10s%-14s%-8s%-10s\n", "Num:", "Value", "Size", "Type", "Bind", "Visibility", "Index", "Name");
        for(uint16_t i = 0; i < n; i++) {
            Elf64_Sym *sym = dynsym + i;
            printf(" %4hu: %#018llx  %#08llx  %-10s%-10s%-14s%-8s%s\n", i, sym->st_value, sym->st_size, _get_symtab_type(sym->st_info), _get_symtab_bind(sym->st_info), _get_symtab_vis(sym->st_other), _get_symtab_index(sym->st_shndx), &dynstr_buf[sym->st_name]);
        }
    }
}

static char *_get_dynamic_type(Elf64_Dyn *d, char *dynstr, char *out, int len)
{
    int64_t val = d->d_tag;
    switch(val) {
        case DT_NULL:
            snprintf(out, len, "0x0");
            return "(NULL)";
        case DT_NEEDED:
            strncpy(out, dynstr + d->d_un.d_val, len);
            return "(NEEDED)";
        case DT_PLTRELSZ:
            snprintf(out, len, "%llu (bytes)", d->d_un.d_val);
            return "(PLTRELSZ)";
        case DT_PLTGOT:
            snprintf(out, len, "%#llx", d->d_un.d_ptr);
            return "(PLTGOT)";
        case DT_HASH:
            snprintf(out, len, "%#llx", d->d_un.d_ptr);
            return "(HASH)";
        case DT_STRTAB:
            snprintf(out, len, "%#llx", d->d_un.d_ptr);
            return "(STRTAB)";
        case DT_SYMTAB:
            snprintf(out, len, "%#llx", d->d_un.d_ptr);
            return "(SYMTAB)";
        case DT_RELA:
            snprintf(out, len, "%#llx", d->d_un.d_ptr);
            return "(RELA)";
        case DT_RELASZ:
            snprintf(out, len, "%llu (bytes)", d->d_un.d_val);
            return "(RELASZ)";
        case DT_RELAENT:
            snprintf(out, len, "%llu (bytes)", d->d_un.d_val);
            return "(RELAENT)";
        case DT_STRSZ:
            snprintf(out, len, "%llu (bytes)", d->d_un.d_val);
            return "(STRSZ)";
        case DT_SYMENT:
            snprintf(out, len, "%llu (bytes)", d->d_un.d_val);
            return "(SYMENT)";
        case DT_INIT:
            snprintf(out, len, "%#llx", d->d_un.d_ptr);
            return "(INIT)";
        case DT_FINI:
            snprintf(out, len, "%#llx", d->d_un.d_ptr);
            return "(FINI)";
        case DT_SONAME:
            strncpy(out, dynstr + d->d_un.d_val, len);
            return "(SONAME)";
        case DT_RPATH:
            strncpy(out, dynstr + d->d_un.d_val, len);
            return "(RPATH)";
        case DT_SYMBOLIC:
            snprintf(out, len, "Ignored");
            return "(SYMBOLIC)";
        case DT_REL:
            snprintf(out, len, "%#llx", d->d_un.d_ptr);
            return "(REL)";
        case DT_RELSZ:
            snprintf(out, len, "%llu (bytes)", d->d_un.d_val);
            return "(RELSZ)";
        case DT_RELENT:
            snprintf(out, len, "%llu (bytes)", d->d_un.d_val);
            return "(RELENT)";
        case DT_PLTREL:
            snprintf(out, len, "%s", d->d_un.d_val == DT_REL ? "REL" : "RELA");
            return "(PLTREL)";
        case DT_DEBUG:
            snprintf(out, len, "%#llx", d->d_un.d_ptr);
            return "(DEBUG)";
        case DT_TEXTREL:
            snprintf(out, len, "Ignored");
            return "(TEXTREL)";
        case DT_JMPREL:
            snprintf(out, len, "%#llx", d->d_un.d_ptr);
            return "(JMPREL)";
        case DT_BIND_NOW:
            snprintf(out, len, "Ignored");
            return "(BIND_NOW)";
        case DT_INIT_ARRAY:
            snprintf(out, len, "%#llx", d->d_un.d_ptr);
            return "(INIT_ARRAY)";
        case DT_FINI_ARRAY:
            snprintf(out, len, "%#llx", d->d_un.d_ptr);
            return "(FINI_ARRAY)";
        case DT_INIT_ARRAYSZ:
            snprintf(out, len, "%llu (bytes)", d->d_un.d_val);
            return "(INIT_ARRAYSZ)";
        case DT_FINI_ARRAYSZ:
            snprintf(out, len, "%llu (bytes)", d->d_un.d_val);
            return "(FINI_ARRAYSZ)";
        case DT_RUNPATH:
            strncpy(out, dynstr + d->d_un.d_val, len);
            return "(RUNPATH)";
        case DT_FLAGS:
            snprintf(out, len, "%llu", d->d_un.d_val);
            return "(FLAGS)";
        case DT_PREINIT_ARRAY:
            snprintf(out, len, "%#llx", d->d_un.d_ptr);
            return "(PREINIT_ARRAY)";
        case DT_PREINIT_ARRAYSZ:
            snprintf(out, len, "%llu (bytes)", d->d_un.d_val);
            return "(PREINIT_ARRAYSZ)";
        case DT_VALRNGLO:
            snprintf(out, len, "Ignored");
            return "(VALRNGLO)";
        case DT_GNU_PRELINKED:
            snprintf(out, len, "Ignored");
            return "(GNU_PRELINKED)";
        case DT_GNU_CONFLICTSZ:
            snprintf(out, len, "Ignored");
            return "(GNU_CONFLICTSZ)";
        case DT_GNU_LIBLISTSZ:
            snprintf(out, len, "Ignored");
            return "(GNU_LIBLISTSZ)";
        case DT_CHECKSUM:
            snprintf(out, len, "%llu", d->d_un.d_val);
            return "(CHECKSUM)";
        case DT_PLTPADSZ:
            snprintf(out, len, "%llu (bytes)", d->d_un.d_val);
            return "(PLTPADSZ)";
        case DT_MOVEENT:
            snprintf(out, len, "%llu (bytes)", d->d_un.d_val);
            return "(MOVEENT)";
        case DT_MOVESZ:
            snprintf(out, len, "%llu (bytes)", d->d_un.d_val);
            return "(MOVESZ)";
        case DT_FEATURE_1:
            snprintf(out, len, "%llu", d->d_un.d_val);
            return "(FEATURE_1)";
        case DT_POSFLAG_1:
            snprintf(out, len, "%llu", d->d_un.d_val);
            return "(POSFLAG_1)";
        case DT_SYMINSZ:
            snprintf(out, len, "%llu (bytes)", d->d_un.d_val);
            return "(SYMINSZ)";
        case DT_SYMINENT:
            snprintf(out, len, "%llu (bytes)", d->d_un.d_val);
            return "(SYMINENT)";
        case DT_ADDRRNGLO:
            snprintf(out, len, "Ignored");
            return "(ADDRRNGLO)";
        case DT_GNU_HASH:
            snprintf(out, len, "%#llx", d->d_un.d_ptr);
            return "(GNU_HASH)";
        case DT_TLSDESC_PLT:
            snprintf(out, len, "Ignored");
            return "(TLSDESC_PLT)";
        case DT_TLSDESC_GOT:
            snprintf(out, len, "Ignored");
            return "(TLSDESC_GOT)";
        case DT_GNU_CONFLICT:
            snprintf(out, len, "Ignored");
            return "(GNU_CONFLICT)";
        case DT_GNU_LIBLIST:
            snprintf(out, len, "Ignored");
            return "(GNU_LIBLIST)";
        case DT_CONFIG:
            snprintf(out, len, "%#llx", d->d_un.d_ptr);
            return "(CONFIG)";
        case DT_DEPAUDIT:
            snprintf(out, len, "%#llx", d->d_un.d_ptr);
            return "(DEPAUDIT)";
        case DT_AUDIT:
            snprintf(out, len, "%#llx", d->d_un.d_ptr);
            return "(AUDIT)";
        case DT_PLTPAD:
            snprintf(out, len, "%#llx", d->d_un.d_ptr);
            return "(PLTPAD)";
        case DT_MOVETAB:
            snprintf(out, len, "%#llx", d->d_un.d_ptr);
            return "(MOVETAB)";
        case DT_SYMINFO:
            snprintf(out, len, "%#llx", d->d_un.d_ptr);
            return "(SYMINFO)";
        case DT_VERSYM:
            snprintf(out, len, "Ignored");
            return "(VERSYM)";
        case DT_RELACOUNT:
            snprintf(out, len, "%llu", d->d_un.d_val);
            return "(RELACOUNT)";
        case DT_RELCOUNT:
            snprintf(out, len, "%llu", d->d_un.d_val);
            return "(RELCOUNT)";
        case DT_FLAGS_1:
            snprintf(out, len, "%llu", d->d_un.d_val);
            return "(FLAGS_1)";
        case DT_VERDEF:
            snprintf(out, len, "%#llx", d->d_un.d_ptr);
            return "(VERDEF)";
        case DT_VERDEFNUM:
            snprintf(out, len, "%llu", d->d_un.d_val);
            return "(VERDEFNUM)";
        case DT_VERNEED:
            snprintf(out, len, "%#llx", d->d_un.d_ptr);
            return "(VERNEED)";
        case DT_VERNEEDNUM:
            snprintf(out, len, "%llu", d->d_un.d_val);
            return "(VERNEEDNUM)";
        default:
            return "(Unknown)";
    }
    return NULL;
}

void elf_print_dyn(void *buf, struct elf_struct *e)
{
    uint16_t dyn_index = 0, dynstr_index = 0;
    for(uint16_t i = 1; i < e->shnum; i++) {
        if(strcmp(".dynamic", e->sh_basic[i].name) == 0)
            dyn_index = i;
        else if(strcmp(".dynstr", e->sh_basic[i].name) == 0)
            dynstr_index = i;
    }
    if(dyn_index == 0 || dynstr_index == 0) {
        fprintf(stderr, "\ncannot find dynamic section!\n");
        return;
    }

    Elf64_Dyn *dyn_start = (Elf64_Dyn *) ((char *) buf + e->sh_basic[dyn_index].offset);
    char *dynstr = (char *) ((char *) buf + e->sh_basic[dynstr_index].offset);

    uint16_t n = e->sh_basic[dyn_index].size / sizeof(Elf64_Dyn);
    for(uint16_t i = n - 1; i >= 0; i--) {
        Elf64_Dyn *d = dyn_start + i;
        if(d->d_tag != 0) {
            n = i + 2;
            break;
        }
    }
    printf("\nThere are %hu entries in dynamic section\n", n);
    printf("  %-20s%-20s%-20s\n", "Tag", "Type", "Name/Value");

    char temp[128];
    for(uint16_t i = 0; i < n; i++) {
        Elf64_Dyn *d = dyn_start + i;
        memset(temp, 0, 128);
        printf("  %#018llx  %-20s%s\n", d->d_tag, _get_dynamic_type(d, dynstr, temp, 128), temp);
    }
}
