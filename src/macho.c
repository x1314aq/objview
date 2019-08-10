//
// Created by x1314aq on 2019/04/07.
//


#include "common.h"
#include "detect.h"
#include <unistd.h>
#include <mach-o/loader.h>

int macho_detect(void *buf)
{
    return *(uint32_t *) buf == MH_MAGIC_64;
}

static char *_get_file_type(uint32_t val)
{
    switch(val) {
        case MH_OBJECT:
            return "OBJECT";
        case MH_EXECUTE:
            return "EXECUTE";
        case MH_FVMLIB:
            return "FVMLIB";
        case MH_CORE:
            return "CORE";
        case MH_PRELOAD:
            return "PRELOAD";
        case MH_DYLIB:
            return "DYLIB";
        case MH_DYLINKER:
            return "DYLINKER";
        case MH_BUNDLE:
            return "BUNDLE";
        case MH_DYLIB_STUB:
            return "DYLIB_STUB";
        case MH_DSYM:
            return "DSYM";
        case MH_KEXT_BUNDLE:
            return "KEXT_BUNDLE";
        default:
            return "Unknown";
    }
    return NULL;
}

static char *_get_cpu_type(int32_t val)
{
    switch(val) {
        case CPU_TYPE_VAX:
            return "VAX";
        case CPU_TYPE_MC680x0:
            return "MC680x0";
        case CPU_TYPE_X86:
            return "X86";
        case CPU_TYPE_X86_64:
            return "X86_64";
        case CPU_TYPE_MC98000:
            return "MC98000";
        case CPU_TYPE_HPPA:
            return "HPPA";
        case CPU_TYPE_ARM:
            return "ARM";
        case CPU_TYPE_ARM64:
            return "ARM64";
        case CPU_TYPE_ARM64_32:
            return "ARM64_32";
        case CPU_TYPE_MC88000:
            return "MC88000";
        case CPU_TYPE_SPARC:
            return "SPARC";
        case CPU_TYPE_I860:
            return "I860";
        case CPU_TYPE_POWERPC:
            return "POWERPC";
        case CPU_TYPE_POWERPC64:
            return "POWERPC64";
        default:
            return "Unknown";
    }
    return NULL;
}

void macho_print_header(void *buf)
{
    struct mach_header_64 *hdr = (struct mach_header_64 *) buf;
    printf("Mach-O header\n");
    printf("  %-20s: %#x\n", "Magic", hdr->magic);
    printf("  %-20s: %s\n", "CPU type", _get_cpu_type(hdr->cputype));
    printf("  %-20s: %d\n", "CPU subtype", hdr->cpusubtype);
    printf("  %-20s: %s\n", "File type", _get_file_type(hdr->filetype));
    printf("  %-20s: %u\n", "Number of load cmds", hdr->ncmds);
    printf("  %-20s: %u\n", "Size of cmds", hdr->sizeofcmds);
    printf("  %-20s: %#x\n", "Flags", hdr->flags);
}
