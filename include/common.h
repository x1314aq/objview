//
// Created by x1314aq on 2018/8/27.
//

#ifndef _OBJVIEW_COMMON_H_
#define _OBJVIEW_COMMON_H_

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>


#ifndef offsetof
#define offsetof(type, member)  ((size_t) &((type *)0)->member)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({    \
        const typeof(((type *)0)->member)* __mptr = (ptr);    \
        (type *)((char *)__mptr - offsetof(type, member));})
#endif

#ifndef NULL
#define NULL ((void *) 0)
#endif

#ifndef likely
#define likely(x)  __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)  __builtin_expect(!!(x), 0)
#endif

#ifndef MIN
#define MIN(x, y) ({    \
        const typeof(x) _x = (x);    \
        const typeof(y) _y = (y);    \
        _x < _y ? _x : _y;})
#endif

#ifndef MAX
#define MAX(x, y) ({    \
        const typeof(x) _x = (x);    \
        const typeof(y) _y = (y);    \
        _x > _y ? _x : _y;})
#endif

#ifndef __CACHE_ALIGNED
#define __CACHE_LINE_SIZE  64
#define __CACHE_LINE_MASK  63
#define __CACHE_ALIGNED __attribute__((__aligned__(__CACHE_LINE_SIZE)))
#endif

#ifdef __cplusplus
#define BEGIN_DECL  extern "C" {
#define END_DECL  }
#else
#define BEGIN_DECL
#define END_DECL
#endif

BEGIN_DECL

static inline uint64_t
rdtsc(void)
{
    union {
        uint64_t tsc_64;
        struct _t{
            uint32_t lo_32;
            uint32_t hi_32;
        } t;
    } tsc;

    __asm__ volatile("rdtsc" :
    "=a" (tsc.t.lo_32),
    "=d" (tsc.t.hi_32));
    return tsc.tsc_64;
}

END_DECL

#endif // _OBJVIEW_COMMON_H_
