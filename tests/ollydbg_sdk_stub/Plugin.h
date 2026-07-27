#ifndef OLLYDBG_TEST_PLUGIN_H
#define OLLYDBG_TEST_PLUGIN_H

/*
 * Test-only compile shim for CI.
 *
 * This is deliberately not an OllyDbg SDK replacement and must never be used
 * to produce a distributable plugin. It supplies only the names and fields
 * referenced by ollydbg110_bridge.c so Windows CI can compile and link the
 * complete DLL. Real builds must use the genuine OllyDbg 1.10 Plugin.h.
 */

#include <windows.h>

#pragma pack(push, 1)

#define PLUGIN_VERSION 110
#define TEXTLEN 256
#define SHORTLEN 8

#ifdef __cplusplus
#define extc extern "C"
#else
#define extc extern
#endif

#ifndef cdecl
#define cdecl __cdecl
#endif

typedef unsigned char uchar;
typedef unsigned long ulong;

enum {
  REG_EAX = 0,
  REG_ECX = 1,
  REG_EDX = 2,
  REG_EBX = 3,
  REG_ESP = 4,
  REG_EBP = 5,
  REG_ESI = 6,
  REG_EDI = 7
};

typedef struct t_reg {
  ulong r[8];
  ulong ip;
} t_reg;

typedef struct t_disasm {
  char result[TEXTLEN];
} t_disasm;

typedef struct t_hardbpoint {
  ulong addr;
  int size;
  int type;
  ulong reserved[4];
} t_hardbpoint;

typedef struct t_thread {
  ulong threadid;
  ulong entry;
  ulong stacktop;
  ulong stackbottom;
  int suspendcount;
  int regvalid;
  t_reg reg;
} t_thread;

typedef struct t_memory {
  ulong base;
  ulong size;
  ulong type;
  ulong access;
  char sect[SHORTLEN];
} t_memory;

typedef struct t_module {
  ulong base;
  ulong size;
  ulong entry;
  ulong codebase;
  ulong codesize;
  char name[SHORTLEN];
  char path[MAX_PATH];
} t_module;

typedef struct t_bpoint {
  ulong addr;
  ulong dummy;
  ulong type;
  char cmd;
  ulong passcount;
} t_bpoint;

typedef struct t_sorted {
  int n;
  void *data;
  int itemsize;
} t_sorted;

typedef struct t_table {
  t_sorted data;
} t_table;

typedef enum t_status {
  STAT_NONE = 0,
  STAT_STOPPED,
  STAT_EVENT,
  STAT_RUNNING,
  STAT_FINISHED,
  STAT_CLOSING
} t_status;

#define VAL_HWMAIN 1
#define VAL_BREAKPOINTS 2
#define VAL_MODULES 3
#define VAL_THREADS 4

#define PM_MAIN 0

#define CPU_ASMHIST 0x00001
#define CPU_ASMCENTER 0x00004
#define CPU_ASMFOCUS 0x00008

#define MM_RESTORE 0x01
#define MM_SILENT 0x02
#define MM_DELANAL 0x04

#define DISASM_ALL 0

#define TY_ACTIVE 0x01

#define HB_CODE 1
#define HB_ACCESS 2
#define HB_WRITE 3

#define NM_LABEL 1
#define NM_COMMENT 2

#define STEP_RUN 1
#define STEP_OVER 2
#define STEP_IN 3

#define PP_MAIN 0x000000FF

#pragma pack(pop)

#endif
