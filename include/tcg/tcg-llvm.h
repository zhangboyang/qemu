/*
 * QEMU TCG JIT using LLVM
 *
 * Copyright (C) 2020, Zhang Boyang <zhangboyang.id@gmail.com>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */

#ifndef TCG_LLVM_H
#define TCG_LLVM_H
#ifdef CONFIG_TCG_LLVM

#include <llvm-c/Core.h>
#include <llvm-c/Target.h>
#include <llvm-c/Orc.h>
#include <llvm-c/OrcEE.h>
#include <llvm-c/LLJIT.h>
#include <llvm-c/Transforms/PassManagerBuilder.h>

typedef struct TCGLLVMTemp {
    TCGTempKind kind;
    TCGType type;
    int64_t val;
    LLVMValueRef solt;
    intptr_t mem_offset;
    int mem_base;
    char name[28];
} TCGLLVMTemp;

typedef struct TCGLLVMContext {

    /* Created objects */
    LLVMOrcLLJITRef jit;
    LLVMOrcThreadSafeContextRef tsctx;
    LLVMContextRef ctx;
    LLVMBuilderRef bldr;
    LLVMOrcJITDylibRef jd;
    LLVMOrcExecutionSessionRef es;
    LLVMPassManagerBuilderRef pmb;
    //LLVMPassManagerRef fpm;
    LLVMPassManagerRef mpm;
    GChecksum *hasher;

    /* Convenient values */
    LLVMAttributeRef attr_noalias;
    LLVMAttributeRef attr_qemuenv;
    unsigned md_aliasscope;
    unsigned md_noalias;
    LLVMValueRef env_scope;

    /* Translate block */
    int nfastreg;
    signed char *tbregmap;
    LLVMTypeRef tbtype;
    unsigned tbcallconv;

    /* Temporary values */
    TCGLLVMTemp temps[TCG_MAX_TEMPS];
    GHashTable *labels;
    LLVMValueRef *fastreg;
    LLVMModuleRef mod;
    LLVMValueRef fn;
    LLVMValueRef env;

    /* Prologue */
    uintptr_t (*prologue)(void *func, CPUArchState *env);
    GArray *helpers;

    /* Hot code finder */
    GPtrArray *hot_tb;
    uint64_t hot_limit1, hot_limit2;
} TCGLLVMContext;

void tcg_llvm_serialize_tb(TCGContext *s, TranslationBlock *tb);
bool tcg_llvm_try_exec_tb(TCGContext *s, TranslationBlock *tb,
    CPUArchState *env, uintptr_t *ret);
void tcg_llvm_init_tb(TCGContext *s, TranslationBlock *tb);
void tcg_llvm_remove_tb(TCGContext *s, TranslationBlock *tb);
void tcg_llvm_register_helper(TCGContext *s, int idx, void *func);
void tcg_llvm_register_helper_done(TCGContext *s);
void tcg_llvm_context_init(TCGContext *s);
void tcg_llvm_init(void);


void QLLVMDeleteFunctionBody(LLVMValueRef Fn);

#endif
#endif