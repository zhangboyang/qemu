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

typedef struct TCGLLVMContext {
    TCGContext *s;

    /* Created objects */
    LLVMOrcLLJITRef jit;
    LLVMOrcThreadSafeContextRef tsctx;
    LLVMContextRef ctx;
    LLVMBuilderRef bldr;
    LLVMBuilderRef ebldr; /* builder for function entry block */
    LLVMBuilderRef tbldr; /* builder for temporary purpose */
    LLVMOrcJITDylibRef jd;
    LLVMPassManagerBuilderRef pmb;
    //LLVMPassManagerRef fpm;
    LLVMPassManagerRef mpm;


    /* Convenient values */
    LLVMAttributeRef noalias;
    LLVMAttributeRef alwaysinline;
    int tbargs;
    LLVMTypeRef tbtype;
    unsigned tbcallconv;

    /* Temporary values */
    LLVMValueRef temps[TCG_MAX_TEMPS];
    LLVMModuleRef mod;
    LLVMValueRef fn;
    LLVMValueRef env;

    /* Prologue */
    uintptr_t (*prologue)(void *func, CPUArchState *env);

    /* Hot code finder */
    QLIST_HEAD(, TranslationBlock) hot_tb;
    uint64_t hot_limit1, hot_limit2;
} TCGLLVMContext;


void tcg_llvm_gen_code(TCGContext *s, TranslationBlock *tb);
bool tcg_llvm_try_exec_tb(TCGContext *s, TranslationBlock *tb,
    CPUArchState *env, uintptr_t *ret);
void tcg_llvm_init_tb(TCGContext *s, TranslationBlock *tb);
void tcg_llvm_remove_tb(TCGContext *s, TranslationBlock *tb);
void tcg_llvm_context_init(TCGContext *s);
void tcg_llvm_init(void);


void QLLVMDeleteFunctionBody(LLVMValueRef Fn);

#endif
#endif