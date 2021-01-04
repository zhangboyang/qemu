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
#include <llvm-c/LLJIT.h>

typedef struct TCGLLVMContext {
    TCGContext *s;

    /* Created objects */
    LLVMOrcLLJITRef jit;
    LLVMOrcThreadSafeContextRef tsctx;
    LLVMContextRef ctx;
    LLVMBuilderRef bldr;
    LLVMBuilderRef ebldr; /* builder for function entry block */
    LLVMOrcJITDylibRef jd;
    LLVMPassManagerRef pm;

    /* Convenient values */
    LLVMAttributeRef noreturn;
    LLVMAttributeRef noalias;
    int tbargs;
    LLVMTypeRef tbtype;

    /* Temporary values */
    LLVMValueRef temps[TCG_MAX_TEMPS];
    LLVMModuleRef mod;
    LLVMValueRef fn;
    LLVMValueRef env;

    /* Hot code finder */
    QLIST_HEAD(, TranslationBlock) hot_tb;
} TCGLLVMContext;


void tcg_llvm_gen_code(TCGContext *s, TranslationBlock *tb);
bool tcg_llvm_try_exec_tb(TCGContext *s, TranslationBlock *tb,
    CPUArchState *env, uintptr_t *ret);
void tcg_llvm_init_tb(TCGContext *s, TranslationBlock *tb);
void tcg_llvm_remove_tb(TCGContext *s, TranslationBlock *tb);
void tcg_llvm_context_init(TCGContext *s);
void tcg_llvm_init(void);

#endif
#endif