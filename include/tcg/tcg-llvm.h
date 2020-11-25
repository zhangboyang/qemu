#ifndef TCG_LLVM_H
#define TCG_LLVM_H

#include <llvm-c/LLJIT.h>
#include <llvm-c/Orc.h>

typedef struct TCGLLVMContext {
    LLVMOrcLLJITRef JIT;
    LLVMOrcThreadSafeContextRef TSCtx;
} TCGLLVMContext;

void tcg_llvm_gen_code(TCGContext *s, TranslationBlock *tb);
void tcg_llvm_context_init(TCGContext *s);
void tcg_llvm_init(void);


#endif