#ifndef TCG_LLVM_H
#define TCG_LLVM_H
#ifdef CONFIG_TCG_LLVM

#include <llvm-c/Core.h>
#include <llvm-c/Target.h>
#include <llvm-c/Orc.h>
#include <llvm-c/LLJIT.h>

typedef struct TCGLLVMContext {
    /* Created objects */
    LLVMOrcLLJITRef jit;
    LLVMOrcThreadSafeContextRef tsctx;
    LLVMContextRef ctx;
    LLVMBuilderRef bldr;
    LLVMOrcJITDylibRef jd;

    /* Convenient values */
    LLVMAttributeRef noreturn;
    LLVMTypeRef hostty;
    LLVMTypeRef guestty;
    int tbargs;
    LLVMTypeRef tbtype;

    /* Temporary values */
    char tbname[128];
    LLVMValueRef temps[TCG_MAX_TEMPS];
    LLVMValueRef env;
} TCGLLVMContext;

void tcg_llvm_gen_code(TCGContext *s, TranslationBlock *tb);
void tcg_llvm_context_init(TCGContext *s);
void tcg_llvm_init(void);

#endif
#endif