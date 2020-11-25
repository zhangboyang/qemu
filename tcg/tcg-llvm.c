#include "qemu/osdep.h"
#include "exec/log.h"
#include "tcg/tcg.h"
#include "tcg/tcg-llvm.h"

#include <llvm-c/Core.h>
#include <llvm-c/Target.h>
#include <llvm-c/Orc.h>
#include <llvm-c/LLJIT.h>

static void check_error(LLVMErrorRef e)
{
    if (e) {
        char *m = LLVMGetErrorMessage(e);
        puts(m);
        LLVMDisposeErrorMessage(m);
        exit(1);
    }
}

void tcg_llvm_gen_code(TCGContext *s, TranslationBlock *tb)
{
    printf("gen tb %p\n", tb);
    
    LLVMContextRef context = LLVMOrcThreadSafeContextGetContext(s->llvm_ctx->TSCtx);
    LLVMModuleRef module = LLVMModuleCreateWithNameInContext("my module", context);
    LLVMBuilderRef builder = LLVMCreateBuilderInContext(context);

    LLVMTypeRef ft = LLVMFunctionType(LLVMInt32TypeInContext(context), NULL, 0, 0);
    LLVMValueRef fn = LLVMAddFunction(module, "myfunc", ft);
    LLVMBasicBlockRef bb = LLVMAppendBasicBlockInContext(context, fn, "entry");
    LLVMPositionBuilderAtEnd(builder, bb);
    unsigned noreturn = LLVMGetEnumAttributeKindForName("noreturn", strlen("noreturn"));
    LLVMAddAttributeAtIndex(fn, LLVMAttributeFunctionIndex, LLVMCreateEnumAttribute(context, noreturn, 0));
    LLVMBuildRetVoid(builder);
    
    char *str = LLVMPrintModuleToString(module);
    puts(str);
    LLVMDisposeMessage(str);

    LLVMOrcThreadSafeModuleRef TSM = LLVMOrcCreateNewThreadSafeModule(module, s->llvm_ctx->TSCtx);
    LLVMOrcJITDylibRef JD = LLVMOrcLLJITGetMainJITDylib(s->llvm_ctx->JIT);
    check_error(LLVMOrcLLJITAddLLVMIRModule(s->llvm_ctx->JIT, JD, TSM));

    LLVMOrcJITTargetAddress addr;
    check_error(LLVMOrcLLJITLookup(s->llvm_ctx->JIT, &addr, "myfunc"));
    printf("myfunc = %p\n", addr);

    log_disas((void *)addr, 100);

    TCGOp *op;

    QTAILQ_FOREACH(op, &s->ops, link) {
        const TCGOpDef *def;
        TCGOpcode c;
        
        c = op->opc;
        def = &tcg_op_defs[c];
        
        switch (c) {
        case INDEX_op_ld_i32:
            op->args[0];
        default:
            printf("%d\n", c);
            //tcg_abort();
        }
    }
}
void tcg_llvm_context_init(TCGContext *s)
{
    puts("context init!");
    s->llvm_ctx = g_malloc(sizeof(TCGLLVMContext));
    
    //LLVMOrcLLJITBuilderRef LB = LLVMOrcCreateLLJITBuilder();
    //LLVMOrcLLJITBuilderSetJITTargetMachineBuilder(LB, JTMB);
    //LLVMOrcCreateLLJIT(&JIT, 
    
    check_error(LLVMOrcCreateLLJIT(&s->llvm_ctx->JIT, NULL));
    s->llvm_ctx->TSCtx = LLVMOrcCreateNewThreadSafeContext();
}
void tcg_llvm_init(void)
{
    puts("llvm init!");
    LLVMInitializeNativeTarget();
    LLVMInitializeNativeAsmPrinter();
    LLVMInitializeNativeAsmParser();
}