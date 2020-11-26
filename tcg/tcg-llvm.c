#include "qemu/osdep.h"
#include "qemu/log.h"
#include "exec/exec-all.h"
#include "exec/log.h"
#include "tcg/tcg.h"
#include "tcg/tcg-llvm.h"

static inline void check_error(LLVMErrorRef e)
{
    if (e) {
        char *m = LLVMGetErrorMessage(e);
        qemu_log("%s\n", m);
        LLVMDisposeErrorMessage(m);
        exit(1);
    }
}

static inline void dump_module(LLVMModuleRef mdl)
{
    char *str = LLVMPrintModuleToString(mdl);
    qemu_log("%s", str);
    LLVMDisposeMessage(str);
}

void tcg_llvm_gen_code(TCGContext *s, TranslationBlock *tb)
{
    char tbname[128];
    sprintf(tbname, "tb_%016" PRIx64, (uint64_t) tb->pc); // FIXME

    TCGLLVMContext *l = s->llvm_ctx;
    
    LLVMModuleRef mdl = LLVMModuleCreateWithNameInContext("my module", l->ctx);


    LLVMTypeRef ft = LLVMFunctionType(LLVMInt32TypeInContext(l->ctx), NULL, 0, 0);

    LLVMValueRef fn = LLVMAddFunction(mdl, tbname, ft);
    LLVMBasicBlockRef bb = LLVMAppendBasicBlockInContext(l->ctx, fn, "entry");
    LLVMPositionBuilderAtEnd(l->bldr, bb);

    LLVMAddAttributeAtIndex(fn, LLVMAttributeFunctionIndex, l->noreturn);
    LLVMBuildRetVoid(l->bldr);
    
    dump_module(mdl);


    LLVMOrcThreadSafeModuleRef tsm = LLVMOrcCreateNewThreadSafeModule(mdl, l->tsctx);
    check_error(LLVMOrcLLJITAddLLVMIRModule(l->jit, l->jd, tsm));
    LLVMOrcJITTargetAddress addr;
    check_error(LLVMOrcLLJITLookup(l->jit, &addr, tbname));
    printf("%s = %p\n", tbname, addr);

    log_disas((void *)addr, 50);

    TCGOp *op;

    QTAILQ_FOREACH(op, &s->ops, link) {
        const TCGOpDef *def;
        TCGOpcode c;
        
        c = op->opc;
        def = &tcg_op_defs[c];
        
       /* switch (c) {
        case INDEX_op_ld_i32:
            op->args[0];
        default:
            printf("%d\n", c);
            //tcg_abort();
        }*/
    }
}
void tcg_llvm_context_init(TCGContext *s)
{
    TCGLLVMContext *l = g_malloc(sizeof(*l));
    s->llvm_ctx = l;
    
    check_error(LLVMOrcCreateLLJIT(&l->jit, NULL));
    l->tsctx = LLVMOrcCreateNewThreadSafeContext();
    l->ctx = LLVMOrcThreadSafeContextGetContext(l->tsctx);
    l->bldr = LLVMCreateBuilderInContext(l->ctx);
    l->jd = LLVMOrcLLJITGetMainJITDylib(l->jit);

#define GET_KINDID(s) LLVMGetEnumAttributeKindForName(s, strlen(s))
    l->noreturn = LLVMCreateEnumAttribute(l->ctx, GET_KINDID("noreturn"), 0);
#undef GET_KINDID
}
void tcg_llvm_init(void)
{
    LLVMInitializeNativeTarget();
    LLVMInitializeNativeAsmPrinter();
    LLVMInitializeNativeAsmParser();
}