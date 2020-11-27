#include "qemu/osdep.h"
#include "qemu/log.h"
#include "exec/exec-all.h"
#include "exec/log.h"
#include "tcg/tcg.h"
#include "tcg/tcg-llvm.h"

#ifdef CONFIG_SOFTMMU
#error LLVM + SOFTMMU Not supported
#endif

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

static inline LLVMValueRef arg_lvalue(TCGContext *s, TCGArg arg)
{
    char buf[128];
    TCGLLVMContext *l = s->llvm_ctx;
    TCGTemp *ts = arg_temp(arg);
    int idx = temp_idx(ts);

    if (ts->temp_global) {
        //pstrcpy(buf, buf_size, ts->name);
        
        assert(strcmp(ts->name, "env") != 0);
        if (!l->temps[idx]) {
            l->temps[idx] = LLVMBuildAlloca(l->bldr, l->hostty, ts->name);
        }
        return l->temps[idx];
    } else if (ts->temp_local) {
        //snprintf(buf, buf_size, "loc%d", idx - s->nb_globals);
    } else {
        sprintf(buf, "tmp%d", idx - s->nb_globals);
        if (!l->temps[idx]) {
            l->temps[idx] = LLVMBuildAlloca(l->bldr, l->hostty, buf);
        }
        return l->temps[idx];
    }
}

static inline LLVMValueRef arg_rvalue(TCGContext *s, TCGArg arg)
{
    TCGLLVMContext *l = s->llvm_ctx;
    TCGTemp *ts = arg_temp(arg);

    if (ts->temp_global) {
        /* XXX: do not use string compare here */
        if (strcmp(ts->name, "env") == 0) {
            return l->env;
        }
    }
    return LLVMBuildLoad(l->bldr, arg_lvalue(s, arg), "");
}

static inline LLVMValueRef arg_const(TCGContext *s, TCGArg arg)
{
    TCGLLVMContext *l = s->llvm_ctx;

    return LLVMConstInt(l->hostty, arg, 0);
}

void tcg_llvm_gen_code(TCGContext *s, TranslationBlock *tb)
{
    TCGLLVMContext *l = s->llvm_ctx;

    sprintf(l->tbname, "tb_%016" PRIx64, (uint64_t) tb->pc);
    memset(l->temps, 0, sizeof(l->temps));
    
    LLVMModuleRef mdl = LLVMModuleCreateWithNameInContext(l->tbname, l->ctx);
    LLVMValueRef fn = LLVMAddFunction(mdl, l->tbname, l->tbtype);
    //LLVMSetFunctionCallConv(fn, LLVMFastCallConv);
    //LLVMAddAttributeAtIndex(fn, LLVMAttributeFunctionIndex, l->noreturn);
    LLVMBasicBlockRef bb = LLVMAppendBasicBlockInContext(l->ctx, fn, "entry");
    LLVMPositionBuilderAtEnd(l->bldr, bb);

    //l->env = LLVMBuildAlloca(l->bldr, l->hostty, "env");
    //LLVMBuildStore(l->bldr, LLVMGetParam(fn, l->tbargs), l->env);
    l->env = LLVMGetParam(fn, l->tbargs);
    

    TCGOp *op;

    QTAILQ_FOREACH(op, &s->ops, link) {
        const TCGOpDef *def;
        TCGOpcode c;
        
        c = op->opc;
        def = &tcg_op_defs[c];
        printf(">%s(%d)\n", tcg_op_defs[c].name, c);

        LLVMValueRef lval, addr_int, addr_ptr;
        switch (c) {
        case INDEX_op_ld_i32:
            lval = arg_lvalue(s, op->args[0]);
            addr_int = LLVMBuildAdd(l->bldr, arg_rvalue(s, op->args[1]), arg_const(s, op->args[2]), "");
            addr_ptr = LLVMBuildIntToPtr(l->bldr, addr_int, LLVMPointerType(l->hostty, 0), "");
            LLVMBuildStore(l->bldr, LLVMBuildLoad(l->bldr, addr_ptr, ""), lval);
            break;
        default:
            if(0)exit(1);
        }
    }

    LLVMBuildRetVoid(l->bldr);
    dump_module(mdl);


    LLVMOrcThreadSafeModuleRef tsm = LLVMOrcCreateNewThreadSafeModule(mdl, l->tsctx);
    check_error(LLVMOrcLLJITAddLLVMIRModule(l->jit, l->jd, tsm));

    LLVMOrcJITTargetAddress addr;
    check_error(LLVMOrcLLJITLookup(l->jit, &addr, l->tbname));
    printf("%s = %p\n", l->tbname, addr);
    log_disas((void *)addr, 50);
}

void tcg_llvm_context_init(TCGContext *s)
{
    TCGLLVMContext *l = g_malloc0(sizeof(*l));
    s->llvm_ctx = l;
    
    check_error(LLVMOrcCreateLLJIT(&l->jit, NULL));
    l->tsctx = LLVMOrcCreateNewThreadSafeContext();
    l->ctx = LLVMOrcThreadSafeContextGetContext(l->tsctx);
    l->bldr = LLVMCreateBuilderInContext(l->ctx);
    l->jd = LLVMOrcLLJITGetMainJITDylib(l->jit);

#define GET_KINDID(s) LLVMGetEnumAttributeKindForName(s, strlen(s))
    l->noreturn = LLVMCreateEnumAttribute(l->ctx, GET_KINDID("noreturn"), 0);
#undef GET_KINDID

#if TCG_TARGET_REG_BITS == 32
    l->hostty = LLVMInt32TypeInContext(l->ctx);
#elif TCG_TARGET_REG_BITS == 64
    l->hostty = LLVMInt64TypeInContext(l->ctx);
#else
#error Unhandled TARGET_LONG_BITS value
#endif

#if TARGET_LONG_BITS == 32
    l->guestty = LLVMInt32TypeInContext(l->ctx);
#elif TARGET_LONG_BITS == 64
    l->guestty = LLVMInt64TypeInContext(l->ctx);
#else
#error Unhandled TARGET_LONG_BITS value
#endif

    
    l->tbargs = 4;
    {
        int nargs = l->tbargs + 1;
        LLVMTypeRef args[nargs];
        int i;
        for (i = 0; i < l->tbargs; i++) {
            args[i] = l->guestty;
        }
        args[l->tbargs] = l->hostty;
        l->tbtype = LLVMFunctionType(l->guestty, args, nargs, 0);
    }
}

void tcg_llvm_init(void)
{
    LLVMInitializeNativeTarget();
    LLVMInitializeNativeAsmPrinter();
    LLVMInitializeNativeAsmParser();
}