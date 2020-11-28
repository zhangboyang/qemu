#include "qemu/osdep.h"
#include "qemu/log.h"
#include "exec/exec-all.h"
#include "exec/log.h"
#include "tcg/tcg.h"
#include "tcg/tcg-llvm.h"

#ifdef CONFIG_SOFTMMU
#error LLVM + SOFTMMU Not supported
#endif

#define _CAT(x, y) x ## y
#define CAT(x, y) _CAT(x, y)
#define CAT3(x, y, z) CAT(CAT(x, y), z)


/* Convenient macros */



#define HBITS TCG_TARGET_REG_BITS
#define GBITS TARGET_LONG_BITS

#define BLDR (l->bldr)
#define INTTY(bits) CAT3(LLVMInt, bits, TypeInContext)(l->ctx)
#define PTRTY(ty) LLVMPointerType(ty, 0)

#define HOSTTY INTTY(HBITS)
#define GUESTTY INTTY(GBITS)



#undef LD
#undef ST
#define LD(ptr) LLVMBuildLoad(BLDR, ptr, "")
#define ST(val, ptr) LLVMBuildStore(BLDR, val, ptr)

#define ALLOCA(name) LLVMBuildAlloca(BLDR, HOSTTY, name)
#define CONST(c) LLVMConstInt(HOSTTY, c, 0)

#define I2P(i, bits) LLVMBuildIntToPtr(BLDR, i, PTRTY(INTTY(bits)), "")
#define II2P(i1, i2, bits) I2P(LLVMBuildAdd(BLDR, i1, i2, ""), bits)

#define CAST(val, src_bits, dst_bits, ext_kind) ( \
    (src_bits) < (dst_bits) ? ( \
        CAT3(LLVMBuild, ext_kind, Ext)(BLDR, val, INTTY(dst_bits), "") \
    ) : ( \
        (src_bits) > (dst_bits) ? ( \
            LLVMBuildTrunc(BLDR, val, INTTY(dst_bits), "") \
        ) : ( \
            val \
        ) \
    ) \
)
#define CASTS(val, src_bits, dst_bits) CAST(val, src_bits, dst_bits, S)
#define CASTZ(val, src_bits, dst_bits) CAST(val, src_bits, dst_bits, Z)



/* write value to l-value */
#define VARW(v, val, val_bits, ext_kind) \
    ST(CAST(val, val_bits, HBITS, ext_kind), v)
#define VARW32(v, val) VARW(v, val, 32, Z)
#define VARW64(v, val) VARW(v, val, 64, Z)

/* read value from l-value */
#define VARR(v, val_bits) \
    CASTZ(LD(v), HBITS, val_bits)
#define VARR32(v) VARR(v, 32)
#define VARR64(v) VARR(v, 64)




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

static inline LLVMValueRef arg_lvalue(TCGLLVMContext *l, TCGArg arg)
{
    char buf[128];
    TCGTemp *ts = arg_temp(arg);
    int idx = temp_idx(ts);

    if (ts->temp_global) {
        //pstrcpy(buf, buf_size, ts->name);
        
        assert(strcmp(ts->name, "env") != 0);
        if (!l->temps[idx]) {
            l->temps[idx] = ALLOCA(ts->name);

            assert(strcmp(ts->mem_base->name, "env") == 0);
            switch (ts->type) {
#define PREPARE_TEMP(bits) \
    ST(CASTZ(LD(II2P(l->env, CONST(ts->mem_offset), bits)), bits, HBITS), l->temps[idx])
            case TCG_TYPE_I32: PREPARE_TEMP(32); break;
            case TCG_TYPE_I64: PREPARE_TEMP(64); break;
            default:
                tcg_abort();
            }
        }
        return l->temps[idx];
    } else if (ts->temp_local) {
        //snprintf(buf, buf_size, "loc%d", idx - s->nb_globals);
        tcg_abort();
    } else {
        sprintf(buf, "tmp%d", idx - l->s->nb_globals);
        if (!l->temps[idx]) {
            l->temps[idx] = ALLOCA(buf);
        }
        return l->temps[idx];
    }
}

static inline LLVMValueRef arg_rvalue(TCGLLVMContext *l, TCGArg arg)
{
    TCGTemp *ts = arg_temp(arg);
    if (ts->temp_global) {
        /* XXX: do not use string compare here */
        if (strcmp(ts->name, "env") == 0) {
            return l->env;
        }
    }
    return LD(arg_lvalue(l, arg));
}

static inline LLVMValueRef arg_const(TCGLLVMContext *l, TCGArg arg)
{
    return CONST(arg);
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

        switch (c) {
#define ARG0L arg_lvalue(l, op->args[0])
#define ARG1L arg_lvalue(l, op->args[1])
#define ARG2L arg_lvalue(l, op->args[2])
#define ARG3L arg_lvalue(l, op->args[3])
#define ARG0  arg_rvalue(l, op->args[0])
#define ARG1  arg_rvalue(l, op->args[1])
#define ARG2  arg_rvalue(l, op->args[2])
#define ARG3  arg_rvalue(l, op->args[3])
#define ARG0C arg_const (l, op->args[0])
#define ARG1C arg_const (l, op->args[1])
#define ARG2C arg_const (l, op->args[2])
#define ARG3C arg_const (l, op->args[3])

#define OP_LD(src_bits, ext_kind) \
    VARW(ARG0L, LD(II2P(ARG1, ARG2C, src_bits)), src_bits, ext_kind)
        case INDEX_op_ld8u_i32:   OP_LD( 8, Z); break;
        case INDEX_op_ld8s_i32:   OP_LD( 8, S); break;
        case INDEX_op_ld16u_i32:  OP_LD(16, Z); break;
        case INDEX_op_ld16s_i32:  OP_LD(16, S); break;
        case INDEX_op_ld_i32:     OP_LD(32, Z); break;
#if HBITS == 64
        case INDEX_op_ld8u_i64:   OP_LD( 8, Z); break;
        case INDEX_op_ld8s_i64:   OP_LD( 8, S); break;
        case INDEX_op_ld16u_i64:  OP_LD(16, Z); break;
        case INDEX_op_ld16s_i64:  OP_LD(16, S); break;
        case INDEX_op_ld32u_i64:  OP_LD(32, Z); break;
        case INDEX_op_ld32s_i64:  OP_LD(32, S); break;
        case INDEX_op_ld_i64:     OP_LD(64, Z); break;
#endif

        case INDEX_op_mov_i32:  VARW32(ARG0L, ARG1); break;
        case INDEX_op_movi_i32: VARW32(ARG0L, ARG1C); break;

#if HBITS == 64
        case INDEX_op_mov_i64:  VARW64(ARG0L, ARG1); break;
        case INDEX_op_movi_i64: VARW64(ARG0L, ARG1C); break;
#endif

#define OP_BRCOND(src_bits) \
do { \
} while (0)
        //case INDEX_op_brcond_i32: OP_BRCOND(32); break;
        //case INDEX_op_brcond_i64: OP_BRCOND(64); break;

        default:
            printf("TODO: %s\n", tcg_op_defs[c].name);
            dump_module(mdl);exit(1);

        // TODO
        case INDEX_op_insn_start:
        case INDEX_op_qemu_ld_i32:
            break;
        }
    }

    LLVMBuildRetVoid(l->bldr);
    LLVMVerifyFunction(fn, LLVMAbortProcessAction);
    dump_module(mdl);


    LLVMOrcThreadSafeModuleRef tsm = LLVMOrcCreateNewThreadSafeModule(mdl, l->tsctx);
    check_error(LLVMOrcLLJITAddLLVMIRModule(l->jit, l->jd, tsm));

    LLVMOrcJITTargetAddress addr;
    check_error(LLVMOrcLLJITLookup(l->jit, &addr, l->tbname));
    printf("%s = %p\n", l->tbname, addr);
    log_disas((void *)addr, 200);
}

void tcg_llvm_context_init(TCGContext *s)
{
    TCGLLVMContext *l = g_malloc0(sizeof(*l));
    s->llvm_ctx = l;
    l->s = s;
    
    check_error(LLVMOrcCreateLLJIT(&l->jit, NULL));
    l->tsctx = LLVMOrcCreateNewThreadSafeContext();
    l->ctx = LLVMOrcThreadSafeContextGetContext(l->tsctx);
    l->bldr = LLVMCreateBuilderInContext(l->ctx);
    l->jd = LLVMOrcLLJITGetMainJITDylib(l->jit);

#define GET_KINDID(s) LLVMGetEnumAttributeKindForName(s, strlen(s))
    l->noreturn = LLVMCreateEnumAttribute(l->ctx, GET_KINDID("noreturn"), 0);
#undef GET_KINDID


    
    l->tbargs = 4;
    {
        int nargs = l->tbargs + 1;
        LLVMTypeRef args[nargs];
        int i;
        for (i = 0; i < l->tbargs; i++) {
            args[i] = GUESTTY;
        }
        args[l->tbargs] = HOSTTY;
        l->tbtype = LLVMFunctionType(LLVMVoidTypeInContext(l->ctx), args, nargs, 0);
    }
}

void tcg_llvm_init(void)
{
    LLVMInitializeNativeTarget();
    LLVMInitializeNativeAsmPrinter();
    LLVMInitializeNativeAsmParser();
}