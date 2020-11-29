#include "qemu/osdep.h"
#include "qemu/log.h"
#include "exec/exec-all.h"
#include "exec/log.h"
#include "tcg/tcg.h"
#include "tcg/tcg-llvm.h"

#include <llvm-c/Analysis.h>
#include <llvm-c/Transforms/Utils.h>
#include <llvm-c/Transforms/Scalar.h>

#ifdef CONFIG_SOFTMMU
#error LLVM + SOFTMMU Not supported
#endif

#define _CAT(x, y) x ## y
#define CAT(x, y) _CAT(x, y)
#define CAT3(x, y, z) CAT(CAT(x, y), z)


/* Convenient macros */



#define HBITS TCG_TARGET_REG_BITS
#define GBITS TARGET_LONG_BITS

#define CTX (l->ctx)
#define FN (l->fn)
#define INTTY(bits) CAT3(LLVMInt, bits, TypeInContext)(CTX)
#define PTRTY(ty) LLVMPointerType(ty, 0)

#define HOSTTY INTTY(HBITS)
#define GUESTTY INTTY(GBITS)

#undef LD
#undef ST
#define LD(ptr) LLVMBuildLoad(BLDR, ptr, "")
#define ST(val, ptr) LLVMBuildStore(BLDR, val, ptr)

#define NEWBB(name) LLVMAppendBasicBlockInContext(CTX, FN, name)
#define BR(dst) LLVMBuildBr(BLDR, dst)

#define CONDBR(i1, t, f) LLVMBuildCondBr(BLDR, i1, t, f)
#define INTCMP(x, y, tcg_cond) LLVMBuildICmp(BLDR, map_cond(tcg_cond), x, y, "")
#define CMPBR(x, y, tcg_cond, t, f) CONDBR(INTCMP(x, y, tcg_cond), t, f)


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

#define TRUNC(val, dst_bits) CAST(val, HBITS, dst_bits, Z)






static inline LLVMIntPredicate map_cond(TCGCond tcg_cond)
{
    switch (tcg_cond) {
    case TCG_COND_EQ:  return LLVMIntEQ;
    case TCG_COND_NE:  return LLVMIntNE;
    case TCG_COND_LT:  return LLVMIntSLT;
    case TCG_COND_GE:  return LLVMIntSGE;
    case TCG_COND_LE:  return LLVMIntSLE;
    case TCG_COND_GT:  return LLVMIntSGT;
    case TCG_COND_LTU: return LLVMIntULT;
    case TCG_COND_GEU: return LLVMIntUGE;
    case TCG_COND_LEU: return LLVMIntULE;
    case TCG_COND_GTU: return LLVMIntUGT;
    default: tcg_abort();
    }
}

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

static inline LLVMValueRef get_lvalue(TCGLLVMContext *l, TCGArg arg)
{
#define BLDR (l->ebldr)
    TCGTemp *ts = arg_temp(arg);
    int idx = temp_idx(ts);

    if (ts->temp_global) {
        //printf("lval=%s\n", ts->name);
        
        assert(strcmp(ts->name, "env") != 0);
        if (!l->temps[idx]) {
            l->temps[idx] = ALLOCA(ts->name);

            assert(strcmp(ts->mem_base->name, "env") == 0);
            switch (ts->type) {
#define PREPARE_TEMP(bits) \
    ST( \
        CASTZ(LD(II2P(l->env, CONST(ts->mem_offset), bits)), bits, HBITS), \
        l->temps[idx] \
    )
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
        char buf[100];
        sprintf(buf, "tmp%d", idx - l->s->nb_globals);
        //printf("lval=%s\n", buf);
        if (!l->temps[idx]) {
            l->temps[idx] = ALLOCA(buf);
        }
        return l->temps[idx];
    }
#undef BLDR
}

static inline LLVMValueRef get_rvalue(TCGLLVMContext *l, TCGArg arg)
{
    TCGTemp *ts = arg_temp(arg);
    if (ts->temp_global) {
        /* XXX: do not use string compare here */
        if (strcmp(ts->name, "env") == 0) {
            return l->env;
        }
    }
#define BLDR (l->bldr)
    return LD(get_lvalue(l, arg));
#undef BLDR
}

static inline LLVMValueRef get_const(TCGLLVMContext *l, TCGArg arg)
{
    return CONST(arg);
}

static inline LLVMBasicBlockRef get_label(TCGLLVMContext *l, TCGArg arg)
{
    TCGLabel *label = arg_label(arg);
    if (!label->llvm_bb) {
        char buf[100];
        sprintf(buf, "L%d", label->id);
        label->llvm_bb = NEWBB(buf);
    }
    return label->llvm_bb;
}

static inline void switch_bb(TCGLLVMContext *l, LLVMBasicBlockRef next_bb)
{
    if (!LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(l->bldr))) {
        LLVMBuildBr(l->bldr, next_bb);
    }
    LLVMPositionBuilderAtEnd(l->bldr, next_bb);
}

void tcg_llvm_gen_code(TCGContext *s, TranslationBlock *tb)
{
    TCGLLVMContext *l = s->llvm_ctx;

    sprintf(l->tbname, "tb_%016" PRIx64, (uint64_t) tb->pc);
    memset(l->temps, 0, sizeof(l->temps));
    
    LLVMModuleRef mdl = LLVMModuleCreateWithNameInContext(l->tbname, l->ctx);
    l->fn = LLVMAddFunction(mdl, l->tbname, l->tbtype);
    //LLVMSetFunctionCallConv(fn, LLVMFastCallConv);
    //LLVMAddAttributeAtIndex(fn, LLVMAttributeFunctionIndex, l->noreturn);
    LLVMBasicBlockRef entry_bb, body_bb;
    entry_bb = LLVMAppendBasicBlockInContext(l->ctx, l->fn, "entry");
    body_bb = LLVMAppendBasicBlockInContext(l->ctx, l->fn, "body");
    LLVMPositionBuilderAtEnd(l->ebldr, entry_bb);
    LLVMPositionBuilderBefore(l->ebldr, LLVMBuildBr(l->ebldr, body_bb));
    LLVMPositionBuilderAtEnd(l->bldr, body_bb);

    //l->env = LLVMBuildAlloca(l->bldr, l->hostty, "env");
    //LLVMBuildStore(l->bldr, LLVMGetParam(fn, l->tbargs), l->env);
    l->env = LLVMGetParam(l->fn, l->tbargs);
    

    TCGOp *op;

    QTAILQ_FOREACH(op, &s->ops, link) {
        const TCGOpDef *def;
        TCGOpcode c;
        
        c = op->opc;
        def = &tcg_op_defs[c];

        printf(">>%s\n", def->name);

        switch (c) {
#define BLDR (l->bldr)

/* l-value of op args */
#define ARG0L  get_lvalue(l, op->args[0])
#define ARG1L  get_lvalue(l, op->args[1])
#define ARG2L  get_lvalue(l, op->args[2])
#define ARG3L  get_lvalue(l, op->args[3])
/* write value to l-value */
#define VARW(lval, val, val_bits, ext_kind) \
    ST(CAST(val, val_bits, HBITS, ext_kind), lval)
#define VARW32(lval, val) VARW(lval, val, 32, Z)
#define VARW64(lval, val) VARW(lval, val, 64, Z)
/* read value from l-value */
#define VARR(lval, val_bits) \
    CASTZ(LD(lval), HBITS, val_bits)
#define VARR32(lval) VARR(lval, 32)
#define VARR64(lval) VARR(lval, 64)

/* r-value of op args */
#define ARG0   get_rvalue(l, op->args[0])
#define ARG1   get_rvalue(l, op->args[1])
#define ARG2   get_rvalue(l, op->args[2])
#define ARG3   get_rvalue(l, op->args[3])
#define ARG0C  get_const (l, op->args[0])
#define ARG1C  get_const (l, op->args[1])
#define ARG2C  get_const (l, op->args[2])
#define ARG3C  get_const (l, op->args[3])

#define ARG0BB get_label (l, op->args[0])
#define ARG1BB get_label (l, op->args[1])
#define ARG2BB get_label (l, op->args[2])
#define ARG3BB get_label (l, op->args[3])


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

#define OP_ST(dst_bits) \
    ST(VARR(ARG0L, dst_bits), II2P(ARG1, ARG2C, dst_bits))
        case INDEX_op_st8_i32:   OP_ST( 8); break;
        case INDEX_op_st16_i32:  OP_ST(16); break;
        case INDEX_op_st_i32:    OP_ST(32); break;
#if HBITS == 64
        case INDEX_op_st8_i64:   OP_ST( 8); break;
        case INDEX_op_st16_i64:  OP_ST(16); break;
        case INDEX_op_st32_i64:  OP_ST(32); break;
        case INDEX_op_st_i64:    OP_ST(64); break;
#endif

        case INDEX_op_mov_i32:  VARW32(ARG0L, ARG1); break;
        case INDEX_op_movi_i32: VARW32(ARG0L, ARG1C); break;

#if HBITS == 64
        case INDEX_op_mov_i64:  VARW64(ARG0L, ARG1); break;
        case INDEX_op_movi_i64: VARW64(ARG0L, ARG1C); break;
#endif

#define OP_BRCOND(src_bits) \
do { \
    LLVMBasicBlockRef next_bb = NEWBB(""), branch_bb = ARG3BB; \
    CMPBR( \
        TRUNC(ARG0, src_bits), TRUNC(ARG1, src_bits), op->args[2], \
        branch_bb, next_bb \
    ); \
    switch_bb(l, next_bb); \
} while (0)
        case INDEX_op_brcond_i32: OP_BRCOND(32); break;
        case INDEX_op_brcond_i64: OP_BRCOND(64); break;

        case INDEX_op_set_label: {
            switch_bb(l, arg_label(op->args[0])->llvm_bb);
            break;
        }

        default:
            printf("TODO: %s\n", def->name);
            //dump_module(mdl);exit(1);
            break;

        // TODO
        case INDEX_op_exit_tb:
            LLVMBuildRetVoid(l->bldr);
            break;
#undef BLDR
        }
    }

    
    dump_module(mdl);
    LLVMVerifyFunction(l->fn, LLVMAbortProcessAction);

    LLVMRunPassManager(l->pm, mdl);
    dump_module(mdl);


    LLVMOrcThreadSafeModuleRef tsm = LLVMOrcCreateNewThreadSafeModule(mdl, l->tsctx);
    check_error(LLVMOrcLLJITAddLLVMIRModule(l->jit, l->jd, tsm));

    LLVMOrcJITTargetAddress addr;
    check_error(LLVMOrcLLJITLookup(l->jit, &addr, l->tbname));
    printf("%s = %p\n", l->tbname, (void *)addr);
    log_disas((void *)addr, 50);
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
    l->ebldr = LLVMCreateBuilderInContext(l->ctx);
    l->jd = LLVMOrcLLJITGetMainJITDylib(l->jit);

    l->pm = LLVMCreatePassManager();
    LLVMAddPromoteMemoryToRegisterPass(l->pm);
    LLVMAddCFGSimplificationPass(l->pm);
    LLVMAddInstructionCombiningPass(l->pm);
    //LLVMAddReassociatePass(l->pm);
    //LLVMAddGVNPass(l->pm);
    

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