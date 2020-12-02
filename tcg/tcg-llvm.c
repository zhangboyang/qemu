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



/* LLVM convenient macros */

/* Context */
#define CTX (l->ctx)
#define FN (l->fn)

/* HBITS: host word bits */
#define HBITS TCG_TARGET_REG_BITS
/* GBITS: guest word bits */
#define GBITS TARGET_LONG_BITS

/* Types for integers and pointer to integers */
#define INTTY(bits) CAT3(LLVMInt, bits, TypeInContext)(CTX)
#define PTRTY(ty) LLVMPointerType(ty, 0)

/* Load and Store */
#undef LD
#undef ST
#define LD(ptr) LLVMBuildLoad(BLDR, ptr, "")
#define ST(val, ptr) LLVMBuildStore(BLDR, val, ptr)

/* Create a new basic block */
#define NEWBB(name) LLVMAppendBasicBlockInContext(CTX, FN, name)

/* Branch and Conditional branch */
#define BR(dst) LLVMBuildBr(BLDR, dst)
#define CONDBR(i1, t, f) LLVMBuildCondBr(BLDR, i1, t, f)
#define INTCMP(x, y, tcg_cond) LLVMBuildICmp(BLDR, map_cond(tcg_cond), x, y, "")
#define CMPBR(x, y, tcg_cond, t, f) CONDBR(INTCMP(x, y, tcg_cond), t, f)

/* Convert integer to pointer */
#define I2P(i, bits) LLVMBuildIntToPtr(BLDR, i, PTRTY(INTTY(bits)), "")
/* Convert integer+offset to pointer */
#define II2P(i1, i2, bits) I2P(LLVMBuildAdd(BLDR, i1, i2, ""), bits)

/* Extend or truncate integers */
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

/* Operations on HBITS integer */ 
#define ALLOCA(name) LLVMBuildAlloca(BLDR, INTTY(HBITS), name)
#define DISCARD LLVMGetUndef(INTTY(HBITS))
#define CONST(c) LLVMConstInt(INTTY(HBITS), c, 0)
#define TRUNC(hval, dst_bits) CAST(hval, HBITS, dst_bits, Z)
#define EXTEND(val, src_bits, ext_kind) CAST(val, src_bits, HBITS, ext_kind)
#define ZEXT(val, src_bits) EXTEND(val, src_bits, Z)
#define SEXT(val, src_bits) EXTEND(val, src_bits, S)
#define TRUNCEXTEND(hval, value_bits, ext_kind) \
    EXTEND(TRUNC(hval, value_bits), value_bits, ext_kind)
#define TZEXT(hval, value_bits) TRUNCEXTEND(hval, value_bits, Z)
#define TSEXT(hval, value_bits) TRUNCEXTEND(hval, value_bits, S)
#define STZ(hval, value_bits, ptr) ST(TZEXT(hval, value_bits), ptr)
#define STZ32(hval, ptr) STZ(hval, 32, ptr)
#define STZ64(hval, ptr) STZ(hval, 64, ptr)

/* Map TCG Condition to LLVM Integer Predicate */
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

/* Get L-value of tcg-op arg */
static inline LLVMValueRef get_lvalue(TCGLLVMContext *l, TCGArg arg)
{
/* Definitions and initializations should in entry basic block
 * So define builder to l->ebldr which is pointed to entry basic block */
#define BLDR (l->ebldr)
    TCGTemp *ts = arg_temp(arg);
    int idx = temp_idx(ts);

    if (ts->temp_global) {        
        if (!l->temps[idx]) {
            LLVMValueRef env = LLVMGetParam(l->fn, l->tbargs);

            /* Allocate a stack variable */
            l->temps[idx] = ALLOCA(ts->name);

            /* Assign initial value */
            if (strcmp(ts->name, "env") == 0) {
                /* env is last function argument */
                ST(env, l->temps[idx]);
            } else {
                if (strcmp(ts->mem_base->name, "env") != 0) {
                    tcg_abort(); /* TODO: non-env global temp */
                }
                switch (ts->type) {
#define PREPARE_TEMP(bits) \
    ST( \
        ZEXT(LD(II2P(env, CONST(ts->mem_offset), bits)), bits), \
        l->temps[idx] \
    )
                case TCG_TYPE_I32: PREPARE_TEMP(32); break;
                case TCG_TYPE_I64: PREPARE_TEMP(64); break;
                default:
                    tcg_abort();
                }
            }
        }
        return l->temps[idx];
    } else if (ts->temp_local) {
        tcg_abort(); /* TODO */
    } else {
        if (!l->temps[idx]) {
            char buf[100];
            sprintf(buf, "tmp%d", idx - l->s->nb_globals);
            l->temps[idx] = ALLOCA(buf);
        }
        return l->temps[idx];
    }
#undef BLDR
}

static inline void flush_temps(TCGLLVMContext *l)
{
#define BLDR (l->bldr)
    LLVMValueRef env = LLVMGetParam(l->fn, l->tbargs);
    int idx;
    for (idx = 0; idx < TCG_MAX_TEMPS; idx++) {
        if (l->temps[idx]) {
            TCGTemp *ts = &l->s->temps[idx];
            if (ts->temp_global && strcmp(ts->name, "env") != 0) {
                switch (ts->type) {
#define FLUSH_TEMP(bits) \
    ST( \
        TRUNC(LD(l->temps[idx]), bits), \
        II2P(env, CONST(ts->mem_offset), bits) \
    )
                case TCG_TYPE_I32: FLUSH_TEMP(32); break;
                case TCG_TYPE_I64: FLUSH_TEMP(64); break;
                default:
                    tcg_abort();
                }
            }
        }
    }
#undef BLDR
}

/* Get basic block of tcg-op arg label */
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

/* Finish current block and switch builder to the given block */
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

    char tbname[128];
    sprintf(tbname, "tb_%016" PRIx64, (uint64_t) tb->pc);
    memset(l->temps, 0, sizeof(l->temps));
    
    LLVMModuleRef mdl = LLVMModuleCreateWithNameInContext(tbname, l->ctx);
    l->fn = LLVMAddFunction(mdl, tbname, l->tbtype);
    //LLVMSetFunctionCallConv(fn, LLVMFastCallConv);
    //LLVMAddAttributeAtIndex(fn, LLVMAttributeFunctionIndex, l->noreturn);
    LLVMBasicBlockRef entry_bb, body_bb;
    entry_bb = LLVMAppendBasicBlockInContext(l->ctx, l->fn, "entry");
    body_bb = LLVMAppendBasicBlockInContext(l->ctx, l->fn, "body");
    LLVMPositionBuilderAtEnd(l->ebldr, entry_bb);
    LLVMPositionBuilderBefore(l->ebldr, LLVMBuildBr(l->ebldr, body_bb));
    LLVMPositionBuilderAtEnd(l->bldr, body_bb);

    

    TCGOp *op;

    QTAILQ_FOREACH(op, &s->ops, link) {
        const TCGOpDef *def;
        TCGOpcode c;
        
        c = op->opc;
        def = &tcg_op_defs[c];

        printf(">>%s\n", def->name);

        switch (c) {
#define BLDR (l->bldr)

/* op args */
#define ARG0 op->args[0]
#define ARG1 op->args[1]
#define ARG2 op->args[2]
#define ARG3 op->args[3]
/* L-value of op args */
#define ARG0L  get_lvalue(l, ARG0)
#define ARG1L  get_lvalue(l, ARG1)
#define ARG2L  get_lvalue(l, ARG2)
#define ARG3L  get_lvalue(l, ARG3)
/* R-value of op args */
#define ARG0R  LD(ARG0L)
#define ARG1R  LD(ARG1L)
#define ARG2R  LD(ARG2L)
#define ARG3R  LD(ARG3L)
/* Const-value of op args */
#define ARG0C  CONST(ARG0)
#define ARG1C  CONST(ARG1)
#define ARG2C  CONST(ARG2)
#define ARG3C  CONST(ARG3)
/* Basic block of op args */
#define ARG0BB get_label(l, ARG0)
#define ARG1BB get_label(l, ARG1)
#define ARG2BB get_label(l, ARG2)
#define ARG3BB get_label(l, ARG3)

        case INDEX_op_discard: ST(DISCARD, ARG0L); break;
        
#define OP_LD(src_bits, dst_bits, ext_kind) \
    STZ( \
        EXTEND(LD(II2P(ARG1R, ARG2C, src_bits)), src_bits, ext_kind), \
        dst_bits, \
        ARG0L \
    )
        case INDEX_op_ld8u_i32:   OP_LD( 8, 32, Z); break;
        case INDEX_op_ld8s_i32:   OP_LD( 8, 32, S); break;
        case INDEX_op_ld16u_i32:  OP_LD(16, 32, Z); break;
        case INDEX_op_ld16s_i32:  OP_LD(16, 32, S); break;
        case INDEX_op_ld_i32:     OP_LD(32, 32, Z); break;
#if HBITS == 64
        case INDEX_op_ld8u_i64:   OP_LD( 8, 64, Z); break;
        case INDEX_op_ld8s_i64:   OP_LD( 8, 64, S); break;
        case INDEX_op_ld16u_i64:  OP_LD(16, 64, Z); break;
        case INDEX_op_ld16s_i64:  OP_LD(16, 64, S); break;
        case INDEX_op_ld32u_i64:  OP_LD(32, 64, Z); break;
        case INDEX_op_ld32s_i64:  OP_LD(32, 64, S); break;
        case INDEX_op_ld_i64:     OP_LD(64, 64, Z); break;
#endif

#define OP_ST(bits) \
    ST(TRUNC(ARG0R, bits), II2P(ARG1R, ARG2C, bits))
        case INDEX_op_st8_i32:   OP_ST( 8); break;
        case INDEX_op_st16_i32:  OP_ST(16); break;
        case INDEX_op_st_i32:    OP_ST(32); break;
#if HBITS == 64
        case INDEX_op_st8_i64:   OP_ST( 8); break;
        case INDEX_op_st16_i64:  OP_ST(16); break;
        case INDEX_op_st32_i64:  OP_ST(32); break;
        case INDEX_op_st_i64:    OP_ST(64); break;
#endif

        case INDEX_op_mov_i32:  STZ32(ARG1R, ARG0L); break;
        case INDEX_op_movi_i32: STZ32(ARG1C, ARG0L); break;
#if HBITS == 64
        case INDEX_op_mov_i64:  STZ64(ARG1R, ARG0L); break;
        case INDEX_op_movi_i64: STZ64(ARG1C, ARG0L); break;
#endif

        case INDEX_op_ext8s_i32:    STZ32(TSEXT(ARG0R,  8), ARG0L); break;
        case INDEX_op_ext16s_i32:   STZ32(TSEXT(ARG0R, 16), ARG0L); break;
        case INDEX_op_ext8u_i32:    STZ32(TZEXT(ARG0R,  8), ARG0L); break;
        case INDEX_op_ext16u_i32:   STZ32(TZEXT(ARG0R, 16), ARG0L); break;

        case INDEX_op_ext8s_i64:    STZ64(TSEXT(ARG0R,  8), ARG0L); break;
        case INDEX_op_ext16s_i64:   STZ64(TSEXT(ARG0R, 16), ARG0L); break;
        case INDEX_op_ext32s_i64:   STZ64(TSEXT(ARG0R, 32), ARG0L); break;
        case INDEX_op_ext_i32_i64:  STZ64(TSEXT(ARG0R, 32), ARG0L); break;
        case INDEX_op_ext8u_i64:    STZ64(TZEXT(ARG0R,  8), ARG0L); break;
        case INDEX_op_ext16u_i64:   STZ64(TZEXT(ARG0R, 16), ARG0L); break;
        case INDEX_op_ext32u_i64:   STZ64(TZEXT(ARG0R, 32), ARG0L); break;
        case INDEX_op_extu_i32_i64: STZ64(TZEXT(ARG0R, 32), ARG0L); break;


#define OP_ARITH(bits, name) \
    STZ( \
        CAT(LLVMBuild, name)(l->bldr, ARG1R, ARG2R, ""), \
        bits, \
        ARG0L \
    )
        case INDEX_op_add_i64: OP_ARITH(64, Add); break;
        case INDEX_op_sub_i64: OP_ARITH(64, Sub); break;
        case INDEX_op_and_i64: OP_ARITH(64, And); break;


#define OP_BRCOND(bits) \
do { \
    LLVMBasicBlockRef next_bb = NEWBB(""), branch_bb = ARG3BB; \
    CMPBR( \
        TRUNC(ARG0R, bits), TRUNC(ARG1R, bits), ARG2, \
        branch_bb, next_bb \
    ); \
    switch_bb(l, next_bb); \
} while (0)
        case INDEX_op_brcond_i32: OP_BRCOND(32); break;
        case INDEX_op_brcond_i64: OP_BRCOND(64); break;
        case INDEX_op_set_label: {
            switch_bb(l, arg_label(ARG0)->llvm_bb);
            break;
        }
        case INDEX_op_insn_start: break;
        

// XXX: memory barrier and endian swap
#define OP_QEMU_LD_HELPER(src_bits, dst_bits, ext_kind) \
    STZ( \
        EXTEND(LD(I2P(ARG1R, src_bits)), src_bits, ext_kind), \
        dst_bits, \
        ARG0L \
    )
#define OP_QEMU_LD(bits) \
do { \
    switch (get_memop(ARG2) & (MO_BSWAP | MO_SSIZE)) { \
    case MO_UB:   OP_QEMU_LD_HELPER( 8, bits, Z); break; \
    case MO_SB:   OP_QEMU_LD_HELPER( 8, bits, S); break; \
    case MO_LEUW: OP_QEMU_LD_HELPER(16, bits, Z); break; \
    case MO_LESW: OP_QEMU_LD_HELPER(16, bits, S); break; \
    case MO_LEUL: OP_QEMU_LD_HELPER(32, bits, Z); break; \
    case MO_LESL: OP_QEMU_LD_HELPER(32, bits, S); break; \
    case MO_LEQ:  OP_QEMU_LD_HELPER(64, bits, Z); break; \
    default: tcg_abort(); \
    } \
} while (0)
        case INDEX_op_qemu_ld_i32: OP_QEMU_LD(32); break;
        case INDEX_op_qemu_ld_i64: OP_QEMU_LD(64); break;

#define OP_QEMU_ST_HELPER(bits) \
    ST(TRUNC(ARG0R, bits), I2P(ARG1R, bits))
        case INDEX_op_qemu_st_i32:
        case INDEX_op_qemu_st_i64: {
            switch (get_memop(ARG2) & (MO_BSWAP | MO_SSIZE)) {
            case MO_UB:   OP_QEMU_ST_HELPER( 8); break;
            case MO_LEUW: OP_QEMU_ST_HELPER(16); break;
            case MO_LEUL: OP_QEMU_ST_HELPER(32); break;
            case MO_LEQ:  OP_QEMU_ST_HELPER(64); break;
            default: tcg_abort();
            }
            break;
        }

        default:
            printf("TODO: %s\n", def->name);
            dump_module(mdl);exit(1);
            break;

        // TODO
        case INDEX_op_goto_tb:
            break;
        case INDEX_op_exit_tb:
            flush_temps(l);
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
    check_error(LLVMOrcLLJITLookup(l->jit, &addr, tbname));
    printf("%s = %p\n", tbname, (void *)addr);
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
    l->ebldr = LLVMCreateBuilderInContext(l->ctx);
    l->jd = LLVMOrcLLJITGetMainJITDylib(l->jit);

    l->pm = LLVMCreatePassManager();
    LLVMAddPromoteMemoryToRegisterPass(l->pm);
    LLVMAddCFGSimplificationPass(l->pm);
    LLVMAddInstructionCombiningPass(l->pm);
    LLVMAddReassociatePass(l->pm);
    LLVMAddGVNPass(l->pm);

#define GET_KINDID(s) LLVMGetEnumAttributeKindForName(s, strlen(s))
    l->noreturn = LLVMCreateEnumAttribute(l->ctx, GET_KINDID("noreturn"), 0);
#undef GET_KINDID


    
    l->tbargs = 4;
    {
        int nargs = l->tbargs + 1;
        LLVMTypeRef args[nargs];
        int i;
        for (i = 0; i < l->tbargs; i++) {
            args[i] = INTTY(GBITS);
        }
        args[l->tbargs] = INTTY(HBITS);
        l->tbtype = LLVMFunctionType(LLVMVoidTypeInContext(l->ctx), args, nargs, 0);
    }
}

void tcg_llvm_init(void)
{
    LLVMInitializeNativeTarget();
    LLVMInitializeNativeAsmPrinter();
    LLVMInitializeNativeAsmParser();
}