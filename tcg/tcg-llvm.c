/*
 * QEMU TCG JIT using LLVM
 *
 * Copyright (C) 2020, Zhang Boyang <zhangboyang.id@gmail.com>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */

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
#define VOIDTY LLVMVoidTypeInContext(CTX)
#define INTTY(bits) CAT3(LLVMInt, bits, TypeInContext)(CTX)
#define PTRTY(ty) LLVMPointerType(ty, 0)
#define ELETY(ptr) LLVMGetElementType(ptr)
#define TYOF(val) LLVMTypeOf(val)

/* Alloca */
#define ALLOCA(bits, name) LLVMBuildAlloca(BLDR, INTTY(bits), name)
#define ALLOCAH(name) ALLOCA(HBITS, name)

/* Constant values */
#define CONST(bits, c) LLVMConstInt(INTTY(bits), c, 0)
#define CONSTH(c) CONST(HBITS, c)

/* Load and Store */
#undef LD
#undef ST
#define LD(ptr) LLVMBuildLoad(BLDR, ptr, "")
#define ST(val, ptr) LLVMBuildStore(BLDR, val, ptr)

/* Arith Ops */
#define ADD(x, y) LLVMBuildAdd(BLDR, x, y, "")
#define SUB(x, y) LLVMBuildSub(BLDR, x, y, "")
#define MUL(x, y) LLVMBuildMul(BLDR, x, y, "")
#define DIV(x, y, div_kind) CAT3(LLVMBuild, div_kind, Div)(BLDR, x, y, "")
#define REM(x, y, div_kind) CAT3(LLVMBuild, div_kind, Rem)(BLDR, x, y, "")
#define AND(x, y) LLVMBuildAnd(BLDR, x, y, "")
#define OR(x, y) LLVMBuildOr(BLDR, x, y, "")
#define SHL(x, y) LLVMBuildShl(BLDR, x, y, "")
#define SHR(x, y, shr_kind) CAT3(LLVMBuild, shr_kind, Shr)(BLDR, x, y, "")
#define LSHR(x, y) SHR(x, y, L)
#define ASHR(x, y) SHR(x, y, A)

/* Create a new basic block */
#define NEWBB(name) LLVMAppendBasicBlockInContext(CTX, FN, name)

/* Branch and Conditional branch */
#define BR(dst) LLVMBuildBr(BLDR, dst)
#define CONDBR(i1, t, f) LLVMBuildCondBr(BLDR, i1, t, f)
#define INTCMP(x, y, tcg_cond) LLVMBuildICmp(BLDR, map_cond(tcg_cond), x, y, "")
#define SELECT(cond, t, f) LLVMBuildSelect(BLDR, cond, t, f, "")
#define CMPBR(x, y, tcg_cond, t, f) CONDBR(INTCMP(x, y, tcg_cond), t, f)

/* Convert pointers */
#define P2I(p) LLVMBuildPtrToInt(BLDR, p, INTTY(HBITS), "")
#define I2P(i, bits) LLVMBuildIntToPtr(BLDR, i, PTRTY(INTTY(bits)), "")
/* Convert integer+offset to pointer */
#define II2P(i1, i2, bits) I2P(ADD(i1, i2), bits)
#define PI2P(p, i, bits) II2P(P2I(p), i, bits)

/* Extend or truncate integers */
#define TRUNC(val, dst_bits) LLVMBuildTrunc(BLDR, val, INTTY(dst_bits), "")
#define EXTEND(val, dst_bits, ext_kind) \
    CAT3(LLVMBuild, ext_kind, Ext)(BLDR, val, INTTY(dst_bits), "")
#define ZEXT(val, dst_bits) EXTEND(val, dst_bits, Z)
#define SEXT(val, dst_bits) EXTEND(val, dst_bits, S)
#define TZEXT(val, src_bits, dst_bits) ZEXT(TRUNC(val, src_bits), dst_bits)
#define TSEXT(val, src_bits, dst_bits) SEXT(TRUNC(val, src_bits), dst_bits)


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

/* Build a call to llvm intrinsic
 *  call_intrinsic(l,
 *      "llvm.foo.bar",
 *      [Overload types], NULL,
 *      [Arg values], NULL
 *  );
 */
static LLVMValueRef call_intrinsic(TCGLLVMContext *l, const char *name, ...)
{
#define MAX_INTRINSIC_ARGS 10
    va_list ap;
    int nty = 0;
    int narg = 0;
    LLVMTypeRef ty[MAX_INTRINSIC_ARGS + 1], t;
    LLVMValueRef arg[MAX_INTRINSIC_ARGS + 1], a;
    LLVMValueRef fn;
    unsigned iid;
    
    va_start(ap, name);
    while ((t = va_arg(ap, LLVMTypeRef))) {
        if (nty >= MAX_INTRINSIC_ARGS) tcg_abort();
        ty[nty++] = t;
    }
    while ((a = va_arg(ap, LLVMValueRef))) {
        if (narg >= MAX_INTRINSIC_ARGS) tcg_abort();
        arg[narg++] = a;
    }
    va_end(ap);

    iid = LLVMLookupIntrinsicID(name, strlen(name));
    fn = LLVMGetIntrinsicDeclaration(l->mod, iid, ty, nty);
    return LLVMBuildCall(l->bldr, fn, arg, narg, "");
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
            /* Assign initial value */
            if (strcmp(ts->name, "env") == 0) {
                l->temps[idx] = ALLOCAH(ts->name);
                /* env is a function argument */
                ST(P2I(l->env), l->temps[idx]);
            } else {
                LLVMValueRef off, gep;
                LLVMTypeRef dst_ty;

                if (strcmp(ts->mem_base->name, "env") != 0) {
                    tcg_abort(); /* TODO: non-env global temp */
                }
                
                switch (ts->type) {
                case TCG_TYPE_I32: dst_ty = PTRTY(INTTY(32)); break;
                case TCG_TYPE_I64: dst_ty = PTRTY(INTTY(64)); break;
                default:
                    tcg_abort();
                }
                
                off = CONSTH(ts->mem_offset);
                gep = LLVMBuildInBoundsGEP2(BLDR,
                    INTTY(8),
                    l->env,
                    &off, 1,
                    ts->name);
                l->temps[idx] = LLVMBuildBitCast(BLDR, gep, dst_ty, "");
            }
        }
        return l->temps[idx];
    } else {
        if (!l->temps[idx]) {
            char buf[100];
            sprintf(buf, "%s%d", 
                ts->temp_local ? "loc" : "tmp",
                idx - l->s->nb_globals);
            switch (ts->type) {
            case TCG_TYPE_I32: l->temps[idx] = ALLOCA(32, buf); break;
            case TCG_TYPE_I64: l->temps[idx] = ALLOCA(64, buf); break;
            default: tcg_abort();
            }
        }
        return l->temps[idx];
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

#define MAX_TB_NAME 128
static inline void make_tb_name(char *tb_name, TranslationBlock *tb)
{
    sprintf(tb_name, "tb_%016" PRIx64, (uint64_t) tb->pc);
}

void tcg_llvm_gen_code(TCGContext *s, TranslationBlock *tb)
{
    TCGLLVMContext *l = s->llvm_ctx;
    LLVMBasicBlockRef entry_bb, body_bb;
    TCGOp *op;
    char tb_name[MAX_TB_NAME];

    memset(l->temps, 0, sizeof(l->temps));

    make_tb_name(tb_name, tb);
    if (l->mod == NULL) {
        l->mod = LLVMModuleCreateWithNameInContext(tb_name, l->ctx);
    }
    l->fn = LLVMAddFunction(l->mod, tb_name, l->tbtype);
    l->env = LLVMGetParam(l->fn, l->tbargs);
    LLVMAddAttributeAtIndex(l->fn, 1 + l->tbargs, l->noalias);
    //LLVMSetFunctionCallConv(fn, LLVMFastCallConv);
    //LLVMAddAttributeAtIndex(fn, LLVMAttributeFunctionIndex, l->noreturn);

    entry_bb = LLVMAppendBasicBlockInContext(l->ctx, l->fn, "entry");
    body_bb = LLVMAppendBasicBlockInContext(l->ctx, l->fn, "body");
    LLVMPositionBuilderAtEnd(l->ebldr, entry_bb);
    LLVMPositionBuilderBefore(l->ebldr, LLVMBuildBr(l->ebldr, body_bb));
    LLVMPositionBuilderAtEnd(l->bldr, body_bb);

    
    QTAILQ_FOREACH(op, &s->ops, link) {
        const TCGOpDef *def;
        TCGOpcode c;
        
        c = op->opc;
        def = &tcg_op_defs[c];

        //printf(">>%s\n", def->name);

        switch (c) {
#define BLDR (l->bldr)

/* op args */
#define ARG0 op->args[0]
#define ARG1 op->args[1]
#define ARG2 op->args[2]
#define ARG3 op->args[3]
#define ARG4 op->args[4]
#define ARG5 op->args[5]
/* L-value of op args */
#define ARG0L  get_lvalue(l, ARG0)
#define ARG1L  get_lvalue(l, ARG1)
#define ARG2L  get_lvalue(l, ARG2)
#define ARG3L  get_lvalue(l, ARG3)
#define ARG4L  get_lvalue(l, ARG4)
#define ARG5L  get_lvalue(l, ARG5)
/* R-value of op args */
#define ARG0R  LD(ARG0L)
#define ARG1R  LD(ARG1L)
#define ARG2R  LD(ARG2L)
#define ARG3R  LD(ARG3L)
#define ARG4R  LD(ARG4L)
#define ARG5R  LD(ARG5L)
/* Const-value of op args */
#define ARG0C  CONSTH(ARG0)
#define ARG1C  CONSTH(ARG1)
#define ARG2C  CONSTH(ARG2)
#define ARG3C  CONSTH(ARG3)
#define ARG4C  CONSTH(ARG4)
#define ARG5C  CONSTH(ARG5)
/* Basic block of op args */
#define ARG0BB get_label(l, ARG0)
#define ARG1BB get_label(l, ARG1)
#define ARG2BB get_label(l, ARG2)
#define ARG3BB get_label(l, ARG3)
#define ARG4BB get_label(l, ARG4)
#define ARG5BB get_label(l, ARG5)
/* store to op args */
#define ST0(v) ST(v, ARG0L)
#define ST1(v) ST(v, ARG1L)

        case INDEX_op_discard:
            ST0(LLVMGetUndef(ELETY(TYOF(ARG0L))));
            break;
        
#define OP_LD(src_bits, dst_bits, ext_kind) \
    ST0(EXTEND(LD(II2P(ARG1R, ARG2C, src_bits)), dst_bits, ext_kind))
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

        case INDEX_op_mov_i32:  ST0(TRUNC(ARG1R, 32)); break;
        case INDEX_op_movi_i32: ST0(TRUNC(ARG1C, 32)); break;
#if HBITS == 64
        case INDEX_op_mov_i64:  ST0(ARG1R); break;
        case INDEX_op_movi_i64: ST0(ARG1C); break;
#endif

        case INDEX_op_ext8s_i32:    ST0(TSEXT(ARG1R,  8, 32)); break;
        case INDEX_op_ext16s_i32:   ST0(TSEXT(ARG1R, 16, 32)); break;
        case INDEX_op_ext8u_i32:    ST0(TZEXT(ARG1R,  8, 32)); break;
        case INDEX_op_ext16u_i32:   ST0(TZEXT(ARG1R, 16, 32)); break;

#if HBITS == 64
        case INDEX_op_ext8s_i64:    ST0(TSEXT(ARG1R,  8, 64)); break;
        case INDEX_op_ext16s_i64:   ST0(TSEXT(ARG1R, 16, 64)); break;
        case INDEX_op_ext32s_i64:   ST0(TSEXT(ARG1R, 32, 64)); break;
        case INDEX_op_ext_i32_i64:  ST0(TSEXT(ARG1R, 32, 64)); break;
        case INDEX_op_ext8u_i64:    ST0(TZEXT(ARG1R,  8, 64)); break;
        case INDEX_op_ext16u_i64:   ST0(TZEXT(ARG1R, 16, 64)); break;
        case INDEX_op_ext32u_i64:   ST0(TZEXT(ARG1R, 32, 64)); break;
        case INDEX_op_extu_i32_i64: ST0(TZEXT(ARG1R, 32, 64)); break;
#endif


#define OP_ARITH2(op2) \
    ST0(CAT(LLVMBuild, op2)(BLDR, ARG1R, ARG2R, ""))
#define OP_ARITH1(op1) \
    ST0(CAT(LLVMBuild, op1)(BLDR, ARG1R, ""))
#define OP_ARITH12(op1, op2) \
    ST0( \
        CAT(LLVMBuild, op1)(BLDR, \
            CAT(LLVMBuild, op2)(BLDR, ARG1R, ARG2R, ""), \
            "" \
        ) \
    )
#define OP_ARITH21(op2, op1) \
    ST0( \
        CAT(LLVMBuild, op2)(BLDR, \
            ARG1R, \
            CAT(LLVMBuild, op1)(BLDR, ARG2R, ""), \
            "" \
        ) \
    )
#if HBITS == 64
#define CASE_ARITH(tcg_op, stmt) \
    case CAT3(INDEX_op_, tcg_op, _i32): stmt; break; \
    case CAT3(INDEX_op_, tcg_op, _i64): stmt; break;
#else
#define CASE_ARITH(tcg_op, stmt) \
    case CAT3(INDEX_op_, tcg_op, _i32): stmt; break;
#endif
        CASE_ARITH(add, OP_ARITH2(Add))
        CASE_ARITH(sub, OP_ARITH2(Sub))
        CASE_ARITH(neg, OP_ARITH1(Neg))
        CASE_ARITH(mul, OP_ARITH2(Mul))
        CASE_ARITH(and, OP_ARITH2(And))
        CASE_ARITH(or , OP_ARITH2(Or))
        CASE_ARITH(xor, OP_ARITH2(Xor))
        CASE_ARITH(shl, OP_ARITH2(Shl))
        CASE_ARITH(shr, OP_ARITH2(LShr))
        CASE_ARITH(sar, OP_ARITH2(AShr))
        CASE_ARITH(not, OP_ARITH1(Not))
        CASE_ARITH(andc, OP_ARITH21(And, Not))

#define OP_MUL2(bits, bits2x, mul_kind) \
do { \
    LLVMValueRef product = MUL( \
        EXTEND(ARG2R, bits2x, mul_kind), \
        EXTEND(ARG3R, bits2x, mul_kind) \
    ); \
    ST0(TRUNC(product, bits)); \
    ST1(TRUNC(LSHR(product, CONST(bits2x, bits)), bits)); \
} while (0)
        case INDEX_op_mulu2_i32:  OP_MUL2(32, 64, Z); break;
        case INDEX_op_muls2_i32:  OP_MUL2(32, 64, S); break;
#if HBITS == 64
        case INDEX_op_mulu2_i64:  OP_MUL2(64, 128, Z); break;
        case INDEX_op_muls2_i64:  OP_MUL2(64, 128, S); break;
#endif

#define OP_DIV2(bits, bits2x, div_kind) \
do { \
    LLVMValueRef a = OR( \
        ZEXT(ARG2R, bits2x), \
        SHL(ZEXT(ARG3R, bits2x), CONST(bits2x, bits)) \
    ); \
    LLVMValueRef b = ZEXT(ARG4R, bits2x); \
    ST0(TRUNC(DIV(a, b, div_kind), bits)); \
    ST1(TRUNC(REM(a, b, div_kind), bits)); \
} while (0)
        case INDEX_op_divu2_i32:  OP_DIV2(32, 64, U); break;
        case INDEX_op_div2_i32:   OP_DIV2(32, 64, S); break;
#if HBITS == 64
        case INDEX_op_divu2_i64:  OP_DIV2(64, 128, U); break;
        case INDEX_op_div2_i64:   OP_DIV2(64, 128, S); break;
#endif

#define OP_ADDSUB2(op, bits, bits2x) \
do { \
    LLVMValueRef a = OR( \
        ZEXT(ARG2R, bits2x), \
        SHL(ZEXT(ARG3R, bits2x), CONST(bits2x, bits)) \
    ); \
    LLVMValueRef b = OR( \
        ZEXT(ARG4R, bits2x), \
        SHL(ZEXT(ARG5R, bits2x), CONST(bits2x, bits)) \
    ); \
    LLVMValueRef result = op(a, b); \
    ST0(TRUNC(result, bits)); \
    ST1(TRUNC(LSHR(result, CONST(bits2x, bits)), bits)); \
} while (0)
        case INDEX_op_add2_i32:  OP_ADDSUB2(ADD, 32, 64); break;
        case INDEX_op_sub2_i32:  OP_ADDSUB2(SUB, 32, 64); break;
#if HBITS == 64
        case INDEX_op_add2_i64:  OP_ADDSUB2(ADD, 64, 128); break;
        case INDEX_op_sub2_i64:  OP_ADDSUB2(SUB, 64, 128); break;
#endif

#define OP_DEPOSIT(bits) \
do { \
    unsigned long long mask = ((1LL << ARG4) - 1) << ARG3; \
    ST0( \
        OR( \
            AND(ARG1R, CONST(bits, ~mask)), \
            AND(SHL(ARG2R, CONST(bits, ARG3)), CONST(bits, mask)) \
        ) \
    ); \
} while (0)
        case INDEX_op_deposit_i32:  OP_DEPOSIT(32); break;
#if HBITS == 64
        case INDEX_op_deposit_i64:  OP_DEPOSIT(64); break;
#endif

#define OP_EXTRACT(bits, shr_kind) \
    ST0( \
        SHR(\
            SHL(ARG1R, CONST(bits, bits - ARG2 - ARG3)), \
            CONST(bits, bits - ARG3), \
            shr_kind \
        ) \
    )
        case INDEX_op_extract_i32:  OP_EXTRACT(32, L); break;
        case INDEX_op_sextract_i32: OP_EXTRACT(32, A); break;
#if HBITS == 64
        case INDEX_op_extract_i64:  OP_EXTRACT(64, L); break;
        case INDEX_op_sextract_i64: OP_EXTRACT(64, A); break;
#endif

#define OP_EXTRACT2(bits) \
    ST0( \
        call_intrinsic(l, "llvm.fshr", \
            INTTY(bits), NULL, \
            ARG2R, ARG1R, CONST(bits, ARG3), NULL \
        ) \
    )
        case INDEX_op_extract2_i32:  OP_EXTRACT2(32); break;
#if HBITS == 64
        case INDEX_op_extract2_i64:  OP_EXTRACT2(64); break;
#endif

#define OP_BSWAP(swap_bits, dst_bits) \
    ST0( \
        ZEXT( \
            call_intrinsic(l, \
                "llvm.bswap", INTTY(swap_bits), NULL, \
                TRUNC(ARG1R, swap_bits), NULL \
            ), \
            dst_bits \
        ) \
    )
        case INDEX_op_bswap16_i32: OP_BSWAP(16, 32); break;
        case INDEX_op_bswap32_i32: OP_BSWAP(32, 32); break;
#if HBITS == 64
        case INDEX_op_bswap16_i64: OP_BSWAP(16, 64); break;
        case INDEX_op_bswap32_i64: OP_BSWAP(32, 64); break;
        case INDEX_op_bswap64_i64: OP_BSWAP(64, 64); break;
#endif

#define OP_ROT(name, bits) \
    ST0( \
        call_intrinsic(l, \
            name, INTTY(bits), NULL, \
            ARG1R, ARG1R, ARG2R, NULL \
        ) \
    )
        case INDEX_op_rotl_i32: OP_ROT("llvm.fshl", 32); break;
        case INDEX_op_rotr_i32: OP_ROT("llvm.fshr", 32); break;
#if HBITS == 64
        case INDEX_op_rotl_i64: OP_ROT("llvm.fshl", 64); break;
        case INDEX_op_rotr_i64: OP_ROT("llvm.fshr", 64); break;
#endif

#define OP_CNTZERO(name, bits) \
    ST0( \
        SELECT( \
            INTCMP(ARG1R, CONST(bits, 0), TCG_COND_NE), \
            call_intrinsic(l, \
                name, INTTY(bits), NULL, \
                ARG1R, CONST(1, 0), NULL \
            ), \
            ARG2R \
        ) \
    )
        case INDEX_op_clz_i32: OP_CNTZERO("llvm.ctlz", 32); break;
        case INDEX_op_ctz_i32: OP_CNTZERO("llvm.cttz", 32); break;
#if HBITS == 64
        case INDEX_op_clz_i64: OP_CNTZERO("llvm.ctlz", 64); break;
        case INDEX_op_ctz_i64: OP_CNTZERO("llvm.cttz", 64); break;
#endif

        case INDEX_op_br: {
            LLVMBuildBr(l->bldr, ARG0BB);
            break;
        }
        case INDEX_op_set_label: {
            switch_bb(l, ARG0BB);
            break;
        }

#define OP_BRCOND(bits) \
do { \
    LLVMBasicBlockRef next_bb = NEWBB(""), branch_bb = ARG3BB; \
    CMPBR( \
        ARG0R, ARG1R, ARG2, \
        branch_bb, next_bb \
    ); \
    switch_bb(l, next_bb); \
} while (0)
        case INDEX_op_brcond_i32: OP_BRCOND(32); break;
#if HBITS == 64
        case INDEX_op_brcond_i64: OP_BRCOND(64); break;
#endif

#define OP_MOVCOND(bits) \
    ST0( \
        SELECT( \
            INTCMP(ARG1R, ARG2R, ARG5), \
            ARG3R, \
            ARG4R \
        ) \
    )
        case INDEX_op_movcond_i32: OP_MOVCOND(32); break;
#if HBITS == 64
        case INDEX_op_movcond_i64: OP_MOVCOND(64); break;
#endif

#define OP_SETCOND(bits) \
    ST0(ZEXT(INTCMP(ARG1R, ARG2R, ARG3), bits))
        case INDEX_op_setcond_i32: OP_SETCOND(32); break;
#if HBITS == 64
        case INDEX_op_setcond_i64: OP_SETCOND(64); break;
#endif

// XXX: memory barrier!!! and endian swap
#define OP_QEMU_LD_HELPER(src_bits, dst_bits, ext_kind) \
    ST0(EXTEND(LD(I2P(ARG1R, src_bits)), dst_bits, ext_kind))
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
#if HBITS == 64
        case INDEX_op_qemu_ld_i64: OP_QEMU_LD(64); break;
#endif

#define OP_QEMU_ST_HELPER(bits) \
    ST(TRUNC(ARG0R, bits), I2P(ARG1R, bits))
        case INDEX_op_qemu_st_i32:
#if HBITS == 64
        case INDEX_op_qemu_st_i64:
#endif
            switch (get_memop(ARG2) & (MO_BSWAP | MO_SSIZE)) {
            case MO_UB:   OP_QEMU_ST_HELPER( 8); break;
            case MO_LEUW: OP_QEMU_ST_HELPER(16); break;
            case MO_LEUL: OP_QEMU_ST_HELPER(32); break;
            case MO_LEQ:  OP_QEMU_ST_HELPER(64); break;
            default: tcg_abort();
            }
            break;

        case INDEX_op_call: {
            int i, nb_oargs, nb_iargs;
            LLVMTypeRef ret_ty;
            LLVMTypeRef args_ty[MAX_OPC_PARAM_IARGS];
            LLVMTypeRef fn_ty;
            LLVMValueRef args[MAX_OPC_PARAM_IARGS];
            LLVMValueRef fn, result;

            nb_oargs = TCGOP_CALLO(op);
            nb_iargs = TCGOP_CALLI(op);
            if (nb_oargs > 1) {
                tcg_abort();
            }
            
            for (i = 0; i < nb_iargs; i++) {
                LLVMValueRef lval = get_lvalue(l, op->args[nb_oargs + i]);
                args_ty[i] = ELETY(TYOF(lval));
                args[i] = LD(lval);
            }
            
            ret_ty = nb_oargs ? ELETY(TYOF(ARG0L)) : VOIDTY;
            fn_ty = LLVMFunctionType(ret_ty, args_ty, nb_iargs, 0);
            fn = LLVMBuildIntToPtr(BLDR,
                CONSTH(op->args[nb_oargs + nb_iargs]),
                PTRTY(fn_ty), "");

            result = LLVMBuildCall(BLDR, fn, args, nb_iargs, "");
            if (nb_oargs) {
                ST0(result);
            }
            break;
        }

        case INDEX_op_insn_start: break;

        default:
            qemu_log("TODO: %s\n", def->name);
            dump_module(l->mod);
            tcg_abort();
            break;

        // TODO
        case INDEX_op_goto_tb:
            break;
        case INDEX_op_goto_ptr:
            LLVMBuildRet(BLDR, CONST(HBITS, (unsigned long long)tb));
            break;
        case INDEX_op_exit_tb:
            LLVMBuildRet(BLDR, ARG0C);
            break;
#undef BLDR
        }
    }

    //dump_module(l->mod);
    LLVMVerifyFunction(l->fn, LLVMAbortProcessAction);

}

bool tcg_llvm_try_exec_tb(TCGContext *s, TranslationBlock *tb,
    CPUArchState *env, uintptr_t *ret)
{
    TCGLLVMContext *l = s->llvm_ctx;

    uint64_t limit1 = 2000, limit2 = 20000;

    if (!tb->llvm_tc) {
        LLVMOrcThreadSafeModuleRef tsm;
        LLVMOrcJITTargetAddress addr;
        uint64_t tb_count = 0;
        char tb_name[MAX_TB_NAME];
        TranslationBlock *htb, *nhtb;

        tb->exec_count++;
        if (tb->exec_count < limit2) {
            return false;
        }

        
        printf("trigger compile!\n");

        LLVMModuleRef tmp_mod = LLVMCloneModule(l->mod); // XXX

        printf("find hot code!\n");

        QLIST_FOREACH(htb, &l->hot_tb, hot_link) {
            make_tb_name(tb_name, htb);
            if (htb->exec_count < limit1) {
                LLVMDeleteFunction(LLVMGetNamedFunction(tmp_mod, tb_name));
            }
        }

        printf("LLVMRunPassManager bgein!\n");
        LLVMRunPassManager(l->pm, tmp_mod);
        //dump_module(tmp_mod);
        printf("LLVMRunPassManager end!\n");

        tsm = LLVMOrcCreateNewThreadSafeModule(tmp_mod, l->tsctx);
        check_error(LLVMOrcLLJITAddLLVMIRModule(l->jit, l->jd, tsm));


        QLIST_FOREACH_SAFE(htb, &l->hot_tb, hot_link, nhtb) {
            if (htb->exec_count < limit1) {
                continue;
            }
            tb_count++;
            make_tb_name(tb_name, htb);
            QLIST_REMOVE(htb, hot_link);
            LLVMDeleteFunction(LLVMGetNamedFunction(l->mod, tb_name));
            check_error(LLVMOrcLLJITLookup(l->jit, &addr, tb_name));
            printf("%s = %p; %" PRIu64 "\n", tb_name, (void *)addr, htb->exec_count);
            //log_disas((void *)addr, 200);
            htb->llvm_tc = (void *)addr;
        }

        printf("compile done! (%" PRIu64 " compiled)\n", tb_count);
    }
    *ret = ((uintptr_t (*)(void *))tb->llvm_tc)(env);
    return true;
}

void tcg_llvm_init_tb(TCGContext *s, TranslationBlock *tb)
{
    tb->llvm_tc = NULL;
    tb->exec_count = 0;
    QLIST_INSERT_HEAD(&s->llvm_ctx->hot_tb, tb, hot_link);
}
void tcg_llvm_remove_tb(TCGContext *s, TranslationBlock *tb)
{
    printf("tb %p removed!\n", tb);
    QLIST_REMOVE(tb, hot_link);
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
    LLVMAddBasicAliasAnalysisPass(l->pm);
    LLVMAddCFGSimplificationPass(l->pm);
    LLVMAddInstructionCombiningPass(l->pm);
    LLVMAddReassociatePass(l->pm);
    LLVMAddInstructionCombiningPass(l->pm);
    LLVMAddGVNPass(l->pm);
    LLVMAddInstructionCombiningPass(l->pm);
    LLVMAddDeadStoreEliminationPass(l->pm);

#define GET_KINDID(s) LLVMGetEnumAttributeKindForName(s, strlen(s))
    l->noreturn = LLVMCreateEnumAttribute(l->ctx, GET_KINDID("noreturn"), 0);
    l->noalias = LLVMCreateEnumAttribute(l->ctx, GET_KINDID("noalias"), 0);
#undef GET_KINDID


    QLIST_INIT(&l->hot_tb);

    l->tbargs = 0;
    {
        int nargs = l->tbargs + 1;
        LLVMTypeRef args[nargs];
        int i;
        for (i = 0; i < l->tbargs; i++) {
            args[i] = INTTY(GBITS);
        }
        args[l->tbargs] = PTRTY(INTTY(8));
        l->tbtype = LLVMFunctionType(INTTY(HBITS), args, nargs, 0);
    }
}

void tcg_llvm_init(void)
{
    LLVMInitializeNativeTarget();
    LLVMInitializeNativeAsmPrinter();
    LLVMInitializeNativeAsmParser();
}