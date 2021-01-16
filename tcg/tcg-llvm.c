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
#include <llvm-c/Transforms/IPO.h>

#ifdef CONFIG_SOFTMMU
#error LLVM + SOFTMMU Not supported
#endif

#define _CAT(x, y) x ## y
#define CAT(x, y) _CAT(x, y)
#define CAT3(x, y, z) CAT(CAT(x, y), z)


static void serialize(GByteArray *buf, const void *mem, size_t size)
{
    g_byte_array_append(buf, mem, size);
}
static void deserialize(const guint8 **buf, void *mem, size_t size)
{
    memcpy(mem, *buf, size);
    *buf += size;
}

static void serialize_temp(GByteArray *temp_buf, TCGContext *s, TCGTemp *ts)
{
    TCGTempKind kind = ts->kind;
    TCGType type = ts->type;
    int mem_base;
    intptr_t mem_offset;
    int name_id;
    int64_t val;
    serialize(temp_buf, &kind, sizeof(kind));
    serialize(temp_buf, &type, sizeof(type));
    switch (kind) {
    case TEMP_GLOBAL: case TEMP_FIXED:
        mem_base = ts->mem_base ? temp_idx(ts->mem_base) : -1;
        serialize(temp_buf, &mem_base, sizeof(mem_base));
        mem_offset = ts->mem_offset;
        serialize(temp_buf, &mem_offset, sizeof(mem_offset));
        serialize(temp_buf, ts->name, strlen(ts->name) + 1);
        break;
    case TEMP_LOCAL: case TEMP_NORMAL:
        name_id = temp_idx(ts) - s->nb_globals;
        serialize(temp_buf, &name_id, sizeof(name_id));
        break;
    case TEMP_CONST:
        val = ts->val;
        serialize(temp_buf, &val, sizeof(val));
        break;
    }
}
static void deserialize_temp(const guint8 **temp_buf, TCGLLVMTemp *t)
{
    int name_id;
    deserialize(temp_buf, &t->kind, sizeof(t->kind));
    deserialize(temp_buf, &t->type, sizeof(t->type));
    switch (t->kind) {
    case TEMP_GLOBAL: case TEMP_FIXED:
        deserialize(temp_buf, &t->mem_base, sizeof(t->mem_base));
        deserialize(temp_buf, &t->mem_offset, sizeof(t->mem_offset));
        snprintf(t->name, sizeof(t->name), "%s", (char *) *temp_buf);
        *temp_buf += strlen((char *) *temp_buf) + 1;
        break;
    case TEMP_LOCAL: case TEMP_NORMAL:
        deserialize(temp_buf, &name_id, sizeof(name_id));
        snprintf(t->name, sizeof(t->name), "%s%d",
            t->kind == TEMP_LOCAL ? "loc" : "tmp", name_id);
        break;
    case TEMP_CONST:
        deserialize(temp_buf, &t->val, sizeof(t->val));
        break;
    }
}

static bool carg_is_label[NB_OPS][MAX_OPC_PARAM] = {
    [INDEX_op_set_label][0] = true,
    [INDEX_op_br][0] = true,
    [INDEX_op_brcond_i32][1] = true,
    [INDEX_op_brcond_i64][1] = true,
    [INDEX_op_brcond2_i32][1] = true,
};
#define carg_is_helper(opc, carg) ((opc) == INDEX_op_call && (carg) == 0)
#define carg_is_exitcode(opc, carg) ((opc) == INDEX_op_exit_tb && (carg) == 0)
static void serialize_op(GByteArray *op_buf, TCGOp *op, bool *temp_used)
{
    TCGOpcode c = op->opc;
    const TCGOpDef *def = &tcg_op_defs[c];
    int nb_oargs = def->nb_oargs;
    int nb_iargs = def->nb_iargs;
    int nb_cargs = def->nb_cargs;
    int i, j;
    serialize(op_buf, &c, sizeof(c));
    if (c == INDEX_op_call) {
        nb_oargs = TCGOP_CALLO(op);
        nb_iargs = TCGOP_CALLI(op);
        serialize(op_buf, &nb_oargs, sizeof(nb_oargs));
        serialize(op_buf, &nb_iargs, sizeof(nb_iargs));
    }
    for (i = 0; i < nb_oargs + nb_iargs; i++) {
        int idx = temp_idx(arg_temp(op->args[i]));
        serialize(op_buf, &idx, sizeof(idx));
        temp_used[idx] = true;
    }
    for (j = 0; j < nb_cargs; i++, j++) {
        uint64_t carg = op->args[i];
        if (carg_is_label[c][j]) {
            carg = arg_label(op->args[i])->id;
        }
        if (carg_is_helper(c, j)) {
            carg = helper_idx(op->args[i]);
        }
        if (carg_is_exitcode(c, j)) {
            carg = carg & TB_EXIT_MASK;
        }
        serialize(op_buf, &carg, sizeof(carg));
    }
}
static void deserialize_op(const guint8 **op_buf,
    TCGOpcode *c, int *nb_oargs, int *nb_iargs, int *nb_cargs, uint64_t *args)
{
    const TCGOpDef *def;
    int i, j;
    deserialize(op_buf, c, sizeof(*c));
    def = &tcg_op_defs[*c];
    *nb_oargs = def->nb_oargs;
    *nb_iargs = def->nb_iargs;
    *nb_cargs = def->nb_cargs;
    if (*c == INDEX_op_call) {
        deserialize(op_buf, nb_oargs, sizeof(*nb_oargs));
        deserialize(op_buf, nb_iargs, sizeof(*nb_iargs));
    }
    for (i = 0; i < *nb_oargs + *nb_iargs; i++) {
        uint32_t idx;
        deserialize(op_buf, &idx, sizeof(idx));
        args[i] = idx;
    }
    for (j = 0; j < *nb_cargs; i++, j++) {
        deserialize(op_buf, &args[i], sizeof(args[i]));
    }
}

void tcg_llvm_serialize_tb(TCGContext *s, TranslationBlock *tb)
{
    TCGLLVMContext *l = s->llvm_ctx;
    TCGOp *op;
    bool temp_used[TCG_MAX_TEMPS] = {};
    int idx;
    GByteArray *temp_buf = tb->packed_tcg.temp_buf;
    GByteArray *op_buf = tb->packed_tcg.op_buf;

    QTAILQ_FOREACH(op, &s->ops, link) {
        serialize_op(op_buf, op, temp_used);
    }

    for (idx = 0; idx < TCG_MAX_TEMPS; idx++) {
        if (temp_used[idx]) {
            serialize(temp_buf, &idx, sizeof(idx));
            serialize_temp(temp_buf, s, &s->temps[idx]);
        }
    }

    g_checksum_reset(l->hasher);
    g_checksum_update(l->hasher, temp_buf->data, temp_buf->len);
    g_checksum_update(l->hasher, op_buf->data, op_buf->len);
    tb->packed_tcg.digest = g_strdup(g_checksum_get_string(l->hasher));
}




/* LLVM convenient macros */

/* Context */
#define BLDR (l->bldr)
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

/* Alias scope */
#define SCOPE_ENV(v) ({ \
    LLVMValueRef __v = (v); \
    LLVMSetMetadata(__v, l->md_aliasscope, l->env_scope); \
    __v; \
})
#define NOALIAS_ENV(v) ({ \
    LLVMValueRef __v = (v); \
    LLVMSetMetadata(__v, l->md_noalias, l->env_scope); \
    __v; \
})

/* Load and Store */
#undef LD
#undef ST
#define LD(ptr) SCOPE_ENV(LLVMBuildLoad(BLDR, ptr, ""))
#define ST(val, ptr) SCOPE_ENV(LLVMBuildStore(BLDR, val, ptr))
#define SET_VOLATILE(v) ({ \
    LLVMValueRef __v = (v); \
    LLVMSetVolatile(__v, 1); \
    __v; \
})
#define QEMU_LD(ptr) \
    SET_VOLATILE(NOALIAS_ENV(LLVMBuildLoad(BLDR, ptr, "")))
#define QEMU_ST(val, ptr) \
    SET_VOLATILE(NOALIAS_ENV(LLVMBuildStore(BLDR, val, ptr)))

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

/* Convert i8* + offset to pointer, using GEP and bitcast */
#define PI2P(ptr, off, bits, name) ({ \
        LLVMValueRef off_value = (off); \
        LLVMBuildBitCast(BLDR, \
            LLVMBuildInBoundsGEP2(BLDR, \
                INTTY(8), \
                ptr, \
                &off_value, 1, \
                "" \
            ), \
            PTRTY(INTTY(bits)), \
            name \
        ); \
    })

/* Extend or truncate integers */
#define TRUNC(val, dst_bits) LLVMBuildTrunc(BLDR, val, INTTY(dst_bits), "")
#define EXTEND(val, dst_bits, ext_kind) \
    CAT3(LLVMBuild, ext_kind, Ext)(BLDR, val, INTTY(dst_bits), "")
#define ZEXT(val, dst_bits) EXTEND(val, dst_bits, Z)
#define SEXT(val, dst_bits) EXTEND(val, dst_bits, S)
#define TZEXT(val, src_bits, dst_bits) ZEXT(TRUNC(val, src_bits), dst_bits)
#define TSEXT(val, src_bits, dst_bits) SEXT(TRUNC(val, src_bits), dst_bits)


/* Map TCG Condition to LLVM Integer Predicate */
static LLVMIntPredicate map_cond(TCGCond tcg_cond)
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


/* Get basic block of tcg-op arg label */
static LLVMBasicBlockRef get_label(TCGLLVMContext *l, unsigned label_id)
{
    if (!g_hash_table_contains(l->labels, GINT_TO_POINTER(label_id))) {
        char buf[32];
        sprintf(buf, "L%u", label_id);
        g_hash_table_insert(l->labels, GINT_TO_POINTER(label_id), NEWBB(buf));
    }
    return g_hash_table_lookup(l->labels, GINT_TO_POINTER(label_id));
}

/* Finish current block and switch builder to the given block */
static void switch_bb(TCGLLVMContext *l, LLVMBasicBlockRef next_bb)
{
    if (!LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(l->bldr))) {
        LLVMBuildBr(l->bldr, next_bb);
    }
    LLVMPositionBuilderAtEnd(l->bldr, next_bb);
}



#define MAX_SYMNAME 128
static void make_helper_symbol(char *symname, int idx)
{
    snprintf(symname, MAX_SYMNAME, "helper_%d", idx);
}

static LLVMValueRef get_helper(TCGLLVMContext *l, int idx)
{
    LLVMValueRef g;
    char symname[MAX_SYMNAME];
    make_helper_symbol(symname, idx);
    g = LLVMGetNamedGlobal(l->mod, symname);
    if (!g) {
        g = LLVMAddGlobal(l->mod, INTTY(8), symname);
        LLVMSetLinkage(g, LLVMExternalLinkage);
    }
    return g;
}


static void make_tb_symbol(char *symname, const char *t, target_ulong pc)
{
    snprintf(symname, MAX_SYMNAME, "%s_%016" PRIx64, t, (uint64_t) pc);
}
static LLVMValueRef get_tb_stub(TCGLLVMContext *l, target_ulong pc)
{
    LLVMValueRef g;
    char symname[MAX_SYMNAME];
    make_tb_symbol(symname, "stub", pc);
    g = LLVMGetNamedGlobal(l->mod, symname);
    if (!g) {
        g = LLVMAddGlobal(l->mod, PTRTY(l->tb_type), symname);
        LLVMSetInitializer(g, LLVMConstPointerNull(PTRTY(l->tb_type)));
        LLVMSetLinkage(g, LLVMWeakAnyLinkage);
    }
    return g;
}
static LLVMValueRef get_tb_func(TCGLLVMContext *l, target_ulong pc)
{
    LLVMValueRef fn;
    char symname[MAX_SYMNAME];
    make_tb_symbol(symname, "tb", pc);
    fn = LLVMGetNamedFunction(l->mod, symname);
    if (!fn) {
        fn = LLVMAddFunction(l->mod, symname, l->tb_type);
        LLVMSetFunctionCallConv(fn, l->tb_callconv);
        LLVMAddAttributeAtIndex(fn, l->nb_fastreg + 1, l->attr_noalias);
        LLVMAddAttributeAtIndex(fn, l->nb_fastreg + 1, l->attr_qemuenv);
    }
    return fn;
}
static LLVMValueRef get_epilogue(TCGLLVMContext *l)
{
    LLVMValueRef fn;
    fn = LLVMGetNamedFunction(l->mod, "epilogue");
    if (!fn) {
        fn = LLVMAddFunction(l->mod, "epilogue", l->epilogue_ty);
        LLVMSetFunctionCallConv(fn, l->tb_callconv);
        LLVMAddAttributeAtIndex(fn, l->nb_fastreg + 1, l->attr_noalias);
        LLVMAddAttributeAtIndex(fn, l->nb_fastreg + 1, l->attr_qemuenv);
    }
    return fn;
}

static void init_fastreg(TCGLLVMContext *l, bool use_arg)
{
    unsigned i;
    LLVMValueRef envreg, *fastreg;
    for (i = 0; i < sizeof(CPUArchState); i += GBITS / 8) {
        int fr = l->regmap[i];
        if (fr < 0) continue;
        fastreg = &l->fastreg[fr];
        envreg = PI2P(l->env, CONSTH(i), GBITS, "");
        *fastreg = ALLOCA(GBITS, "");
        if (use_arg) {
            ST(LLVMGetParam(l->fn, fr), *fastreg);
        } else {
            ST(LD(envreg), *fastreg);
        }
    }
}
static void sync_fastreg(TCGLLVMContext *l, bool to_env)
{
    unsigned i;
    LLVMValueRef envreg, *fastreg;
    for (i = 0; i < sizeof(CPUArchState); i += GBITS / 8) {
        int fr = l->regmap[i];
        if (fr < 0) continue;
        fastreg = &l->fastreg[fr];
        envreg = PI2P(l->env, CONSTH(i), GBITS, "");
        if (to_env) {
            ST(LD(*fastreg), envreg);
            ST(LLVMGetUndef(ELETY(TYOF(*fastreg))), *fastreg);
        } else {
            ST(LD(envreg), *fastreg);
            ST(LLVMGetUndef(ELETY(TYOF(envreg))), envreg);
        }
    }
}

static void gen_code(TCGLLVMContext *l, TranslationBlock *tb)
{
    LLVMBasicBlockRef bb;
    LLVMValueRef stub;
    const guint8 *buf, *buf_end;

    memset(l->temps, 0, sizeof(l->temps));
    g_hash_table_remove_all(l->labels);

    l->fn = get_tb_func(l, tb->pc);
    stub = get_tb_stub(l, tb->pc); // FIXME
    LLVMSetInitializer(stub, l->fn);
    //LLVMSetGlobalConstant(stub, 1);
    //LLVMSetLinkage(stub, LLVMWeakAnyLinkage);

    l->env = LLVMGetParam(l->fn, l->nb_fastreg);
    bb = LLVMAppendBasicBlockInContext(l->ctx, l->fn, "entry");
    LLVMPositionBuilderAtEnd(l->bldr, bb);

    init_fastreg(l, true);

#define is_env(idx) (strcmp(l->temps[idx].name, "env") == 0)
    buf = tb->packed_tcg.temp_buf->data;
    buf_end = buf + tb->packed_tcg.temp_buf->len;
    while (buf < buf_end) {
        int idx;
        TCGLLVMTemp *t;
        deserialize(&buf, &idx, sizeof(idx));
        t = &l->temps[idx];
        deserialize_temp(&buf, t);

        switch (t->kind) {
        case TEMP_FIXED:
        case TEMP_GLOBAL:
            /* Assign initial value */
            if (is_env(idx)) {
                t->solt = ALLOCAH(t->name);
                /* env is a function argument */
                ST(P2I(l->env), t->solt);
            } else {
                if (!is_env(t->mem_base)) {
                    tcg_abort();
                }
                LLVMValueRef off;
                if (l->regmap[t->mem_offset] < 0) {
                    off = CONSTH(t->mem_offset);
                    switch (t->type) {
                    case TCG_TYPE_I32:
                        t->solt = PI2P(l->env, off, 32, t->name); break;
                    case TCG_TYPE_I64:
                        t->solt = PI2P(l->env, off, 64, t->name); break;
                    default: tcg_abort();
                    }
                } else {
                    t->solt = l->fastreg[l->regmap[t->mem_offset]];
                    if (t->type == TCG_TYPE_I32 && GBITS != 32) tcg_abort();
                    if (t->type == TCG_TYPE_I64 && GBITS != 64) tcg_abort();
                }
            }
            break;
        case TEMP_LOCAL:
        case TEMP_NORMAL:
            switch (t->type) {
            case TCG_TYPE_I32:
                t->solt = ALLOCA(32, t->name); break;
            case TCG_TYPE_I64:
                t->solt = ALLOCA(64, t->name); break;
            default: tcg_abort();
            }
            break;
        case TEMP_CONST:
            switch (t->type) {
            case TCG_TYPE_I32:
                ST(CONST(32, t->val), (t->solt = ALLOCA(32, ""))); break;
            case TCG_TYPE_I64:
                ST(CONST(64, t->val), (t->solt = ALLOCA(64, ""))); break;
            default: tcg_abort();
            }
            break;
        }
        qemu_log("%x:%p\n", idx, t->solt);
    }

    buf = tb->packed_tcg.op_buf->data;
    buf_end = buf + tb->packed_tcg.op_buf->len;
    while (buf < buf_end) {
        TCGOpcode c;
        const TCGOpDef *def;
        int nb_oargs, nb_iargs, nb_cargs;
        uint64_t op_args[MAX_OPC_PARAM] = {};
        deserialize_op(&buf, &c, &nb_oargs, &nb_iargs, &nb_cargs, op_args);
        def = &tcg_op_defs[c];
        qemu_log(">>%s\n", def->name);

        switch (c) {

/* op args */
#define ARG0 op_args[0]
#define ARG1 op_args[1]
#define ARG2 op_args[2]
#define ARG3 op_args[3]
#define ARG4 op_args[4]
#define ARG5 op_args[5]
/* L-value of op args */
#define ARG0L  l->temps[ARG0].solt
#define ARG1L  l->temps[ARG1].solt
#define ARG2L  l->temps[ARG2].solt
#define ARG3L  l->temps[ARG3].solt
#define ARG4L  l->temps[ARG4].solt
#define ARG5L  l->temps[ARG5].solt
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
do { \
    tcg_debug_assert(is_env(ARG1)); \
    ST0(EXTEND(LD(PI2P(l->env, ARG2C, src_bits, "")), dst_bits, ext_kind)); \
} while (0)
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
do { \
    tcg_debug_assert(is_env(ARG1)); \
    ST(TRUNC(ARG0R, bits), PI2P(l->env, ARG2C, bits, "")); \
} while (0)
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
#if HBITS == 64
        case INDEX_op_mov_i64:  ST0(ARG1R); break;
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
    ST0(EXTEND(QEMU_LD(I2P(ARG1R, src_bits)), dst_bits, ext_kind))
#define OP_QEMU_LD(bits) \
do { \
    tcg_debug_assert(guest_base == 0); \
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
    QEMU_ST(TRUNC(ARG0R, bits), I2P(ARG1R, bits))
        case INDEX_op_qemu_st_i32:
#if HBITS == 64
        case INDEX_op_qemu_st_i64:
#endif
            tcg_debug_assert(guest_base == 0);
            switch (get_memop(ARG2) & (MO_BSWAP | MO_SSIZE)) {
            case MO_UB:   OP_QEMU_ST_HELPER( 8); break;
            case MO_LEUW: OP_QEMU_ST_HELPER(16); break;
            case MO_LEUL: OP_QEMU_ST_HELPER(32); break;
            case MO_LEQ:  OP_QEMU_ST_HELPER(64); break;
            default: tcg_abort();
            }
            break;

        case INDEX_op_call: {
            int i;
            LLVMTypeRef ret_ty;
            LLVMTypeRef args_ty[MAX_OPC_PARAM_IARGS];
            LLVMTypeRef fn_ty;
            LLVMValueRef args[MAX_OPC_PARAM_IARGS];
            LLVMValueRef fn, result;

            if (nb_oargs > 1) {
                tcg_abort(); /* TODO */
            }
            
            for (i = 0; i < nb_iargs; i++) {
                LLVMValueRef lval = l->temps[op_args[nb_oargs + i]].solt;
                args_ty[i] = ELETY(TYOF(lval));
                args[i] = LD(lval);
            }
            
            ret_ty = nb_oargs ? ELETY(TYOF(ARG0L)) : VOIDTY;
            fn_ty = LLVMFunctionType(ret_ty, args_ty, nb_iargs, 0);
            fn = LLVMBuildBitCast(BLDR,
                get_helper(l, op_args[nb_oargs + nb_iargs]),
                PTRTY(fn_ty), "");

            sync_fastreg(l, true);
            result = LLVMBuildCall(BLDR, fn, args, nb_iargs, "");
            if (nb_oargs) {
                ST0(result);
            }
            sync_fastreg(l, false);
            break;
        }

        case INDEX_op_insn_start: break;

        case INDEX_op_goto_tb: {
            target_ulong next_pc = ARG1;
            LLVMBasicBlockRef bb_exist = NEWBB("");
            LLVMBasicBlockRef bb_notexist = NEWBB("");
            LLVMValueRef args[l->nb_fastreg + 1];
            LLVMValueRef next_tb;
            LLVMValueRef exist_flag;
            LLVMValueRef result;
            LLVMValueRef br_instr;
            int i;

            next_tb = LD(get_tb_stub(l, next_pc));
            exist_flag = LLVMBuildICmp(BLDR, LLVMIntNE,
                next_tb, LLVMConstPointerNull(TYOF(next_tb)), "");
            br_instr = CONDBR(exist_flag, bb_exist, bb_notexist);
            LLVMSetMetadata(br_instr, l->md_prof, l->prof_likely);

            switch_bb(l, bb_exist);
            for (i = 0; i < l->nb_fastreg; i++) {
                args[i] = LD(l->fastreg[i]);
            }
            args[l->nb_fastreg] = l->env;
            result = LLVMBuildCall(BLDR, next_tb, args, l->nb_fastreg + 1, "");
            LLVMSetInstructionCallConv(result, l->tb_callconv);
            LLVMBuildRet(BLDR, result);

            switch_bb(l, bb_notexist);
            break;
        }
        case INDEX_op_goto_ptr:
        case INDEX_op_exit_tb: {
            int i;
            LLVMValueRef args[l->nb_fastreg + 2];
            LLVMValueRef result;
            for (i = 0; i < l->nb_fastreg; i++) {
                args[i] = LD(l->fastreg[i]);
            }
            args[l->nb_fastreg] = l->env;
            args[l->nb_fastreg + 1] = c == INDEX_op_exit_tb ? ARG0C : CONSTH(0);
            result = LLVMBuildCall(BLDR,
                get_epilogue(l), args, l->nb_fastreg + 2, "");
            LLVMSetInstructionCallConv(result, l->tb_callconv);
            LLVMBuildRet(BLDR, result);
            break;
        }
        default:
            qemu_log("TODO: %s\n", def->name);
            /*dump_module(l->mod);*/
            tcg_abort();
            break;
        }
    }

    //dump_module(l->mod);
    LLVMVerifyFunction(l->fn, LLVMAbortProcessAction);

}

static void batch_compile(TCGLLVMContext *l)
{
    TranslationBlock *tb;
    LLVMOrcThreadSafeModuleRef tsm;
    LLVMOrcJITTargetAddress func_addr, stub_addr;
    char symname[MAX_SYMNAME];
    unsigned long i;

    qemu_log("batch compile!\n");
    l->mod = LLVMModuleCreateWithNameInContext("jit", l->ctx);

    for (i = 0; i < l->hot_tb->len; i++) {
        tb = g_ptr_array_index(l->hot_tb, i);
        gen_code(l, tb);
    }

    qemu_log("LLVMRunPassManager bgein!\n");
    LLVMRunPassManager(l->mpm, l->mod);
    dump_module(l->mod);
    qemu_log("LLVMRunPassManager end!\n");

    tsm = LLVMOrcCreateNewThreadSafeModule(l->mod, l->tsctx);
    check_error(LLVMOrcLLJITAddLLVMIRModule(l->jit, l->jd, tsm));


    for (i = 0; i < l->hot_tb->len; i++) {
        tb = g_ptr_array_index(l->hot_tb, i);

        make_tb_symbol(symname, "stub", tb->pc);
        check_error(LLVMOrcLLJITLookup(l->jit, &stub_addr, symname));
        make_tb_symbol(symname, "tb", tb->pc);
        check_error(LLVMOrcLLJITLookup(l->jit, &func_addr, symname));

        tb->llvm_tc = (void *)func_addr;
        *(void **)stub_addr = (void *)func_addr;

        qemu_log("%s = %p; %" PRIu64 "; %s\n", symname, tb->llvm_tc, tb->exec_count, tb->packed_tcg.digest);
        /*unsigned char *ptr = tb->packed_tcg.op_buf->data;
        int len = tb->packed_tcg.op_buf->len;
        for (int p = 0; p < len; p++) {
            if (p % 16 == 0) {
                if (p) qemu_log("\n");
                qemu_log("%04x: ", p);
            }
            qemu_log("%02x ", ptr[p]);
        }
        qemu_log("\n");*/
    }

    qemu_log("compile done! (%u compiled)\n", l->hot_tb->len);
    g_ptr_array_set_size(l->hot_tb, 0);
}

bool tcg_llvm_try_exec_tb(TCGContext *s, TranslationBlock *tb,
    CPUArchState *env, uintptr_t *ret)
{
    TCGLLVMContext *l = s->llvm_ctx;
    if (!tb->llvm_tc) {
        if (tb->exec_count == l->hot_limit1) {
            g_ptr_array_add(l->hot_tb, tb);
        }
        if (tb->exec_count < l->hot_limit2) {
            tb->exec_count++;
            return false;
        }
        batch_compile(l);
    }
    //qemu_log("llvm exec! begin\n");
    *ret = l->prologue(tb->llvm_tc, env);
    //qemu_log("llvm exec! done; ret=%p\n", (void *)*ret);
    return true;
}

void tcg_llvm_init_tb(TCGContext *s, TranslationBlock *tb)
{
    tb->llvm_tc = NULL;
    tb->exec_count = 0;
    tb->packed_tcg.temp_buf = g_byte_array_new();
    tb->packed_tcg.op_buf = g_byte_array_new();
    tb->packed_tcg.digest = NULL;
}
void tcg_llvm_remove_tb(TCGContext *s, TranslationBlock *tb)
{
    qemu_log("tb %p removed!\n", tb);
    /* TODO: free tb->llvm_tc */
    g_byte_array_free(tb->packed_tcg.temp_buf, TRUE);
    g_byte_array_free(tb->packed_tcg.op_buf, TRUE);
    g_free(tb->packed_tcg.digest);
}

void tcg_llvm_register_helper(TCGContext *s, int idx, void *func)
{
    TCGLLVMContext *l = s->llvm_ctx;
    LLVMJITCSymbolMapPair *sympair;
    char symname[MAX_SYMNAME];
    make_helper_symbol(symname, idx);
    if (idx >= l->helpers->len) {
        g_array_set_size(l->helpers, idx + 1);
    }

    sympair = &g_array_index(l->helpers, LLVMJITCSymbolMapPair, idx);
    sympair->Name = LLVMOrcExecutionSessionIntern(l->es, symname);
    sympair->Sym.Address = (LLVMOrcJITTargetAddress) func;
}
void tcg_llvm_register_helper_done(TCGContext *s)
{
    TCGLLVMContext *l = s->llvm_ctx;
    check_error(LLVMOrcJITDylibDefine(l->jd,
        LLVMOrcAbsoluteSymbols((void *) l->helpers->data, l->helpers->len)));
}

static void init_prologue(TCGLLVMContext *l)
{
    int i;
    LLVMTypeRef prologue_argty[2] = {PTRTY(INTTY(8)), PTRTY(INTTY(8))};
    LLVMValueRef prologue_argvl[l->nb_fastreg + 1];
    LLVMValueRef prologue_call;
    LLVMTypeRef epilogue_argty[l->nb_fastreg + 2];
    LLVMOrcThreadSafeModuleRef tsm;
    LLVMOrcJITTargetAddress addr;

    l->mod = LLVMModuleCreateWithNameInContext("prologue", l->ctx);

    l->fn = LLVMAddFunction(l->mod, "prologue", 
        LLVMFunctionType(INTTY(HBITS), prologue_argty, 2, 0));
    LLVMPositionBuilderAtEnd(l->bldr, 
        LLVMAppendBasicBlockInContext(l->ctx, l->fn, "entry"));
    l->env = LLVMGetParam(l->fn, 1);
    init_fastreg(l, false);
    for (i = 0; i < l->nb_fastreg; i++) {
        prologue_argvl[i] = LD(l->fastreg[i]);
    }
    prologue_argvl[l->nb_fastreg] = l->env;
    prologue_call = LLVMBuildCall(l->bldr,
        LLVMBuildBitCast(l->bldr,
            LLVMGetParam(l->fn, 0),
            LLVMPointerType(l->tb_type, 0), ""),
        prologue_argvl, l->nb_fastreg + 1, "");
    LLVMSetInstructionCallConv(prologue_call, l->tb_callconv);
    LLVMBuildRet(l->bldr, prologue_call);
    LLVMVerifyFunction(l->fn, LLVMAbortProcessAction);

    for (i = 0; i < l->nb_fastreg; i++) {
        epilogue_argty[i] = INTTY(GBITS);
    }
    epilogue_argty[l->nb_fastreg] = PTRTY(INTTY(8)); /* env */
    epilogue_argty[l->nb_fastreg + 1] = INTTY(HBITS); /* ret code */
    l->epilogue_ty = LLVMFunctionType(
        INTTY(HBITS), epilogue_argty, l->nb_fastreg + 2, 0);
    l->fn = get_epilogue(l);
    LLVMPositionBuilderAtEnd(l->bldr,
        LLVMAppendBasicBlockInContext(l->ctx, l->fn, "entry"));
    l->env = LLVMGetParam(l->fn, l->nb_fastreg);
    init_fastreg(l, true);
    sync_fastreg(l, true);
    LLVMBuildRet(l->bldr, LLVMGetParam(l->fn, l->nb_fastreg + 1));
    LLVMVerifyFunction(l->fn, LLVMAbortProcessAction);

    LLVMRunPassManager(l->mpm, l->mod);
    dump_module(l->mod);
    tsm = LLVMOrcCreateNewThreadSafeModule(l->mod, l->tsctx);
    check_error(LLVMOrcLLJITAddLLVMIRModule(l->jit, l->jd, tsm));

    check_error(LLVMOrcLLJITLookup(l->jit, &addr, "prologue"));
    l->prologue = (void *)addr;
    log_disas((void *)addr, 50);
    check_error(LLVMOrcLLJITLookup(l->jit, &addr, "epilogue"));
    l->epilogue = (void *)addr;
    log_disas((void *)addr, 50);
}

static LLVMOrcObjectLayerRef create_oll_with_jitperf(
    void *ctx, LLVMOrcExecutionSessionRef es, const char *triple)
{
    /*TCGLLVMContext *l = Ctx;*/
    LLVMOrcObjectLayerRef ol;
    LLVMJITEventListenerRef perf;
    ol = LLVMOrcCreateRTDyldObjectLinkingLayerWithSectionMemoryManager(es);
    perf = LLVMCreatePerfJITEventListener();
    if (!perf) {
        tcg_abort(); /* LLVM need to be compiled with LLVM_USE_PERF=On */
    }
    LLVMOrcRTDyldObjectLinkingLayerRegisterJITEventListener(ol, perf);
    return ol;
}

void tcg_llvm_context_init(TCGContext *s)
{
    int i;
    LLVMOrcLLJITBuilderRef jb = NULL;
    LLVMMetadataRef adomain, ascope;
    LLVMTypeRef *tb_args;
    TCGLLVMContext *l = g_malloc0(sizeof(*l));
    s->llvm_ctx = l;
    
    if (1) { /* use jit perf */
        jb = LLVMOrcCreateLLJITBuilder();
        LLVMOrcLLJITBuilderSetObjectLinkingLayerCreator(jb, 
            create_oll_with_jitperf, l);
    }

    check_error(LLVMOrcCreateLLJIT(&l->jit, jb));
    l->tsctx = LLVMOrcCreateNewThreadSafeContext();
    l->ctx = LLVMOrcThreadSafeContextGetContext(l->tsctx);
    l->bldr = LLVMCreateBuilderInContext(l->ctx);
    l->jd = LLVMOrcLLJITGetMainJITDylib(l->jit);
    l->es = LLVMOrcLLJITGetExecutionSession(l->jit);

    l->pmb = LLVMPassManagerBuilderCreate();
    l->mpm = LLVMCreatePassManager();
    LLVMPassManagerBuilderSetOptLevel(l->pmb, 2);
    LLVMPassManagerBuilderUseInlinerWithThreshold(l->pmb, 100000);
    LLVMPassManagerBuilderPopulateModulePassManager(l->pmb, l->mpm);

#define ATTR_KINDID(s) LLVMGetEnumAttributeKindForName(s, strlen(s))
    l->attr_noalias = LLVMCreateEnumAttribute(l->ctx,
        ATTR_KINDID("noalias"), 0);
    l->attr_qemuenv = LLVMCreateEnumAttribute(l->ctx,
        ATTR_KINDID("dereferenceable"), sizeof(CPUArchState));
    
#define MD_KINDID(s) LLVMGetMDKindIDInContext(l->ctx, s, strlen(s))
    l->md_aliasscope = MD_KINDID("alias.scope");
    l->md_noalias = MD_KINDID("noalias");
    l->md_prof = MD_KINDID("prof");

#define MD_STRING(s) LLVMMDStringInContext2(l->ctx, s, strlen(s))
#define MD_NODE(...) ({ \
    LLVMMetadataRef __args[] = {__VA_ARGS__}; \
    LLVMMDNodeInContext2(l->ctx, __args, ARRAY_SIZE(__args)); \
})
#define MD2VAL(md) LLVMMetadataAsValue(l->ctx, md)
#define VAL2MD(val) LLVMValueAsMetadata(val)
    adomain = MD_NODE(MD_STRING("qemu_domain"));
    ascope = MD_NODE(MD_STRING("env_scope"), adomain);
    l->env_scope = MD2VAL(MD_NODE(ascope));
    l->prof_likely = MD2VAL(MD_NODE(MD_STRING("branch_weights"),
        VAL2MD(CONST(32, 2000)), VAL2MD(CONST(32, 1))));

    l->hasher = g_checksum_new(G_CHECKSUM_SHA256);
    l->labels = g_hash_table_new(NULL, NULL);

    l->hot_tb = g_ptr_array_new();
    l->hot_limit1 = 2000;
    l->hot_limit2 = 20000;

    l->tb_callconv = 10; /* GHC-CC */
    l->nb_fastreg = 8;

    l->regmap = g_malloc(sizeof(CPUArchState));
    memset(l->regmap, -1, sizeof(CPUArchState));
    l->fastreg = g_malloc_n(l->nb_fastreg, sizeof(LLVMValueRef));
    for (i = 0; i < l->nb_fastreg; i++) {
        l->regmap[i * (GBITS / 8)] = i;
    }
    tb_args = alloca((l->nb_fastreg + 1) * sizeof(LLVMTypeRef));
    for (i = 0; i < l->nb_fastreg; i++) {
        tb_args[i] = INTTY(GBITS);
    }
    tb_args[l->nb_fastreg] = PTRTY(INTTY(8));
    l->tb_type = LLVMFunctionType(INTTY(HBITS), tb_args, l->nb_fastreg + 1, 0);

    l->helpers = g_array_new(FALSE, TRUE, sizeof(LLVMJITCSymbolMapPair));

    init_prologue(l);
}

void tcg_llvm_init(void)
{
    LLVMInitializeNativeTarget();
    LLVMInitializeNativeAsmPrinter();
    LLVMInitializeNativeAsmParser();
}