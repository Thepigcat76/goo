#include "../../include/compiler.h"
#include "lilc/eq.h"
#include "lilc/hash.h"
#include "lilc/log.h"
#include <lilc/alloc.h>
#include <lilc/hashmap.h>
#include <threads.h>

#define STACK_OBJ(_offset, _size)                                              \
  (StackObject) { .offset = _offset, .size = _size }

#define REG_EIP 0

#define RELOCATIONS_ADD(compiler_ptr, ...)                                     \
  do {                                                                         \
    Relocation _internal_reloc = __VA_ARGS__;                                  \
    _internal_reloc.program_offset = compiler_ptr->program_size;               \
    array_add(compiler_ptr->relocations, _internal_reloc);                     \
  } while (0)

static size_t type_sizeof(Compiler *compiler, const Type *type) {
  switch (type->kind) {
  case TYPE_IDENT: {
    ModulePath mod_path = type->var.type_ident;
    if (strv_eq(mod_path.path[0], "i8")) {
      return 1;
    } else if (strv_eq(mod_path.path[0], "i16")) {
      return 2;
    } else if (strv_eq(mod_path.path[0], "i32")) {
      return 4;
    } else if (strv_eq(mod_path.path[0], "i64")) {
      return 8;
    }
    return 0;
  } break;
  case TYPE_ARRAY: {
    TypeArray type_arr = type->var.type_array;
    size_t arr_type_size = type_sizeof(compiler, type_arr.type);
    switch (type_arr.variant) {
    case TYPE_ARRAY_VARIANT_SIZED: {
      return arr_type_size * type_arr.size;
    } break;
    case TYPE_ARRAY_VARIANT_SIZE_UNKNOWN: {
      panic("NYI Unknown size array compilation");
    } break;
    case TYPE_ARRAY_VARIANT_DYNAMIC: {
      panic("NYI Dynamic array compilation");
    } break;
    }
  } break;
  case TYPE_UNIT: {
    return 0;
  } break;
  case TYPE_POINTER: {
    return POINTER_SIZE;
  } break;
  case TYPE_FUNCTION:
  case TYPE_TUPLE:
  case TYPE_STRUCT: {
    panic("NYI Function, Tuple, Struct size");
  } break;
  }
}

static size_t data_section_add(DataSection *section, Ident *key,
                               const uint8_t *data_bytes, size_t data_len) {
  if (section->data_len + data_len >= section->data_capacity) {
    section->data_bytes =
        realloc(section->data_bytes, section->data_capacity *= 2);
  }
  memcpy(section->data_bytes + section->data_len, data_bytes, data_len);
  size_t offset = section->data_len;
  if (key != NULL)
    hashmap_insert(&section->section_lookup, key, &offset);
  section->data_len += data_len;
  return offset;
}

static inline void insns_add(Compiler *compiler, Instruction ins) {
  array_add(compiler->insns, ins);
  size_t len = ins_gen(&ins, NULL);
  compiler->program_size += len;
}

static void stmt_compile(Compiler *compiler, const Statement *stmt);

static inline void stack_frame_push(Compiler *compiler) {
  Instruction ins = INS_PUSH_R32(REG_EBP);
  insns_add(compiler, ins);
}

static inline void stack_frame_reset(Compiler *compiler) {
  Instruction ins = INS_MOV_R64_R64(REG_ESP, REG_EBP);
  insns_add(compiler, ins);
}

static inline void stack_frame_pop(Compiler *compiler) {
  Instruction ins = INS_POP_R32(REG_EBP);
  insns_add(compiler, ins);
}

static inline void insns_add_return(Compiler *compiler) {
  insns_add(compiler, INS_RET);
}

#define INSN(_opcode, ...)                                                     \
  (Instruction) {                                                              \
    .opcode = _opcode, .args = { __VA_ARGS__ }                                 \
  }

static size_t
expr_string_lit_compile(Compiler *compiler,
                        const ExprStringLiteral *expr_string_lit) {
  size_t offset = data_section_add(&compiler->rodata_section, NULL,
                                   (uint8_t *)expr_string_lit->string,
                                   strlen(expr_string_lit->string) + 1);
  return offset;
}

typedef enum {
  COMPARISON_EQ,
  COMPARISON_LT,
  COMPARISON_GT,
  COMPARISON_LTE,
  COMPARISON_GTE,
} ComparisonKind;

typedef struct {
  DataType data_type;
  size_t offset;
  bool read_only;
} DataOffset;

typedef struct {
  enum {
    EXPR_COMPILE_RES_DATA_OFFSET,
    EXPR_COMPILE_RES_IMM32,
    EXPR_COMPILE_RES_STACK_OBJ,
    EXPR_COMPILE_RES_REG,
    EXPR_COMPILE_RES_COMPARISON,
  } kind;
  union {
    DataOffset data_offset;
    u32 imm32;
    StackObject stack_obj;
    Register reg;
    ComparisonKind cmp_kind;
  } var;
  size_t size;
} ExprCompileResult;

#define EXPR_COMPILE_RES(_kind, _size, ...)                                    \
  (ExprCompileResult) { .kind = _kind, .var = {__VA_ARGS__}, .size = _size }

#define EXPR_COMPILE_CTX(...)                                                  \
  (ExprCompileContext) { __VA_ARGS__ }

#define EXPR_COMPILE_CTX_EMPTY (ExprCompileContext){0}

static void compiler_arg_push(Compiler *compiler, size_t arg_idx,
                              const ExprCompileResult *res);

static ExprCompileResult expr_compile_with_res(Compiler *compiler,
                                               const Expression *expr,
                                               ExprCompileContext ctx,
                                               Register bin_op_res_reg);

static ExprCompileResult expr_compile(Compiler *compiler,
                                      const Expression *expr,
                                      ExprCompileContext ctx) {
  return expr_compile_with_res(compiler, expr, ctx, -1);
}

static ExprCompileResult expr_call_compile(Compiler *compiler,
                                           const ExprCall *expr_call) {
  for (size_t i = 0; i < array_len(expr_call->args); i++) {
    Expression arg = expr_call->args[i];
    ExprCompileResult res =
        expr_compile(compiler, &arg, EXPR_COMPILE_CTX_EMPTY);
    compiler_arg_push(compiler, i, &res);
  }

  Ident *mangled_function_name =
      hashmap_value(&compiler->mangled_functions, &expr_call->function);

  if (mangled_function_name != NULL) {
    RELOCATIONS_ADD(compiler,
                    {.sec = SECTION_TYPE_TEXT,
                     .r_offset = 1,
                     .symbol = strv_eq(expr_call->function.path[0], "println")
                                   ? "puts"
                                   : *mangled_function_name});
  } else {
    RELOCATIONS_ADD(compiler,
                    {.sec = SECTION_TYPE_TEXT,
                     .r_offset = 1,
                     .symbol = strv_eq(expr_call->function.path[0], "println")
                                   ? "puts"
                                   : expr_call->function.path[0]});
  }

  insns_add(compiler, INS_CALL);

  if (strv_eq(expr_call->function.path[0], "IsKeyDown")) {
    insns_add(compiler, INS_MOV_R8_R32(REG_EAX, REG_EAX));
  }

  TypeTableValue *func_val =
      hashmap_value(&compiler->type_tables[0].type_table, &expr_call->function);

  Type ret_type = UNIT_BUILTIN_TYPE;
  if (func_val != NULL && func_val->expr_variant.kind == EXPR_VAR_REG_EXPR) {
    Expression func_reg_expr = func_val->expr_variant.var.expr_var_reg_expr;
    if (func_reg_expr.kind == EXPR_FUNCTION) {
      ExprFunction expr_func = func_reg_expr.var.expr_function;
      if (expr_func.desc.has_ret_type) {
        ret_type = expr_func.desc.ret_type;
      }
    }
  }

  size_t ret_type_size = type_sizeof(compiler, &ret_type);

  return EXPR_COMPILE_RES(EXPR_COMPILE_RES_REG, ret_type_size, .reg = REG_EAX);
}

static void compiler_stack_alloc_imm32(Compiler *compiler, Ident *name,
                                       uint32_t imm32) {
  compiler->cur_frame.sp_offset += sizeof(int32_t);
  hashmap_insert(&compiler->cur_frame.symbol_table, name,
                 &STACK_OBJ(compiler->cur_frame.sp_offset, sizeof(uint32_t)));
  insns_add(compiler,
            INS_MOV_I32_R32_DISP8(REG_EBP, compiler->cur_frame.sp_offset,
                                  IMM32_PACK(imm32)));
}

static void compiler_stack_alloc_imm64(Compiler *compiler, Ident *name,
                                       uint32_t imm32) {
  compiler->cur_frame.sp_offset += sizeof(int32_t);
  hashmap_insert(&compiler->cur_frame.symbol_table, name,
                 &STACK_OBJ(compiler->cur_frame.sp_offset, sizeof(uint32_t)));
  insns_add(compiler,
            INS_MOV_I64_R64_DISP8(REG_EBP, compiler->cur_frame.sp_offset,
                                  IMM32_PACK(imm32)));
}

static void compiler_stack_alloc_expr_res(Compiler *compiler,
                                          ExprCompileResult expr_res,
                                          size_t sp_offset) {
  compiler->cur_frame.sp_offset = sp_offset;
  switch (expr_res.kind) {
  case EXPR_COMPILE_RES_DATA_OFFSET: {
  } break;
  case EXPR_COMPILE_RES_IMM32: {
    insns_add(compiler,
              INS_MOV_I32_R32_DISP8(REG_EBP, compiler->cur_frame.sp_offset,
                                    IMM32_PACK(expr_res.var.imm32)));
  } break;
  case EXPR_COMPILE_RES_STACK_OBJ: {
  } break;
  case EXPR_COMPILE_RES_REG: {
  } break;
  case EXPR_COMPILE_RES_COMPARISON: {
  } break;
  }
}

static void compiler_stack_alloc_reg(Compiler *compiler, Ident *name,
                                     Register reg) {
  compiler->cur_frame.sp_offset += 8;
  hashmap_insert(&compiler->cur_frame.symbol_table, name,
                 &STACK_OBJ(compiler->cur_frame.sp_offset, sizeof(uint64_t)));
  insns_add(compiler,
            INS_MOV_R64_R64_DISP8(
                reg, REG_EBP, IMM32_PACK(256 - compiler->cur_frame.sp_offset)));
}

// Returns whether there is a reg for this arg
static bool reg_for_arg(Register *reg, size_t arg_idx) {
  switch (arg_idx) {
  case 0:
    *reg = REG_EDI;
    return true;
  case 1:
    *reg = REG_ESI;
    return true;
  case 2:
    *reg = REG_EDX;
    return true;
  case 3:
    *reg = REG_ECX;
    return true;
  }
  return false;
}

#define ALIGN_BY(val, align_factor) ((val + align_factor - 1) & (-align_factor))

static void stack_fix_sub_stack_size(Instruction *insns, size_t index,
                                     size_t stack_size) {
  insns[index].imm[0] = stack_size;
}

static void expr_func_compile(Compiler *compiler, const ExprFunction *expr_func,
                              CompileContext context) {
  if (debug_flags.print_compile_info) {
    log_info("[COMPILER] Pushed new stack frame");
  }
  compiler->cur_frame =
      (Frame){.sp_offset = 0,
              .symbol_table = hashmap_new(Ident *, StackObject, &HEAP_ALLOCATOR,
                                          str_ptrv_hash, str_ptrv_eq, NULL)};

  bool uses_stack = array_len(expr_func->block->statements) > 0;
  if (uses_stack) {
    stack_frame_push(compiler);
    stack_frame_reset(compiler);
    compiler->cur_frame.sub_stack_size_ins_idx = array_len(compiler->insns);
    insns_add(compiler, INS_SUB_I8_R64(IMM32_PACK(0x10), REG_ESP));
    // insns_add(compiler, INSN(INS_SUB_IMM8_RSP, .op0 = {.imm = 0x10},
    //                                 .op0_size = sizeof(uint8_t)));
  }

  size_t args_len = array_len(expr_func->desc.args);
  if (args_len > 0) {
    for (size_t i = 0; i < args_len; i++) {
      Argument arg = expr_func->desc.args[i];
      if (arg.kind == ARG_TYPED_ARG) {
        Register reg;
        bool valid = reg_for_arg(&reg, i);
        if (valid) {
          compiler_stack_alloc_reg(compiler, &arg.var.typed_arg.ident, reg);
        } else {
          break;
        }
      }
    }
  }

  CompileContext prev_ctx = compiler->context;
  CompileContext func_ctx = {.level = COMPILE_LEVEL_LOCAL,
                             .function_name = context.function_name};
  compiler->context = func_ctx;
  for (size_t i = 0; i < array_len(expr_func->block->statements); i++) {
    Statement *stmt = &expr_func->block->statements[i];
    stmt_compile(compiler, stmt);
  }

  if (context.function_name != NULL && strv_eq(context.function_name, "main")) {
    insns_add(compiler, INS_XOR_R32_R32(REG_EAX, REG_EAX));
  }

  compiler->context = prev_ctx;

  if (uses_stack) {
    size_t stack_size = ALIGN_BY(compiler->cur_frame.sp_offset, 16);
    // insns_add(compiler, INSN(INS_ADD_IMM8_RSP, .op0 = {.imm = 0x10},
    //                                 .op0_size = sizeof(uint8_t)));
    insns_add(
        compiler,
        INS_ADD_I8_R64(IMM32_PACK(stack_size == 0 ? 16 : stack_size), REG_ESP));
    stack_frame_pop(compiler);
    stack_fix_sub_stack_size(compiler->insns,
                             compiler->cur_frame.sub_stack_size_ins_idx,
                             stack_size == 0 ? 16 : stack_size);
  }

  insns_add_return(compiler);

  Frame *cur_frame = &compiler->cur_frame;
  hashmap_free(&cur_frame->symbol_table);

  memset(&compiler->cur_frame, 0, sizeof(Frame));
}

static uint32_t apply_lit_bin_op(uint32_t a, uint32_t b, BinOperator op) {
  switch (op) {
  case BIN_OP_ADD:
    return a + b;
  case BIN_OP_SUB:
    return a - b;
  case BIN_OP_MUL:
    return a * b;
  case BIN_OP_DIV:
    return a / b;
  case BIN_OP_EQ:
    return a == b;
  case BIN_OP_LT:
    return a < b;
  case BIN_OP_GT:
    return a > b;
  case BIN_OP_LTE:
    return a <= b;
  case BIN_OP_GTE:
    return a >= b;
  }
}

#define SECTION_FROM_EXPR_RES(expr_res_type)                                   \
  expr_res_type == EXPR_COMPILE_RES_DATA_OFFSET ? SECTION_TYPE_DATA            \
                                                : SECTION_TYPE_RODATA

static void mov_global_data_reg(Compiler *compiler, Register res_reg,
                                SectionType sec, size_t offset) {
  RELOCATIONS_ADD(compiler, {.r_offset = 3, .sec = sec, .data_offset = offset});
  insns_add(compiler, INS_MOV_ABS_ADDR32_R64({0}, res_reg));
}

static Instruction ins_bin_op_i32_r64(BinOperator op, int32_t imm,
                                      Register reg) {
  switch (op) {
  case BIN_OP_ADD:
    return INS_ADD_I32_R64(IMM32_PACK(imm), reg);
  case BIN_OP_SUB:
    return INS_SUB_I32_R64(IMM32_PACK(imm), reg);
  case BIN_OP_MUL:
    return INS_MUL_I32_R64(IMM32_PACK(imm), reg, reg);
  case BIN_OP_DIV:
  case BIN_OP_EQ:
  case BIN_OP_LT:
  case BIN_OP_GT:
  case BIN_OP_LTE:
  case BIN_OP_GTE:
    break;
  }
  log_error("Trying to compile bin op that hasnt been implemented yet");
  exit(1);
}

// res_reg is either REG_EAX or REG_EDX, depending on the side of the bin op
// REG_ECX is sometimes used as a temporary register
static ExprCompileResult expr_bin_op_compile(Compiler *compiler,
                                             const ExprBinOp *expr_bin_op,
                                             Register res_reg, Type *res_type) {
  ExprCompileResult res_left = expr_compile_with_res(
      compiler, expr_bin_op->left, EXPR_COMPILE_CTX(.variable_type = res_type),
      REG_EAX);
  ExprCompileResult res_right = expr_compile_with_res(
      compiler, expr_bin_op->right, EXPR_COMPILE_CTX(.variable_type = res_type),
      REG_EDX);
  if (res_left.kind == EXPR_COMPILE_RES_IMM32 &&
      res_right.kind == EXPR_COMPILE_RES_IMM32) {
    return EXPR_COMPILE_RES(EXPR_COMPILE_RES_IMM32, sizeof(uint32_t),
                            .imm32 = apply_lit_bin_op(res_left.var.imm32,
                                                      res_right.var.imm32,
                                                      expr_bin_op->op));
  } else if (expr_bin_op->op == BIN_OP_ADD || expr_bin_op->op == BIN_OP_SUB ||
             expr_bin_op->op == BIN_OP_MUL) {
    switch (res_left.kind) {
    case EXPR_COMPILE_RES_IMM32: {
      switch (res_right.kind) {
      case EXPR_COMPILE_RES_DATA_OFFSET: {
        printf("REG_IMM32 target register during bin op: %d\n", res_reg);
        if (expr_bin_op->op == BIN_OP_ADD || expr_bin_op->op == BIN_OP_MUL) {
          mov_global_data_reg(compiler, res_reg,
                              SECTION_FROM_EXPR_RES(res_right.kind),
                              res_right.var.data_offset.offset);
          insns_add(compiler, ins_bin_op_i32_r64(expr_bin_op->op,
                                                 res_left.var.imm32, res_reg));
        } else if (expr_bin_op->op == BIN_OP_SUB) {
          insns_add(compiler,
                    INS_MOV_I32_R64(res_reg, IMM32_PACK(res_left.var.imm32)));
          RELOCATIONS_ADD(compiler,
                          {.r_offset = 3,
                           .sec = SECTION_FROM_EXPR_RES(res_right.kind),
                           .data_offset = res_right.var.data_offset.offset});
          insns_add(compiler, INS_SUB_ABS_ADDR_R64(res_reg));
        }
        return EXPR_COMPILE_RES(EXPR_COMPILE_RES_REG, DATA_SECTION_SIZE,
                                .reg = res_reg);
      }
      case EXPR_COMPILE_RES_STACK_OBJ: {
        if (expr_bin_op->op == BIN_OP_ADD || expr_bin_op->op == BIN_OP_MUL) {
          insns_add(compiler,
                    INS_MOV_R64_DISP32_R64(
                        REG_EBP, IMM32_PACK(-res_right.var.stack_obj.offset),
                        res_reg));
          insns_add(compiler, ins_bin_op_i32_r64(expr_bin_op->op,
                                                 res_left.var.imm32, res_reg));
        }
        return EXPR_COMPILE_RES(EXPR_COMPILE_RES_REG, sizeof(uint64_t),
                                .reg = res_reg);
      }
      case EXPR_COMPILE_RES_REG: {
        if (expr_bin_op->op == BIN_OP_ADD) {
          insns_add(compiler, INS_MOV_R64_R64(res_right.var.reg, res_reg));
          insns_add(compiler, ins_bin_op_i32_r64(expr_bin_op->op,
                                                 res_left.var.imm32, res_reg));
          return EXPR_COMPILE_RES(EXPR_COMPILE_RES_REG, sizeof(uint64_t),
                                  .reg = res_reg);
        } else if (expr_bin_op->op == BIN_OP_MUL) {
          insns_add(compiler, INS_MUL_I32_R64(IMM32_PACK(res_left.var.imm32),
                                              res_right.var.reg, res_reg));
          return EXPR_COMPILE_RES(EXPR_COMPILE_RES_REG, sizeof(uint64_t),
                                  .reg = res_reg);
        } else if (expr_bin_op->op == BIN_OP_SUB) {
          insns_add(compiler,
                    INS_MOV_I32_R64(res_reg, IMM32_PACK(res_left.var.imm32)));
          insns_add(compiler, INS_SUB_R64_R64(res_right.var.reg, res_reg));
          return EXPR_COMPILE_RES(EXPR_COMPILE_RES_REG, sizeof(uint64_t),
                                  .reg = res_reg);
        }
        log_error("Not implemented yet (imm32 and register)");
        exit(1);
      }
      case EXPR_COMPILE_RES_IMM32:
      case EXPR_COMPILE_RES_COMPARISON:
        break;
      }
      break;
    }
    case EXPR_COMPILE_RES_DATA_OFFSET: {
      mov_global_data_reg(compiler, res_reg,
                          SECTION_FROM_EXPR_RES(res_left.kind),
                          res_left.var.data_offset.offset);
      switch (res_right.kind) {
      case EXPR_COMPILE_RES_DATA_OFFSET: {
        size_t offset = res_right.var.data_offset.offset;
        Register other_reg = REG_ECX;
        mov_global_data_reg(compiler, other_reg,
                            SECTION_FROM_EXPR_RES(res_right.kind), offset);
        insns_add(compiler, INS_ADD_R64_R64(other_reg, res_reg));
        return EXPR_COMPILE_RES(EXPR_COMPILE_RES_REG, sizeof(uint64_t),
                                .reg = res_reg);
      }
      case EXPR_COMPILE_RES_IMM32: {
        insns_add(compiler,
                  INS_ADD_I32_R64(IMM32_PACK(res_right.var.imm32), res_reg));
        return EXPR_COMPILE_RES(EXPR_COMPILE_RES_REG, sizeof(uint64_t),
                                .reg = res_reg);
      }
      case EXPR_COMPILE_RES_STACK_OBJ: {
        StackObject stack_obj = res_right.var.stack_obj;
        Register other_reg = REG_ECX;
        insns_add(compiler,
                  INS_MOV_R64_DISP32_R64(REG_EBP, IMM32_PACK(-stack_obj.offset),
                                         other_reg));
        insns_add(compiler, INS_ADD_R64_R64(other_reg, res_reg));
        return EXPR_COMPILE_RES(EXPR_COMPILE_RES_REG, sizeof(uint64_t),
                                .reg = res_reg);
      }
      case EXPR_COMPILE_RES_REG: {
        break;
      }
      case EXPR_COMPILE_RES_COMPARISON: {
        break;
      } break;
      }
      break;
    }
    case EXPR_COMPILE_RES_STACK_OBJ: {
      StackObject stack_obj = res_left.var.stack_obj;
      insns_add(compiler, INS_MOV_R64_DISP32_R64(
                              REG_EBP, IMM32_PACK(-stack_obj.offset), res_reg));
      switch (res_right.kind) {
      case EXPR_COMPILE_RES_DATA_OFFSET: {
        Register other_reg = REG_ECX;
        mov_global_data_reg(compiler, other_reg,
                            SECTION_FROM_EXPR_RES(res_right.kind),
                            res_right.var.data_offset.offset);
        insns_add(compiler, INS_ADD_R64_R64(other_reg, res_reg));
        return EXPR_COMPILE_RES(EXPR_COMPILE_RES_REG, sizeof(uint64_t),
                                .reg = res_reg);
      }
      case EXPR_COMPILE_RES_IMM32: {
        if (expr_bin_op->op == BIN_OP_ADD) {
          log_debug("Stack obj + Imm32");
          insns_add(compiler,
                    INS_ADD_I32_R64(IMM32_PACK(res_right.var.imm32), res_reg));
        } else if (expr_bin_op->op == BIN_OP_SUB) {
          insns_add(compiler,
                    INS_SUB_I32_R64(IMM32_PACK(res_right.var.imm32), res_reg));
        }
        return EXPR_COMPILE_RES(EXPR_COMPILE_RES_REG, sizeof(uint64_t),
                                .reg = res_reg);
      }
      case EXPR_COMPILE_RES_STACK_OBJ: {
        Register other_reg = REG_ECX;
        StackObject right_stack_obj = res_right.var.stack_obj;
        insns_add(compiler,
                  INS_MOV_R64_DISP32_R64(
                      REG_EBP, IMM32_PACK(-right_stack_obj.offset), other_reg));
        insns_add(compiler, INS_ADD_R64_R64(other_reg, res_reg));
        return EXPR_COMPILE_RES(EXPR_COMPILE_RES_REG, sizeof(uint64_t),
                                .reg = res_reg);
      }
      case EXPR_COMPILE_RES_REG: {
        Register reg = res_right.var.reg;
        log_debug("Register: %d", reg);
        break;
      }
      case EXPR_COMPILE_RES_COMPARISON: {
        log_error("Bin op with comparison NYI");
        exit(1);
        break;
      }
      }
      break;
    }
    case EXPR_COMPILE_RES_REG: {
      switch (res_right.kind) {
      case EXPR_COMPILE_RES_DATA_OFFSET: {
        size_t offset = res_right.var.data_offset.offset;
        mov_global_data_reg(compiler, REG_ECX,
                            SECTION_FROM_EXPR_RES(res_right.kind), offset);
        insns_add(compiler, INS_ADD_R64_R64(REG_ECX, res_reg));
        return EXPR_COMPILE_RES(EXPR_COMPILE_RES_REG, sizeof(uint64_t),
                                .reg = res_reg);
      }
      case EXPR_COMPILE_RES_IMM32: {
        insns_add(compiler,
                  INS_ADD_I32_R64(IMM32_PACK(res_right.var.imm32), res_reg));
        return EXPR_COMPILE_RES(EXPR_COMPILE_RES_REG, sizeof(uint64_t),
                                .reg = res_reg);
      }
      case EXPR_COMPILE_RES_STACK_OBJ: {
        StackObject obj = res_right.var.stack_obj;
        Register other_reg = REG_ECX;
        insns_add(compiler, INS_MOV_R64_DISP32_R64(
                                REG_EBP, IMM32_PACK(-obj.offset), other_reg));
        insns_add(compiler, INS_ADD_R64_R64(other_reg, res_reg));
        return EXPR_COMPILE_RES(EXPR_COMPILE_RES_REG, sizeof(uint64_t),
                                .reg = res_reg);
      }
      case EXPR_COMPILE_RES_REG: {
        if (expr_bin_op->op == BIN_OP_ADD) {
          insns_add(compiler,
                    INS_ADD_R64_R64(res_left.var.reg, res_right.var.reg));
          if (res_right.var.reg != res_reg) {
            insns_add(compiler, INS_MOV_R64_R64(res_right.var.reg, res_reg));
          }
        }
        return EXPR_COMPILE_RES(EXPR_COMPILE_RES_REG, sizeof(uint64_t),
                                .reg = res_reg);
      }
      case EXPR_COMPILE_RES_COMPARISON: {
        break;
      }
      }
      break;
    }
    case EXPR_COMPILE_RES_COMPARISON: {
      break;
    }
    }
  } else if (expr_bin_op->op == BIN_OP_EQ || expr_bin_op->op == BIN_OP_GT ||
             expr_bin_op->op == BIN_OP_LT || expr_bin_op->op == BIN_OP_GTE ||
             expr_bin_op->op == BIN_OP_LTE) {
    if (res_left.kind == EXPR_COMPILE_RES_STACK_OBJ) {
      StackObject stack_obj = res_left.var.stack_obj;
      insns_add(compiler, INS_MOV_R64_DISP32_R64(
                              REG_EBP, IMM32_PACK(-stack_obj.offset), res_reg));
      if (res_right.kind == EXPR_COMPILE_RES_IMM32) {
        insns_add(compiler,
                  INS_CMP_I32_R64(res_reg, IMM32_PACK(res_right.var.imm32)));
      }
    }
    return EXPR_COMPILE_RES(EXPR_COMPILE_RES_COMPARISON, sizeof(bool),
                            .cmp_kind = COMPARISON_GT);
  }
  log_debug("Unimplement bin op expr");
  exit(1);
}

static void stack_dump(const Frame *frame) {
  puts("-- STACK-DUMP --");
  printf("Stack size: %zu\n", frame->sp_offset);
  hashmap_foreach(&frame->symbol_table, Ident * key, StackObject * val, {
    printf("| '%s' at %zu with size %zu\n", *key, val->offset, val->size);
  });
  puts("-- END-STACK-DUMP --");
}

static void expr_res_move_to_reg(Compiler *compiler, ExprCompileResult res,
                                 Register reg) {
  switch (res.kind) {
  case EXPR_COMPILE_RES_DATA_OFFSET: {
    log_warn("NYI move data to reg");
  } break;
  case EXPR_COMPILE_RES_IMM32: {
    insns_add(compiler, INS_MOV_I32_R64(reg, IMM32_PACK(res.var.imm32)));
  } break;
  case EXPR_COMPILE_RES_STACK_OBJ: {
    insns_add(compiler,
              INS_MOV_R64_DISP32_R64(
                  REG_EBP, IMM32_PACK(-res.var.stack_obj.offset), reg));
  } break;
  case EXPR_COMPILE_RES_REG: {
    insns_add(compiler, INS_MOV_R64_R64(res.var.reg, reg));
  } break;
  case EXPR_COMPILE_RES_COMPARISON: {
    log_warn("NYI move cmp to reg");
  } break;
  }
}

static ExprCompileResult expr_compile_with_res(Compiler *compiler,
                                               const Expression *expr,
                                               ExprCompileContext ctx,
                                               Register bin_op_res_reg) {
  switch (expr->kind) {
  case EXPR_STRING_LIT: {
    size_t rodata_idx =
        expr_string_lit_compile(compiler, &expr->var.expr_string_literal);
    return EXPR_COMPILE_RES(EXPR_COMPILE_RES_DATA_OFFSET, sizeof(uint8_t *),
                            .data_offset = {.offset = rodata_idx,
                                            .data_type = DATA_POINTER,
                                            .read_only = true});
  }
  case EXPR_INTEGER_LIT: {
    return EXPR_COMPILE_RES(EXPR_COMPILE_RES_IMM32, sizeof(uint32_t),
                            .imm32 = expr->var.expr_integer_literal.integer);
  }
  case EXPR_CALL: {
    return expr_call_compile(compiler, &expr->var.expr_call);
  }
  case EXPR_IDENT: {
    Ident ident = expr->var.expr_ident.ident.path[0];
    Hashmap(Ident *, GlobalDataLocation) globals = compiler->globals;
    GlobalDataLocation *data_loc = hashmap_value(&globals, &ident);
    if (data_loc != NULL) {
      return EXPR_COMPILE_RES(
          data_loc->kind == EXPR_COMPILE_RES_DATA_OFFSET, sizeof(uint8_t *),
          .data_offset = {.offset = data_loc->data_offset,
                          .data_type = data_loc->data_type,
                          .read_only = data_loc->kind != GLOB_DATA_LOC_DATA});
    } else {
      StackObject *stack_obj =
          hashmap_value(&compiler->cur_frame.symbol_table, &ident);
      if (stack_obj != NULL) {
        return EXPR_COMPILE_RES(EXPR_COMPILE_RES_STACK_OBJ, stack_obj->size,
                                .stack_obj = {.offset = stack_obj->offset,
                                              .size = stack_obj->size});
      }
    }
    log_error("Failed to find global variable: %s", ident);
    stack_dump(&compiler->cur_frame);
    exit(1);
  }
  case EXPR_BIN_OP: {
    ExprBinOp expr_bin_op = expr->var.expr_bin_op;
    return expr_bin_op_compile(compiler, &expr_bin_op,
                               bin_op_res_reg == -1 ? REG_EAX : bin_op_res_reg,
                               ctx.variable_type);
  }
  case EXPR_FOR: {
    ExprFor expr_for = expr->var.expr_for;
    Statement *stmts = expr_for.block.statements;
    if (expr_for.has_range) {
      Ident iter_var = expr_for.variable_name;
      ExprCompileResult min_res =
          expr_compile(compiler, expr_for.range.min,
                       EXPR_COMPILE_CTX(.variable_type = &I32_BUILTIN_TYPE));
      if (min_res.kind != EXPR_COMPILE_RES_IMM32) {
        log_error("Only immediate integers are supported in ranges");
        exit(1);
      }
      ExprCompileResult max_res = expr_compile(
          compiler, expr_for.range.max, EXPR_COMPILE_CTX(&I32_BUILTIN_TYPE));
      if (max_res.kind != EXPR_COMPILE_RES_IMM32) {
        log_error("Only immediate integers are supported in ranges");
        exit(1);
      }

      compiler_stack_alloc_imm64(compiler, &iter_var, min_res.var.imm32);
      // insns_add(compiler, INS_JMP_DISP32(IMM32_PACK(0)));
      size_t for_loop_begin = compiler->program_size;

      for (size_t i = 0; i < array_len(stmts); i++) {
        stmt_compile(compiler, &stmts[i]);
      }

      StackObject *stack_obj =
          hashmap_value(&compiler->cur_frame.symbol_table, &iter_var);
      insns_add(compiler,
                INS_ADD_I32_R64_DISP32(IMM32_PACK(1), REG_EBP,
                                       IMM32_PACK(-stack_obj->offset)));
      if (compiler->program_data != NULL) {
        uint8_t offset_bytes[] =
            IMM32_PACK(compiler->program_size - for_loop_begin + 6);
        for (size_t i = 0; i < 4; i++) {
          compiler->program_data[for_loop_begin - 1 - i] = offset_bytes[i];
        }
      }
      insns_add(compiler,
                INS_CMP_I32_R64_DISP32(IMM32_PACK(max_res.var.imm32), REG_EBP,
                                       IMM32_PACK(-stack_obj->offset)));
      insns_add(compiler, INS_JL_DISP32(IMM32_PACK(
                              for_loop_begin - compiler->program_size - 6)));
    } else {
      size_t for_loop_begin = compiler->program_size;

      for (size_t i = 0; i < array_len(stmts); i++) {
        stmt_compile(compiler, &stmts[i]);
      }

      insns_add(compiler, INS_JMP_DISP32(IMM32_PACK(
                              for_loop_begin - compiler->program_size - 5)));
      log_debug("Jmp offset: %ld",
                (int64_t)for_loop_begin - compiler->program_size - 5);
    }
    return (ExprCompileResult){0};
  }
  case EXPR_ARRAY_INIT: {
    if (compiler->context.level == COMPILE_LEVEL_LOCAL) {
      ExprArrayInit expr_arr_init = expr->var.expr_array_init;
      size_t arr_len = array_len(expr_arr_init.items);
      size_t stack_offset = compiler->cur_frame.sp_offset + 8;
      for (size_t i = arr_len; i > 0; i--) {
        ExprCompileResult expr_res =
            expr_compile(compiler, &expr_arr_init.items[arr_len - i], ctx);
        compiler_stack_alloc_expr_res(compiler, expr_res, stack_offset + i * 4);
      }
      // insns_add(compiler,
      //           INS_LEA_R32_R32_DISP32(
      //               REG_EBP, REG_EAX, IMM32_PACK(-(stack_offset + arr_len *
      //               4))));
      StackObject stack_obj =
          STACK_OBJ(stack_offset + arr_len * 4, arr_len * 4);
      stack_obj.inline_val = true;
      log_debug("Stack offset: 0x%zx", stack_offset);
      return EXPR_COMPILE_RES(EXPR_COMPILE_RES_STACK_OBJ, arr_len * 4,
                              .stack_obj = stack_obj);
    } else {
      log_error("Global arrays not implemented yet");
      exit(1);
    }
  }
  case EXPR_ARRAY_ACCESS: {
    ExprArrayAccess expr_arr_access = expr->var.expr_array_access;
    ExprCompileResult index_res =
        expr_compile(compiler, expr_arr_access.index_expr, ctx);
    ExprCompileResult arr_res =
        expr_compile(compiler, expr_arr_access.array_expr, ctx);
    if (arr_res.kind != EXPR_COMPILE_RES_STACK_OBJ) {
      log_error("Array expression must be stack allocated");
      exit(1);
    }

    StackObject stack_obj = arr_res.var.stack_obj;

    if (index_res.kind == EXPR_COMPILE_RES_IMM32) {
      i32 index = index_res.var.imm32;
      insns_add(
          compiler,
          INS_MOV_R64_DISP32_R64(
              REG_EBP, IMM32_PACK(-stack_obj.offset + index * 4), REG_EAX));

      if (debug_flags.print_compile_info) {
        log_debug("Index: %d", index);
      }
    } else {
      log_debug("Access offset: 0x%zx", stack_obj.offset);
      expr_res_move_to_reg(compiler, index_res, REG_EAX);
      insns_add(compiler, INS_MOV_INDEXED_R64_DISP32(
                              REG_EBP, IMM32_PACK(-stack_obj.offset), REG_EAX,
                              SIB_SCALE(4), REG_EAX));
    }

    return EXPR_COMPILE_RES(EXPR_COMPILE_RES_REG, 8, .reg = REG_EAX);
  }
  case EXPR_BOOLEAN_LIT: {
    return EXPR_COMPILE_RES(EXPR_COMPILE_RES_IMM32, 4,
                            .imm32 = expr->var.expr_boolean_literal.boolean);
  }
  case EXPR_IF: {
    log_debug("Compiling if expression");
    ExprIf expr_if = expr->var.expr_if;
    ExprCompileResult expr_res = expr_compile(compiler, expr_if.condition, ctx);
    if (expr_res.kind == EXPR_COMPILE_RES_REG) {
      insns_add(compiler, INS_CMP_I8_R64(expr_res.var.reg, IMM32_PACK(0)));
    }

    size_t jump_ins_idx = array_len(compiler->insns);

    if (expr_res.kind == EXPR_COMPILE_RES_COMPARISON) {
      if (expr_res.var.cmp_kind == COMPARISON_GT) {
        insns_add(compiler, INS_JLE_DISP32(IMM32_PACK(0)));
      } else {
        log_error("This comparison type is not implemented yet");
        exit(1);
      }
    } else {
      insns_add(compiler, INS_JE_DISP8(IMM32_PACK(0)));
    }
    size_t jump_program_size = compiler->program_size;

    for (size_t i = 0; i < array_len(expr_if.block.statements); i++) {
      Statement *stmt = &expr_if.block.statements[i];
      stmt_compile(compiler, stmt);
    }

    compiler->insns[jump_ins_idx].disp[0] =
        compiler->program_size - jump_program_size;
    log_debug("IF block size: %zu", compiler->program_size - jump_program_size);
    return (ExprCompileResult){0};
  }
  default: {
    fprintf(stderr, "Failed to compile expr %d, not yet implemented\n",
            expr->kind);
    exit(1);
  }
  }
}

static void compiler_arg_push(Compiler *compiler, size_t arg_idx,
                              const ExprCompileResult *res) {
  switch (res->kind) {
  case EXPR_COMPILE_RES_IMM32: {
    Register arg_reg;
    reg_for_arg(&arg_reg, arg_idx);
    insns_add(compiler, INS_MOV_I32_R64(arg_reg, IMM32_PACK(res->var.imm32)));
    break;
  }
  case EXPR_COMPILE_RES_DATA_OFFSET: {
    Register arg_reg;
    bool valid = reg_for_arg(&arg_reg, arg_idx);
    if (res->var.data_offset.data_type == DATA_POINTER) {
      // TODO: Relocation info
      RELOCATIONS_ADD(compiler, {.sec = SECTION_FROM_EXPR_RES(res->kind),
                                 .r_offset = 3,
                                 .data_offset = res->var.data_offset.offset});
      insns_add(compiler, INS_LEA_ABS_ADDR32_R64(IMM32_PACK(0), arg_reg));
      // insns_add(compiler,
      //           INSN(INS_LEA_RIP_REG, .op0 = {.reg = REG_BASE_05(arg_reg)},
      //                .op0_size = sizeof(uint64_t),
      //                .disp = res->var.data_idx.idx, .near_disp = false,
      //                .reloc_info = {.foreign = true,
      //                               .sec = SECTION_FROM_EXPR_RES(res->type),
      //                               .r_offset = 3}));
    } else {
      RELOCATIONS_ADD(compiler, {.sec = SECTION_FROM_EXPR_RES(res->kind),
                                 .r_offset = 3,
                                 .data_offset = res->var.data_offset.offset});
      insns_add(compiler, INS_LEA_ABS_ADDR32_R64(IMM32_PACK(0), arg_reg));
      // insns_add(compiler,
      //           INSN(INS_MOV_RIP_REG_DISP32,
      //                .op0 = {.reg = REG_BASE_05(arg_reg)},
      //                .op0_size = sizeof(uint64_t),
      //                .disp = res->var.data_idx.idx, .near_disp = false,
      //                .reloc_info = {.r_offset = 3,
      //                               .foreign = true,
      //                               .sec =
      //                               SECTION_FROM_EXPR_RES(res->type)}));
    }
    break;
  }
  case EXPR_COMPILE_RES_STACK_OBJ: {
    Register arg_reg;
    bool valid = reg_for_arg(&arg_reg, arg_idx);
    if (valid) {
      insns_add(
          compiler,
          INS_MOV_R64_DISP8_R64_HACKY(
              REG_EBP, IMM32_PACK(256 - res->var.stack_obj.offset), arg_reg));
    }
    break;
  }
  case EXPR_COMPILE_RES_REG: {
    Register arg_reg;
    bool valid = reg_for_arg(&arg_reg, arg_idx);
    log_debug("[COMPILER] reg to reg for call arg");
    if (valid) {
      insns_add(compiler, INS_MOV_R32_R32(res->var.reg, arg_reg));
    }
    break;
  }
  }
}

static void stmt_compile(Compiler *compiler, const Statement *stmt) {
  switch (stmt->kind) {
  case STMT_EXPR: {
    Expression expr = stmt->var.stmt_expr.expr;
    if (expr.kind == EXPR_CALL) {
      ExprCall expr_call = expr.var.expr_call;
      expr_call_compile(compiler, &expr_call);
    } else if (expr.kind == EXPR_FOR || expr.kind == EXPR_IF) {
      expr_compile(compiler, &expr, EXPR_COMPILE_CTX_EMPTY);
    }
    break;
  }
  case STMT_DECL: {
    StmtDecl stmt_decl = stmt->var.stmt_decl;
    if (stmt_decl.value.kind == EXPR_VAR_REG_EXPR) {
      Expression expr = stmt_decl.value.var.expr_var_reg_expr;
      if (compiler->context.level == COMPILE_LEVEL_GLOBAL) {
        DataSection *data_section =
            stmt_decl.mut ? &compiler->data_section : &compiler->rodata_section;
        if (expr.kind == EXPR_FUNCTION) {
          ModulePath func_name_mod_path = module_path_copy(&compiler->mod_path, &compiler->compiler_arena_allocator);
          array_add(func_name_mod_path.path, stmt_decl.name);
          Ident *module_func_name =
              hashmap_value(&compiler->mangled_functions, &func_name_mod_path);

          Ident mangled_func_name;
          if (module_func_name != NULL) {
            mangled_func_name = *module_func_name;
          } else {
            mangled_func_name = stmt_decl.name;
          }
          hashmap_insert(&compiler->symbols, &mangled_func_name,
                         &compiler->program_size);
          expr_func_compile(compiler, &expr.var.expr_function,
                            (CompileContext){.level = COMPILE_LEVEL_GLOBAL,
                                             .function_name = stmt_decl.name});
        } else if (expr.kind == EXPR_INTEGER_LIT) {
          uint64_t val = expr.var.expr_integer_literal.integer;
          uint64_t le = htole64(val);

          uint8_t *bytes = malloc(8);
          memcpy(bytes, &le, sizeof(le));

          size_t offset =
              data_section_add(data_section, &stmt_decl.name, bytes, 8);
          GlobalDataLocation loc = {
              .kind = stmt_decl.mut ? GLOB_DATA_LOC_DATA : GLOB_DATA_LOC_RODATA,
              .data_type = DATA_IMMEDIATE,
              .data_offset = offset};
          hashmap_insert(&compiler->globals, &stmt_decl.name, &loc);

          log_debug("Added data to section: %zu", val);
        } else if (expr.kind == EXPR_STRING_LIT) {
          char *string = expr.var.expr_string_literal.string;
          size_t offset =
              data_section_add(data_section, &stmt_decl.name, (uint8_t *)string,
                               strlen(string) + 1);
          GlobalDataLocation loc = {
              .kind = stmt_decl.mut ? GLOB_DATA_LOC_DATA : GLOB_DATA_LOC_RODATA,
              .data_type = DATA_POINTER,
              .data_offset = offset};
          hashmap_insert(&compiler->globals, &stmt_decl.name, &loc);
        }
      } else {
        ExprCompileResult res = expr_compile(
            compiler, &expr,
            stmt_decl.type.present
                ? EXPR_COMPILE_CTX(.variable_type = &stmt_decl.type.type)
                : EXPR_COMPILE_CTX_EMPTY);
        switch (res.kind) {
        case EXPR_COMPILE_RES_IMM32: {
          compiler_stack_alloc_imm32(compiler, &stmt_decl.name, res.var.imm32);
        } break;
        case EXPR_COMPILE_RES_DATA_OFFSET: {
          compiler->cur_frame.sp_offset += sizeof(char *);
          hashmap_insert(
              &compiler->cur_frame.symbol_table, &stmt_decl.name,
              &STACK_OBJ(compiler->cur_frame.sp_offset, sizeof(char *)));
          RELOCATIONS_ADD(compiler, {.sec = SECTION_FROM_EXPR_RES(res.kind),
                                     .data_offset = res.var.data_offset.offset,
                                     .r_offset = 3});
          insns_add(compiler, INS_LEA_ABS_ADDR32_R64(IMM32_PACK(0), REG_EAX));
          insns_add(compiler, INS_MOV_R64_R64_DISP32(
                                  REG_EAX, REG_EBP,
                                  IMM32_PACK(-compiler->cur_frame.sp_offset)));
        } break;
        case EXPR_COMPILE_RES_REG: {
          compiler_stack_alloc_reg(compiler, &stmt_decl.name, res.var.reg);
        } break;
        case EXPR_COMPILE_RES_STACK_OBJ: {
          StackObject stack_obj = res.var.stack_obj;
          // Alloc as a stack variable if the value should not be inlined
          compiler->cur_frame.sp_offset += stack_obj.size;
          log_debug("Size: %zu", stack_obj.size);
          StackObject ret_obj;
          if (!stack_obj.inline_val) {
            insns_add(compiler,
                      INS_MOV_R64_DISP32_R64(
                          REG_EBP, IMM32_PACK(-stack_obj.offset), REG_EAX));
            insns_add(compiler,
                      INS_MOV_R64_R64_DISP32(
                          REG_EAX, REG_EBP,
                          IMM32_PACK(-compiler->cur_frame.sp_offset)));
            ret_obj = STACK_OBJ(compiler->cur_frame.sp_offset, stack_obj.size);
          } else {
            ret_obj = stack_obj;
          }
          hashmap_insert(&compiler->cur_frame.symbol_table, &stmt_decl.name,
                         &stack_obj);
        } break;
        default: {
        } break;
        }
      }
    }
  } break;
  case STMT_RETURN: {
    StmtReturn stmt_return = stmt->var.stmt_return;
    if (stmt_return.has_ret_val) {
      ModulePath func_name = module_path_root(compiler->context.function_name, &HEAP_ALLOCATOR);
      TypeTableValue *type_table_val =
          hashmap_value(&compiler->type_tables[0].type_table, &func_name);

      const Type *func_ret_type = NULL;

      if (type_table_val != NULL &&
          type_table_val->expr_variant.kind == EXPR_VAR_REG_EXPR) {
        Expression func_expr_raw =
            type_table_val->expr_variant.var.expr_var_reg_expr;
        if (func_expr_raw.kind == EXPR_FUNCTION) {
          ExprFunction func_expr = func_expr_raw.var.expr_function;
          func_ret_type = func_expr.desc.has_ret_type ? &func_expr.desc.ret_type
                                                      : &UNIT_BUILTIN_TYPE;
        }
      }

      ExprCompileResult res = expr_compile(compiler, &stmt_return.ret_val,
                                           EXPR_COMPILE_CTX(func_ret_type));
      switch (res.kind) {
      case EXPR_COMPILE_RES_IMM32: {
        insns_add(compiler,
                  INS_MOV_I32_R32(REG_EAX, IMM32_PACK(res.var.imm32)));
      } break;
      case EXPR_COMPILE_RES_DATA_OFFSET: {
        RELOCATIONS_ADD(compiler, {.sec = SECTION_FROM_EXPR_RES(res.kind),
                                   .r_offset = 3,
                                   .data_offset = res.var.data_offset.offset});
        insns_add(compiler, INS_LEA_ABS_ADDR32_R64(IMM32_PACK(0), REG_EAX));
      } break;
      default: {
      } break;
      }
    }
    break;
  }
  case STMT_ASSIGN: {
    StmtAssign stmt_assign = stmt->var.stmt_assign;
    if (stmt_assign.left_ident_kind == ACCESS_TYPE_STRUCT_ACCESS)
      return;

    StackObject *stack_obj = hashmap_value(&compiler->cur_frame.symbol_table,
                                           &stmt_assign.left_ident.ident);
    if (stack_obj != NULL) {
      ModulePath mod_path = module_path_root(stmt_assign.left_ident.ident, &HEAP_ALLOCATOR);
      
      ExprCompileResult expr_compile_res =
          expr_compile(compiler, &stmt_assign.right_expr, EXPR_COMPILE_CTX());
      hashmap_insert(&compiler->cur_frame.symbol_table,
                     &stmt_assign.left_ident.ident,
                     &STACK_OBJ(stack_obj->offset, expr_compile_res.size));
      switch (expr_compile_res.kind) {
      case EXPR_COMPILE_RES_DATA_OFFSET: {
        break;
      }
      case EXPR_COMPILE_RES_IMM32: {
        insns_add(compiler, INS_MOV_I32_R32_DISP8(
                                REG_EBP, stack_obj->offset,
                                IMM32_PACK(expr_compile_res.var.imm32)));
        break;
      }
      case EXPR_COMPILE_RES_STACK_OBJ: {
        insns_add(compiler,
                  INS_MOV_R64_DISP32_R64(
                      REG_EBP,
                      IMM32_PACK(-expr_compile_res.var.stack_obj.offset),
                      REG_EAX));
        insns_add(compiler,
                  INS_MOV_R64_R64_DISP32(REG_EAX, REG_EBP,
                                         IMM32_PACK(-stack_obj->offset)));
        break;
      }
      case EXPR_COMPILE_RES_REG: {
        insns_add(compiler,
                  INS_MOV_R64_R64_DISP32(expr_compile_res.var.reg, REG_EBP,
                                         IMM32_PACK(-stack_obj->offset)));
        break;
      }
      }
    }
    break;
  }
  // We ignore dis
  case STMT_FOREIGN: {
    break;
  }
  }
}

static const CompileContext GLOBAL_COMPILE_CONTEXT = {
    .level = COMPILE_LEVEL_GLOBAL, .function_name = NULL};

void compiler_compile(Compiler *compiler) {
  compiler->step = COMPILE_STEP_COMPILE_SRC;

  if (debug_flags.print_compile_info) {
    log_info("[COMPILER] Start compiling file %s", "?");
  }

  compiler->context = GLOBAL_COMPILE_CONTEXT;

  size_t stmts_len = array_len(compiler->stmts);
  while (compiler->stmt_index < stmts_len) {
    stmt_compile(compiler, &compiler->stmts[compiler->stmt_index]);
    compiler->stmt_index++;
  }
}
