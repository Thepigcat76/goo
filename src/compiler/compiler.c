#include "../../include/compiler.h"
#include "lilc/array.h"
#include "lilc/eq.h"
#include "lilc/hash.h"
#include <complex.h>
#include <elf.h>
#include <endian.h>
#include <lilc/alloc.h>
#include <lilc/hashmap.h>
#include <lilc/log.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

static inline DataSection data_section_new(void) {
  return (DataSection){.values = array_new(DataValue, &HEAP_ALLOCATOR),
                       .section_lookup =
                           hashmap_new(Ident *, DataValue, &HEAP_ALLOCATOR,
                                       str_ptrv_hash, str_ptrv_eq, NULL)};
}

Compiler compiler_new(const Statement *statements) {
  return (Compiler){
      .stmts = statements,
      .relocations = array_new(Relocation, &HEAP_ALLOCATOR),
      .insns = array_new_capacity(Instruction, 32, &HEAP_ALLOCATOR),
      .labels = hashmap_new(Ident *, size_t, &HEAP_ALLOCATOR, str_ptrv_hash,
                            str_ptrv_eq, NULL),
      .extern_functions = hashmap_new(Ident *, size_t, &HEAP_ALLOCATOR,
                                      str_ptrv_hash, str_ptrv_eq, NULL),
      .globals = hashmap_new(Ident *, GlobalDataLocation, &HEAP_ALLOCATOR,
                             str_ptrv_hash, str_ptrv_eq, NULL),
      .data_section = data_section_new(),
      .rodata_section = data_section_new()};
}

static void data_section_print(char *buf, const DataSection *ds) {
  buf[0] = '\0';
  strcat(buf, "--- BEGIN ---\n");
  size_t *printed_indices = array_new(size_t, &HEAP_ALLOCATOR);
  hashmap_foreach(&ds->section_lookup, Ident * key, size_t *val, {
    DataValue dv = ds->values[*val];
    char bytes_buf[256] = {0};
    for (size_t i = 0; i < dv.bytes_len; i++) {
      char byte_buf[16];
      sprintf(byte_buf, "%02X ", dv.bytes[i]);
      strcat(bytes_buf, byte_buf);
    }
    strcat(bytes_buf, "(");
    for (size_t i = 0; i < dv.bytes_len; i++) {
      char byte_buf[16];
      sprintf(byte_buf, "%c", dv.bytes[i]);
      if (dv.bytes[i] == 0) {
        sprintf(byte_buf, "\\0");
      }
      strcat(bytes_buf, byte_buf);
    }
    strcat(bytes_buf, ")");
    char final_buf[512];
    sprintf(final_buf, "'%s' - %s\n", *key, bytes_buf);
    strcat(buf, final_buf);
    array_add(printed_indices, *val);
  });
  for (size_t i = 0; i < array_len(ds->values); i++) {
    bool printed = false;
    for (size_t j = 0; j < array_len(printed_indices); j++) {
      if (printed_indices[j] == i) {
        printed = true;
        break;
      }
    }
    if (!printed) {
      DataValue dv = ds->values[i];
      char bytes_buf[256] = {0};
      for (size_t i = 0; i < dv.bytes_len; i++) {
        char byte_buf[16];
        sprintf(byte_buf, "%02X ", dv.bytes[i]);
        strcat(bytes_buf, byte_buf);
      }
      strcat(bytes_buf, "(");
      for (size_t i = 0; i < dv.bytes_len; i++) {
        char byte_buf[16];
        sprintf(byte_buf, "%c", dv.bytes[i]);
        if (dv.bytes[i] == 0) {
          sprintf(byte_buf, "\\0");
        }
        strcat(bytes_buf, byte_buf);
      }
      strcat(bytes_buf, ")");
      char final_buf[512];
      sprintf(final_buf, "<inlined> - %s\n", bytes_buf);
      strcat(buf, final_buf);
    }
  }
  strcat(buf, "--- END ---");
}

static size_t data_section_add(DataSection *section, Ident *key,
                               DataValue value) {
  size_t idx = array_len(section->values);
  array_add(section->values, value);
  hashmap_insert(&section->section_lookup, key, &idx);
  return idx;
}

typedef enum {
  COMPILE_LEVEL_GLOBAL,
  COMPILE_LEVEL_LOCAL,
} CompileLevel;

typedef struct {
  CompileLevel level;
  const char *function_name;
} CompileContext;

static void stmt_compile(Compiler *compiler, const Statement *stmt,
                         CompileContext context);

static inline void stack_frame_push(Instruction *insns) {
  Instruction ins = {.opcode = INS_PUSH_SP};
  array_add(insns, ins);
}

static inline void stack_frame_reset(Instruction *insns) {
  Instruction ins = {.opcode = INS_RESET_SP};
  array_add(insns, ins);
}

static inline void stack_frame_pop(Instruction *insns) {
  Instruction ins = {.opcode = INS_POP_SP};
  array_add(insns, ins);
}

static inline void insns_add_return(Instruction *insns) {
  Instruction ins = {.opcode = INS_RET};
  array_add(insns, ins);
}

static inline void insns_add(Instruction *insns, Instruction ins) {
  array_add(insns, ins);
}

#define INSN(_opcode, ...)                                                     \
  (Instruction) {                                                              \
    .opcode = _opcode, .args = { __VA_ARGS__ }                                 \
  }

static size_t
expr_string_lit_compile(Compiler *compiler,
                        const ExprStringLiteral *expr_string_lit) {
  size_t rodata_idx = array_len(compiler->rodata_section.values);
  DataValue val = {.bytes = (uint8_t *)expr_string_lit->string,
                   .bytes_len = strlen(expr_string_lit->string) + 1};
  array_add(compiler->rodata_section.values, val);
  return rodata_idx;
}

typedef struct {
  enum {
    EXPR_COMPILE_RES_RODATA_IDX,
    EXPR_COMPILE_RES_DATA_IDX,
    EXPR_COMPILE_RES_IMM32,
    EXPR_COMPILE_RES_STACK_LOC,
    EXPR_COMPILE_RES_REG,
  } type;
  union {
    struct {
      DataType data_type;
      size_t idx;
    } data_idx;
    uint32_t imm32;
    size_t stack_loc;
    Register reg;
  } var;
} ExprCompileResult;

typedef struct {
  enum {
    EXPR_CALL_RES_IMM32,
  } type;
  union {
    uint32_t imm32;
  } var;
} ExprCallResult;

static char *PRINTF_FUNCTION_NAME = "puts";

#define EXPR_COMPILE_RES(_type, ...)                                           \
  (ExprCompileResult) {                                                        \
    .type = _type, .var = { __VA_ARGS__ }                                      \
  }

static void compiler_arg_push(Compiler *compiler, size_t arg_idx,
                              const ExprCompileResult *res);

static ExprCompileResult expr_compile(Compiler *compiler,
                                      const Expression *expr);

static ExprCompileResult expr_call_compile(Compiler *compiler,
                                           const ExprCall *expr_call) {
  for (size_t i = 0; i < array_len(expr_call->args); i++) {
    Expression arg = expr_call->args[i];
    ExprCompileResult res = expr_compile(compiler, &arg);
    compiler_arg_push(compiler, i, &res);
  }

  size_t placeholder_0 = 0;
  if (strv_eq(expr_call->function, "println")) {
    hashmap_insert(&compiler->extern_functions, &PRINTF_FUNCTION_NAME,
                   &placeholder_0);
    insns_add(compiler->insns,
              INSN(INS_CALL, .call_ins = {.function_name = PRINTF_FUNCTION_NAME,
                                          .foreign = true}));
  } else if (strv_eq(expr_call->function, "exit") ||
             strv_eq(expr_call->function, "print_int")) {
    hashmap_insert(&compiler->extern_functions, &expr_call->function,
                   &placeholder_0);
    insns_add(compiler->insns,
              INSN(INS_CALL, .call_ins = {.function_name = expr_call->function,
                                          .foreign = true}));
  } else {
    insns_add(
        compiler->insns,
        INSN(INS_CALL, .call_ins = {.function_name = expr_call->function}));
  }

  return EXPR_COMPILE_RES(EXPR_COMPILE_RES_REG, .reg = REG_RAX);
}

static void compiler_stack_alloc_imm32(Compiler *compiler, Ident *name,
                                       uint32_t imm32) {
  compiler->cur_frame.sp_offset += sizeof(int32_t);
  hashmap_insert(&compiler->cur_frame.symbol_table, name,
                 &compiler->cur_frame.sp_offset);
  insns_add(compiler->insns,
            INSN(INS_MOV_I32_RBP_DISP8,
                 .imm32_disp8 = {
                     .imm = imm32,
                     .disp = 256 - compiler->cur_frame.sp_offset,
                 }));
}

static void compiler_stack_alloc_reg(Compiler *compiler, Ident *name,
                                     Register reg) {
  compiler->cur_frame.sp_offset += 8;
  hashmap_insert(&compiler->cur_frame.symbol_table, name,
                 &compiler->cur_frame.sp_offset);
  insns_add(compiler->insns,
            INSN(INS_MOV_REG_RBP_DISP8,
                 .reg_disp8 = {.reg = MOV_REG(reg),
                               .disp = 256 - compiler->cur_frame.sp_offset}));
}

// Returns whether there is a reg for this arg
static bool reg_for_arg(Register *reg, size_t arg_idx) {
  switch (arg_idx) {
  case 0:
    *reg = REG_RDI;
    return true;
  case 1:
    *reg = REG_RSI;
    return true;
  case 2:
    *reg = REG_RDX;
    return true;
  case 3:
    *reg = REG_RCX;
    return true;
  }
  return false;
}

static void expr_func_compile(Compiler *compiler, const ExprFunction *expr_func,
                              CompileContext context) {
  log_info("New stack frame");
  compiler->cur_frame =
      (Frame){.sp_offset = 0,
              .symbol_table = hashmap_new(Ident *, size_t, &HEAP_ALLOCATOR,
                                          str_ptrv_hash, str_ptrv_eq, NULL)};

  bool uses_stack = array_len(expr_func->block->statements) > 0;
  if (uses_stack) {
    stack_frame_push(compiler->insns);
    stack_frame_reset(compiler->insns);
    insns_add(compiler->insns, INSN(INS_SUB_IMM8_RSP, .imm8 = {.imm = 0x10}));
  }
  size_t args_len = array_len(expr_func->desc.args);
  if (args_len > 0) {
    for (size_t i = 0; i < args_len; i++) {
      Argument arg = expr_func->desc.args[i];
      if (arg.type == ARG_TYPED_ARG) {
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

  for (size_t i = 0; i < array_len(expr_func->block->statements); i++) {
    Statement *stmt = &expr_func->block->statements[i];
    stmt_compile(compiler, stmt,
                 (CompileContext){.level = COMPILE_LEVEL_LOCAL,
                                  .function_name = context.function_name});
  }

  printf("func name: %s\n", context.function_name);
  if (context.function_name != NULL && strv_eq(context.function_name, "main")) {
    insns_add(compiler->insns, INSN(INS_XOR_RAX_RAX));
  }

  if (uses_stack) {
    insns_add(compiler->insns, INSN(INS_ADD_IMM8_RSP, .imm8 = {.imm = 0x10}));
    stack_frame_pop(compiler->insns);
  }

  insns_add_return(compiler->insns);
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

/* Sets the opcode to the one for performing specified op with imm32. Returns
 * whether the operation is supported */
static bool opcode_imm32_rax_bin_op(Opcode *opcode, BinOperator op) {
  switch (op) {
  case BIN_OP_ADD:
    *opcode = INS_ADD_IMM32_RAX;
    return true;
  case BIN_OP_SUB:
    *opcode = INS_SUB_IMM32_RAX;
    return true;
  case BIN_OP_MUL:
    *opcode = INS_MUL_IMM32_RAX;
    return true;
  default:
    return false;
  }
}

/* Sets the opcode to the one for performing specified op with imm32. Returns
 * whether the operation is supported */
static bool opcode_rdx_rax_bin_op(Opcode *opcode, BinOperator op) {
  switch (op) {
  case BIN_OP_ADD:
    *opcode = INS_ADD_RDX_RAX;
    return true;
  case BIN_OP_SUB:
    *opcode = INS_SUB_RDX_RAX;
    return true;
  case BIN_OP_MUL:
    *opcode = INS_IMUL_RDX_RAX;
    return true;
  default:
    return false;
  }
}

static ExprCompileResult expr_bin_op_compile(Compiler *compiler,
                                             const ExprBinOp *expr_bin_op) {
  ExprCompileResult res_left = expr_compile(compiler, expr_bin_op->left);
  ExprCompileResult res_right = expr_compile(compiler, expr_bin_op->right);
  if (res_left.type == EXPR_COMPILE_RES_IMM32 &&
      res_right.type == EXPR_COMPILE_RES_IMM32) {
    return EXPR_COMPILE_RES(EXPR_COMPILE_RES_IMM32,
                            .imm32 = apply_lit_bin_op(res_left.var.imm32,
                                                      res_right.var.imm32,
                                                      expr_bin_op->op));
  } else if (expr_bin_op->op == BIN_OP_ADD || expr_bin_op->op == BIN_OP_SUB ||
             expr_bin_op->op == BIN_OP_MUL) {
    Opcode imm32_rax_bin_op_opcode;
    opcode_imm32_rax_bin_op(&imm32_rax_bin_op_opcode, expr_bin_op->op);
    Opcode rdx_rax_bin_op_opcode;
    opcode_rdx_rax_bin_op(&rdx_rax_bin_op_opcode, expr_bin_op->op);
    switch (res_left.type) {
    case EXPR_COMPILE_RES_REG: {
      Register reg = res_left.var.reg;
      if (reg != REG_RAX) {
        insns_add(compiler->insns, INSN(INS_MOV_REG_RAX, .reg = {.reg = reg}));
      }
      if (res_right.type == EXPR_COMPILE_RES_IMM32) {
        insns_add(compiler->insns,
                  INSN(imm32_rax_bin_op_opcode, .imm32 = {
                                              .imm = res_right.var.imm32,
                                          }));
      }
      return EXPR_COMPILE_RES(EXPR_COMPILE_RES_REG, .reg = REG_RAX);
    }
    case EXPR_COMPILE_RES_RODATA_IDX:
    case EXPR_COMPILE_RES_DATA_IDX: {
      insns_add(compiler->insns,
                INSN(INS_MOV_I32_RAX,
                     .imm32 = {.imm = res_left.var.data_idx.idx,
                               .r_offset = 3,
                               .foreign = true,
                               .sec = res_left.type == EXPR_COMPILE_RES_DATA_IDX
                                          ? SECTION_DATA
                                          : SECTION_RODATA}));
      switch (res_right.type) {
      case EXPR_COMPILE_RES_RODATA_IDX:
      case EXPR_COMPILE_RES_DATA_IDX: {
        insns_add(
            compiler->insns,
            INSN(INS_MOV_I32_RDX,
                 .imm32 = {.imm = res_right.var.data_idx.idx,
                           .r_offset = 3,
                           .foreign = true,
                           .sec = res_right.type == EXPR_COMPILE_RES_DATA_IDX
                                      ? SECTION_DATA
                                      : SECTION_RODATA}));
        insns_add(compiler->insns, INSN(rdx_rax_bin_op_opcode));
        break;
      }
      case EXPR_COMPILE_RES_IMM32: {
        insns_add(compiler->insns, INSN(imm32_rax_bin_op_opcode,
                                        .imm32 = {.imm = res_right.var.imm32}));
        break;
      }
      case EXPR_COMPILE_RES_STACK_LOC: {
        break;
      }
      case EXPR_COMPILE_RES_REG: {
        break;
      }
      }
      return EXPR_COMPILE_RES(EXPR_COMPILE_RES_REG, .reg = REG_RAX);
    }
    case EXPR_COMPILE_RES_IMM32: {

      break;
    }
    case EXPR_COMPILE_RES_STACK_LOC: {
      break;
    }
    default:
      break;
    }
  }
}

static ExprCompileResult expr_compile(Compiler *compiler,
                                      const Expression *expr) {
  switch (expr->type) {
  case EXPR_STRING_LIT: {
    size_t rodata_idx =
        expr_string_lit_compile(compiler, &expr->var.expr_string_literal);
    return EXPR_COMPILE_RES(
        EXPR_COMPILE_RES_RODATA_IDX,
        .data_idx = {.idx = rodata_idx, .data_type = DATA_POINTER});
  }
  case EXPR_INTEGER_LIT: {
    return EXPR_COMPILE_RES(EXPR_COMPILE_RES_IMM32,
                            .imm32 = expr->var.expr_integer_literal.integer);
  }
  case EXPR_CALL: {
    return expr_call_compile(compiler, &expr->var.expr_call);
  }
  case EXPR_IDENT: {
    Ident ident = expr->var.expr_ident.ident;
    Hashmap(Ident *, GlobalDataLocation) globals = compiler->globals;
    GlobalDataLocation *data_loc = hashmap_value(&globals, &ident);
    if (data_loc != NULL) {
      return EXPR_COMPILE_RES(data_loc->type == GLOB_DATA_LOC_DATA
                                  ? EXPR_COMPILE_RES_DATA_IDX
                                  : EXPR_COMPILE_RES_RODATA_IDX,
                              .data_idx = {.idx = data_loc->data_index,
                                           .data_type = data_loc->data_type});
    } else {
      size_t *sp_offset =
          hashmap_value(&compiler->cur_frame.symbol_table, &ident);
      if (sp_offset != NULL) {
        return EXPR_COMPILE_RES(EXPR_COMPILE_RES_STACK_LOC,
                                .stack_loc = *sp_offset);
      }
    }
    log_error("Failed to find global variable: %s", ident);
    exit(1);
  }
  case EXPR_BIN_OP: {
    ExprBinOp expr_bin_op = expr->var.expr_bin_op;
    return expr_bin_op_compile(compiler, &expr_bin_op);
  }
  default: {
    fprintf(stderr, "Failed to compile expr, not yet implemented\n");
    exit(1);
  }
  }
}

static void compiler_arg_push(Compiler *compiler, size_t arg_idx,
                              const ExprCompileResult *res) {
  switch (res->type) {
  case EXPR_COMPILE_RES_IMM32: {
    insns_add(compiler->insns,
              INSN(INS_MOV_I32_EDI, .imm32 = {.imm = res->var.imm32}));
    break;
  }
  case EXPR_COMPILE_RES_DATA_IDX:
  case EXPR_COMPILE_RES_RODATA_IDX: {
    Register arg_reg;
    bool valid = reg_for_arg(&arg_reg, arg_idx);
    if (res->var.data_idx.data_type == DATA_POINTER) {
      insns_add(compiler->insns,
                INSN(INS_LEA_RIP_REG,
                     .reg_disp32 = {
                         .reg = LEA_REG(arg_reg),
                         .disp = res->var.data_idx.idx,
                         .r_offset = 3,
                         .foreign = true,
                         .sec = res->type == EXPR_COMPILE_RES_DATA_IDX
                                    ? SECTION_DATA
                                    : SECTION_RODATA,
                     }));
    } else {
      insns_add(compiler->insns,
                INSN(INS_MOV_RIP_REG_DISP32,
                     .reg_disp32 = {
                         .reg = LEA_REG(arg_reg),
                         .disp = res->var.data_idx.idx,
                         .r_offset = 3,
                         .foreign = true,
                         .sec = res->type == EXPR_COMPILE_RES_DATA_IDX
                                    ? SECTION_DATA
                                    : SECTION_RODATA,
                     }));
    }
    break;
  }
  case EXPR_COMPILE_RES_STACK_LOC: {
    Register arg_reg;
    bool valid = reg_for_arg(&arg_reg, arg_idx);
    if (valid) {
      insns_add(compiler->insns,
                INSN(INS_MOV_RPB_DISP8_REG,
                     .reg_disp8 = {.reg = MOV_REG(arg_reg),
                                   .disp = 256 - res->var.stack_loc}));
    }
    break;
  }
  }
}

static void stmt_compile(Compiler *compiler, const Statement *stmt,
                         CompileContext context) {
  switch (stmt->type) {
  case STMT_EXPR: {
    Expression expr = stmt->var.stmt_expr.expr;
    if (expr.type == EXPR_CALL) {
      ExprCall expr_call = expr.var.expr_call;
      expr_call_compile(compiler, &expr_call);
    }
    break;
  }
  case STMT_DECL: {
    StmtDecl stmt_decl = stmt->var.stmt_decl;
    if (stmt_decl.value.type == EXPR_VAR_REG_EXPR) {
      Expression expr = stmt_decl.value.var.expr_var_reg_expr;
      if (context.level == COMPILE_LEVEL_GLOBAL) {
        DataSection *data_section =
            stmt_decl.mut ? &compiler->data_section : &compiler->rodata_section;
        if (expr.type == EXPR_FUNCTION) {
          size_t len = array_len(compiler->insns);
          hashmap_insert(&compiler->labels, &stmt_decl.name, &len);
          expr_func_compile(compiler, &expr.var.expr_function,
                            (CompileContext){.level = COMPILE_LEVEL_GLOBAL,
                                             .function_name = stmt_decl.name});
        } else if (expr.type == EXPR_INTEGER_LIT) {
          uint64_t val = expr.var.expr_integer_literal.integer;
          uint64_t le = htole64(val);

          uint8_t *bytes = malloc(8);
          memcpy(bytes, &le, sizeof(le));

          DataValue data_val = {.bytes = bytes, .bytes_len = 8};
          size_t idx =
              data_section_add(data_section, &stmt_decl.name, data_val);
          GlobalDataLocation loc = {
              .type = stmt_decl.mut ? GLOB_DATA_LOC_DATA : GLOB_DATA_LOC_RODATA,
              .data_type = DATA_IMMEDIATE,
              .data_index = idx};
          hashmap_insert(&compiler->globals, &stmt_decl.name, &loc);

          log_debug("Added data to section: %zu", val);
        } else if (expr.type == EXPR_STRING_LIT) {
          char *string = expr.var.expr_string_literal.string;
          DataValue data_val = {.bytes = (uint8_t *)string,
                                .bytes_len = strlen(string) + 1};
          size_t idx =
              data_section_add(data_section, &stmt_decl.name, data_val);
          GlobalDataLocation loc = {
              .type = stmt_decl.mut ? GLOB_DATA_LOC_DATA : GLOB_DATA_LOC_RODATA,
              .data_type = DATA_POINTER,
              .data_index = idx};
          hashmap_insert(&compiler->globals, &stmt_decl.name, &loc);
        }
      } else {
        ExprCompileResult res = expr_compile(compiler, &expr);
        switch (res.type) {
        case EXPR_COMPILE_RES_IMM32: {
          compiler_stack_alloc_imm32(compiler, &stmt_decl.name, res.var.imm32);
          break;
        }
        case EXPR_COMPILE_RES_DATA_IDX:
        case EXPR_COMPILE_RES_RODATA_IDX: {
          compiler->cur_frame.sp_offset += sizeof(char *);
          hashmap_insert(&compiler->cur_frame.symbol_table, &stmt_decl.name,
                         &compiler->cur_frame.sp_offset);
          insns_add(compiler->insns,
                    INSN(INS_LEA_RIP_RAX,
                         .imm32 = {
                             .imm = res.var.data_idx.idx,
                             .r_offset = 3,
                             .foreign = true,
                             .sec = res.type == EXPR_COMPILE_RES_DATA_IDX
                                        ? SECTION_DATA
                                        : SECTION_RODATA,
                         }));
          insns_add(
              compiler->insns,
              INSN(INS_MOV_REG_RBP_DISP8,
                   .reg_disp8 = {.reg = MOV_REG(REG_RAX),
                                 .disp = 256 - compiler->cur_frame.sp_offset}));
          break;
        }
        case EXPR_COMPILE_RES_REG: {
          compiler_stack_alloc_reg(compiler, &stmt_decl.name, res.var.reg);
          break;
        }
        default: {
          break;
        }
        }
      }
    }
    break;
  }
  case STMT_RETURN: {
    StmtReturn stmt_return = stmt->var.stmt_return;
    if (stmt_return.has_ret_val) {
      ExprCompileResult res = expr_compile(compiler, &stmt_return.ret_val);
      switch (res.type) {
      case EXPR_COMPILE_RES_IMM32: {
        insns_add(compiler->insns,
                  INSN(INS_MOV_I32_EAX, .imm32 = {.imm = res.var.imm32}));
        break;
      }
      case EXPR_COMPILE_RES_DATA_IDX:
      case EXPR_COMPILE_RES_RODATA_IDX: {
        insns_add(compiler->insns,
                  INSN(INS_LEA_RIP_RAX,
                       .imm32 = {
                           .imm = res.var.data_idx.idx,
                           .r_offset = 3,
                           .foreign = true,
                           .sec = res.type == EXPR_COMPILE_RES_DATA_IDX
                                      ? SECTION_DATA
                                      : SECTION_RODATA,
                       }));
        break;
      }
      default: {
        break;
      }
      }
    }
    break;
  }
  }
}

static const CompileContext GLOBAL_COMPILE_CONTEXT = {
    .level = COMPILE_LEVEL_GLOBAL, .function_name = NULL};

void compiler_compile(Compiler *compiler) {
  compiler->step = COMPILE_STEP_COMPILE_SRC;

  size_t stmts_len = array_len(compiler->stmts);
  while (compiler->stmt_index < stmts_len) {
    stmt_compile(compiler, &compiler->stmts[compiler->stmt_index],
                 GLOBAL_COMPILE_CONTEXT);
    compiler->stmt_index++;
  }

  log_debug("Labels:");
  hashmap_foreach(&compiler->labels, Ident * key, size_t *val, {
    log_debug("Key: %s", *key);
    log_debug("Value: %zu", *val);
  });
  log_debug("Labels amount: %zu", compiler->labels.len);

  char buf[2048];
  data_section_print(buf, &compiler->rodata_section);
  printf("Data Section:\n%s\n", buf);
}

/* Generate the opcode of the instruction. Return the size. Size is always <= 3
 */
static size_t insn_opcode(Opcode insn_type, uint8_t *opcode) {
  uint8_t len = (insn_type >> 6) & 0x03;
  if (opcode != NULL) {
    for (size_t i = 0; i < len; i++) {
      opcode[i] = (insn_type >> ((i + 1) * 8)) & 0xff;
    }
  }
  return len;
}

typedef struct {
  Hashmap(Ident *, size_t) * labels;
  const DataSection *rodata_section;
  const size_t *rodata_offsets;
  const DataSection *data_section;
  const size_t *data_offsets;
  size_t program_data_offset;
} GenerationContext;

static void relocations_add_data(Relocation *relocations, SectionType sec,
                                 uint64_t idx, uint8_t r_offset,
                                 GenerationContext context) {
  if (relocations != NULL) {
    const size_t *offsets;
    if (sec == SECTION_DATA) {
      offsets = context.data_offsets;
    } else {
      offsets = context.rodata_offsets;
    }

    size_t offset;
    if (/*idx < array_len(offsets)*/ true) {
      offset = offsets[idx];
    } else {
      // log_error("Index (%zu) out of bounds for data offsets (len: %zu)", idx,
      // array_len(offsets)); exit(1);
    }

    Relocation reloc = {
        .rel_type = sec == SECTION_DATA ? RELOCATION_DATA : RELOCATION_RODATA,
        .data_offset = (sec == SECTION_DATA ? context.data_offsets
                                            : context.rodata_offsets)[idx],
        .r_offset = r_offset,
        .program_offset = context.program_data_offset,
    };
    array_add(relocations, reloc);
  }
}

static size_t insn_generate(Instruction *ins, Relocation *relocations,
                            uint8_t *insn_bytes, GenerationContext context) {
  uint8_t flag = (ins->opcode >> 0) & 0x3F;
  size_t opcode_len = insn_opcode(ins->opcode, insn_bytes);

  size_t ins_len = opcode_len;

  switch (flag) {
  case IF_NO_ARG | IF_SPECIAL: {
    break;
  }
  case IF_ARG_IMM8: {
    /* If the instruction is foreign, we just put 1 empty byte */
    if (!ins->args.imm8.foreign) {
      uint8_t imm8 = htole32(ins->args.imm8.imm);
      for (size_t i = 0; i < sizeof(uint8_t); i++) {
        insn_bytes[ins_len + i] = (imm8 >> (i * 8)) & 0xff;
      }
    } else {
      relocations_add_data(relocations, ins->args.imm8.sec, ins->args.imm8.imm,
                           ins->args.imm8.r_offset, context);
    }
    ins_len += sizeof(uint8_t);
    break;
  }
  /* 32 bit immediates */
  case IF_ARG_IMM32_DISP8: {
    /* If the instruction is foreign, we just put 4 empty bytes */
    if (!ins->args.imm32_disp8.foreign) {
      insn_bytes[opcode_len] = ins->args.imm32_disp8.disp;
      ins_len += 1;
      uint32_t imm32 = htole32(ins->args.imm32_disp8.imm);
      for (size_t i = 0; i < sizeof(uint32_t); i++) {
        insn_bytes[ins_len + i] = (imm32 >> (i * 8)) & 0xff;
      }
    } else {
      relocations_add_data(relocations, ins->args.imm32_disp8.sec,
                           ins->args.imm32_disp8.imm,
                           ins->args.imm32_disp8.r_offset, context);
    }
    ins_len += sizeof(uint32_t);
    break;
  }
  case IF_ARG_IMM32: {
    /* If the instruction is foreign, we just put 4 empty bytes */
    if (!ins->args.imm32.foreign) {
      uint32_t imm32 = htole32(ins->args.imm32.imm);
      for (size_t i = 0; i < sizeof(uint32_t); i++) {
        insn_bytes[ins_len + i] = (imm32 >> (i * 8)) & 0xff;
      }
    } else {
      relocations_add_data(relocations, ins->args.imm32.sec,
                           ins->args.imm32.imm, ins->args.imm32.r_offset,
                           context);
    }
    ins_len += sizeof(uint32_t);
    break;
  }
  /* 64 bit immediates */
  // TODO: Use 64 bit integers again
  case IF_ARG_IMM64_DISP8: {
    insn_bytes[opcode_len] = ins->args.imm64_disp8.disp;
    ins_len += 1;
    /* If the instruction is foreign, we just put 8 empty bytes */
    if (!ins->args.imm64_disp8.foreign) {
      uint64_t imm64 = htole64(ins->args.imm64_disp8.imm);
      for (size_t i = 0; i < sizeof(uint64_t); i++) {
        insn_bytes[ins_len + i] = (imm64 >> (i * 8)) & 0xff;
      }
    } else {
      relocations_add_data(relocations, ins->args.imm64_disp8.sec,
                           ins->args.imm64_disp8.imm,
                           ins->args.imm64_disp8.r_offset, context);
    }
    ins_len += sizeof(uint64_t);
    break;
  }
  case IF_ARG_IMM64: {
    /* If the instruction is foreign, we just put 8 empty bytes */
    if (!ins->args.imm64.foreign) {
      uint64_t imm64 = htole64(ins->args.imm64.imm);
      for (size_t i = 0; i < sizeof(uint64_t); i++) {
        insn_bytes[ins_len + i] = (imm64 >> (i * 8)) & 0xff;
      }
    } else {
      relocations_add_data(relocations, ins->args.imm64.sec,
                           ins->args.imm64.imm, ins->args.imm64.r_offset,
                           context);
    }
    ins_len += sizeof(uint64_t);
    break;
  }
  case IF_ARG_DISP8: {
    insn_bytes[ins_len] = ins->args.disp8.disp;
    ins_len += 1;
    break;
  }
  case IF_ARG_DISP32: {
    /* If the instruction is foreign, we just put 4 empty bytes */
    if (!ins->args.disp32.foreign) {
      uint32_t disp32 = htole32(ins->args.disp32.disp);
      for (size_t i = 0; i < sizeof(uint32_t); i++) {
        insn_bytes[ins_len + i] = (disp32 >> (i * 8)) & 0xff;
      }
    } else {
      relocations_add_data(relocations, ins->args.disp32.sec,
                           ins->args.disp32.disp, ins->args.disp32.r_offset,
                           context);
    }
    ins_len += sizeof(uint32_t);
    break;
  }
  case IF_ARG_REG: {
    insn_bytes[ins_len] = ins->args.reg.reg;
    ins_len += 1;
    break;
  }
  case IF_ARG_REG_DISP8: {
    insn_bytes[ins_len] = ins->args.reg_disp8.reg;
    insn_bytes[ins_len + 1] = ins->args.reg_disp8.disp;
    ins_len += 2;
    break;
  }
  case IF_ARG_REG_DISP32: {
    insn_bytes[ins_len] = ins->args.reg_disp32.reg;
    if (!ins->args.reg_disp32.foreign) {
      uint32_t disp32 = htole32(ins->args.reg_disp32.disp);
      for (size_t i = 0; i < sizeof(uint32_t); i++) {
        insn_bytes[ins_len + i] = (disp32 >> (i * 8)) & 0xff;
      }
    } else {
      relocations_add_data(relocations, ins->args.reg_disp32.sec,
                           ins->args.reg_disp32.disp,
                           ins->args.reg_disp32.r_offset, context);
    }
    ins_len += 5;
  }
  }

  switch (ins->opcode) {
  case INS_CALL: {
    if (!ins->args.call_ins.foreign) {
      // Ident function_name = ins->args.call_ins.function_name;
      //
      // uint32_t *offset = hashmap_value(context.labels, &function_name);
      // if (offset != NULL) {
      //  uint32_t encoded =
      //      htole32((*offset) - (context.program_data_offset + opcode_len +
      //      4));
      //  memcpy(insn_bytes + 1, &encoded, sizeof(uint32_t));
      //  ins_len += 4;
      //} else {
      //  fprintf(stderr,
      //          "Tried to call function that doesn't have an offset: %s\n",
      //          function_name);
      //  exit(1);
      //}
      if (relocations != NULL) {
        Relocation reloc = {
            .rel_type = RELOCATION_FUNCTION,
            .symbol = ins->args.call_ins.function_name,
            .program_offset = context.program_data_offset,
        };
        array_add(relocations, reloc);
      }
      ins_len += 4;
    } else {
      if (relocations != NULL) {
        Relocation reloc = {
            .rel_type = RELOCATION_FUNCTION,
            .symbol = ins->args.call_ins.function_name,
            .program_offset = context.program_data_offset,
        };
        array_add(relocations, reloc);
      }
      /* Leave the rest of the instruction bytes 0, relocation will fix it */
      ins_len += 4;
    }
    break;
  }
  case INS_IMUL_RDX_RAX: {
    insn_bytes[ins_len++] = 0xc2;
    break;
  }
  default: {
    break;
  }
  }

  log_debug("Ins len: %zu, opcode len: %zu for ins: %02X %02X %02X", ins_len,
            opcode_len, insn_bytes[0], insn_bytes[1], insn_bytes[2]);

  return ins_len;
}

int cmp_size_t(const void *a, const void *b) {
  size_t x = *(const size_t *)a;
  size_t y = *(const size_t *)b;
  return (x > y) - (x < y); // returns positive, zero, or negative
}

static void data_section_calc_offsets(const DataSection *data_section,
                                      size_t *offsets) {
  size_t offset = 0;
  for (size_t i = 0; i < array_len(data_section->values); i++) {
    array_add(offsets, offset);
    offset += data_section->values[i].bytes_len;
  }
}

void compiler_generate(Compiler *compiler) {
  if (compiler->step != COMPILE_STEP_COMPILE_SRC)
    return;
  compiler->step = COMPILE_STEP_GENERATE_MACHINE;

  compiler->program_data = malloc(512);
  size_t program_data_offset = 0;

  /* Data section indices and their corresponding offsets */
  size_t *data_offsets = array_new(size_t, &HEAP_ALLOCATOR);
  data_section_calc_offsets(&compiler->data_section, data_offsets);
  size_t *rodata_offsets = array_new(size_t, &HEAP_ALLOCATOR);
  data_section_calc_offsets(&compiler->rodata_section, rodata_offsets);

  size_t sizes[compiler->labels.len];
  hashmap_foreach(&compiler->labels, Ident * key, size_t *val,
                  { sizes[_internal_keys_iter_index] = *val; });
  qsort(sizes, compiler->labels.len, sizeof(size_t), cmp_size_t);
  size_t label_idx = 0;

  for (size_t i = 0; i < array_len(compiler->insns); i++) {
    Instruction ins = compiler->insns[i];
    uint8_t insn_bytes[16] = {0};

    GenerationContext context = {.labels = &compiler->labels,
                                 .rodata_section = &compiler->rodata_section,
                                 .rodata_offsets = rodata_offsets,
                                 .data_section = &compiler->data_section,
                                 .data_offsets = data_offsets,
                                 .program_data_offset = program_data_offset};
    size_t ins_len = insn_generate(&ins, NULL, insn_bytes, context);

    if (sizes[label_idx] == i) {
      Ident *label_key;
      hashmap_foreach(&compiler->labels, Ident * key, size_t *val, {
        if ((*val) == i) {
          label_key = key;
          break;
        }
      });

      log_debug("Key for index adjustment: %s", *label_key);

      hashmap_insert(&compiler->labels, label_key, &program_data_offset);

      if (label_idx < array_len(compiler->insns)) {
        label_idx++;
      }
    }

    program_data_offset += ins_len;
  }

  program_data_offset = 0;

  for (size_t i = 0; i < array_len(compiler->insns); i++) {
    Instruction ins = compiler->insns[i];
    uint8_t insn_bytes[16] = {0};

    GenerationContext context = {.labels = &compiler->labels,
                                 .rodata_section = &compiler->rodata_section,
                                 .rodata_offsets = rodata_offsets,
                                 .data_section = &compiler->data_section,
                                 .data_offsets = data_offsets,
                                 .program_data_offset = program_data_offset};
    size_t ins_len =
        insn_generate(&ins, compiler->relocations, insn_bytes, context);

    memcpy(compiler->program_data + program_data_offset, insn_bytes, ins_len);

    program_data_offset += ins_len;
  }

  compiler->program_data_size = program_data_offset;

  log_debug("Labels (fixed)");
  hashmap_foreach(&compiler->labels, Ident * key, size_t *val, {
    log_debug("Key: %s", *key);
    log_debug("Value: %zu", *val);
  });
  log_debug("Labels amount: %zu", compiler->labels.len);
}

#define WRITE(fp, ptr) fwrite(ptr, 1, sizeof(*ptr), fp)

static const char shstrtab_data[] = "\0"
                                    ".text\0"      // Index 1
                                    ".data\0"      // Index 7
                                    ".rodata\0"    // Index 13
                                    ".strtab\0"    // Index 21
                                    ".symtab\0"    // Index 29
                                    ".rela.text\0" // Index 37
                                    ".shstrtab\0"; // Index 48

#define TEXT_INDEX 1
#define DATA_INDEX 2
#define RODATA_INDEX 3
#define STRTAB_INDEX 4
#define SYMTAB_INDEX 5

#define OFF_TEXT_NAME 1
#define OFF_DATA_NAME 7
#define OFF_RODATA_NAME 13
#define OFF_STRTAB_NAME 21
#define OFF_SYMTAB_NAME 29
#define OFF_RELA_TEXT_NAME 37
#define OFF_SHSTRTAB_NAME 48

typedef struct {
  Elf64_Ehdr eh;
  uint8_t *text_section_data;
  size_t text_section_size;
  uint8_t *data_section_data;
  size_t data_section_size;
  uint8_t *rodata_section_data;
  size_t rodata_section_size;
  char *strtab_section_data;
  size_t strtab_section_size;
  size_t strtab_section_capacity;
  const char *shstrtab_section_data;
  Elf64_Sym *symbols;
  Elf64_Rela *relocations;
  Elf64_Shdr sh_null;
  Elf64_Shdr sh_text;
  Elf64_Shdr sh_data;
  Elf64_Shdr sh_rodata;
  Elf64_Shdr sh_strtab;
  Elf64_Shdr sh_symtab;
  Elf64_Shdr sh_rela_text;
  Elf64_Shdr sh_shstrtab;
} Object;

static void obj_write(const Object *obj, FILE *file) {
  WRITE(file, &obj->eh);
  fwrite(obj->text_section_data, 1, obj->text_section_size, file);
  fwrite(obj->data_section_data, 1, obj->data_section_size, file);
  fwrite(obj->rodata_section_data, 1, obj->rodata_section_size, file);
  fwrite(obj->strtab_section_data, 1, obj->strtab_section_size, file);
  // fwrite(obj->symtab_section_data, 1, obj->symtab_section_size, file);
  for (size_t i = 0; i < array_len(obj->symbols); i++) {
    WRITE(file, &obj->symbols[i]);
    log_info("Writing symbol %zu", i);
  }
  for (size_t i = 0; i < array_len(obj->relocations); i++) {
    WRITE(file, &obj->relocations[i]);
    log_info("Writing relocation %zu", i);
  }
  fwrite(shstrtab_data, 1, sizeof(shstrtab_data), file);
  WRITE(file, &obj->sh_null);
  WRITE(file, &obj->sh_text);
  WRITE(file, &obj->sh_data);
  WRITE(file, &obj->sh_rodata);
  WRITE(file, &obj->sh_strtab);
  WRITE(file, &obj->sh_symtab);
  WRITE(file, &obj->sh_rela_text);
  WRITE(file, &obj->sh_shstrtab);
}

static size_t data_section_calc_size(const DataSection *section) {
  size_t values_amount = array_len(section->values);
  size_t data_section_size = 0;
  for (size_t i = 0; i < values_amount; i++) {
    data_section_size += section->values[i].bytes_len;
  }
  return data_section_size;
}

static void data_section_write_bytes(const DataSection *section,
                                     size_t section_size, uint8_t *bytes) {
  size_t values_amount = array_len(section->values);
  size_t i = 0;
  size_t section_offset = 0;
  for (size_t i = 0; i < values_amount; i++) {
    DataValue val = section->values[i];
    for (size_t j = 0; j < val.bytes_len; j++) {
      bytes[section_offset + j] = val.bytes[j];
    }
    section_offset += val.bytes_len;
  }
}

static void obj_add_data(Object *obj, const Compiler *compiler) {
  obj->text_section_data = compiler->program_data;
  obj->text_section_size = compiler->program_data_size;

  size_t data_section_size = data_section_calc_size(&compiler->data_section);
  obj->data_section_data = malloc(data_section_size);
  obj->data_section_size = data_section_size;
  data_section_write_bytes(&compiler->data_section, obj->data_section_size,
                           obj->data_section_data);

  size_t rodata_section_size =
      data_section_calc_size(&compiler->rodata_section);
  obj->rodata_section_data = malloc(rodata_section_size);
  obj->rodata_section_size = rodata_section_size;
  data_section_write_bytes(&compiler->rodata_section, obj->rodata_section_size,
                           obj->rodata_section_data);
}

static size_t obj_string_table_add(Object *obj, char *symbol) {
  size_t symbol_len = strlen(symbol);
  if (obj->strtab_section_capacity <= obj->strtab_section_size + symbol_len) {
    obj->strtab_section_capacity *= 2;
    obj->strtab_section_data =
        realloc(obj->strtab_section_data, obj->strtab_section_capacity + 1);
  }
  memcpy(obj->strtab_section_data + obj->strtab_section_size, symbol,
         symbol_len + 1);
  memcpy(obj->strtab_section_data + obj->strtab_section_size + symbol_len + 2,
         "\0", 1);
  size_t old_size = obj->strtab_section_size;
  obj->strtab_section_size += symbol_len + 1;
  return old_size;
}

static void obj_symbol_table_add_foreign_func(Object *obj, char *func_name) {
  size_t name_idx = obj_string_table_add(obj, func_name);

  Elf64_Sym foreign_func_sym = {0};
  foreign_func_sym.st_name = name_idx;
  foreign_func_sym.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE);
  foreign_func_sym.st_shndx = SHN_UNDEF;
  array_add(obj->symbols, foreign_func_sym);
}

void compiler_write(Compiler *compiler, FILE *file) {
  if (compiler->step != COMPILE_STEP_GENERATE_MACHINE)
    return;
  compiler->step = COMPILE_STEP_OUTPUT_OBJECT;

  Object obj = {0};

  obj.strtab_section_data = malloc(512 + 1);
  memcpy(obj.strtab_section_data, "\0", 2);
  obj.strtab_section_size = 1;
  obj.strtab_section_capacity = 512;

  obj.symbols = array_new(Elf64_Sym, &HEAP_ALLOCATOR);
  obj.relocations = array_new(Elf64_Rela, &HEAP_ALLOCATOR);

  /* Section contents */
  obj_add_data(&obj, compiler);

  /* --- Symbols --- */
  Elf64_Sym sym_null = {0};
  array_add(obj.symbols, sym_null);

  Elf64_Sym sym_text = {0}; // section symbol (.text)
  sym_text.st_info = ELF64_ST_INFO(STB_LOCAL, STT_SECTION);
  sym_text.st_shndx = TEXT_INDEX; // section index of .text
  array_add(obj.symbols, sym_text);

  Elf64_Sym sym_rodata = {0}; // section symbol (.rodata)
  sym_rodata.st_info = ELF64_ST_INFO(STB_LOCAL, STT_SECTION);
  sym_rodata.st_shndx = RODATA_INDEX;
  array_add(obj.symbols, sym_rodata);

  Elf64_Sym sym_data = {0}; // section symbol (.data)
  sym_data.st_info = ELF64_ST_INFO(STB_LOCAL, STT_SECTION);
  sym_data.st_shndx = DATA_INDEX;
  array_add(obj.symbols, sym_data);

  /* Symbols */
  hashmap_foreach(&compiler->labels, Ident * key, size_t *val, {
    size_t name_idx = obj_string_table_add(&obj, *key);

    Elf64_Sym sym = {0};
    sym.st_name = name_idx;
    sym.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    sym.st_other = STV_DEFAULT;
    sym.st_shndx = TEXT_INDEX;
    sym.st_value = *val; // start of section
    sym.st_size = obj.text_section_size;
    array_add(obj.symbols, sym);
  });

  /* Relocations */
  for (size_t i = 0; i < array_len(compiler->relocations); i++) {
    Relocation reloc = compiler->relocations[i];

    Elf64_Rela rela = {0};
    switch (reloc.rel_type) {
    case RELOCATION_FUNCTION: {
      size_t sym_idx = array_len(obj.symbols);
      obj_symbol_table_add_foreign_func(&obj, reloc.symbol);
      /* Uses 1 as an additional offset because thats the opcode length of the
       * call instruction */
      rela.r_offset = reloc.program_offset + 1;
      rela.r_info = ELF64_R_INFO(sym_idx, R_X86_64_PLT32);
      rela.r_addend = -4;
      break;
    }
    case RELOCATION_DATA:
    case RELOCATION_RODATA: {
      rela.r_offset = reloc.program_offset + reloc.r_offset;
      rela.r_info = ELF64_R_INFO(reloc.rel_type == RELOCATION_DATA ? 3 : 2,
                                 R_X86_64_PC32);
      rela.r_addend = -4 + reloc.data_offset;
      log_debug("RODATA/DATA with offset: %zu, symbol shndx: %hu",
                rela.r_offset, obj.symbols[2].st_shndx);
      break;
    }
    default: {
      fprintf(stderr, "Failed to create relocation");
      exit(1);
    }
    }
    log_debug("Created relocation %zu for offset: %zu", i, rela.r_offset);
    array_add(obj.relocations, rela);
  }

  const Elf64_Off elf_header_offset = 0x0;
  const Elf64_Off text_offset = sizeof(Elf64_Ehdr);
  const Elf64_Off data_offset = text_offset + obj.text_section_size;
  const Elf64_Off rodata_offset = data_offset + obj.data_section_size;
  const Elf64_Off strtab_offset = rodata_offset + obj.rodata_section_size;
  const Elf64_Off symtab_offset = strtab_offset + obj.strtab_section_size;
  const Elf64_Off rela_text_off =
      symtab_offset + sizeof(Elf64_Sym) * array_len(obj.symbols);
  const Elf64_Off shstrtab_offset =
      rela_text_off + sizeof(Elf64_Rela) * array_len(obj.relocations);
  const Elf64_Off sh_table_offset = shstrtab_offset + sizeof(shstrtab_data);

  /* Elf Header */
  Elf64_Ehdr *eh = &obj.eh;
  memcpy(eh->e_ident, ELFMAG, SELFMAG);
  eh->e_ident[EI_CLASS] = ELFCLASS64;
  eh->e_ident[EI_DATA] = ELFDATA2LSB;
  eh->e_ident[EI_VERSION] = EV_CURRENT;
  eh->e_ident[EI_OSABI] = ELFOSABI_SYSV;

  eh->e_type = ET_REL;
  eh->e_machine = EM_X86_64;
  eh->e_version = EV_CURRENT;
  eh->e_ehsize = sizeof(Elf64_Ehdr);
  eh->e_shentsize = sizeof(Elf64_Shdr);
  eh->e_shnum = 8; /* 8 Sections: NULL, .text, .data, .rodata, .strtab,
                      .symtab, .rela.text, .shstrtab */
  eh->e_shstrndx = 7;
  eh->e_shoff = sh_table_offset;

  log_info("Symbols: %zu, Relocations: %zu - SH Table offset: %zu, Size: %zu\n",
           array_len(obj.symbols) + 2, array_len(obj.relocations),
           sh_table_offset, eh->e_shoff + eh->e_shentsize * eh->e_shnum);

  /* Section Header */

  /* Text Section */
  Elf64_Shdr *sh_text = &obj.sh_text;
  sh_text->sh_name = OFF_TEXT_NAME;
  sh_text->sh_type = SHT_PROGBITS;
  sh_text->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
  sh_text->sh_offset = text_offset;
  sh_text->sh_size = obj.text_section_size;
  sh_text->sh_addralign = 16;

  /* Data Section */
  Elf64_Shdr *sh_data = &obj.sh_data;
  sh_data->sh_name = OFF_DATA_NAME;
  sh_data->sh_type = SHT_PROGBITS;
  sh_data->sh_flags = SHF_ALLOC | SHF_WRITE;
  sh_data->sh_offset = data_offset;
  sh_data->sh_size = obj.data_section_size;
  sh_data->sh_addralign = 8;

  Elf64_Shdr *sh_rodata = &obj.sh_rodata;
  sh_rodata->sh_name = OFF_RODATA_NAME;
  sh_rodata->sh_type = SHT_PROGBITS;
  sh_rodata->sh_flags = SHF_ALLOC;
  sh_rodata->sh_offset = rodata_offset;
  sh_rodata->sh_size = obj.rodata_section_size;
  sh_rodata->sh_addralign = 8;

  Elf64_Shdr *sh_strtab = &obj.sh_strtab;
  sh_strtab->sh_name = OFF_STRTAB_NAME;
  sh_strtab->sh_type = SHT_STRTAB;
  sh_strtab->sh_offset = strtab_offset;
  sh_strtab->sh_size = obj.strtab_section_size;
  sh_strtab->sh_addralign = 1;

  Elf64_Shdr *sh_symtab = &obj.sh_symtab;
  sh_symtab->sh_name = OFF_SYMTAB_NAME;
  sh_symtab->sh_type = SHT_SYMTAB;
  sh_symtab->sh_offset = symtab_offset;
  sh_symtab->sh_size = sizeof(Elf64_Sym) * array_len(obj.symbols);
  sh_symtab->sh_link = STRTAB_INDEX;
  sh_symtab->sh_info = 4; // 5 because that is the index of the main symbol. All
                          // symbols >= 4 are global
  sh_symtab->sh_addralign = 8;
  sh_symtab->sh_entsize = sizeof(Elf64_Sym);

  Elf64_Shdr *sh_rela_text = &obj.sh_rela_text;
  sh_rela_text->sh_name = OFF_RELA_TEXT_NAME;
  sh_rela_text->sh_type = SHT_RELA;
  sh_rela_text->sh_offset = rela_text_off;
  sh_rela_text->sh_size = sizeof(Elf64_Rela) * array_len(compiler->relocations);
  sh_rela_text->sh_link = SYMTAB_INDEX;
  sh_rela_text->sh_info = TEXT_INDEX;
  sh_rela_text->sh_addralign = 8;
  sh_rela_text->sh_entsize = sizeof(Elf64_Rela);

  /* String Table Section */
  Elf64_Shdr *sh_shstrtab = &obj.sh_shstrtab;
  sh_shstrtab->sh_name = OFF_SHSTRTAB_NAME;
  sh_shstrtab->sh_type = SHT_STRTAB;
  sh_shstrtab->sh_offset = shstrtab_offset;
  sh_shstrtab->sh_size = sizeof(shstrtab_data);
  sh_shstrtab->sh_addralign = 1;

  obj_write(&obj, file);
}
