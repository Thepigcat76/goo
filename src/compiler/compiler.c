#include "../../include/compiler.h"
#include "lilc/array.h"
#include "lilc/eq.h"
#include "lilc/hash.h"
#include <complex.h>
#include <elf.h>
#include <endian.h>
#include <stdio.h>
#include <lilc/alloc.h>
#include <lilc/hashmap.h>
#include <lilc/log.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#define STACK_OBJ(_offset, _size)                                              \
  (StackObject) { .offset = _offset, .size = _size }

#define REG_EIP 0

#define RELOCATIONS_ADD(compiler_ptr, ...)                                     \
  do {                                                                         \
    Relocation _internal_reloc = __VA_ARGS__;                                  \
    _internal_reloc.program_offset = compiler_ptr->program_size;               \
    log_debug("Relocation Program offset: %zu", compiler_ptr->program_size);   \
    array_add(compiler_ptr->relocations, _internal_reloc);                     \
  } while (0)

static inline DataSection data_section_new(void) {
  return (DataSection){.data_bytes = malloc(256),
                       .data_capacity = 256,
                       .section_lookup =
                           hashmap_new(Ident *, size_t, &HEAP_ALLOCATOR,
                                       str_ptrv_hash, str_ptrv_eq, NULL)};
}

Compiler compiler_new(const Statement *statements) {
  return (Compiler){
      .stmts = statements,
      .relocations = array_new(Relocation, &HEAP_ALLOCATOR),
      .insns = array_new_capacity(Instruction, 32, &HEAP_ALLOCATOR),
      .symbols = hashmap_new(Ident *, size_t, &HEAP_ALLOCATOR, str_ptrv_hash,
                             str_ptrv_eq, NULL),
      .globals = hashmap_new(Ident *, GlobalDataLocation, &HEAP_ALLOCATOR,
                             str_ptrv_hash, str_ptrv_eq, NULL),
      .data_section = data_section_new(),
      .rodata_section = data_section_new(),
      .elf64_relocations = array_new(Elf64_Relocation, &HEAP_ALLOCATOR)};
}

static void data_section_print(char *buf, const DataSection *ds) {
  // buf[0] = '\0';
  // strcat(buf, "--- BEGIN ---\n");
  // size_t *printed_indices = array_new(size_t, &HEAP_ALLOCATOR);
  // hashmap_foreach(&ds->section_lookup, Ident * key, size_t *val, {
  //   DataValue dv = ds->values[*val];
  //   char bytes_buf[256] = {0};
  //   for (size_t i = 0; i < dv.bytes_len; i++) {
  //     char byte_buf[16];
  //     sprintf(byte_buf, "%02X ", dv.bytes[i]);
  //     strcat(bytes_buf, byte_buf);
  //   }
  //   strcat(bytes_buf, "(");
  //   for (size_t i = 0; i < dv.bytes_len; i++) {
  //     char byte_buf[16];
  //     sprintf(byte_buf, "%c", dv.bytes[i]);
  //     if (dv.bytes[i] == 0) {
  //       sprintf(byte_buf, "\\0");
  //     }
  //     strcat(bytes_buf, byte_buf);
  //   }
  //   strcat(bytes_buf, ")");
  //   char final_buf[512];
  //   sprintf(final_buf, "'%s' - %s\n", *key, bytes_buf);
  //   strcat(buf, final_buf);
  //   array_add(printed_indices, *val);
  // });
  // for (size_t i = 0; i < array_len(ds->values); i++) {
  //   bool printed = false;
  //   for (size_t j = 0; j < array_len(printed_indices); j++) {
  //     if (printed_indices[j] == i) {
  //       printed = true;
  //       break;
  //     }
  //   }
  //   if (!printed) {
  //     DataValue dv = ds->values[i];
  //     char bytes_buf[256] = {0};
  //     for (size_t i = 0; i < dv.bytes_len; i++) {
  //       char byte_buf[16];
  //       sprintf(byte_buf, "%02X ", dv.bytes[i]);
  //       strcat(bytes_buf, byte_buf);
  //     }
  //     strcat(bytes_buf, "(");
  //     for (size_t i = 0; i < dv.bytes_len; i++) {
  //       char byte_buf[16];
  //       sprintf(byte_buf, "%c", dv.bytes[i]);
  //       if (dv.bytes[i] == 0) {
  //         sprintf(byte_buf, "\\0");
  //       }
  //       strcat(bytes_buf, byte_buf);
  //     }
  //     strcat(bytes_buf, ")");
  //     char final_buf[512];
  //     sprintf(final_buf, "<inlined> - %s\n", bytes_buf);
  //     strcat(buf, final_buf);
  //   }
  // }
  // strcat(buf, "--- END ---");
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

typedef enum {
  COMPILE_LEVEL_GLOBAL,
  COMPILE_LEVEL_LOCAL,
} CompileLevel;

typedef struct {
  CompileLevel level;
  const char *function_name;
} CompileContext;

static inline void insns_add(Compiler *compiler, Instruction ins) {
  array_add(compiler->insns, ins);
  size_t len = ins_gen(&ins, NULL);
  compiler->program_size += len;
  log_debug("Ins len: %zu", len);
}

static void stmt_compile(Compiler *compiler, const Statement *stmt,
                         CompileContext context);

static inline void stack_frame_push(Compiler *compiler) {
  Instruction ins = INS_PUSH_R32(REG_EBP);
  insns_add(compiler, ins);
}

static inline void stack_frame_reset(Compiler *compiler) {
  Instruction ins = INS_MOV_R32_R32(REG_ESP, REG_EBP);
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

typedef struct {
  enum {
    EXPR_COMPILE_RES_RODATA_OFFSET,
    EXPR_COMPILE_RES_DATA_OFFSET,
    EXPR_COMPILE_RES_IMM32,
    EXPR_COMPILE_RES_STACK_OBJ,
    EXPR_COMPILE_RES_REG,
  } type;
  union {
    struct {
      DataType data_type;
      size_t offset;
    } data_offset;
    uint32_t imm32;
    StackObject stack_obj;
    Register reg;
  } var;
  size_t size;
} ExprCompileResult;

typedef struct {
  enum {
    EXPR_CALL_RES_IMM32,
  } type;
  union {
    uint32_t imm32;
  } var;
} ExprCallResult;

#define EXPR_COMPILE_RES(_type, _size, ...)                                    \
  (ExprCompileResult) { .type = _type, .var = {__VA_ARGS__}, .size = _size }

static void compiler_arg_push(Compiler *compiler, size_t arg_idx,
                              const ExprCompileResult *res);

static ExprCompileResult expr_compile_with_res(Compiler *compiler,
                                               const Expression *expr,
                                               Register bin_op_res_reg);

static ExprCompileResult expr_compile(Compiler *compiler,
                                      const Expression *expr) {
  return expr_compile_with_res(compiler, expr, -1);
}

static ExprCompileResult expr_call_compile(Compiler *compiler,
                                           const ExprCall *expr_call) {
  for (size_t i = 0; i < array_len(expr_call->args); i++) {
    Expression arg = expr_call->args[i];
    ExprCompileResult res = expr_compile(compiler, &arg);
    compiler_arg_push(compiler, i, &res);
  }

  RELOCATIONS_ADD(compiler, {.sec = SECTION_TYPE_TEXT,
                             .r_offset = 1,
                             .symbol = strv_eq(expr_call->function, "println")
                                           ? "puts"
                                           : expr_call->function});

  // size_t placeholder_0 = 0;
  //// FIXME: do we need reloc info for these calls?
  // if (strv_eq(expr_call->function, "println")) {
  //   //hashmap_insert(&compiler->extern_functions, &PRINTF_FUNCTION_NAME,
  //   //               &placeholder_0);
  //   insns_add(compiler, INS_CALL);
  // } else if (strv_eq(expr_call->function, "exit") ||
  //            strv_eq(expr_call->function, "print_int")) {
  //   //hashmap_insert(&compiler->extern_functions, &expr_call->function,
  //   //               &placeholder_0);
  //   insns_add(compiler, INS_CALL);
  // } else {
  insns_add(compiler, INS_CALL);
  //}

  return EXPR_COMPILE_RES(EXPR_COMPILE_RES_REG, sizeof(uint64_t),
                          .reg = REG_EAX);
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

static void compiler_stack_alloc_reg(Compiler *compiler, Ident *name,
                                     Register reg) {
  compiler->cur_frame.sp_offset += 8;
  hashmap_insert(&compiler->cur_frame.symbol_table, name,
                 &STACK_OBJ(compiler->cur_frame.sp_offset, sizeof(uint64_t)));
  insns_add(compiler,
            INS_MOV_R32_R32_DISP8(
                reg, REG_EBP, IMM32_PACK(256 - compiler->cur_frame.sp_offset)));
  // TODO: Reenable
  // insns_add(compiler,
  //          INSN(INS_MOV_REG64_REG64_DISP8, .op0_reg = reg, .op1_reg =
  //          REG_RBP,
  //               .op0_size = sizeof(uint64_t), .op1_size = sizeof(uint64_t),
  //               .disp = 256 - compiler->cur_frame.sp_offset,
  //               .near_disp = true));
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
  log_info("[COMPILER] Pushed new stack frame");
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
    insns_add(compiler, INS_XOR_R32_R32(REG_EAX, REG_EAX));
  }

  if (uses_stack) {
    size_t stack_size = ALIGN_BY(compiler->cur_frame.sp_offset, 16);
    // insns_add(compiler, INSN(INS_ADD_IMM8_RSP, .op0 = {.imm = 0x10},
    //                                 .op0_size = sizeof(uint8_t)));
    insns_add(compiler, INS_ADD_I8_R64(IMM32_PACK(stack_size), REG_ESP));
    stack_frame_pop(compiler);
    stack_fix_sub_stack_size(compiler->insns,
                             compiler->cur_frame.sub_stack_size_ins_idx,
                             stack_size);
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

/* Sets the opcode to the one for performing specified op with imm32. Returns
 * whether the operation is supported */
static bool opcode_imm32_rax_bin_op(Opcode *opcode, BinOperator op) {
  switch (op) {
  // case BIN_OP_ADD:
  //   *opcode = INS_ADD_IMM32_RAX;
  //   return true;
  // case BIN_OP_SUB:
  //   *opcode = INS_SUB_IMM32_RAX;
  //   return true;
  // case BIN_OP_MUL:
  //   *opcode = INS_MUL_IMM32_RAX;
  //   return true;
  default:
    return false;
  }
}

/* Sets the opcode to the one for performing specified op with imm32. Returns
 * whether the operation is supported */
static bool opcode_rdx_rax_bin_op(Opcode *opcode, BinOperator op) {
  switch (op) {
  // case BIN_OP_ADD:
  //   *opcode = INS_ADD_RDX_RAX;
  //   return true;
  // case BIN_OP_SUB:
  //   *opcode = INS_SUB_RDX_RAX;
  //   return true;
  // case BIN_OP_MUL:
  //   *opcode = INS_IMUL_RDX_RAX;
  //   return true;
  default:
    return false;
  }
}

static bool opcode_imm32_reg_bin_op(Opcode *opcode, BinOperator op) {
  switch (op) {
  // case BIN_OP_ADD:
  //   *opcode = INS_ADD_IMM32_REG;
  //   return true;
  // case BIN_OP_SUB:
  //   *opcode = INS_SUB_IMM32_REG;
  //   return true;
  // case BIN_OP_MUL:
  //   *opcode = INS_MUL_IMM32_REG;
  //   return true;
  default:
    return false;
  }
}

#define SECTION_FROM_EXPR_RES(expr_res_type)                                   \
  expr_res_type == EXPR_COMPILE_RES_DATA_OFFSET ? SECTION_TYPE_DATA            \
                                                : SECTION_TYPE_RODATA

static ExprCompileResult expr_bin_op_compile(Compiler *compiler,
                                             const ExprBinOp *expr_bin_op,
                                             Register res_reg) {
  ExprCompileResult res_left =
      expr_compile_with_res(compiler, expr_bin_op->left, REG_EAX);
  ExprCompileResult res_right =
      expr_compile_with_res(compiler, expr_bin_op->right, REG_EDX);
  if (res_left.type == EXPR_COMPILE_RES_IMM32 &&
      res_right.type == EXPR_COMPILE_RES_IMM32) {
    return EXPR_COMPILE_RES(EXPR_COMPILE_RES_IMM32, sizeof(uint32_t),
                            .imm32 = apply_lit_bin_op(res_left.var.imm32,
                                                      res_right.var.imm32,
                                                      expr_bin_op->op));
  } else if (expr_bin_op->op == BIN_OP_ADD || expr_bin_op->op == BIN_OP_SUB ||
             expr_bin_op->op == BIN_OP_MUL) {
    switch (res_left.type) {
    case EXPR_COMPILE_RES_IMM32: {
      switch (res_right.type) {
      case EXPR_COMPILE_RES_RODATA_OFFSET:
      case EXPR_COMPILE_RES_DATA_OFFSET: {
        printf("REG_IMM32 target register during bin op: %d\n", res_reg);
        insns_add(compiler, INS_MOV_I32_R32(res_reg, {0}));
        RELOCATIONS_ADD(compiler,
                        {.r_offset = 1,
                         .sec = SECTION_FROM_EXPR_RES(res_right.type),
                         .data_offset = res_right.var.data_offset.offset});
        Opcode opcode;
        opcode_imm32_reg_bin_op(&opcode, expr_bin_op->op);
        insns_add(compiler,
                  INS_ADD_I32_R64(IMM32_PACK(res_left.var.imm32), res_reg));
        //           INSN(INS_ADD_I32_REG, .op0 = {.imm = res_left.var.imm32},
        //                .op0_size = sizeof(uint32_t),
        //                .op1 = {.reg = REG_BASE_05(res_reg)},
        //                .op1_size = sizeof(uint32_t)));
        return EXPR_COMPILE_RES(EXPR_COMPILE_RES_REG, sizeof(uint64_t),
                                .reg = res_reg);
      }
      case EXPR_COMPILE_RES_STACK_OBJ: {
        break;
      }
      case EXPR_COMPILE_RES_REG: {
        break;
      }
      default: {
        break;
      }
      }
      break;
    }
    case EXPR_COMPILE_RES_RODATA_OFFSET:
    case EXPR_COMPILE_RES_DATA_OFFSET:
    case EXPR_COMPILE_RES_STACK_OBJ: {
      StackObject stack_obj = res_left.var.stack_obj;
      insns_add(compiler, INS_MOV_R64_DISP32_R64(
                              REG_EBP, IMM32_PACK(-stack_obj.offset), res_reg));
      switch (res_right.type) {
      case EXPR_COMPILE_RES_RODATA_OFFSET: {
        break;
      }
      case EXPR_COMPILE_RES_DATA_OFFSET: {
        break;
      }
      case EXPR_COMPILE_RES_IMM32: {
        insns_add(compiler,
                  INS_ADD_I32_R64(IMM32_PACK(res_right.var.imm32), res_reg));
        return EXPR_COMPILE_RES(EXPR_COMPILE_RES_REG, sizeof(uint64_t),
                                .reg = res_reg);
      }
      case EXPR_COMPILE_RES_STACK_OBJ: {
        break;
      }
      case EXPR_COMPILE_RES_REG: {
        break;
      }
      }
      break;
    }
    case EXPR_COMPILE_RES_REG:
      break;
    }
  }
}

static void stack_dump(const Frame *frame) {
  puts("-- STACK-DUMP --");
  printf("Stack size: %zu\n", frame->sp_offset);
  hashmap_foreach(&frame->symbol_table, Ident * key, StackObject * val, {
    printf("| '%s' at %zu with size %zu\n", *key, val->offset, val->size);
  });
  puts("-- END-STACK-DUMP --");
}

static size_t for_loop_idx = 0;

static ExprCompileResult expr_compile_with_res(Compiler *compiler,
                                               const Expression *expr,
                                               Register bin_op_res_reg) {
  switch (expr->type) {
  case EXPR_STRING_LIT: {
    size_t rodata_idx =
        expr_string_lit_compile(compiler, &expr->var.expr_string_literal);
    return EXPR_COMPILE_RES(
        EXPR_COMPILE_RES_RODATA_OFFSET, sizeof(uint8_t *),
        .data_offset = {.offset = rodata_idx, .data_type = DATA_POINTER});
  }
  case EXPR_INTEGER_LIT: {
    return EXPR_COMPILE_RES(EXPR_COMPILE_RES_IMM32, sizeof(uint32_t),
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
      return EXPR_COMPILE_RES(
          data_loc->type == GLOB_DATA_LOC_DATA ? EXPR_COMPILE_RES_DATA_OFFSET
                                               : EXPR_COMPILE_RES_RODATA_OFFSET,
          sizeof(uint8_t *),
          .data_offset = {.offset = data_loc->data_offset,
                          .data_type = data_loc->data_type});
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
                               bin_op_res_reg == -1 ? REG_EAX : bin_op_res_reg);
  }
  case EXPR_FOR: {
    if (!expr->var.expr_for.has_range) {
      Statement *stmts = expr->var.expr_for.block.statements;
      for_loop_idx = array_len(compiler->insns);
      size_t for_loop_begin = compiler->program_size;
      for (size_t i = 0; i < array_len(stmts); i++) {
        stmt_compile(compiler, &stmts[i],
                     (CompileContext){.level = COMPILE_LEVEL_LOCAL,
                                      .function_name = NULL});
      }
      insns_add(compiler,
                INS_JMP_DISP8(
                    {for_loop_begin - compiler->program_size - 2, 0, 0, 0}));
    }
    return (ExprCompileResult){0};
  }
  case EXPR_BOOLEAN_LIT: {
    return EXPR_COMPILE_RES(EXPR_COMPILE_RES_IMM32, 4, .imm32 = expr->var.expr_boolean_literal.boolean);
  }
  case EXPR_IF: {
    log_debug("Compiling if expression");
    ExprIf expr_if = expr->var.expr_if;
    ExprCompileResult expr_res = expr_compile(compiler, expr_if.condition);
    if (expr_res.type == EXPR_COMPILE_RES_REG) {
      insns_add(compiler, INS_CMP_I8_R64(expr_res.var.reg, IMM32_PACK(0)));
    }
    size_t jne_ins_idx = array_len(compiler->insns);
    insns_add(compiler, INS_JE_DISP8(IMM32_PACK(0)));
    size_t jne_program_size = compiler->program_size;
    for (size_t i = 0; i < array_len(expr_if.block.statements); i++) {
      Statement *stmt = &expr_if.block.statements[i];
      stmt_compile(compiler, stmt, (CompileContext){});
    }
    compiler->insns[jne_ins_idx].disp[0] = compiler->program_size - jne_program_size;
    return (ExprCompileResult){0};
  }
  default: {
    fprintf(stderr, "Failed to compile expr %d, not yet implemented\n", expr->type);
    exit(1);
  }
  }
}

static void compiler_arg_push(Compiler *compiler, size_t arg_idx,
                              const ExprCompileResult *res) {
  uint32_t x = 0xffffffff;
  switch (res->type) {
  case EXPR_COMPILE_RES_IMM32: {
    Register arg_reg;
    reg_for_arg(&arg_reg, arg_idx);
    insns_add(compiler, INS_MOV_I32_R64(arg_reg, IMM32_PACK(res->var.imm32)));
    break;
  }
  case EXPR_COMPILE_RES_DATA_OFFSET:
  case EXPR_COMPILE_RES_RODATA_OFFSET: {
    Register arg_reg;
    bool valid = reg_for_arg(&arg_reg, arg_idx);
    if (res->var.data_offset.data_type == DATA_POINTER) {
      // TODO: Relocation info
      RELOCATIONS_ADD(compiler, {.sec = SECTION_FROM_EXPR_RES(res->type),
                                 .r_offset = 3,
                                 .data_offset = res->var.data_offset.offset});
      log_debug("Pushed Arg offset: %zu", res->var.data_offset.offset);
      insns_add(compiler, INS_LEA_ABS_ADDR32_R64(IMM32_PACK(0), arg_reg));
      // insns_add(compiler,
      //           INSN(INS_LEA_RIP_REG, .op0 = {.reg = REG_BASE_05(arg_reg)},
      //                .op0_size = sizeof(uint64_t),
      //                .disp = res->var.data_idx.idx, .near_disp = false,
      //                .reloc_info = {.foreign = true,
      //                               .sec = SECTION_FROM_EXPR_RES(res->type),
      //                               .r_offset = 3}));
    } else {
      RELOCATIONS_ADD(compiler, {.sec = SECTION_FROM_EXPR_RES(res->type),
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
          INS_MOV_R32_DISP8_R32(
              REG_EBP, IMM32_PACK(256 - res->var.stack_obj.offset), arg_reg));
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
    } else if (expr.type == EXPR_FOR || expr.type == EXPR_IF) {
      expr_compile(compiler, &expr);
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
          hashmap_insert(&compiler->symbols, &stmt_decl.name,
                         &compiler->program_size);
          expr_func_compile(compiler, &expr.var.expr_function,
                            (CompileContext){.level = COMPILE_LEVEL_GLOBAL,
                                             .function_name = stmt_decl.name});
        } else if (expr.type == EXPR_INTEGER_LIT) {
          uint64_t val = expr.var.expr_integer_literal.integer;
          uint64_t le = htole64(val);

          uint8_t *bytes = malloc(8);
          memcpy(bytes, &le, sizeof(le));

          size_t offset =
              data_section_add(data_section, &stmt_decl.name, bytes, 8);
          GlobalDataLocation loc = {
              .type = stmt_decl.mut ? GLOB_DATA_LOC_DATA : GLOB_DATA_LOC_RODATA,
              .data_type = DATA_IMMEDIATE,
              .data_offset = offset};
          hashmap_insert(&compiler->globals, &stmt_decl.name, &loc);

          log_debug("Added data to section: %zu", val);
        } else if (expr.type == EXPR_STRING_LIT) {
          char *string = expr.var.expr_string_literal.string;
          size_t offset =
              data_section_add(data_section, &stmt_decl.name, (uint8_t *)string,
                               strlen(string) + 1);
          GlobalDataLocation loc = {
              .type = stmt_decl.mut ? GLOB_DATA_LOC_DATA : GLOB_DATA_LOC_RODATA,
              .data_type = DATA_POINTER,
              .data_offset = offset};
          hashmap_insert(&compiler->globals, &stmt_decl.name, &loc);
        }
      } else {
        ExprCompileResult res = expr_compile(compiler, &expr);
        switch (res.type) {
        case EXPR_COMPILE_RES_IMM32: {
          compiler_stack_alloc_imm32(compiler, &stmt_decl.name, res.var.imm32);
          break;
        }
        case EXPR_COMPILE_RES_DATA_OFFSET:
        case EXPR_COMPILE_RES_RODATA_OFFSET: {
          compiler->cur_frame.sp_offset += sizeof(char *);
          hashmap_insert(
              &compiler->cur_frame.symbol_table, &stmt_decl.name,
              &STACK_OBJ(compiler->cur_frame.sp_offset, sizeof(char *)));
          RELOCATIONS_ADD(compiler, {.sec = SECTION_FROM_EXPR_RES(res.type),
                                     .data_offset = res.var.data_offset.offset,
                                     .r_offset = 3});
          insns_add(compiler, INS_LEA_ABS_ADDR32_R64(IMM32_PACK(0), REG_EAX));
          insns_add(compiler, INS_MOV_R64_R64_DISP32(
                                  REG_EAX, REG_EBP,
                                  IMM32_PACK(-compiler->cur_frame.sp_offset)));
          break;
        }
        case EXPR_COMPILE_RES_REG: {
          compiler_stack_alloc_reg(compiler, &stmt_decl.name, res.var.reg);
          break;
        }
        case EXPR_COMPILE_RES_STACK_OBJ: {
          StackObject stack_obj = res.var.stack_obj;
          compiler->cur_frame.sp_offset += stack_obj.size;
          hashmap_insert(
              &compiler->cur_frame.symbol_table, &stmt_decl.name,
              &STACK_OBJ(compiler->cur_frame.sp_offset, stack_obj.size));
          insns_add(compiler,
                    INS_MOV_R64_DISP32_R64(
                        REG_EBP, IMM32_PACK(-stack_obj.offset), REG_EAX));
          insns_add(compiler, INS_MOV_R64_R64_DISP32(
                                  REG_EAX, REG_EBP,
                                  IMM32_PACK(-compiler->cur_frame.sp_offset)));
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
        insns_add(compiler,
                  INS_MOV_I32_R32(REG_EAX, IMM32_PACK(res.var.imm32)));
        break;
      }
      case EXPR_COMPILE_RES_DATA_OFFSET:
      case EXPR_COMPILE_RES_RODATA_OFFSET: {
        RELOCATIONS_ADD(compiler, {.sec = SECTION_FROM_EXPR_RES(res.type),
                                   .r_offset = 3,
                                   .data_offset = res.var.data_offset.offset});
        insns_add(compiler, INS_LEA_ABS_ADDR32_R64(IMM32_PACK(0), REG_EAX));
        break;
      }
      default: {
        break;
      }
      }
    }
    break;
  }
  case STMT_ASSIGN: {
    StmtAssign stmt_assign = stmt->var.stmt_assign;
    if (stmt_assign.left_ident_type == ACCESS_TYPE_STRUCT_ACCESS)
      return;

    StackObject *stack_obj = hashmap_value(&compiler->cur_frame.symbol_table,
                                           &stmt_assign.left_ident.ident);
    if (stack_obj != NULL) {
      ExprCompileResult expr_compile_res =
          expr_compile(compiler, &stmt_assign.right_expr);
      hashmap_insert(&compiler->cur_frame.symbol_table,
                     &stmt_assign.left_ident.ident,
                     &STACK_OBJ(stack_obj->offset, expr_compile_res.size));
      switch (expr_compile_res.type) {
      case EXPR_COMPILE_RES_RODATA_OFFSET: {
        break;
      }
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
  }
}

static const CompileContext GLOBAL_COMPILE_CONTEXT = {
    .level = COMPILE_LEVEL_GLOBAL, .function_name = NULL};

void compiler_compile(Compiler *compiler) {
  compiler->step = COMPILE_STEP_COMPILE_SRC;

  log_info("[COMPILER] Start compiling");

  size_t stmts_len = array_len(compiler->stmts);
  while (compiler->stmt_index < stmts_len) {
    stmt_compile(compiler, &compiler->stmts[compiler->stmt_index],
                 GLOBAL_COMPILE_CONTEXT);
    compiler->stmt_index++;
  }
}

#define htole(imm, size)                                                       \
  size == 2 ? htole16(imm)                                                     \
            : (size == 2 ? htole32(imm) : (size == 3 ? htole64(imm) : imm))

int32_t cmp_size_t(const void *a, const void *b) {
  size_t x = *(const size_t *)a;
  size_t y = *(const size_t *)b;
  return (x > y) - (x < y); // returns positive, zero, or negative
}

void compiler_generate(Compiler *compiler) {
  if (compiler->step != COMPILE_STEP_COMPILE_SRC)
    return;
  compiler->step = COMPILE_STEP_GENERATE_MACHINE;

  log_info("[COMPILER] Start generating machine code");

  compiler->program_data = malloc(512);
  size_t program_data_offset = 0;

  for (size_t i = 0; i < array_len(compiler->insns); i++) {
    Instruction ins = compiler->insns[i];
    uint8_t insn_bytes[16] = {0};

    size_t ins_len = ins_gen(&ins, insn_bytes);

    memcpy(compiler->program_data + program_data_offset, insn_bytes, ins_len);

    program_data_offset += ins_len;
  }

  for (size_t i = 0; i < array_len(compiler->relocations); i++) {
    Relocation reloc = compiler->relocations[i];
    Elf64_Relocation elf64_reloc;
    if (reloc.symbol != NULL && reloc.sec == SECTION_TYPE_TEXT) {
      elf64_reloc.rel_type = RELOCATION_FUNCTION;
      elf64_reloc.symbol = reloc.symbol;
    } else {
      RelocationType rel_type;
      if (reloc.sec == SECTION_TYPE_RODATA) {
        rel_type = RELOCATION_RODATA;
      } else if (reloc.sec == SECTION_TYPE_DATA) {
        rel_type = RELOCATION_DATA;
      } else {
        fprintf(stderr, "Illegal section lol\n");
        exit(1);
      }
      elf64_reloc.rel_type = rel_type;
      elf64_reloc.data_offset = reloc.data_offset;
    }
    elf64_reloc.program_offset = reloc.program_offset;
    elf64_reloc.r_offset = reloc.r_offset;
    log_debug("R-offset: %u", reloc.r_offset);
    array_add(compiler->elf64_relocations, elf64_reloc);
  }

  compiler->program_data_size = program_data_offset;

  log_debug("Labels (fixed)");
  hashmap_foreach(&compiler->symbols, Ident * key, size_t *val, {
    log_debug("Key: %s", *key);
    log_debug("Value: %zu", *val);
  });
  log_debug("Labels amount: %zu", compiler->symbols.len);
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

static inline void data_section_write_bytes(const DataSection *section,
                                            uint8_t *bytes) {
  memcpy(bytes, section->data_bytes, section->data_len);
}

static void obj_add_data(Object *obj, const Compiler *compiler) {
  obj->text_section_data = compiler->program_data;
  obj->text_section_size = compiler->program_data_size;

  obj->data_section_data = malloc(compiler->data_section.data_len);
  obj->data_section_size = compiler->data_section.data_len;
  data_section_write_bytes(&compiler->data_section, obj->data_section_data);

  obj->rodata_section_data = malloc(compiler->rodata_section.data_len);
  obj->rodata_section_size = compiler->rodata_section.data_len;
  data_section_write_bytes(&compiler->rodata_section, obj->rodata_section_data);
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

  log_info("[COMPILER] Start writing object file");

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
  hashmap_foreach(&compiler->symbols, Ident * key, size_t *val, {
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
  for (size_t i = 0; i < array_len(compiler->elf64_relocations); i++) {
    Elf64_Relocation reloc = compiler->elf64_relocations[i];

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
    log_debug("Created relocation %zu for r-offset: %zu, type: %s, "
              "data_offset: %zu, symbol: %s",
              i, rela.r_offset,
              reloc.rel_type == RELOCATION_DATA ||
                      reloc.rel_type == RELOCATION_RODATA
                  ? "DATA"
                  : "FUNCTION",
              reloc.data_offset,
              reloc.rel_type == RELOCATION_FUNCTION ? reloc.symbol : "<EMPTY>");
    array_add(obj.relocations, rela);
  }

  const Elf64_Off elf_header_offset = 0x0;
  const Elf64_Off text_offset = elf_header_offset + sizeof(Elf64_Ehdr);
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
  sh_rela_text->sh_size =
      sizeof(Elf64_Rela) * array_len(compiler->elf64_relocations);
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
