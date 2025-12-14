#include "../../include/compiler.h"
#include "lilc/array.h"
#include "lilc/eq.h"
#include "lilc/hash.h"
#include <elf.h>
#include <endian.h>
#include <lilc/alloc.h>
#include <lilc/hashmap.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

static inline DataSection data_section_new(void) {
  return hashmap_new(Ident *, DataValue, &HEAP_ALLOCATOR, str_ptrv_hash,
                     str_ptrv_eq, NULL);
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
      .data_section = data_section_new(),
      .rodata_section = data_section_new()};
}

static inline void data_section_add(DataSection *section, Ident *key,
                                    DataValue value) {
  hashmap_insert(section, key, &value);
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
  Instruction ins = {.type = INS_PUSH_SP};
  array_add(insns, ins);
}

static inline void stack_frame_reset(Instruction *insns) {
  Instruction ins = {.type = INS_RESET_SP};
  array_add(insns, ins);
}

static inline void stack_frame_pop(Instruction *insns) {
  Instruction ins = {.type = INS_POP_SP};
  array_add(insns, ins);
}

static inline void insns_add_return(Instruction *insns) {
  Instruction ins = {.type = INS_RET};
  array_add(insns, ins);
}

static inline void insns_add(Instruction *insns, Instruction ins) {
  array_add(insns, ins);
}

#define INSN(_type, ...)                                                       \
  (Instruction) {                                                              \
    .type = _type, .var = { __VA_ARGS__ }                                      \
  }

static void expr_func_compile(Compiler *compiler, const ExprFunction *expr_func,
                              CompileContext context) {
  compiler->cur_frame =
      (Frame){.sp_offset = 0,
              .symbol_table = hashmap_new(Ident *, size_t, &HEAP_ALLOCATOR,
                                          str_ptrv_hash, str_ptrv_eq, NULL)};
  bool uses_stack = false;
  bool stack_initialized = false;
  for (size_t i = 0; i < array_len(expr_func->block->statements); i++) {
    Statement *stmt = &expr_func->block->statements[i];
    if (stmt->type == STMT_DECL && !stack_initialized) {
      uses_stack = true;
      stack_frame_push(compiler->insns);
      stack_frame_reset(compiler->insns);
      stack_initialized = true;
    }
    stmt_compile(compiler, stmt,
                 (CompileContext){.level = COMPILE_LEVEL_LOCAL,
                                  .function_name = context.function_name});
  }

  if (uses_stack) {
    stack_frame_pop(compiler->insns);
  }

  printf("func name: %s\n", context.function_name);
  if (context.function_name != NULL && strv_eq(context.function_name, "main")) {
    // insns_add(compiler->insns,
    //           INSN(INS_MOV_I2RAX, .mov_i2rax = {.immediate = 0xc3}));
    // insns_add(compiler->insns, INSN(INS_SYSCALL));
  }

  insns_add_return(compiler->insns);
}

static char *PRINTF_FUNCTION_NAME = "puts";
static char *RODATA_STRING_LITERALS = "string-literal-0";

static void stmt_compile(Compiler *compiler, const Statement *stmt,
                         CompileContext context) {
  switch (stmt->type) {
  case STMT_EXPR: {
    Expression expr = stmt->var.stmt_expr.expr;
    if (expr.type == EXPR_CALL) {
      ExprCall expr_call = expr.var.expr_call;
      for (size_t i = 0; i < array_len(expr_call.args); i++) {
        Expression arg = expr_call.args[i];
        if (arg.type == EXPR_STRING_LIT) {
          char *string = arg.var.expr_string_literal.string;
          DataValue data_val = {.bytes = (uint8_t *)string,
                                .bytes_len = strlen(string) + 1};
          data_section_add(&compiler->rodata_section, &RODATA_STRING_LITERALS,
                           data_val);
          insns_add(compiler->insns, INSN(INS_LEA_RBX));
          insns_add(compiler->insns, INSN(INS_XOR_RDI_RDI));
        }
      }

      if (strv_eq(expr_call.function, "println")) {
        size_t i = 0;
        hashmap_insert(&compiler->extern_functions, &PRINTF_FUNCTION_NAME, &i);
        insns_add(
            compiler->insns,
            INSN(INS_FOREIGN_CALL,
                 .foreign_call_ins = {.function_name = PRINTF_FUNCTION_NAME}));
      } else {
        insns_add(
            compiler->insns,
            INSN(INS_CALL, .call_ins = {.function_name = expr_call.function}));
      }
    }
    break;
  }
  case STMT_DECL: {
    StmtDecl stmt_decl = stmt->var.stmt_decl;
    if (stmt_decl.value.type == EXPR_VAR_REG_EXPR) {
      Expression expr = stmt_decl.value.var.expr_var_reg_expr;
      if (context.level == COMPILE_LEVEL_GLOBAL) {
        DataSection *data_section = stmt_decl.mutable
                                        ? &compiler->data_section
                                        : &compiler->rodata_section;
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
          data_section_add(data_section, &stmt_decl.name, data_val);

          printf("Added data to section: %zu\n", val);
        } else if (expr.type == EXPR_STRING_LIT) {
          char *string = expr.var.expr_string_literal.string;
          DataValue data_val = {.bytes = (uint8_t *) string, .bytes_len = strlen(string) + 1};
          data_section_add(data_section, &stmt_decl.name, data_val);
        }
      } else {
        compiler->cur_frame.sp_offset += sizeof(int32_t);
        hashmap_insert(&compiler->cur_frame.symbol_table, &stmt_decl.name,
                       &compiler->cur_frame.sp_offset);
        insns_add(compiler->insns,
                  INSN(INS_MOV_I2RBP,
                       .mov_i2rbp = {.immediate =
                                         expr.var.expr_integer_literal.integer,
                                     .disp = compiler->cur_frame.sp_offset}));
      }
    }
    break;
  }
  case STMT_RETURN: {
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

  printf("Labels:\n");
  hashmap_foreach(&compiler->labels, Ident * key, size_t *val, {
    printf("Key: %s\n", *key);
    printf("Value: %zu\n", *val);
  });
  printf("Labels amount: %zu\n", compiler->labels.len);
}

#define SAFE_OPCODE(...)                                                       \
  do {                                                                         \
    if (opcode != NULL) {                                                      \
      __VA_ARGS__                                                              \
    }                                                                          \
  } while (0)

/* Generate the opcode of the instruction. Return the size. Size is always <=
 * 3*/
static size_t insn_opcode(InstructionType insn_type, uint8_t *opcode) {
  switch (insn_type) {
  case INS_XOR_RDI_RDI: {
    SAFE_OPCODE({
      // opcode[0] = 0x48;
      opcode[0] = 0x31;
      opcode[1] = 0xc0;
    });
    return 2;
  }
  case INS_MOV_I2RAX: {
    SAFE_OPCODE({
      opcode[0] = 0x48;
      opcode[1] = 0xc7;
      opcode[2] = 0xc0;
    });
    return 3;
  }
  case INS_PUSH_SP: {
    SAFE_OPCODE({ opcode[0] = 0x55; });
    return 1;
  }
  case INS_POP_SP: {
    SAFE_OPCODE({ opcode[0] = 0x5d; });
    return 1;
  }
  case INS_RET: {
    SAFE_OPCODE({ opcode[0] = 0xc3; });
    return 1;
  }
  case INS_SYSCALL: {
    SAFE_OPCODE({
      opcode[0] = 0x0f;
      opcode[1] = 0x05;
    });
    return 2;
  }
  case INS_RESET_SP: {
    SAFE_OPCODE({
      opcode[0] = 0x48;
      opcode[1] = 0x89;
      opcode[2] = 0xe5;
    });
    return 3;
  }
  case INS_MOV_I2RBP: {
    SAFE_OPCODE({
      opcode[0] = 0x48;
      opcode[1] = 0xc7;
      opcode[2] = 0x45;
    });
    return 3;
  }
  case INS_LEA_RBX: {
    SAFE_OPCODE({
      opcode[0] = 0x48;
      opcode[1] = 0x8d;
      opcode[2] = 0x3d;
    });
    return 3;
  }
  case INS_FOREIGN_CALL:
  case INS_CALL: {
    SAFE_OPCODE({ opcode[0] = 0xe8; });
    return 1;
  }
  case INS_MOV_R2R:
  case INS_MOV_M2R:
  case INS_MOV_I2R:
    return 0;
  }
}

typedef struct {
  Hashmap(Ident *, size_t) labels;
  size_t program_data_offset;
} GenerationContext;

static size_t insn_generate(Instruction *ins, Relocation *relocations,
                            uint8_t *insn_bytes, GenerationContext context) {
  size_t opcode_len = insn_opcode(ins->type, insn_bytes);

  size_t ins_len = opcode_len;

  switch (ins->type) {
  case INS_MOV_I2RAX: {
    insn_bytes[3] = 0x3c;
    ins_len += 4;
    break;
  }
  case INS_MOV_I2RBP: {
    insn_bytes[3] = 256 - ins->var.mov_i2rbp.disp;
    uint32_t integer = htole32(ins->var.mov_i2rbp.immediate);
    memcpy(insn_bytes + 4, &integer, sizeof(uint32_t));
    ins_len += 5;
    break;
  }
  case INS_CALL: {
    Ident function_name = ins->var.call_ins.function_name;

    uint32_t *offset = hashmap_value(&context.labels, &function_name);
    if (offset != NULL) {
      uint32_t encoded =
          htole32((*offset) - (context.program_data_offset + opcode_len + 4));
      memcpy(insn_bytes + 1, &encoded, sizeof(uint32_t));
      ins_len += 4;
    } else {
      fprintf(stderr,
              "Tried to call function that doesn't have an offset: %s\n",
              function_name);
      exit(1);
    }
    break;
  }
  case INS_FOREIGN_CALL: {
    if (relocations != NULL) {
      Relocation reloc = {
          .rel_type = RELOCATION_FUNCTION,
          .symbol = ins->var.foreign_call_ins.function_name,
          .program_offset = context.program_data_offset,
      };
      array_add(relocations, reloc);
    }
    /* Leave the rest of the instruction bytes 0, relocation will fix it */
    ins_len += 4;
    break;
  }
  case INS_LEA_RBX: {
    if (relocations != NULL) {
      Relocation reloc = {.rel_type = RELOCATION_RODATA,
                          .program_offset = context.program_data_offset};
      array_add(relocations, reloc);
    }
    /* Leave the rest of the instruction bytes 0, relocation will fix it */
    ins_len += 4;
    break;
  }
  case INS_RESET_SP:
  case INS_XOR_RDI_RDI:
  case INS_MOV_R2R:
  case INS_MOV_M2R:
  case INS_MOV_I2R:
  case INS_PUSH_SP:
  case INS_POP_SP:
  case INS_RET:
  case INS_SYSCALL:
    break;
  }

  return ins_len;
}

int cmp_size_t(const void *a, const void *b) {
  size_t x = *(const size_t *)a;
  size_t y = *(const size_t *)b;
  return (x > y) - (x < y); // returns positive, zero, or negative
}

void compiler_generate(Compiler *compiler) {
  if (compiler->step != COMPILE_STEP_COMPILE_SRC)
    return;
  compiler->step = COMPILE_STEP_GENERATE_MACHINE;

  compiler->program_data = malloc(512);
  size_t program_data_offset = 0;

  size_t sizes[compiler->labels.len];
  hashmap_foreach(&compiler->labels, Ident * key, size_t *val,
                  { sizes[_internal_keys_iter_index] = *val; });
  qsort(sizes, compiler->labels.len, sizeof(size_t), cmp_size_t);
  size_t label_idx = 0;

  for (size_t i = 0; i < array_len(compiler->insns); i++) {
    Instruction ins = compiler->insns[i];
    uint8_t insn_bytes[16] = {0};

    GenerationContext context = {.labels = compiler->labels,
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

      printf("Key for index adjustment: %s\n", *label_key);

      hashmap_insert(&compiler->labels, label_key, &program_data_offset);

      if (label_idx < array_len(compiler->insns)) {
        label_idx++;
      }
    }

    program_data_offset += ins_len;

    printf("Instruction: ");
    for (size_t i = 0; i < ins_len; i++) {
      printf("0x%02X ", insn_bytes[i]);
    }
    puts("");
  }

  program_data_offset = 0;

  for (size_t i = 0; i < array_len(compiler->insns); i++) {
    Instruction ins = compiler->insns[i];
    uint8_t insn_bytes[16] = {0};

    GenerationContext context = {.labels = compiler->labels,
                                 .program_data_offset = program_data_offset};
    size_t ins_len =
        insn_generate(&ins, compiler->relocations, insn_bytes, context);

    memcpy(compiler->program_data + program_data_offset, insn_bytes, ins_len);

    program_data_offset += ins_len;
  }

  compiler->program_data_size = program_data_offset;

  printf("Labels (fixed):\n");
  hashmap_foreach(&compiler->labels, Ident * key, size_t *val, {
    printf("Key: %s\n", *key);
    printf("Value: %zu\n", *val);
  });
  printf("Labels amount: %zu\n", compiler->labels.len);
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
    printf("Writing symbol %zu\n", i);
  }
  for (size_t i = 0; i < array_len(obj->relocations); i++) {
    WRITE(file, &obj->relocations[i]);
    printf("Writing relocation %zu\n", i);
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
  hashmap_foreach(section, Ident * key, DataValue * val,
                  { data_section_size += val->bytes_len; });
  return data_section_size;
}

static void data_section_write_bytes(const DataSection *section,
                                     size_t section_size, uint8_t *bytes) {
  size_t i = 0;
  size_t section_offset = 0;
  hashmap_foreach(section, Ident * key, DataValue * val, {
    for (size_t j = 0; j < val->bytes_len; j++) {
      bytes[section_offset + j] = val->bytes[j];
      // printf("Putting: %u\n", data_val->bytes[j]);
    }
    section_offset += val->bytes_len;
  });
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

static size_t obj_add_label(Object *object, char *symbol,
                            size_t program_index) {
  size_t symbol_len = strlen(symbol);
  if (object->strtab_section_capacity <=
      object->strtab_section_size + symbol_len) {
    object->strtab_section_capacity *= 2;
    object->strtab_section_data = realloc(object->strtab_section_data,
                                          object->strtab_section_capacity + 1);
  }
  memcpy(object->strtab_section_data + object->strtab_section_size, symbol,
         symbol_len + 1);
  memcpy(object->strtab_section_data + object->strtab_section_size +
             symbol_len + 2,
         "\0", 1);
  size_t old_size = object->strtab_section_size;
  object->strtab_section_size += symbol_len + 1;
  return old_size;
}

static void obj_add_symbol(Object *obj, char *key, size_t val) {
  size_t name_idx = obj_add_label(obj, key, val);

  Elf64_Sym extern_sym = {0};
  extern_sym.st_name = name_idx;
  extern_sym.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE);
  extern_sym.st_other = 0;
  extern_sym.st_shndx = SHN_UNDEF;
  extern_sym.st_value = 0; // start of section
  extern_sym.st_size = 0;
  array_add(obj->symbols, extern_sym);
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

  Elf64_Sym sym_rodata_offset_6 = {0};
  sym_rodata_offset_6.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT);
  sym_rodata_offset_6.st_shndx = RODATA_INDEX;
  sym_rodata_offset_6.st_value = 6;
  array_add(obj.symbols, sym_rodata_offset_6);

  /* Symbols */
  hashmap_foreach(&compiler->labels, Ident * key, size_t *val, {
    size_t name_idx = obj_add_label(&obj, *key, *val);

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
      obj_add_symbol(&obj, reloc.symbol, reloc.program_offset);
      /* Uses 1 as an additional offset because thats the opcode length of the
       * call instruction */
      rela.r_offset = reloc.program_offset + 1;
      rela.r_info = ELF64_R_INFO(sym_idx, R_X86_64_PLT32);
      break;
    }
    case RELOCATION_RODATA: {
      rela.r_offset = reloc.program_offset + 3;
      printf("RODATA with offset: %zu, symbol shndx: %hu\n", rela.r_offset,
             obj.symbols[2].st_shndx);
      rela.r_info = ELF64_R_INFO(3, R_X86_64_PC32);
      break;
    }
    default: {
      fprintf(stderr, "Failed to create relocation\n");
      exit(1);
    }
    }
    rela.r_addend = -4;
    printf("Created relocation %zu for offset: %zu\n", i, rela.r_offset);
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

  printf("Symbols: %zu, Relocations: %zu - SH Table offset: %zu, Size: %zu\n",
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
  sh_strtab->sh_size = obj.strtab_section_size; // obj.strtab_section_size;
  sh_strtab->sh_addralign = 1;

  Elf64_Shdr *sh_symtab = &obj.sh_symtab;
  sh_symtab->sh_name = OFF_SYMTAB_NAME;
  sh_symtab->sh_type = SHT_SYMTAB;
  sh_symtab->sh_offset = symtab_offset;
  sh_symtab->sh_size = sizeof(Elf64_Sym) * array_len(obj.symbols);
  sh_symtab->sh_link = STRTAB_INDEX;
  sh_symtab->sh_info = 3; // 3 because that is the index of the main symbol. All
                          // symbols >= 3 are global
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

  printf("Labels: ");

  for (size_t i = 0; i < obj.strtab_section_size; i++) {
    if (obj.strtab_section_data[i] == '\0') {
      printf("\\0");
    }
    putchar(obj.strtab_section_data[i]);
  }

  puts("");

  obj_write(&obj, file);
}
