#include "../../include/compiler.h"
#include "lilc/log.h"

#define htole(imm, size)                                                       \
  size == 2 ? htole16(imm)                                                     \
            : (size == 2 ? htole32(imm) : (size == 3 ? htole64(imm) : imm))

int32_t cmp_size_t(const void *a, const void *b) {
  size_t x = *(const size_t *)a;
  size_t y = *(const size_t *)b;
  return (x > y) - (x < y); // returns positive, zero, or negative
}

void compiler_generate(Compiler *compiler) {
  if (compiler->cur_step != COMPILE_STEP_COMPILE_SRC)
    return;
  compiler->cur_step = COMPILE_STEP_GENERATE_MACHINE;

  ModuleCompileInfo *info = &compiler->cur_mod_compile_info;
  ModuleCompile *mod_compile = &compiler->cur_mod_compile;

  if (debug_flags.print_compile_info) {
    log_info("[COMPILER] Start generating machine code");
  }

  info->program_data_capacity = 512;
  info->program_data = malloc(info->program_data_capacity);
  size_t program_data_offset = 0;

  for (size_t i = 0; i < array_len(*mod_compile->insns); i++) {
    Instruction ins = (*mod_compile->insns)[i];
    uint8_t insn_bytes[16] = {0};

    size_t ins_len = ins_gen(&ins, insn_bytes);

    if (program_data_offset + ins_len > info->program_data_capacity) {
      info->program_data =
          realloc(info->program_data, info->program_data_capacity *= 2);
    }

    memcpy(info->program_data + program_data_offset, insn_bytes, ins_len);

    program_data_offset += ins_len;
  }

  for (size_t i = 0; i < array_len(*mod_compile->relocs); i++) {
    Relocation reloc = (*mod_compile->relocs)[i];
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
    array_add(info->elf64_relocations, elf64_reloc);
  }

  info->program_data_size = program_data_offset;
}