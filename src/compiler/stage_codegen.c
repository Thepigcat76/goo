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
  if (compiler->step != COMPILE_STEP_COMPILE_SRC)
    return;
  compiler->step = COMPILE_STEP_GENERATE_MACHINE;

  log_info("[COMPILER] Start generating machine code");

  compiler->program_data_capacity = 512;
  compiler->program_data = malloc(compiler->program_data_capacity);
  size_t program_data_offset = 0;

  for (size_t i = 0; i < array_len(compiler->insns); i++) {
    Instruction ins = compiler->insns[i];
    uint8_t insn_bytes[16] = {0};

    size_t ins_len = ins_gen(&ins, insn_bytes);

    if (program_data_offset + ins_len > compiler->program_data_capacity) {
      compiler->program_data =
          realloc(compiler->program_data, compiler->program_data_capacity *= 2);
    }

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