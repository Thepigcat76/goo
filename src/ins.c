#define INS_IMPL
#include "../include/ins.h"
#undef INS_IMPL
#include <lilc/log.h>
#include <stdint.h>

static inline void emit_bytes(const uint8_t *bytes, size_t amount,
                              uint8_t *out_bytes) {
  memcpy(out_bytes, bytes, amount);
}

uint8_t sib_gen(SIB sib) {
  uint8_t sib_byte = 0;

  sib_byte |= (sib.scale & 0b11) << 6;
  sib_byte |= (sib.index & 0b111) << 3;
  sib_byte |= (sib.base & 0b111);

  return sib_byte;
}

uint8_t mod_rm_gen(ModRM mod_rm) {
  uint8_t mod_rm_byte = 0;

  mod_rm_byte |= (mod_rm.mod & 0b11) << 6;
  mod_rm_byte |= (mod_rm.reg & 0b111) << 3;
  mod_rm_byte |= (mod_rm.rm & 0b111);

  return mod_rm_byte;
}

static size_t imm_gen(const Instruction *ins, uint8_t *ins_bytes,
                      size_t ins_len) {
  size_t imm_len;
  if (ins->flags.imm8 || ins->imm_size == 1) {
    imm_len = 1;
  } else if (ins->imm_size == 8) {
    imm_len = 8;
  } else if (ins->imm_size == 2) {
    imm_len = 2;
  } else {
    imm_len = 4;
  }
  if (ins_bytes != NULL)
    emit_bytes(ins->imm, imm_len, ins_bytes + ins_len);
  return imm_len;
}

static size_t disp_gen(const Instruction *ins, uint8_t *ins_bytes,
                       size_t ins_len) {
  size_t disp_len;
  if (ins->mod_rm.mod == MOD_MEM_8BIT_DISP || ins->flags.explicit_disp8) {
    disp_len = 1;
  } else {
    disp_len = 4;
  }
  if (ins_bytes != NULL)
    emit_bytes(ins->disp, disp_len, ins_bytes + ins_len);
  return disp_len;
}

size_t ins_gen(const Instruction *ins, uint8_t *ins_bytes) {
  size_t ins_len = 0;

  InsFlags flags = ins->flags;

  Opcode opcode = ins->opcode;
  for (size_t i = 0; i < opcode.len; i++) {
    if (ins_bytes != NULL)
      ins_bytes[i] = opcode.bytes[i];
  }
  ins_len += opcode.len;

  if (flags.has_mod_rm) {
    if (ins_bytes != NULL)
      ins_bytes[ins_len] = mod_rm_gen(ins->mod_rm);
    ins_len++;
  }

  if (flags.has_sib) {
    if (ins_bytes != NULL)
      ins_bytes[ins_len] = sib_gen(ins->sib);
    ins_len++;
  }

  if (!flags.switch_imm_disp) {
    if (flags.has_disp) {
      ins_len += disp_gen(ins, ins_bytes, ins_len);
    }

    if (flags.has_imm) {
      ins_len += imm_gen(ins, ins_bytes, ins_len);
    }
  } else {
    log_debug("Switched imm and disp");

    if (flags.has_imm) {
      ins_len += imm_gen(ins, ins_bytes, ins_len);
    }

    if (flags.has_disp) {
      ins_len += disp_gen(ins, ins_bytes, ins_len);
    }
  }

  return ins_len;
}
