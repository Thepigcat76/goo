#include "../../include/ins.h"

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

size_t ins_gen(const Ins *ins, uint8_t *ins_bytes) {
  size_t ins_len = 0;

  InsFlags flags = ins->flags;

  Opcode opcode = ins->opcode;
  for (size_t i = 0; i < opcode.len; i++) {
    ins_bytes[i] = opcode.bytes[i];
  }
  ins_len += opcode.len;

  if (flags.has_mod_rm) {
    ins_bytes[ins_len] = mod_rm_gen(ins->mod_rm);
    ins_len++;
  }

  if (flags.has_sib) {
    ins_bytes[ins_len] = sib_gen(ins->sib);
    ins_len++;
  }

  if (flags.has_disp) {
    emit_bytes(ins->disp, 4, ins_bytes + ins_len);
    ins_len += 4;
  }

  if (flags.has_imm) {
    emit_bytes(ins->imm, 4, ins_bytes + ins_len);
    ins_len += 4;
  }

  return ins_len;
}
