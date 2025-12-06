#include "../../include/compiler.h"
#include "../../vendor/lilc/array.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <elf.h>

Compiler compiler_new(const Statement *statements) {
  return (Compiler){.stmts = statements};
}

static void stmt_compile(Compiler *compiler, const Statement *stmt) {
  if (stmt->type == STMT_DECL) {
    StmtDecl stmt_decl = stmt->var.stmt_decl;
    if (stmt_decl.value.type == EXPR_VAR_REG_EXPR) {
      Expression expr = stmt_decl.value.var.expr_var_reg_expr;
      if (expr.type == EXPR_FUNCTION) {
        
      }
    }
  }
}

void compiler_compile(Compiler *compiler) {
  compiler->step = COMPILE_STEP_COMPILE_SRC;

  size_t stmts_len = array_len(compiler->stmts);
  while (compiler->stmt_index < stmts_len) {
    stmt_compile(compiler, &compiler->stmts[compiler->stmt_index]);
  }

}

void compiler_generate(Compiler *compiler) {
  if (compiler->step != COMPILE_STEP_COMPILE_SRC) return;
  compiler->step = COMPILE_STEP_GENERATE_MACHINE;
}

void compiler_write(Compiler *compiler, FILE *file) {
  if (compiler->step != COMPILE_STEP_GENERATE_MACHINE) return;
  compiler->step = COMPILE_STEP_OUTPUT_OBJECT;

  Elf64_Ehdr eh = {0};
  /* E_IDENT */
  memcpy(eh.e_ident, ELFMAG, SELFMAG);
  eh.e_ident[EI_CLASS] = ELFCLASS64;
  eh.e_ident[EI_DATA] = ELFDATA2LSB;
  eh.e_ident[EI_VERSION] = EV_CURRENT;
  eh.e_ident[EI_OSABI] = ELFOSABI_SYSV;

  /* Rest of header */

  eh.e_type = ET_REL;
  eh.e_machine = EM_X86_64;
  eh.e_version = EV_CURRENT;
  eh.e_ehsize = sizeof(Elf64_Ehdr);

  fwrite(&eh, sizeof(unsigned char), sizeof(Elf64_Ehdr), file);
}
