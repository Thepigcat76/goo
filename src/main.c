#include "lilc/hashmap0.h"
#include <assert.h>
#include <complex.h>
#include <lilc/dynstr.h>
#include <lilc/eq.h>
#include <lilc/log.h>
#include <stdlib.h>

#include "../include/builtins.h"
#include "../include/checker.h"
#include "../include/compiler.h"
#include "../include/comptime_func_proc.h"
#include "../include/builtins/types.h"
#include "../include/builtins/functions.h"
#include "../include/lexer.h"
#include "../include/parser.h"
#include "../include/preprocess.h"
#include "lilc/alloc.h"
#include "lilc/array.h"
#include "lilc/file.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>


static void type_table_dump(const TypeTable *type_table) {
  ModulePath *key;
  TypeTableValue *val;
  hashmap_foreach(&type_table->type_table, key, val) {
    log_debug("Type table dump key: %s", mod_path_fmt(key).string);
    if (val->opt_type.present) {
      dyn_string_t type_buf =
          type_format(&(TypeFormatter){.debug = true}, &val->opt_type.type);
      printf("Key: %s, Val: %s\n", mod_path_fmt(key).string, type_buf.string);
    }
  }
}
void cli_run(char **argv, size_t argc);

void compile_input(const char *input_path, const char *output_path,
                   const char *raw_module_path) {
  builtin_types_init(&HEAP_ALLOCATOR);

  ModulePath module_path = mod_path_parse_str(raw_module_path, &HEAP_ALLOCATOR);

  dyn_string_t file_content = file_read_to_string(input_path, &HEAP_ALLOCATOR);

  Module module = {0};
  module_init(&module, module_path, input_path, file_content.string);

  // ** LEXER **

  Lexer lexer = {0};
  lexer_init(&lexer);

  SourceLine *lines = array_new(SourceLine, &HEAP_ALLOCATOR);
  Token *tokens = array_new(Token, &HEAP_ALLOCATOR);
  module_tokenize(&module, &lexer, &tokens, &lines);

  if (debug_flags.print_tokens) {
    for (size_t i = 0; i < array_len(tokens); i++) {
      char print_buf[256];
      lexer_tok_print(print_buf, &tokens[i]);
      puts(print_buf);
    }
  }

  // ** PARSER **

  Parser parser = {0};
  parser_init(&parser);

  Statement *stmts = array_new(Statement, &HEAP_ALLOCATOR);
  PpDirective *pp_dirs = array_new(PpDirective, &HEAP_ALLOCATOR);

  ModuleParse mod_parse = {
    .lines = lines,
    .tokens = tokens,
    .pp_dirs = &pp_dirs,
    .stmts = &stmts,
  };
  // init other mod_parse values
  module_parse_init(&mod_parse);

  module_parse(&module, &parser, mod_parse);

  if (debug_flags.print_ast) {
    log_info("AST:\n%s", ast_format(stmts).string);
  }

  // ** PREPROCESSOR **

  PreProcessor preproc = {0};
  preprocessor_init(&preproc);

  IdentArray comptime_param_functions = array_new(Ident, &HEAP_ALLOCATOR);

  module_preprocess(&module, &preproc, stmts, &comptime_param_functions,
                    pp_dirs);

  if (debug_flags.print_preprocessed_ast) {
    log_info("Comptime param functions: %s", comptime_param_functions[0]);
    log_info("PREPROCESSED AST:\n%s",
             dyn_string_temp_copy_and_free(ast_format(preproc.stmts)));
  }

  // ** CHECKER **

  TypeChecker checker = {0};
  checker_init(&checker);

  Hashmap function_type_tables = {0};
  hashmap_init(&function_type_tables, &HEAP_ALLOCATOR, Ident, TypeTables,
               str_ptrv_hash, str_ptrv_eq, NULL);

  TypeTable global_type_table = {0};
  type_table_init(&global_type_table, &HEAP_ALLOCATOR);

  ModulePath *key;
  FuncDescriptor *val;
  hashmap_foreach(&mod_parse.imported_functions, key, val) {
    Expression expr = {
        .kind = EXPR_FUNCTION,
        .var.expr_function.desc = *val,
    };
    type_table_add(&global_type_table, key, EXPR_VAR_EXPR(expr),
                   (OptionalType){.present = false});
  }

  builtin_functions_init(&HEAP_ALLOCATOR, &global_type_table);

  //type_table_dump(&global_type_table);

  ModuleCheck mod_check = {
      .lines = lines,
      .stmts = stmts,
      .imported_modules = mod_parse.imported_modules,

      .function_type_tables = function_type_tables,
      .global_type_table = global_type_table,
  };

  bool check_success = module_check(&module, &checker, mod_check);

  if (!check_success) {
    return;
  }

  ComptimeFuncProcessor cfp = {0};
  cfp_init(&cfp);

  ModuleComptimeParamProcess mod_proc = {
    .comptime_params_process = comptime_param_functions,
    .function_type_tables = function_type_tables,
    .global_type_table = global_type_table,
  };

  module_process_comptime_func_params(&module, &cfp, mod_proc);

  // ** COMPILER **

  Compiler compiler = {0};
  compiler_init(&compiler);

  Relocation *relocs = array_new(Relocation, &HEAP_ALLOCATOR);
  Instruction *insns = array_new(Instruction, &HEAP_ALLOCATOR);

  ModuleCompile mod_compile = {
      .stmts = stmts,
      .function_type_tables = function_type_tables,
      .global_type_table = global_type_table,
      .mangled_functions = mangled_functions,

      .insns = &insns,
      .relocs = &relocs,
  };

  module_compile_init(&mod_compile);

  FILE *out_file = fopen(output_path, "w");

  module_compile(&module, &compiler, mod_compile, out_file);

  fclose(out_file);

  // CLEANUP

  hashmap_deinit(&mangled_functions);

  array_free(tokens);
  array_free(lines);

  array_free(stmts);
  array_free(pp_dirs);

  module_deinit(&module);
  mod_path_deinit(&module_path);

  compiler_deinit(&compiler);
  checker_deinit(&checker);
  preprocessor_deinit(&preproc);
  parser_deinit(&parser);
  lexer_deinit(&lexer);

  dyn_string_free(&file_content);

  builtin_types_deinit();

  builtin_functions_deinit(NULL);

  return;
}

int main(int argc, char **argv) {
  char *_core_lib_path = getenv(CORE_LIB_PATH);
  if (_core_lib_path == NULL) {
    setenv(CORE_LIB_PATH, DEFAULT_CORE_LIB_PATH, 0);
    _core_lib_path = DEFAULT_CORE_LIB_PATH;
  }

  corelib_path = _core_lib_path;

  cli_run(argv, (size_t)argc);
}
