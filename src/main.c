#include <assert.h>
#include <complex.h>
#include <lilc/dynstr.h>
#include <lilc/eq.h>
#include "lilc/hashmap0.h"
#include <lilc/log.h>
#include <stdlib.h>

#include "../include/builtins.h"
#include "../include/checker.h"
#include "../include/compiler.h"
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

void cli_run(char **argv, size_t argc);

void compile_input(const char *input_path, const char *output_path,
                   const char *raw_module_path) {
  builtin_types_init();

  ModulePath module_path = parse_module_path_from_string(raw_module_path, &HEAP_ALLOCATOR);

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
  module_parse(&module, &parser, &stmts, &pp_dirs, tokens, lines);

  if (debug_flags.print_ast) {
    log_info("AST:\n%s", ast_format(stmts).string);
  }

  // ** PREPROCESSOR **

  PreProcessor preproc = {0};
  preprocessor_init(&preproc);

  module_preprocess(&module, &preproc, stmts, pp_dirs);

  if (debug_flags.print_preprocessed_ast) {
    log_info("PREPROCESSED AST:\n%s", dyn_string_temp_copy_and_free(ast_format(preproc.stmts)));
  }

  // ** CHECKER **

  TypeChecker checker = {0};
  checker_init(&checker);
  builtin_functions_init(checker.global_type_table);

  ModulePath *key;
  FuncDescriptor *val;
  hashmap_foreach(&parser.imported_functions, key, val) {
    Expression expr = {
        .kind = EXPR_FUNCTION,
        .var.expr_function =
            {
                .desc = *val,
                .block = NULL,
                .native_function = NULL,
            },
    };
    type_table_add(checker.global_type_table, key, EXPR_VAR_EXPR(expr),
                   (OptionalType){.present = false});
  }

  module_check(&module, &checker, stmts, lines, parser.imported_modules);

  checker_gen_functions(&checker);

  // ** COMPILER **

  Compiler compiler = {0};
  compiler_init(&compiler, stmts, checker.type_tables,
                mangled_functions, module_path);
                
  compiler_compile(&compiler);

  compiler_generate(&compiler);

  FILE *out_file = fopen(output_path, "w");

  compiler_write(&compiler, out_file);

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
