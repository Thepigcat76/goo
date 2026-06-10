#include <assert.h>
#include <complex.h>
#include <lilc/dynstr.h>
#include <lilc/eq.h>
#include <lilc/hashmap.h>
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

  ModulePath module_path = parse_module_path_from_string(raw_module_path);

  dyn_string_t file_content = file_read_to_string(input_path, &HEAP_ALLOCATOR);

  // ** LEXER **

  Lexer lexer = {0};
  lexer_init(&lexer);

  lexer_tokenize(&lexer, file_content.string, input_path);
  array_add(lexer.tokens, (Token){.kind = TOKEN_EOF});

  if (debug_flags.print_tokens) {
    for (size_t i = 0; i < array_len(lexer.tokens); i++) {
      char print_buf[256];
      lexer_tok_print(print_buf, &lexer.tokens[i]);
      puts(print_buf);
    }
  }

  // ** PARSER **

  Parser parser = {0};
  parser_init(&parser, lexer.tokens, file_content.string, input_path, module_path);
  parser.lines = lexer.lines;

  parser_parse(&parser);

  // Parsing finished, free tokens and lexer lines
  lexer_deinit(&lexer);

  if (debug_flags.print_ast) {
    log_debug("AST:\n%s", ast_format(parser.statements).string);
  }

  // ** PREPROCESSOR **

  PreProcessor preprocessor = {0};
  preprocessor_init(&preprocessor, parser.statements, parser.pp_dirs);

  preprocessor_process(&preprocessor);

  preprocessor_deinit(&preprocessor);

  // ** CHECKER **

  TypeChecker checker = {0};
  checker_init(&checker, &parser);
  builtin_functions_init(checker.global_type_table);

  hashmap_foreach(
      &parser.imported_functions, ModulePath * key, FuncDescriptor * val, {
        Expression expr = {.kind = EXPR_FUNCTION,
                           .var = {.expr_function = {.desc = *val,
                                                     .block = NULL,
                                                     .native_function = NULL}}};
        type_table_add(checker.global_type_table, key, EXPR_VAR_EXPR(expr),
                       (OptionalType){.present = false});
      });

  checker_check(&checker);

  checker_gen_functions(&checker);

  // ** COMPILER **

  Compiler compiler = {0};
  compiler_init(&compiler, parser.statements, checker.type_tables,
                mangled_functions, module_path);
  compiler_compile(&compiler);

  // Compilation is done, statements array and others can be freed
  parser_deinit(&parser);
  builtin_functions_deinit(checker.global_type_table);
  // Type checking information like type tables... can also be freed
  checker_deinit(&checker);

  compiler_generate(&compiler);

  FILE *out_file = fopen(output_path, "w");

  compiler_write(&compiler, out_file);

  compiler_deinit(&compiler);

  fclose(out_file);

  bump_free(&lexer.tok_arena);
  bump_free(&parser.ast_arena);
  bump_free(&checker.checker_arena);
  bump_free(&compiler.compiler_arena);

  hashmap_free(&mangled_functions);

  builtin_types_deinit();

  array_free(module_path.path);

  dyn_string_free(&file_content);

}

static char *_corelib_path = NULL;

int main(int argc, char **argv) {
  char *core_lib_path = getenv(CORE_LIB_PATH);
  if (core_lib_path == NULL) {
    setenv(CORE_LIB_PATH, DEFAULT_CORE_LIB_PATH, 0);
    core_lib_path = DEFAULT_CORE_LIB_PATH;
  }

  _corelib_path = core_lib_path;

  cli_run(argv, (size_t) argc);
}
