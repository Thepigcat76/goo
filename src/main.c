#include <assert.h>
#include <lilc/eq.h>
#include <lilc/hashmap.h>
#include <lilc/log.h>
#include <stdlib.h>
#ifdef TARGET_WEB
#include <emscripten.h>
#include <emscripten/emscripten.h>
#define KEEPALIVE EMSCRIPTEN_KEEPALIVE
#define main _regular_main
#else
#define KEEPALIVE
#endif

// #define INTERPRETER

#define COMPILER

#include "../include/builtins.h"
#include "../include/checker.h"
#include "../include/compiler.h"
#include "../include/evaluator.h"
#include "../include/lexer.h"
#include "../include/parser.h"
#include "../include/preprocess.h"
#include "lilc/alloc.h"
#include "lilc/array.h"
#include "tests.c"
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static Object execute_println_custom_buf(Object *args) {
  strcat(println_buf, obj_cast_string(&args[0]));
  return UNIT_OBJ;
}

KEEPALIVE
void function_println_use_buffer(void) {
  PRINTLN_FUNCTION.execute = execute_println_custom_buf;
  PRINTLN_FUNCTION.expr.var.expr_function.native_function =
      execute_println_custom_buf;
}

KEEPALIVE
void run_program(char *buf, const char *filename, const char *output) {
  alloc_init();

  builtin_types_init();

  //  parser_test_functions();

  //  return;

  Lexer lexer = lexer_new();

  lexer_tokenize(&lexer, buf, filename);
  array_add(lexer.tokens, (Token){.type = TOKEN_EOF});

  for (size_t i = 0; i < array_len(lexer.tokens); i++) {
    char print_buf[256];
    lexer_tok_print(print_buf, &lexer.tokens[i]);
    puts(print_buf);
  }

  Parser parser = parser_new(lexer.tokens, buf, filename, MODULE_PATH_ROOT);
  parser.lines = lexer.lines;

  parser_parse(&parser);

  log_debug("AST:\n%s", ast_format(parser.statements).string);

  log_debug("-- FUNCTIONS --");

  hashmap_foreach(&parser.custom_functions, Ident * key, ExprFunction * val,
                  { log_debug("%s", *key); });
  log_debug("Custom functions: %zu", parser.custom_functions.len);

  log_debug("-- TYPES --");

  hashmap_foreach(&parser.custom_types, Ident *key, TypeExpr * val,
                  { log_debug("%s", *key); });

  log_debug("---");

  PreProcessor preprocessor =
      preprocessor_new(parser.statements, parser.pp_dirs);

  preprocessor_process(&preprocessor);

  TypeChecker checker = checker_new(&parser);
#ifdef TARGET_WEB
  function_println_use_buffer();
#endif
  builtin_functions_init(checker.global_type_table);

  hashmap_foreach(
      &parser.imported_functions, ModulePath * key, FuncDescriptor * val, {
        Expression expr = {.type = EXPR_FUNCTION,
                           .var = {.expr_function = {.desc = *val,
                                                     .block = NULL,
                                                     .native_function = NULL}}};
        type_table_add(checker.global_type_table, key, EXPR_VAR_EXPR(expr),
                       (OptionalType){.present = false});
      });

  checker_check(&checker);

  checker_gen_functions(&checker);

#ifdef INTERPRETER
  Evaluator evaluator = evaluator_new(checker.stmts);

  evaluator_eval_global(&evaluator, checker.global_type_table);

  puts("---");

  Expression expr = {.type = EXPR_CALL,
                     .var = {.expr_call = {.function = "main", .args = NULL}}};
  evaluator_eval_expr(&evaluator, &expr);
#elif defined(COMPILER)
  Compiler compiler = compiler_new(parser.statements, checker.type_tables);
  compiler_compile(&compiler);

  compiler_generate(&compiler);

  FILE *out_file = fopen(output, "w");

  compiler_write(&compiler, out_file);

  fclose(out_file);
#endif

  return;
  //  array_free(lexer.tokens);
  //
  //  array_free(parser.statements);
  //  hashmap_free(&parser.custom_functions);
  //  hashmap_free(&parser.custom_types);
  //
  //  array_free(&checker.generated_generic_functions);
  //  for (size_t i = 0; i < array_len(checker.type_tables); i++) {
  //    hashmap_free(&checker.type_tables->type_table);
  //  }
  //  array_free(checker.type_tables);
  //
  //  array_free(&evaluator.environments);
  //  for (size_t i = 0; i < array_len(evaluator.environments); i++) {
  //    hashmap_free(&evaluator.environments->env);
  //  }
  //  array_free(evaluator.environments);
}

KEEPALIVE
char *function_println_buffer(void) { return println_buf; }

KEEPALIVE
void function_println_buffer_clear(void) { println_buf[0] = '\0'; }

#define STR_CMP_OR(str, ...)                                                   \
  _internal_str_cmp_or(str, (char *[128]){__VA_ARGS__})

static bool _internal_str_cmp_or(char *base_str, char **strs) {
  for (int i = 0; strs[i] != NULL; i++) {
    char *str = strs[i];
    if (strcmp(base_str, str) == 0) {
      return true;
    }
  }
  return false;
}

#define NEXT_ARG(i, argc)                                                      \
  if (i < argc)                                                                \
    i++;                                                                       \
  else                                                                         \
    break

typedef struct {
  char *output_path;
  char *input_path;
} CliArgs;

static char *_corelib_path = NULL;

int main(int argc, char **argv) {
  CliArgs args = {0};

  int i = 1;
  while (i < argc) {
    if (i == 1) {
      args.input_path = argv[i];
      NEXT_ARG(i, argc);
    }

    if (STR_CMP_OR(argv[i], "-o", "--output")) {
      NEXT_ARG(i, argc);
      args.output_path = argv[i];
    }
    NEXT_ARG(i, argc);
  }

  if (args.input_path == NULL) {
#ifdef COMPILER
    args.input_path = "tests/modules.goo";
#elif defined(INTERPRETER)
    args.input_path = "tests/test_interpreter.goo";
#endif
  }

  if (args.output_path == NULL) {
    args.output_path = "output/out.o";
  }

  char *core_lib_path = getenv(CORE_LIB_PATH);
  if (core_lib_path == NULL) {
    setenv(CORE_LIB_PATH, DEFAULT_CORE_LIB_PATH, 0);
    core_lib_path = DEFAULT_CORE_LIB_PATH;
  }

  _corelib_path = core_lib_path;

  FILE *file = fopen(args.input_path, "r");
  char file_buf[4096];
  size_t n = fread(file_buf, 1, sizeof(file_buf) - 1, file);
  file_buf[n] = '\0';

  run_program(file_buf, args.input_path, args.output_path);
  log_debug("compiling: %s", args.input_path);

  fclose(file);

  return 0;
}
