#ifdef TARGET_WEB
#include <emscripten.h>
#include <emscripten/emscripten.h>
#define KEEPALIVE EMSCRIPTEN_KEEPALIVE
#define main _regular_main
#else
#define KEEPALIVE
#endif

//#define INTERPRETER

#define COMPILER

#include "../include/builtins.h"
#include "../include/checker.h"
#include "../include/compiler.h"
#include "../include/evaluator.h"
#include "../include/lexer.h"
#include "../include/parser.h"
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
void run_program(char *buf, const char *filename) {
  alloc_init();

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

  Parser parser = parser_new(lexer.tokens, buf, filename);

  parser_parse(&parser);

  puts("---");

  puts("-- FUNCTIONS --");

  hashmap_foreach(&parser.custom_functions, Ident * key, ExprFunction * val,
                  { puts(*key); });
  printf("Custom functions: %zu\n", parser.custom_functions.len);

  puts("---");

  puts("-- TYPES --");

  hashmap_foreach(&parser.custom_types, Ident * *key, TypeExpr * val,
                  { puts(**key); });

  puts("---");

  TypeChecker checker = checker_new(parser.statements);
#ifdef TARGET_WEB
  function_println_use_buffer();
#endif
  builtin_functions_init(checker.global_type_table);

  checker_check(&checker);

  checker_gen_functions(&checker);

  puts("-- AST --");

  for (size_t i = 0; i < array_len(checker.stmts); i++) {
    char print_buf[1024];
    parser_stmt_print(print_buf, &checker.stmts[i]);
    printf("%s\n", print_buf);
  }

#ifdef INTERPRETER
  Evaluator evaluator = evaluator_new(checker.stmts);

  evaluator_eval_global(&evaluator, checker.global_type_table);

  puts("---");

  Expression expr = {.type = EXPR_CALL,
                     .var = {.expr_call = {.function = "main", .args = NULL}}};
  evaluator_eval_expr(&evaluator, &expr);
#elif defined(COMPILER)
  Compiler compiler = compiler_new(parser.statements);
  compiler_compile(&compiler);

  compiler_generate(&compiler);

  FILE *out_file = fopen("output/out.o", "w");

  compiler_write(&compiler, out_file);

  fclose(out_file);
#endif
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

int main(void) {
  char file_buf[4096];
  FILE *file = fopen("test1.goo", "r");
  size_t n = fread(file_buf, 1, sizeof(file_buf) - 1, file);
  file_buf[n] = '\0';

  run_program(file_buf, "test1.goo");

  fclose(file);

  return 0;
}
