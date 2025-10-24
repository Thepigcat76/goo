#ifdef TARGET_WEB
#include <emscripten.h>
#include <emscripten/emscripten.h>
#define KEEPALIVE EMSCRIPTEN_KEEPALIVE
#define main _regular_main
#else
#define KEEPALIVE
#endif

#include "../include/builtins.h"
#include "../include/checker.h"
#include "../include/evaluator.h"
#include "../include/lexer.h"
#include "../include/parser.h"
#include "../vendor/lilc/alloc.h"
#include "../vendor/lilc/array.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "tests.c"

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
void run_program(char *buf) {
  alloc_init();

//  parser_test_functions();

//  return;

  Lexer lexer = lexer_new();

  lexer_tokenize(&lexer, buf);
  array_add(lexer.tokens, (Token){.type = TOKEN_EOF});

  for (size_t i = 0; i < array_len(lexer.tokens); i++) {
    char print_buf[256];
    lexer_tok_print(print_buf, &lexer.tokens[i]);
    puts(print_buf);
  }

  Parser parser = parser_new(lexer.tokens);

  parser_parse(&parser);

  puts("-- AST --");

  for (size_t i = 0; i < array_len(parser.statements); i++) {
    char print_buf[1024];
    parser_stmt_print(print_buf, &parser.statements[i]);
    printf("%s\n", print_buf);
  }

  TypeChecker checker = checker_new(parser.statements);
#ifdef TARGET_WEB
  function_println_use_buffer();
#endif
  builtin_functions_init(checker.global_type_table);

  checker_check(&checker);

  checker_gen_functions(&checker);

  Evaluator evaluator = evaluator_new(checker.stmts);

  evaluator_eval_global(&evaluator, checker.global_type_table);

  puts("---");

  Expression expr = {.type = EXPR_CALL,
                     .var = {.expr_call = {.function = "main", .args = NULL}}};
  evaluator_eval_expr(&evaluator, &expr);
}

KEEPALIVE
char *function_println_buffer(void) { return println_buf; }

KEEPALIVE
void function_println_buffer_clear(void) { println_buf[0] = '\0'; }

int main(void) {
  char file_buf[4096];
  FILE *file = fopen("test.goo", "r");
  size_t n = fread(file_buf, 1, sizeof(file_buf) - 1, file);
  file_buf[n] = '\0';

  run_program(file_buf);
  return 0;
}
