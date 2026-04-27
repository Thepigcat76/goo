#include <assert.h>
#include <complex.h>
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

#ifndef GOO_VERSION
#define GOO_VERSION "0.1"
#endif

#ifndef GOO_VERSION_RELEASE_DATE
#define GOO_VERSION_RELEASE_DATE "2026-04-26"
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
void run_program(char *buf, const char *filename, const char *output,
                 const char *raw_module_path) {
  alloc_init();

  debug_flags.print_tokens = true;

  builtin_types_init();

  //  parser_test_functions();

  //  return;

  ModulePath module_path = parse_module_path_from_string(raw_module_path);

  Lexer lexer = {0};
  lexer_init(&lexer);

  lexer_tokenize(&lexer, buf, filename);
  array_add(lexer.tokens, (Token){.kind = TOKEN_EOF});

  if (debug_flags.print_tokens) {
    for (size_t i = 0; i < array_len(lexer.tokens); i++) {
      char print_buf[256];
      lexer_tok_print(print_buf, &lexer.tokens[i]);
      puts(print_buf);
    }
  }

  Parser parser = {0};
  parser_init(&parser, lexer.tokens, buf, filename, module_path);
  parser.lines = lexer.lines;

  parser_parse(&parser);

  // Parsing finished, free tokens and lexer lines
  lexer_deinit(&lexer);

  if (debug_flags.print_ast) {
    log_debug("AST:\n%s", ast_format(parser.statements).string);
  }

  PreProcessor preprocessor = {0};
  preprocessor_init(&preprocessor, parser.statements, parser.pp_dirs);

  preprocessor_process(&preprocessor);

  preprocessor_deinit(&preprocessor);

  TypeChecker checker = {0};
  checker_init(&checker, &parser);
#ifdef TARGET_WEB
  function_println_use_buffer();
#endif
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

#ifdef INTERPRETER
  Evaluator evaluator = evaluator_new(checker.stmts);

  evaluator_eval_global(&evaluator, checker.global_type_table);

  puts("---");

  Expression expr = {.type = EXPR_CALL,
                     .var = {.expr_call = {.function = "main", .args = NULL}}};
  evaluator_eval_expr(&evaluator, &expr);
#elif defined(COMPILER)
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

  FILE *out_file = fopen(output, "w");

  compiler_write(&compiler, out_file);

  compiler_deinit(&compiler);

  fclose(out_file);
#endif

  bump_free(&lexer.tok_arena);
  bump_free(&parser.ast_arena);
  bump_free(&checker.checker_arena);
  bump_free(&compiler.compiler_arena);

  hashmap_free(&mangled_functions);

  builtin_types_deinit();

  array_free(module_path.path);
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
  if (++i >= argc)                                                             \
  break

typedef struct {
  char *output_path;
  char *input_path;
  char *module_path;
  bool display_help;
  bool display_version;
} CliArgs;

static char *_corelib_path = NULL;

static void display_help(void);

static void display_version(void);

int main(int argc, char **argv) {
  CliArgs args = {0};

  memset(&debug_flags, 0, sizeof(struct debug_flags));

  int i = 1;
  while (i < argc) {
    if (i == 1 && argv[i][0] != '-') {
      args.input_path = argv[i];
      NEXT_ARG(i, argc);
    }

    if (STR_CMP_OR(argv[i], "-h", "--help")) {
      args.display_help = true;
      break;
    } else if (STR_CMP_OR(argv[i], "-v", "--version")) {
      args.display_version = true;
      break;
    } else if (STR_CMP_OR(argv[i], "-o", "--output")) {
      NEXT_ARG(i, argc);
      args.output_path = argv[i];
    } else if (STR_CMP_OR(argv[i], "-mp", "--module-path")) {
      NEXT_ARG(i, argc);
      args.module_path = argv[i];
    } else if (STR_CMP_OR(argv[i], "-di", "--debug-info")) {
      memset(&debug_flags, 1, sizeof(struct debug_flags));
    }
    NEXT_ARG(i, argc);
  }

  if (args.display_help) {
    display_help();
    return 0;
  }

  if (args.display_version) {
    display_version();
    return 0;
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

  if (args.module_path == NULL) {
    args.module_path = "";
  }

  char *core_lib_path = getenv(CORE_LIB_PATH);
  if (core_lib_path == NULL) {
    setenv(CORE_LIB_PATH, DEFAULT_CORE_LIB_PATH, 0);
    core_lib_path = DEFAULT_CORE_LIB_PATH;
  }

  _corelib_path = core_lib_path;

  FILE *file = fopen(args.input_path, "r");

  if (file == NULL) {
    log_error("Failed to find input file %s", args.input_path);
    return 1;
  }

  char file_buf[4096];
  size_t n = fread(file_buf, 1, sizeof(file_buf) - 1, file);
  file_buf[n] = '\0';

  run_program(file_buf, args.input_path, args.output_path, args.module_path);

  fclose(file);

  return 0;
}

constexpr char HELP_INFO[] =
    "Goo is a tool for compiling and managing goo source code.\n"
    "\n"
    "Usage: goo <input_filename> [options]\n"
    "Options:\n"
    "  --version     (-v)                    Display version information.\n"
    "  --help        (-h)                    Display this information.\n"
    "  --ouput       (-o)  <out_filename>    Specify the output path.\n"
    "  --module-path (-mp) <module_path>     Specify the module path of the "
    "input file. (Example: '-mp core.io.files')\n"
    "  --debug-info  (-di)                   Enable debug information like "
    "logs, internal warnings and errors.";

static void display_help(void) { puts(HELP_INFO); }

constexpr char VERSION_INFO[] =
    "goo " GOO_VERSION " (" GOO_VERSION_RELEASE_DATE ")";

static void display_version(void) { puts(VERSION_INFO); }
