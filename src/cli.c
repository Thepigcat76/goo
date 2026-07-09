#include "../include/shared.h"
#include "lilc/log.h"
#include <lilc/alloc.h>
#include <lilc/dynstr.h>
#include <lilc/file.h>
#include <stdio.h>
#include <string.h>

// clang-format off
// full-option, short-option, desc for option
const char *CLI_OPTIONS[] = {
  "--version", "-v", "Display version information (does not require input file)",
  "--help", "-h", "Display help information (this information) (does not require input file)",
  "--output", "-o", "Specify the output path",
  "--module-path", "-mp", "Specify the module path of the input file. (Example: '-mp core.io.files')",
  "--debug-flag=<option>", "-df=<option>", "Enable a specific type of debug information like logs, internal warnings and errors"
};
// clang-format on

typedef struct {
  enum {
    ARG_INVALID,
    ARG_PRINT_VERSION,
    ARG_PRINT_HELP,
    ARG_COMPILE_FILE,
  } kind;
  struct compile_file {
    char *input_path;
    char *output_path;

    char *module_path;
    struct debug_flags debug_flags;
  } compile_file;
} CliArgs;

#define NEXT_ARG(i, argc)                                                      \
  if (++i >= argc)                                                             \
  break

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

static void print_help(FILE *f);

static void print_version(FILE *f);

static void args_parse(CliArgs *args, char **argv, size_t argc) {
  args->kind = ARG_INVALID;

  struct compile_file *compile_file = &args->compile_file;

  size_t i = 1;
  while (i < argc) {
    if (i == 1) {
      if (argv[i][0] != '-') {
        args->kind = ARG_COMPILE_FILE;
        compile_file->input_path = argv[i];
        NEXT_ARG(i, argc);
      } else if (STR_CMP_OR(argv[i], "-h", "--help")) {
        args->kind = ARG_PRINT_HELP;
        break;
      } else if (STR_CMP_OR(argv[i], "-v", "--version")) {
        args->kind = ARG_PRINT_VERSION;
        break;
      }
    }

    if (STR_CMP_OR(argv[i], "-o", "--output")) {
      if (args->kind != ARG_COMPILE_FILE) {
        log_error(
            "Option 'output' can only be used with an input file to compile");
        exit(1);
      }

      NEXT_ARG(i, argc);
      compile_file->output_path = argv[i];
    } else if (STR_CMP_OR(argv[i], "-mp", "--module-path")) {
      if (args->kind != ARG_COMPILE_FILE) {
        log_error("Option 'module-path' can only be used with an input file to "
                  "compile");
        exit(1);
      }

      NEXT_ARG(i, argc);
      compile_file->module_path = argv[i];
    } else if (strncmp(argv[i], "-df", 3) == 0 ||
               strncmp(argv[i], "--debug-flag", strlen("--debug-flag")) == 0) {

      log_debug("DEBUG INFO OPTION");
      if (args->kind != ARG_COMPILE_FILE) {
        log_error("Option 'debug-info' can only be used with an input file to "
                  "compile");
        exit(1);
      }

      size_t arg_len = strlen(argv[i]);
      size_t arg_prefix_len =
          strncmp(argv[i], "-df", 3) == 0 ? 3 : strlen("--debug-flag");

      if (arg_len > 3 && argv[i][3] == '=') {
        char *value = argv[i] + arg_prefix_len + 1;

        if (strcmp(value, "print_tokens") == 0)
          compile_file->debug_flags.print_tokens = true;
        else if (strcmp(value, "print_ast") == 0)
          compile_file->debug_flags.print_ast = true;
        else if (strcmp(value, "print_preprocessed_ast") == 0)
          compile_file->debug_flags.print_preprocessed_ast = true;
        else if (strcmp(value, "print_parse_info") == 0)
          compile_file->debug_flags.print_parse_info = true;
        else if (strcmp(value, "print_preprocessor_info") == 0)
          compile_file->debug_flags.print_preprocessor_info = true;
        else if (strcmp(value, "print_checker_info") == 0)
          compile_file->debug_flags.print_checker_info = true;
        else if (strcmp(value, "print_compile_info") == 0)
          compile_file->debug_flags.print_compile_info = true;
        else if (strcmp(value, "print_codegen_info") == 0)
          compile_file->debug_flags.print_codegen_info = true;
        else if (strcmp(value, "print_obj_write_info") == 0)
          compile_file->debug_flags.print_obj_write_info = true;
        else if (strcmp(value, "extra_parse_err_info") == 0)
          compile_file->debug_flags.extra_parse_err_info = true;
        else
          log_error("Invalid debug info option '%s'", value);
      } else {
        memset(&compile_file->debug_flags, 1, sizeof(struct debug_flags));
      }

    } else {
      log_error("Unrecognized option '%s'", argv[i]);
      exit(1);
    }
    NEXT_ARG(i, argc);
  }
}

void compile_input(const char *input_path, const char *output_path,
                   const char *raw_module_path);

static void args_handle(CliArgs *args) {
  switch (args->kind) {
  case ARG_INVALID: {
    log_error("No arguments provided to compiler. Valid arguments:\n");
    print_help(stdout);
  } break;
  case ARG_PRINT_VERSION: {
    print_version(stdout);
  } break;
  case ARG_PRINT_HELP: {
    print_help(stdout);
  } break;
  case ARG_COMPILE_FILE: {
    if (args->compile_file.input_path == NULL) {
      log_error("No input path provided");
      return;
    }
    if (args->compile_file.output_path == NULL) {
      dyn_string_t default_out_path = {0};
      dyn_string_init(&default_out_path, &HEAP_ALLOCATOR);

      dyn_string_t input_name =
          file_name(args->compile_file.input_path, &HEAP_ALLOCATOR);

      log_debug("Input name: %s", input_name.string);

      dyn_string_printf(&default_out_path, "%s.o", input_name.string);

      dyn_string_free(&input_name);

      args->compile_file.output_path = default_out_path.string;
    }
    if (args->compile_file.module_path == NULL) {
      args->compile_file.module_path = "";
    }

    debug_flags = args->compile_file.debug_flags;

    compile_input(args->compile_file.input_path, args->compile_file.output_path,
                  args->compile_file.module_path);
  } break;
  }
}

void cli_run(char **argv, size_t argc) {
  CliArgs args = {0};
  args_parse(&args, argv, argc);
  args_handle(&args);
}

#ifndef GOO_VERSION
#define GOO_VERSION "0.1"
#endif

#ifndef GOO_VERSION_RELEASE_DATE
#define GOO_VERSION_RELEASE_DATE "2026-04-26"
#endif

static void print_help(FILE *out) {
  dyn_string_t str = {0};
  dyn_string_init(&str, &HEAP_ALLOCATOR);

  size_t CLI_OPTIONS_len = sizeof(CLI_OPTIONS) / sizeof(char *);

  size_t full_opt_max_len = 0;
  size_t short_opt_max_len = 0;
  size_t info_max_len = 0;

  for (size_t i = 0; i < CLI_OPTIONS_len;) {
    full_opt_max_len = max(full_opt_max_len, strlen(CLI_OPTIONS[i]));
    short_opt_max_len = max(short_opt_max_len, strlen(CLI_OPTIONS[i + 1]));
    info_max_len = max(info_max_len, strlen(CLI_OPTIONS[i + 2]));
    i += 3;
  }

  dyn_string_add_str(
      &str, "Goo is a tool for compiling and managing goo source code\n");
  dyn_string_add_str(&str, "Options:\n");

  for (size_t i = 0; i < CLI_OPTIONS_len;) {
    dyn_string_add_str(&str, "  ");
    dyn_string_add_str(&str, CLI_OPTIONS[i]);
    size_t full_opt_len = strlen(CLI_OPTIONS[i]);
    size_t whitespace0 = full_opt_max_len - full_opt_len + 1;
    for (size_t j = 0; j < whitespace0; j++) {
      dyn_string_add_char(&str, ' ');
    }
    dyn_string_add_str(&str, CLI_OPTIONS[i + 1]);
    size_t short_opt_len = strlen(CLI_OPTIONS[i + 1]);
    size_t whitespace1 = short_opt_max_len - short_opt_len + 1;
    for (size_t j = 0; j < whitespace1; j++) {
      dyn_string_add_char(&str, ' ');
    }
    dyn_string_add_str(&str, CLI_OPTIONS[i + 2]);
    dyn_string_add_char(&str, '\n');
    i += 3;
  }

  fputs(str.string, out);
}

constexpr char VERSION_INFO[] =
    "goo " GOO_VERSION " (" GOO_VERSION_RELEASE_DATE ")\n";

static void print_version(FILE *out) { fputs(VERSION_INFO, out); }