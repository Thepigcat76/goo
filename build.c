// To build the project, compile this file with a compiler of your choice and
// run the compiled executable. The project also requires the gurd header, which
// can be found at <https://github.com/Thepigcat76/gurd/blob/main/gurd.h>

#include "gurd.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define COMPILER "clang"
#define STANDARD "gnu23"
#define DEBUG true
#define OUT_NAME "build/goo"

#define GOO_VERSION "\\\"0.1\\\""
#define GOO_VERSION_RELEASE_DATE "\\\"2026-07-04\\\""

#define LIB_LILC "lilc"

static Cmd cmd = {0};

static int compiler_tests(void);

static void visit_entry(struct file_entry entry) {
  if (strcmp(entry.file_ext, "c") != 0)
    return;

  cmd_appendf(&cmd, "%s", entry.path);
}

int main(int argc, char **argv) {
  if (arg_eq(argc, argv, 1, "tests")) {
    return compiler_tests();
  }

  // The compiler to use
  cmd_appendf(&cmd, COMPILER);
  // Flags
  cmd_appendf(&cmd, "-g");
  cmd_appendf(&cmd, "-rdynamic");
  cmd_appendf(&cmd, "-std=%s", STANDARD);
  // Output location
  cmd_appendf(&cmd, "-o");
  cmd_appendf(&cmd, OUT_NAME);
  // Build system info
  cmd_appendf(&cmd, "-DGURD");
  // Goo Version info
  cmd_appendf(&cmd, "-DGOO_VERSION=" GOO_VERSION);
  cmd_appendf(&cmd, "-DGOO_VERSION_RELEASE_DATE=" GOO_VERSION_RELEASE_DATE);

  // Adding src files
  walk_dir("src", visit_entry);

  // Libraries
  cmd_appendf(&cmd, "-l%s", LIB_LILC);

  cmd_fprint(&cmd, stdout);
  putchar('\n');
  fflush(stdout);

  // Run the command
  cmd_execute(&cmd);

  bool run = arg_eq(argc, argv, 1, "r");

  bool debug = run && (args_contains(argc, argv, "--debug") != -1 ||
                       args_contains(argc, argv, "-d") != -1);

  int args_arg_idx = args_contains(argc, argv, "--args");

  if (run) {
    char args[1024] = {'\0'};

    if (args_arg_idx != -1 && args_arg_idx + 1 < argc) {
      for (int i = args_arg_idx + 1; i < argc; i++) {
        strcat(args, argv[i]);
        if (i + 1 < argc) {
          strcat(args, " ");
        }
      }
    }

    char exec_cmd[1024];
    sprintf(exec_cmd, "./%s", OUT_NAME);

    if (debug) {
      sprintf(exec_cmd, "gdb --args ./%s", OUT_NAME);
    } else if (args_contains(argc, argv, "-vg")) {
      sprintf(exec_cmd, "valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --errors-for-leak-kinds=all ./%s", OUT_NAME);
    }

    return WEXITSTATUS(systemf("%s %s", exec_cmd, args));
  }
}

static int cmd_run_capture_out(const char *cmd, char **stdout_buf) {
  FILE *fp = popen(cmd, "r");
  if (fp == NULL) {
    perror("popen");
    return 1;
  }

  size_t sz = 4096;

  *stdout_buf = malloc(sz);

  **stdout_buf = '\0';

  char line_buf[512];
  while (fgets(line_buf, sizeof(line_buf), fp) != NULL) {
    strcat(*stdout_buf, line_buf);
  }

  int status = pclose(fp);
  int exit_code = WEXITSTATUS(status);
  return exit_code;
}

static char *run_test_program0(const char *name, int *exit_code,
                               const char *link_libs) {
  printf("Compiling test '%s'\n", name);
  char run_cmd[1024];
  char *stdout_buf = NULL;
  if (exit_code == NULL) {
    int exit_code0;
    exit_code = &exit_code0;
  }
  sprintf(run_cmd, "./tests/build/%s", name);
  if ((*exit_code = WEXITSTATUS(systemf(
           "gurd r --args tests/%s.goo -o tests/build/%s.o", name, name)))) {
    printf("Compiler exited with code %d\n", *exit_code);
    return stdout_buf;
  }
  if ((*exit_code =
           WEXITSTATUS(systemf("gcc tests/build/%s.o %s -o tests/build/%s",
                               name, link_libs, name)))) {
    printf("Linker exited with code %d\n", *exit_code);
    return stdout_buf;
  }
  printf("Running program '%s'\n", name);
  if ((*exit_code = WEXITSTATUS(cmd_run_capture_out(run_cmd, &stdout_buf)))) {
    printf("Program exited with code %d\n", *exit_code);
    return stdout_buf;
  }

  return stdout_buf;
}

#define run_test_program(name, exit_code, ...)                                 \
  run_test_program0(name, exit_code, "" __VA_ARGS__)

static int compiler_tests(void) {
  ensure_parent_dirs("tests/build/.", 0o755);

  run_test_program("modules", NULL, "-lraylib tests/print_int.a");
  char *out = run_test_program("test_modules", NULL, "-lraylib tests/print_int.a");
  
  printf("Test modules output: %s\n", out);

  assert(strcmp("Modules working\n", out) == 0);

  run_test_program("comptime", NULL, "-lraylib tests/print_int.a");

  return 0;
}
