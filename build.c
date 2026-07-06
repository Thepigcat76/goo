// To build the project, compile this file with a compiler of your choice and
// run the compiled executable. The project also requires the gurd header, which
// can be found at <https://github.com/Thepigcat76/gurd/blob/main/gurd.h>

#include "gurd.h"
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

static void visit_entry(struct file_entry entry) {
  if (strcmp(entry.file_ext, "c") != 0)
    return;

  cmd_appendf(&cmd, "%s", entry.path);
}

int main(int argc, char **argv) {
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

    char exec_cmd[256];
    sprintf(exec_cmd, "./%s", OUT_NAME);

    if (debug) {
      sprintf(exec_cmd, "gdb --args ./%s", OUT_NAME);
    }

    systemf("%s %s", exec_cmd, args);
  }
}
