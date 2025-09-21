#include "../panic.h"
#include "../ansi.h"
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

static void stack_trace_print(void) {
//  void *buffer[100];
//  int nptrs = backtrace(buffer, 100);
//  char **symbols = backtrace_symbols(buffer, nptrs);
//
//  if (symbols == NULL) {
//    perror("backtrace_symbols");
//    exit(EXIT_FAILURE);
//  }
//
//  printf("Stack trace (%d frames):\n", nptrs);
//  for (int i = 0; i < nptrs; i++) {
//    printf("%s\n", symbols[i]);
//  }
//
//  free(symbols);
}

void panic(const char *fmt, ...) {
  puts(ANSI_RED "Program panicked" ANSI_RESET);
  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
  puts("Crashed at:");
  stack_trace_print();
  exit(1);
}
