#pragma once

#include "lexer.h"
#include <stddef.h>
#ifdef GURD
#include "lilc/numbers.h"
#endif

typedef struct {
  size_t ctx_first_line;
  size_t ctx_lines_amount;
  size_t issue_pos;
  size_t issue_line;
  size_t issue_len;
  char *err_msg;
  const char *issue_ctx_msg;
#ifdef GURD
  i32 caller_line;
  const char *caller_file;
#endif
} ErrorMessage;

typedef struct {
  ErrorMessage *msgs;
} ErrorSink;

void error_sink_init(ErrorSink *error_sink);

void error_sink_deinit(ErrorSink *sink);

#define ERR_MSG(...) (ErrorMessage) __VA_ARGS__
#ifdef GURD
void sink_add_err0(ErrorSink *sink, ErrorMessage err_msg, i32 caller_line,
                   const char *caller_file);

#define sink_add_err(sink, err_msg)                                            \
  sink_add_err0(sink, err_msg, __LINE__, __FILE__)
#else
void sink_add_err(ErrorSink *sink, ErrorMessage err_msg);
#endif

void sink_print_errors(const SourceLine *src_lines, const char *filename,
                       const ErrorSink *sink);
