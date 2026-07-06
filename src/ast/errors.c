#pragma once

#include "../../include/errors.h"
#include "../../include/shared.h"
#include "lilc/ansi.h"
#include "lilc/dynstr.h"
#include "lilc/numbers.h"
#include <lilc/alloc.h>
#include <lilc/array.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#define PRINT_SPACE(str_ptr, amount)                                           \
  for (size_t i = 0; i < amount; i++) {                                        \
    dyn_string_add_char(str_ptr, ' ');                                         \
  }

void error_sink_init(ErrorSink *error_sink) {
  error_sink->msgs = array_new(ErrorMessage, &HEAP_ALLOCATOR);
}

static dyn_string_t error_desc_fmt(const LexerLine *src_lines,
                                   const ErrorMessage *msg) {
  dyn_string_t str = {0};
  dyn_string_init(&str, &HEAP_ALLOCATOR);

  size_t first_line_idx = msg->ctx_first_line - 1;
  size_t lines_amount = msg->ctx_lines_amount;

  size_t ctx_last_line = msg->ctx_first_line + lines_amount;

  dyn_string_t str0 = {0};
  dyn_string_init(&str0, &HEAP_ALLOCATOR);
  size_t line_number_max_len = snprintf(NULL, 0, "%zu", ctx_last_line);
  for (size_t i = 0; i < lines_amount; i++) {
    size_t actual_line_idx = first_line_idx + i;
    LexerLine line = src_lines[actual_line_idx];
    char line_number_buf[128] = {0};
    size_t cur_line_number_len =
        sprintf(line_number_buf, "%zu", first_line_idx + i + 1);
    char space_buf[128] = {0};
    for (ssize_t j = 0;
         j < (ssize_t)(line_number_max_len - cur_line_number_len); j++) {
      strcat(space_buf, " ");
    }

    dyn_string_printf(&str0, "%s%s |%.*s\n", space_buf, line_number_buf,
                      (int)line.len, line.begin);
    dyn_string_add_str(&str, str0.string);
    dyn_string_clear(&str0);

    if (msg->issue_len > 1) {
      PRINT_SPACE(&str, line_number_max_len)
      dyn_string_add_str(&str, " |");
      PRINT_SPACE(&str, msg->issue_pos - 1)
      for (size_t j = 0; j < msg->issue_len; j++) {
        dyn_string_add_char(&str, '~');
      }
      dyn_string_add_char(&str, '\n');
    }

    // Draw the issue arrow
    if (msg->issue_line == actual_line_idx + 1) {
      PRINT_SPACE(&str, line_number_max_len)
      dyn_string_add_str(&str, " |");
      PRINT_SPACE(&str, msg->issue_pos - 1 + msg->issue_len - 1)
      dyn_string_add_char(&str, '^');
      dyn_string_add_char(&str, '\n');

      // Print the issue specific tip/message
      if (msg->issue_ctx_msg != NULL) {
        size_t issue_ctx_msg_len = strlen(msg->issue_ctx_msg);
        PRINT_SPACE(&str, line_number_max_len)
        dyn_string_add_str(&str, " |");
        // Issue pos starts at 1 so we subtract 1
        // The first char is fine since arrow is also one char so we add 1
        size_t spaces_len;
        bool msg_excedes_spaces = false;
        if (issue_ctx_msg_len + 1 > msg->issue_pos - 1) {
          spaces_len = msg->issue_pos - 1;
          msg_excedes_spaces = true;
        } else {
          spaces_len = msg->issue_pos - 1 - issue_ctx_msg_len + 1;
        }
        PRINT_SPACE(&str, spaces_len)
        if (msg_excedes_spaces) {
          PRINT_SPACE(&str, msg->issue_len - 1)
          dyn_string_add_char(&str, '|');
          dyn_string_add_char(&str, '\n');
          PRINT_SPACE(&str, line_number_max_len)
          dyn_string_add_str(&str, " |");
          PRINT_SPACE(&str, spaces_len)
        }
        PRINT_SPACE(&str, msg->issue_len - 1)
        dyn_string_add_str(&str, msg->issue_ctx_msg);
        dyn_string_add_char(&str, '\n');
      }
    }
  }

  dyn_string_free(&str0);
  return str;
}

static dyn_string_t error_msg_fmt(const LexerLine *src_lines,
                                  const char *filename,
                                  const ErrorMessage *msg) {
  dyn_string_t str = {0};
  dyn_string_init(&str, &HEAP_ALLOCATOR);

  i32 caller_line = 0;
  const char *caller_file = NULL;
#ifdef GURD
  if (debug_flags.extra_parse_err_info) {
    caller_line = msg->caller_line;
    caller_file = msg->caller_file;
  }
#endif

  dyn_string_printf(&str,
                    "%s[%s:%zu:%zu]: " ANSI_RED "error:" ANSI_RESET " %s\n",
                    debug_flags.extra_parse_err_info
                        ? str_fmt_temp("(%s:%d) ", caller_file, caller_line)
                        : "",
                    filename, msg->issue_line, msg->issue_pos, msg->err_msg);

  dyn_string_t str0 = error_desc_fmt(src_lines, msg);
  dyn_string_add_str(&str, str0.string);

  dyn_string_free(&str0);

  return str;
}

#ifdef GURD
void sink_add_err0(ErrorSink *sink, ErrorMessage err_msg, i32 caller_line,
                   const char *caller_file)
#else
void sink_add_err(ErrorSink *sink, ErrorMessage err_msg)
#endif
{
#ifdef GURD
  err_msg.caller_line = caller_line;
  err_msg.caller_file = caller_file;
#endif
  if (err_msg.issue_len == 0) {
    err_msg.issue_len = 1;
  }
  array_add(sink->msgs, err_msg);
}

static void err_msg_print(const LexerLine *src_lines, const char *filename,
                          ErrorMessage *err_msg) {
  dyn_string_t msg = error_msg_fmt(src_lines, filename, err_msg);
  printf("%s", msg.string);
}

void sink_print_errors(const LexerLine *src_lines, const char *filename,
                       const ErrorSink *sink) {
  ErrorMessage *msg;
  array_foreach(sink->msgs, msg) { err_msg_print(src_lines, filename, msg); }
}
