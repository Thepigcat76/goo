#include "../include/parser.h"
#include "../include/preprocess.h"
#include "lilc/alloc.h"
#include "lilc/array.h"
#include "lilc/eq.h"
#include "lilc/hash.h"
#include "lilc/panic.h"
#include <lilc/ansi.h>
#include <lilc/hashmap.h>
#include <lilc/log.h>
#include <lilc/str.h>
#include <lilc/todo.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

Hashmap(ModulePath, Ident) mangled_functions = {.keys = NULL};

#define DEBUG_TOK(tok_ptr, ctx_msg)                                            \
  do {                                                                         \
    char tok_buf[64];                                                          \
    lexer_tok_print(tok_buf, tok_ptr);                                         \
    printf("DEBUG: TOKEN %s - " ctx_msg "\n", tok_buf);                        \
  } while (0)

typedef struct {
  Expression expr;
  bool present;
  char *error_msg;
} OptionalExpr;

typedef struct {
  char *error_msg;
  bool success;
  int line;
  int pos;
} ParseResult;

#define PARSE_RESULT(...) (ParseResult) __VA_ARGS__

#define EXPECTED_TOKEN_ERR(expected, received_ptr)                             \
  do {                                                                         \
    char print_buf[64];                                                        \
    lexer_tok_print(print_buf, received_ptr);                                  \
    fprintf(stderr, "Expected " #expected ", received: %s\n", print_buf);      \
    exit(1);                                                                   \
  } while (0)

#define ILLEGAL_TOKEN_ERR(tok)                                                 \
  fprintf(stderr, "Illegal " #tok " at beginning of stmt\n");                  \
  exit(1)

const Expression UNIT_EXPR = {.kind = EXPR_UNIT};
const OptionalType OPT_TYPE_EMPTY = {.present = false};

#define AST_ARENA_SIZE 160000

void parser_init(Parser *parser, Token *tokens, const char *source,
                 const char *filename, ModulePath path) {
  if (mangled_functions.keys == NULL) {
    mangled_functions =
        hashmap_new(ModulePath, Ident, &HEAP_ALLOCATOR, module_path_ptrv_hash,
                    module_path_ptrv_eq, NULL);
  }
  parser->tokens = tokens;
  parser->statements = array_new(Statement, &HEAP_ALLOCATOR);
  parser->custom_types = hashmap_new(Ident *, TypeExpr, &HEAP_ALLOCATOR,
                                     str_ptrv_hash, str_ptrv_eq, NULL);
  parser->custom_functions = hashmap_new(Ident *, ExprFunction, &HEAP_ALLOCATOR,
                                         str_ptrv_hash, str_ptrv_eq, NULL);
  parser->pp_dirs = array_new(PpDirective, &HEAP_ALLOCATOR);
  parser->pp_dir_conditionals = array_new(size_t, &HEAP_ALLOCATOR);
  parser->filename = filename;
  parser->source = source;
  parser->path = path;
  parser->foreign_functions = array_new(ModulePath, &HEAP_ALLOCATOR);
  parser->imported_modules = array_new(ModulePath, &HEAP_ALLOCATOR);
  parser->imported_functions =
      hashmap_new(ModulePath, FuncDescriptor, &HEAP_ALLOCATOR,
                  module_path_ptrv_hash, module_path_ptrv_eq, NULL);
  parser->module = (Module){0};
  module_init(&parser->module, filename, source);

  bump_init(&parser->ast_arena, AST_ARENA_SIZE);
  bump_allocator_init(&parser->ast_arena_allocator, &parser->ast_arena);
}

void parser_deinit(Parser *parser) {
  hashmap_free(&parser->custom_types);
  hashmap_free(&parser->custom_functions);

  module_deinit(&parser->module);
  array_free(parser->pp_dirs);
  array_free(parser->pp_dir_conditionals);
  array_free(parser->foreign_functions);
  array_free(parser->imported_modules);
  hashmap_free(&parser->imported_functions);
  array_free(parser->statements);
}

static void next_token(Parser *parser) {
  parser->cur_tok = parser->peek_tok;
  parser->peek_tok++;
}

// first: first ident of module path
// end: last ident of the module path
static ModulePath parse_module_path(Parser *parser) {
  ModulePath path = {.path = array_new(Ident, &parser->ast_arena_allocator)};
  while (parser->cur_tok->kind != TOKEN_EOF) {
    if (parser->cur_tok->kind == TOKEN_IDENT) {
      array_add(path.path, parser->cur_tok->var.ident);
    } else {
      log_error("[PARSER] Non ident found in module path");
      exit(1);
    }

    if (parser->peek_tok->kind == TOKEN_DOT) {
      next_token(parser);
      if (parser->peek_tok->kind == TOKEN_IDENT) {
        next_token(parser);
      } else {
        log_error("[PARSER] Parsing module path, encountered dot at the end of "
                  "the path");
        exit(1);
      }
      continue;
    } else {
      break;
    }
  }
  return path;
}

static Statement parse_stmt(Parser *parser);

// begin: cur_tok must be first token of type
// end: cur_tok is last token of type
static Type parse_type(Parser *parser) {
  switch (parser->cur_tok->kind) {
  case TOKEN_IDENT: {
    ModulePath ident = parse_module_path(parser);
    if (strv_eq(ident.path[0], "string")) {
      return STRING_BUILTIN_TYPE;
    }
    return (Type){.kind = TYPE_IDENT, .var = {.type_ident = ident}};
  }
  case TOKEN_ASTERISK: {
    // cur_tok is type
    next_token(parser);
    Type type = parse_type(parser);

    return (Type){.kind = TYPE_POINTER,
                  .var = {.type_pointer = {.type = heap_clone(&type)}}};
  }
  case TOKEN_LPAREN: {
    if (parser->peek_tok->kind == TOKEN_RPAREN) {
      // cur_tok is right parenthesis
      next_token(parser);
      return (Type){.kind = TYPE_UNIT};
    }
    Type *types = array_new(Type, &HEAP_ALLOCATOR);
    while (parser->peek_tok->kind != TOKEN_RPAREN) {
      // cur_tok is first token of type
      next_token(parser);
      Type type = parse_type(parser);
      array_add(types, type);
      if (parser->peek_tok->kind == TOKEN_COMMA) {
        // cur_tok is comma
        next_token(parser);
      }
    }
    return (Type){.kind = TYPE_TUPLE, .var = {.type_tuple = {.types = types}}};
  }
  case TOKEN_LSQUARE: {
    TypeArray type_array = {};
    if (parser->peek_tok->kind == TOKEN_IDENT &&
        strcmp(parser->peek_tok->var.ident, "dyn") == 0) {
      type_array.variant = TYPE_ARRAY_VARIANT_DYNAMIC;
      // cur_tok is ident
      next_token(parser);
    } else if (parser->peek_tok->kind == TOKEN_INT) {
      type_array.variant = TYPE_ARRAY_VARIANT_SIZED;
      type_array.size = parser->peek_tok->var.integer;
      // cur_tok is int
      next_token(parser);
    } else if (parser->peek_tok->kind == TOKEN_RSQUARE) {
      type_array.variant = TYPE_ARRAY_VARIANT_SIZE_UNKNOWN;
    }
    // cur_tok is right parenthesis
    next_token(parser);
    // cur_tok is first token of type
    next_token(parser);
    Type type = parse_type(parser);
    type_array.type = bump_clone(&parser->ast_arena, &type);
    return (Type){.kind = TYPE_ARRAY, .var = {.type_array = type_array}};
  }
  // case TOKEN_LANGLE: {
  //   break;
  // }
  default: {
    char cur_tok_buf[64];
    lexer_tok_print(cur_tok_buf, parser->cur_tok);
    char next_tok_buf[64];
    lexer_tok_print(next_tok_buf, parser->peek_tok);
    printf("Type parsing nyi for type, cur_tok: %s, next: %s\n", cur_tok_buf,
           next_tok_buf);
    exit(1);
  }
  }
}

// begin: cur_tok must be first ident or end
// end: cur_tok is end
static TypedIdent *parse_typed_ident_list(Parser *parser, TokenKind end) {
  TypedIdent *idents = array_new_capacity(TypedIdent, 8, &parser->ast_arena_allocator);
  while (parser->cur_tok->kind != end) {
    TypedIdent ti;
    if (parser->cur_tok->kind == TOKEN_IDENT) {
      ti.ident = parser->cur_tok->var.ident;
    }
    // cur_tok is colon
    next_token(parser);
    if (parser->cur_tok->kind != TOKEN_COLON) {
      EXPECTED_TOKEN_ERR(TOKEN_COLON, parser->cur_tok);
    }
    // cur_tok is type
    next_token(parser);
    ti.type = parse_type(parser);

    if (parser->peek_tok->kind == TOKEN_COMMA) {
      // cur_tok is comma
      next_token(parser);
      // cur_tok is ident or end
      next_token(parser);
    } else if (parser->peek_tok->kind == end) {
      // cur_tok is end
      next_token(parser);
    }
    array_add(idents, ti);
  }
  return idents;
}

static ParseResult parse_expr1(Parser *parser, Expression *expr,
                               Precedence prec);

// begin: cur_tok must be first ident or end
// end: cur_tok is end
static LabeledExpr *parse_labeled_expr_list(Parser *parser, TokenKind end) {
  LabeledExpr *labels = array_new_capacity(LabeledExpr, 8, &HEAP_ALLOCATOR);
  while (parser->cur_tok->kind != end) {
    LabeledExpr le;
    if (parser->cur_tok->kind == TOKEN_IDENT) {
      le.field = parser->cur_tok->var.ident;
    }
    // cur_tok is colon
    next_token(parser);
    if (parser->cur_tok->kind != TOKEN_COLON) {
      EXPECTED_TOKEN_ERR(TOKEN_COLON, parser->cur_tok);
    }
    // cur_tok is expr
    next_token(parser);
    Expression expr;
    ParseResult result = parse_expr1(parser, &expr, PREC_LOWEST);
    if (result.success) {
      le.expr = expr;
    } else {
      fprintf(stderr,
              "Failed to parse expr for labeled expr list, error message: %s",
              result.error_msg);
      exit(1);
    }

    if (parser->peek_tok->kind == TOKEN_COMMA) {
      // cur_tok is comma
      next_token(parser);
      // cur_tok is ident or end
      next_token(parser);
    } else if (parser->peek_tok->kind == end) {
      // cur_tok is end
      next_token(parser);
    }
    array_add(labels, le);
  }
  return labels;
}

// begin: cur_tok must be first type or end
// end: cur_tok is end
static Type *parse_type_list(Parser *parser, TokenKind end) {
  Type *types = array_new_capacity(Type, 8, &HEAP_ALLOCATOR);
  while (parser->cur_tok->kind != end) {
    Type t = {};
    if (parser->cur_tok->kind == TOKEN_IDENT) {
      t = parse_type(parser);
    } else {
      char print_buf[64];
      lexer_tok_print(print_buf, parser->cur_tok);
      fprintf(stderr, "Expected type, received tok: %s", print_buf);
      exit(1);
    }

    if (parser->peek_tok->kind == TOKEN_COMMA) {
      // cur_tok is comma
      next_token(parser);
      // cur_tok is ident or end
      next_token(parser);
    } else if (parser->peek_tok->kind == end) {
      // cur_tok is end
      next_token(parser);
    }
    array_add(types, t);
  }
  return types;
}

// begin: cur_tok must be first token of first statement
// end: cur_tok is end
static Statement *parse_block_statements(Parser *parser, TokenKind end) {
  Statement *stmts = array_new_capacity(Statement, 16, &parser->ast_arena_allocator);
  while (parser->cur_tok->kind != end) {
    Statement stmt = parse_stmt(parser);
    array_add(stmts, stmt);
    next_token(parser);
  }
  return stmts;
}

static ParseResult parse_expr_list(Parser *parser, Expression *exprs,
                                   TokenKind end) {
  while (parser->cur_tok->kind != end) {
    Expression expr = {0};
    ParseResult result = parse_expr1(parser, &expr, PREC_LOWEST);

    if (result.success) {
      array_add(exprs, expr);
    } else {
      return (ParseResult){.success = false, .error_msg = result.error_msg};
    }

    if (parser->peek_tok->kind != TOKEN_COMMA &&
        parser->peek_tok->kind != end) {
      return (ParseResult){
          .success = false,
          .line = parser->cur_tok->line,
          .pos = parser->cur_tok->begin_pos + parser->cur_tok->len,
          .error_msg = "Function call is missing closing right parenthesis"};
    }

    if (parser->peek_tok->kind == TOKEN_COMMA) {
      next_token(parser);
    }

    if (parser->peek_tok->kind == TOKEN_RPAREN) {
      next_token(parser);
      return (ParseResult){.success = true, .error_msg = NULL};
    }

    // cur_tok is next expr
    next_token(parser);
  }
  return (ParseResult){.success = true, .error_msg = NULL};
}

// TODO: Generic functions
// begin: cur_tok must be left parenthesis
// end: cur_tok is return_type ident or right parenthesis
static ParseResult parse_func_desc(Parser *parser, FuncDescriptor *desc);

// begin: cur_tok must be function name
// end: cur_tok is return_type ident or right parenthesis
static FuncSignature parse_func_signature(Parser *parser) {
  FuncSignature signature = {.name = parser->cur_tok->var.ident};
  // cur_tok is left parenthesis
  next_token(parser);
  // cur_tok is first ident or end of args
  next_token(parser);
  // cur_tok is end
  signature.arg_types = parse_type_list(parser, TOKEN_RPAREN);
  if (parser->peek_tok->kind == TOKEN_ARROW) {
    // cur_tok is arrow
    next_token(parser);

    // cur_tok is ident
    next_token(parser);
    signature.ret_type = parse_type(parser);
  }

  return signature;
}

// begin: cur_tok must be generic name
// end: cur_tok is end of func descriptor or generic ident
static Generic parse_generic(Parser *parser) {
  Generic generic = {.name = parser->cur_tok->var.ident};
  if (parser->peek_tok->kind == TOKEN_COLON) {
    // cur_tok is colon
    next_token(parser);
    // cur_tok is first tok of func descriptor
    next_token(parser);
    generic.bounds = array_new(FuncSignature, &HEAP_ALLOCATOR);
    while (parser->cur_tok->kind != TOKEN_COMMA &&
           parser->cur_tok->kind != TOKEN_RANGLE) {
      FuncSignature signature = parse_func_signature(parser);
      array_add(generic.bounds, signature);

      if (parser->peek_tok->kind == TOKEN_PLUS) {
        // cur_tok is plus
        next_token(parser);
      } else if (parser->peek_tok->kind == TOKEN_RANGLE) {
        break;
      }

      // next token is next function name or comma or rangle
      next_token(parser);
    }
  }
  return generic;
}

// TODO: Generic functions
// begin: cur_tok must be left parenthesis
// end: cur_tok is return_type ident or right parenthesis
static ParseResult parse_func_desc(Parser *parser, FuncDescriptor *desc) {
  // cur_tok is first ident or end of args
  next_token(parser);
  TypedIdent *typed_ident_args = parse_typed_ident_list(parser, TOKEN_RPAREN);
  desc->args = array_new_capacity(Argument, array_len(typed_ident_args),
                                  &parser->ast_arena_allocator);
  for (size_t i = 0; i < array_len(typed_ident_args); i++) {
    array_add(desc->args,
              (Argument){.kind = ARG_TYPED_ARG,
                         .var = {.typed_arg = typed_ident_args[i]}});
  }
  bool has_ret_type = parser->peek_tok->kind == TOKEN_ARROW;
  if (has_ret_type) {
    // cur_tok is arrow
    next_token(parser);
    // cur_tok is type
    next_token(parser);
    desc->ret_type = parse_type(parser);
  }
  desc->has_ret_type = has_ret_type;

  return (ParseResult){.success = true};
}

static bool ident_is_struct(Parser *parser, Ident *struct_name) {
  TypeExpr *type_expr = hashmap_value(&parser->custom_types, struct_name);
  return type_expr != NULL && type_expr->kind == TYPE_EXPR_STRUCT;
}

// static bool ident_is_imported_function(const Parser *parser,
//                                        Ident function_name) {
//   hashmap_foreach(&parser->imported_functions, Ident * key,
//                   FuncDescriptor * val, {
//                     if (strv_eq(*key, function_name)) {
//                       return true;
//                     }
//                   });
//   return false;
// }

// static bool ident_is_builtin_function(const Parser *parser,
//                                       Ident *function_name) {
//   for (size_t i = 0; i < array_len(parser->foreign_functions); i++) {
//     if (strv_eq(parser->foreign_functions[i], *function_name))
//       return true;
//   }
//   return strv_eq(*function_name, "println") ||
//          strv_eq(*function_name, "printfn") ||
//          strv_eq(*function_name, "format") || strv_eq(*function_name, "exit")
//          || strv_eq(*function_name, "print_int") || strv_eq(*function_name,
//          "print_int_ptr");
// }

#define OPTIONAL_EXPR(...)                                                     \
  (OptionalExpr) { .expr = (Expression)__VA_ARGS__, .present = true }

#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 1, 2)))
#endif
static OptionalExpr _internal_empty_expr(char *format, ...) {
  char *buf = malloc(256);

  va_list ap;
  va_start(ap, format);
  vsprintf(buf, format, ap);
  va_end(ap);

  return (OptionalExpr){.present = false, .error_msg = buf};
}

#define EMPTY_EXPR(msg, ...)                                                   \
  _internal_empty_expr(msg __VA_OPT__(, ) __VA_ARGS__)

static bool is_func_desc(Parser *parser) {
  const Token *cur_tok = parser->cur_tok;
  while (cur_tok->kind != TOKEN_EOF) {
    if (cur_tok->kind == TOKEN_RPAREN && (cur_tok + 1)->kind == TOKEN_LCURLY) {
      return true;
    }
    cur_tok++;
  }
  return false;
}

typedef struct {
  size_t ctx_first_line;
  size_t ctx_lines_amount;
  size_t issue_pos;
  size_t issue_line;
  const char *issue_ctx_msg;
} ErrorMessage;

#define PRINT_SPACE(str_ptr, amount)                                           \
  for (size_t i = 0; i < amount; i++) {                                        \
    dyn_string_add_char(str_ptr, ' ');                                         \
  }

static dyn_string_t error_msg_fmt(const Parser *parser,
                                  const ErrorMessage *msg) {
  dyn_string_t str = {0};
  dyn_string_init(&str, &HEAP_ALLOCATOR);

  size_t first_line_idx = msg->ctx_first_line - 1;

  size_t ctx_last_line = msg->ctx_first_line + msg->ctx_lines_amount;

  dyn_string_t str0 = {0};
  dyn_string_init(&str0, &HEAP_ALLOCATOR);
  size_t line_number_max_len = snprintf(NULL, 0, "%zu", ctx_last_line);
  for (size_t i = 0; i < msg->ctx_lines_amount; i++) {
    size_t actual_line_idx = first_line_idx + i;
    LexerLine line = parser->lines[actual_line_idx];
    char line_number_buf[128] = {0};
    size_t cur_line_number_len =
        sprintf(line_number_buf, "%zu", first_line_idx + i + 1);
    char space_buf[128] = {0};
    for (ssize_t i = 0;
         i < (ssize_t)(line_number_max_len - cur_line_number_len); i++) {
      strcat(space_buf, " ");
    }

    dyn_string_printf(&str0, "%s%s |%.*s\n", space_buf, line_number_buf,
                      (int)line.len, line.begin);
    dyn_string_add_str(&str, str0.string);
    dyn_string_clear(&str0);

    if (msg->issue_line == actual_line_idx + 1) {
      PRINT_SPACE(&str, line_number_max_len)
      dyn_string_add_str(&str, " |");
      PRINT_SPACE(&str, msg->issue_pos - 1)
      dyn_string_add_char(&str, '^');
      dyn_string_add_char(&str, '\n');

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
          dyn_string_add_str(&str, "|");
          dyn_string_add_char(&str, '\n');
          PRINT_SPACE(&str, line_number_max_len)
          dyn_string_add_str(&str, " |");
          PRINT_SPACE(&str, spaces_len)
        }
      }
      dyn_string_add_str(&str, msg->issue_ctx_msg);
      dyn_string_add_char(&str, '\n');
    }
  }

  dyn_string_free(&str0);
  return str;
}

static dyn_string_t error_msg_deco_fmt(const Parser *parser,
                                       const ErrorMessage *msg,
                                       const char *error_msg_text, size_t line,
                                       size_t pos) {
  dyn_string_t str = {0};
  dyn_string_init(&str, &HEAP_ALLOCATOR);

  dyn_string_printf(&str, "%s:%zu:%zu: " ANSI_RED "error:" ANSI_RESET " %s\n",
                    parser->filename, line, pos, error_msg_text);

  dyn_string_t str0 = error_msg_fmt(parser, msg);
  dyn_string_add_str(&str, str0.string);

  dyn_string_free(&str0);

  return str;
}

// TODO: Might want to factor out into extra step

static ModulePath module_path_resolve(Parser *parser, const ModulePath *path) {
  size_t modules_len = array_len(parser->imported_modules);
  for (size_t i = 0; i < modules_len; i++) {
    ModulePath imported_path = parser->imported_modules[i];
    size_t path_len = array_len(imported_path.path);
    Ident last_path_segment = imported_path.path[path_len - 1];

    if (strv_eq(path->path[0], last_path_segment)) {
      ModulePath new_path = module_path_copy(&imported_path, &HEAP_ALLOCATOR);
      for (size_t i = 1; i < array_len(path->path); i++) {
        array_add(new_path.path, path->path[i]);
      }
      return new_path;
    }
  }
  return *path;
}

static ParseResult parse_expr(Parser *parser, Expression *expr) {
  switch (parser->cur_tok->kind) {
  case TOKEN_STRING: {
    *expr = (Expression){.kind = EXPR_STRING_LIT,
                         .var = {.expr_string_literal = {
                                     .string = parser->cur_tok->var.string}}};
    return PARSE_RESULT({.success = true});
  }
  case TOKEN_BOOL: {
    *expr = (Expression){.kind = EXPR_BOOLEAN_LIT,
                         .var = {.expr_boolean_literal = {
                                     .boolean = parser->cur_tok->var.boolean}}};
    return PARSE_RESULT({.success = true});
  }
  case TOKEN_LPAREN: {
    if (is_func_desc(parser)) {
      FuncDescriptor desc = {0};
      parse_func_desc(parser, &desc);
      ExprBlock *block_expr = bump_alloc(&parser->ast_arena, sizeof(ExprBlock));

      if (parser->peek_tok->kind == TOKEN_LCURLY) {
        // cur_tok is left curly
        next_token(parser);
        // cur_tok is first stmt
        next_token(parser);

        Statement *stmts = parse_block_statements(parser, TOKEN_RCURLY);
        ExprBlock block = {.statements = stmts};
        memcpy(block_expr, &block, sizeof(ExprBlock));
      } else {
        EXPECTED_TOKEN_ERR(TOKEN_LCURLY, parser->peek_tok);
      }

      // cur_tok is rcurly
      *expr = (Expression){
          .kind = EXPR_FUNCTION,
          .var = {.expr_function = {.desc = desc, .block = block_expr}}};
      return PARSE_RESULT({.success = true});
    } else {
      next_token(parser);
      Expression grouped_expr;
      ParseResult result = parse_expr1(parser, &grouped_expr, PREC_LOWEST);

      if (parser->peek_tok->kind != TOKEN_RPAREN) {
        return PARSE_RESULT({.success = false});
      }

      next_token(parser);

      *expr = grouped_expr;
      return PARSE_RESULT({.success = true});
    }
  }
  case TOKEN_LCURLY: {
    // cur_tok is first tok of first stmt of block
    next_token(parser);
    Statement *stmts = parse_block_statements(parser, TOKEN_RCURLY);
    *expr = (Expression){.kind = EXPR_BLOCK,
                         .var = {.expr_block = {.statements = stmts}}};
  }
  case TOKEN_IDENT: {
    Token first_token = *parser->cur_tok;
    Ident ident = parser->cur_tok->var.ident;
    ModulePath raw_path = parse_module_path(parser);
    ModulePath resolved_path = module_path_resolve(parser, &raw_path);
    if (parser->peek_tok->kind == TOKEN_LPAREN) {
      // if (hashmap_contains(&parser->custom_functions, &ident)||
      //     ident_is_imported_function(parser, ident) ||
      //     ident_is_builtin_function(parser, &ident)) {
      // if (true) {
      //  cur_tok is left parenthesis
      next_token(parser);
      // cur_tok is first expr
      next_token(parser);

      Expression *exprs = array_new_capacity(Expression, 8, &parser->ast_arena_allocator);
      ParseResult result = parse_expr_list(parser, exprs, TOKEN_RPAREN);
      if (!result.success) {
        size_t first_line = first_token.line;
        size_t cur_line = parser->cur_tok->line;
        ErrorMessage msg = {.ctx_first_line = first_line,
                            .ctx_lines_amount = cur_line - first_line + 1,
                            .issue_pos = result.pos,
                            .issue_line = result.line,
                            .issue_ctx_msg = ")"};
        dyn_string_t err_msg = error_msg_deco_fmt(
            parser, &msg, result.error_msg, result.line, result.pos);
        printf("%s", err_msg.string);
        exit(1);
      }
      // end: right parenthesis

      if (parser->cur_tok->kind != TOKEN_RPAREN) {
        fprintf(stderr, "No TOKEN_RPAREN at end of call");
        exit(1);
      }

      *expr = (Expression){.kind = EXPR_CALL,
                           .var = {.expr_call = {
                                       .function = resolved_path,
                                       .args = exprs,
                                   }}};
      return PARSE_RESULT({.success = true});
    } else if (parser->peek_tok->kind == TOKEN_LCURLY) {
      if (ident_is_struct(parser, &ident)) {
        // cur_tok is lcurly
        next_token(parser);
        // cur_tok is first field name or rcurly
        next_token(parser);

        LabeledExpr *field_inits =
            parse_labeled_expr_list(parser, TOKEN_RCURLY);

        *expr = (Expression){
            .kind = EXPR_STRUCT_INIT,
            .var = {.expr_struct_init = {.struct_name = ident,
                                         .field_inits = field_inits}}};
        return PARSE_RESULT({.success = true});
      }
    } /*else if (parser->peek_tok->kind == TOKEN_DOT &&
               (parser->peek_tok + 2)->type == TOKEN_LPAREN) {
      // cur_tok is dot
      next_token(parser);
      // cur_tok is call name
      next_token(parser);

      ModulePath call_name = parse_module_path(parser);

      { // cur_tok is left parenthesis
        next_token(parser);
        // cur_tok is first token of first expr
        next_token(parser);

        Expression *exprs = array_new_capacity(Expression, 8, &HEAP_ALLOCATOR);
        ParseResult result = parse_expr_list(parser, exprs, TOKEN_RPAREN);
        // end: right parenthesis
        return OPTIONAL_EXPR(
            {.type = EXPR_GENERIC_CALL,
             .var = {.expr_generic_call = {.generic = ident,
                                           .expr_call = {.function = call_name,
                                                         .args = exprs}}}});
      }
    }*/
    *expr = (Expression){.kind = EXPR_IDENT,
                         .var = {.expr_ident = {.ident = raw_path}}};
    return PARSE_RESULT({.success = true});
  }
  case TOKEN_INT: {
    *expr = (Expression){.kind = EXPR_INTEGER_LIT,
                         .var = {.expr_integer_literal = {
                                     .integer = parser->cur_tok->var.integer}}};
    return PARSE_RESULT({.success = true});
  }
  case TOKEN_LANGLE: {
    Generic *generics;
    if (parser->peek_tok->kind == TOKEN_RANGLE) {
      generics = NULL;
    } else {
      generics = array_new(Generic, &HEAP_ALLOCATOR);
      if (parser->peek_tok->kind == TOKEN_IDENT) {
        // cur_tok is generic name
        next_token(parser);

        while (parser->cur_tok->kind != TOKEN_RANGLE) {
          Generic generic = parse_generic(parser);
          array_add(generics, generic);
          if (parser->peek_tok->kind == TOKEN_COMMA) {
            // cur_tok is comma
            next_token(parser);
            if (parser->peek_tok->kind == TOKEN_IDENT) {
              // cur_tok is ident
              next_token(parser);
            } else if (parser->peek_tok->kind == TOKEN_RANGLE) {
              break;
            }
          } else if (parser->peek_tok->kind == TOKEN_RANGLE) {
            // cur_tok is rangle
            next_token(parser);
            break;
          }
        }
      } else {
        fprintf(stderr, "Expected token after left angle bracket to be generic "
                        "name or right angle bracket\n");
        exit(1);
      }
    }
    // cur_tok is left paren
    next_token(parser);
    FuncDescriptor desc = {0};
    parse_func_desc(parser, &desc);
    desc.generics = generics;
    ExprBlock *block_expr = malloc(sizeof(ExprBlock));

    if (parser->peek_tok->kind == TOKEN_LCURLY) {
      // cur_tok is left curly
      next_token(parser);
      // cur_tok is first stmt
      next_token(parser);

      Statement *stmts = parse_block_statements(parser, TOKEN_RCURLY);
      ExprBlock block = {.statements = stmts};
      memcpy(block_expr, &block, sizeof(ExprBlock));
    } else {
      EXPECTED_TOKEN_ERR(TOKEN_LCURLY, parser->peek_tok);
    }

    // cur_tok is rcurly
    *expr = (Expression){
        .kind = EXPR_FUNCTION,
        .var = {.expr_function = {.desc = desc, .block = block_expr}}};
    return PARSE_RESULT({.success = true});
  }
  case TOKEN_LSQUARE: {
    printf("Left square tok :3\n");
    Type type = parse_type(parser);
    if (parser->peek_tok->kind != TOKEN_LCURLY) {
      size_t first_line = parser->cur_tok->line;
      size_t cur_line = parser->cur_tok->line;
      ErrorMessage msg = {.ctx_first_line = first_line,
                          .ctx_lines_amount = cur_line - first_line + 1,
                          .issue_pos =
                              parser->cur_tok->begin_pos + parser->cur_tok->len,
                          .issue_line = parser->cur_tok->line,
                          .issue_ctx_msg = "{"};
      dyn_string_t err_msg = error_msg_deco_fmt(
          parser, &msg, "Expected left curly after array type for initializer",
          parser->cur_tok->line,
          parser->cur_tok->begin_pos + parser->cur_tok->len);
      printf("%s", err_msg.string);
      exit(1);
    }

    // cur_tok is left curly
    next_token(parser);
    // cur_tok is first token of expr
    next_token(parser);
    // TODO: Use expr list?
    Expression *exprs = array_new(Expression, &parser->ast_arena_allocator);
    while (parser->cur_tok->kind != TOKEN_RCURLY) {
      Expression expr;
      ParseResult result = parse_expr1(parser, &expr, PREC_LOWEST);
      if (!result.success) {
        printf("%s:%d:%zu: " ANSI_RED "error:" ANSI_RESET " %s\n",
               parser->filename, result.line,
               parser->cur_tok->begin_pos + parser->cur_tok->len,
               "Expected left curly after array type for initializer");
        // TODO: THESE ARE LITERALLY THE SAME THING
        size_t first_line = result.line;
        size_t cur_line = result.line;
        ErrorMessage msg = {.ctx_first_line = first_line,
                            .ctx_lines_amount = cur_line - first_line + 1,
                            .issue_pos = result.pos,
                            .issue_line = result.line};
        dyn_string_t err_msg = error_msg_fmt(parser, &msg);
        printf("%s", err_msg.string);
        exit(1);
      }
      array_add(exprs, expr);
      if (parser->peek_tok->kind == TOKEN_COMMA) {
        // cur_tok is comma
        next_token(parser);
      }
      // cur_tok is right parenthesis or next expr
      next_token(parser);
    }
    *expr =
        (Expression){.kind = EXPR_ARRAY_INIT,
                     .var = {.expr_array_init = {.type = type.var.type_array,
                                                 .items = exprs}}};
    return PARSE_RESULT({.success = true});
  }
  case TOKEN_IF: {
    // cur_tok is expression
    next_token(parser);

    Expression cond_expr;
    ParseResult result = parse_expr1(parser, &cond_expr, PREC_LOWEST);

    if (result.success) {
      if (parser->peek_tok->kind != TOKEN_LCURLY) {
        printf("%s:%d:%d: " ANSI_RED "error:" ANSI_RESET " %s\n",
               parser->filename, result.line, result.pos, result.error_msg);
        ErrorMessage err_msg = {.ctx_first_line = parser->cur_tok->line,
                                .ctx_lines_amount = 1,
                                .issue_line = parser->cur_tok->line,
                                .issue_pos = parser->cur_tok->begin_pos +
                                             parser->custom_types.len,
                                .issue_ctx_msg = "{"};
        printf("%s\n", error_msg_fmt(parser, &err_msg).string);
        exit(1);
      }

      // cur_tok is left curly
      next_token(parser);

      // cur_tok is first statement
      next_token(parser);

      Statement *stmts = parse_block_statements(parser, TOKEN_RCURLY);

      *expr =
          (Expression){.kind = EXPR_IF,
                       .var = {.expr_if = {.condition = heap_clone(&cond_expr),
                                           .block = {.statements = stmts}}}};
      return PARSE_RESULT({.success = true});
    }
    fprintf(stderr,
            "Failed to parse condition of if-statement. Error message: %s\n",
            result.error_msg);
    exit(1);
  }
  case TOKEN_IT: {
    *expr = (Expression){.kind = EXPR_IT};
    return PARSE_RESULT({.success = true});
  }
  case TOKEN_TILDE: {
    // cur_tok is first token of expr
    next_token(parser);

    Expression deref_expr;
    ParseResult result = parse_expr1(parser, &deref_expr, PREC_LOWEST);

    if (!result.success) {
      printf("%s:%d:%d: " ANSI_RED "error:" ANSI_RESET " %s\n",
             parser->filename, result.line, result.pos, result.error_msg);
      ErrorMessage err_msg = {
          .ctx_first_line = result.line,
          .ctx_lines_amount = 1,
          .issue_line = result.line,
          .issue_pos = parser->cur_tok->begin_pos + parser->custom_types.len,
      };
      printf("%s\n", error_msg_fmt(parser, &err_msg).string);
      exit(1);
    }
    *expr = (Expression){
        .kind = EXPR_PTR_DEREF,
        .var = {.expr_ptr_deref = {.expr = heap_clone(&deref_expr)}}};
    return PARSE_RESULT({.success = true});
  }
  case TOKEN_AMPERSAND: {
    // cur_tok is first token of expr
    next_token(parser);

    Expression addr_of_expr;
    ParseResult result = parse_expr1(parser, &addr_of_expr, PREC_LOWEST);

    if (!result.success) {
      printf("%s:%d:%d: " ANSI_RED "error:" ANSI_RESET " %s\n",
             parser->filename, result.line, result.pos, result.error_msg);
      ErrorMessage err_msg = {
          .ctx_first_line = result.line,
          .ctx_lines_amount = 1,
          .issue_line = result.line,
          .issue_pos = parser->cur_tok->begin_pos + parser->custom_types.len,
      };
      printf("%s\n", error_msg_fmt(parser, &err_msg).string);
      exit(1);
    }
    *expr = (Expression){
        .kind = EXPR_ADDR_OF,
        .var = {.expr_addr_of = {.expr = heap_clone(&addr_of_expr)}}};
    return PARSE_RESULT({.success = true});
  }
  case TOKEN_FOR: {
    // cur_tok is <var name> or range expr
    next_token(parser);

    ExprFor expr_for = {0};

    bool has_range = true;
    if (parser->cur_tok->kind == TOKEN_LCURLY) {
      has_range = false;
    }

    expr_for.has_range = has_range;

    if (has_range) {
      Expression first_expr;
      // TODO: handle results
      ParseResult first_result = parse_expr1(parser, &first_expr, PREC_LOWEST);
      if (parser->peek_tok->kind == TOKEN_RANGE) {
        expr_for.variable_name = NULL;

        expr_for.range.min = heap_clone(&first_expr);
        // cur_tok is TOKEN_RANGE
        next_token(parser);
        // cur_tok is second expr
        next_token(parser);
        Expression sec_expr;
        ParseResult sec_result = parse_expr1(parser, &sec_expr, PREC_LOWEST);
        expr_for.range.max = heap_clone(&sec_expr);
      } else if (parser->peek_tok->kind == TOKEN_IN) {
        if (parser->cur_tok->kind != TOKEN_IDENT) {
          EXPECTED_TOKEN_ERR(TOKEN_IDENT, parser->cur_tok);
        }

        expr_for.variable_name = parser->cur_tok->var.ident;

        // cur_tok is TOKEN_IN
        next_token(parser);

        // cur_tok is first token of range expr
        next_token(parser);

        // TODO: handle min and max results
        Expression min_expr;
        ParseResult min_result = parse_expr1(parser, &min_expr, PREC_LOWEST);
        expr_for.range.min = heap_clone(&min_expr);

        // cur_tok is TOKEN_RANGE
        next_token(parser);
        // cur_tok is second expr
        next_token(parser);

        Expression max_expr;
        ParseResult max_result = parse_expr1(parser, &max_expr, PREC_LOWEST);
        expr_for.range.max = heap_clone(&max_expr);
      }

      // cur_tok is curly bracket
      next_token(parser);

      if (parser->cur_tok->kind != TOKEN_LCURLY) {
        EXPECTED_TOKEN_ERR(TOKEN_LCURLY, parser->cur_tok);
      }
    }

    // cur_tok is first stmt of block
    next_token(parser);

    char token_buf[128];
    lexer_tok_print(token_buf, parser->cur_tok);
    puts(token_buf);

    Statement *block_stmts = parse_block_statements(parser, TOKEN_RCURLY);

    expr_for.block.statements = block_stmts;

    *expr = (Expression){.kind = EXPR_FOR, .var = {.expr_for = expr_for}};
    return PARSE_RESULT({.success = true});
  }
  case TOKEN_CAST: {
    if (parser->peek_tok->kind != TOKEN_LANGLE) {
      EXPECTED_TOKEN_ERR(TOKEN_LANGLE, parser->peek_tok);
    }
    // cur_tok is left angle
    next_token(parser);
    // cur_tok is first token of type
    next_token(parser);
    Type type = parse_type(parser);

    if (parser->peek_tok->kind != TOKEN_RANGLE) {
      EXPECTED_TOKEN_ERR(TOKEN_RANGLE, parser->peek_tok);
    }
    // cur_tok is right angle
    next_token(parser);

    if (parser->peek_tok->kind != TOKEN_LPAREN) {
      EXPECTED_TOKEN_ERR(TOKEN_LPAREN, parser->peek_tok);
    }
    // cur_tok is left parenthesis
    next_token(parser);
    // cur_tok is first token of expr
    next_token(parser);
    Expression cast_expr;
    ParseResult result = parse_expr1(parser, &cast_expr, PREC_LOWEST);

    if (!result.success) {
      // TODO: Implement result handling
      return result;
    }
    if (parser->peek_tok->kind != TOKEN_RPAREN) {
      EXPECTED_TOKEN_ERR(TOKEN_RPAREN, parser->peek_tok);
    }

    // cur_tok is right parenthesis
    next_token(parser);

    ExprCast expr_cast = {.type = type, .expr = malloc(sizeof(Expression))};
    memcpy(expr_cast.expr, &cast_expr, sizeof(Expression));
    *expr = (Expression){.kind = EXPR_CAST, .var = {.expr_cast = expr_cast}};
    return PARSE_RESULT({.success = true});
  }
  case TOKEN_RANGLE:
  case TOKEN_ARROW:
  case TOKEN_COMMA:
  case TOKEN_RPAREN:
  case TOKEN_RCURLY:
  case TOKEN_DECL_CONST:
  case TOKEN_DECL_VAR:
  case TOKEN_COLON:
  case TOKEN_EOF:
  case TOKEN_DOT:
  case TOKEN_PLUS:
  case TOKEN_MINUS:
  case TOKEN_ASTERISK:
  case TOKEN_SLASH:
  case TOKEN_LTE:
  case TOKEN_GTE:
  case TOKEN_ASSIGN:
  case TOKEN_RSQUARE:
  case TOKEN_STRUCT:
  case TOKEN_RANGE:
  case TOKEN_IN:
  case TOKEN_RETURN:
  case TOKEN_EQUALS:
  case TOKEN_HASH:
  case TOKEN_FOREIGN:
  case TOKEN_COMPTIME:
  case TOKEN_ILLEGAL: {
    char print_buf[64];
    lexer_tok_print(print_buf, parser->cur_tok);
    printf("%s:%d:%d nyi/illegal token: %s\n", parser->filename,
           parser->cur_tok->line, parser->cur_tok->begin_pos, print_buf);
    exit(1);
  }
  }
}

static bool tok_is_op(const Token *tok) {
  return tok->kind == TOKEN_PLUS || tok->kind == TOKEN_MINUS ||
         tok->kind == TOKEN_ASTERISK || tok->kind == TOKEN_SLASH ||
         tok->kind == TOKEN_EQUALS || tok->kind == TOKEN_RANGLE;
}

static BinOperator tok_to_bin_op(const Token *tok) {
  switch (tok->kind) {
  case TOKEN_PLUS: {
    return BIN_OP_ADD;
  }
  case TOKEN_MINUS: {
    return BIN_OP_SUB;
  }
  case TOKEN_ASTERISK: {
    return BIN_OP_MUL;
  }
  case TOKEN_SLASH: {
    return BIN_OP_DIV;
  }
  case TOKEN_EQUALS: {
    return BIN_OP_EQ;
  }
  case TOKEN_RANGLE: {
    return BIN_OP_GT;
  }
  default: {
    char print_buf[128];
    lexer_tok_print(print_buf, tok);
    panic("Tok %s cannot be converted to op", print_buf);
    return -1;
  }
  }
}

void *_internal_heap_clone(void *ptr, size_t size) {
  void *new_ptr = malloc(size);
  memcpy(new_ptr, ptr, size);
  return new_ptr;
}

void *_internal_bump_clone(Bump *bump, void *ptr, size_t size) {
  void *new_ptr = bump_alloc(bump, size);
  memcpy(new_ptr, ptr, size);
  return new_ptr;
}

static Precedence op_to_prec(BinOperator op) {
  switch (op) {
  case BIN_OP_ADD:
  case BIN_OP_SUB: {
    return PREC_SUM;
  }
  case BIN_OP_MUL:
  case BIN_OP_DIV: {
    return PREC_PRODUCT;
  }
  case BIN_OP_GT:
  case BIN_OP_GTE:
  case BIN_OP_LT:
  case BIN_OP_LTE:
  case BIN_OP_EQ: {
    return PREC_CMP;
  }
  default: {
    return PREC_LOWEST;
  }
  }
}

static ParseResult parse_expr1(Parser *parser, Expression *expr,
                               Precedence prec);

static Expression parse_infix_expr(Parser *parser, Expression *left) {
  switch (parser->cur_tok->kind) {
  case TOKEN_PLUS:
  case TOKEN_MINUS:
  case TOKEN_ASTERISK:
  case TOKEN_SLASH:
  case TOKEN_RANGLE:
  case TOKEN_EQUALS: {
    BinOperator op = tok_to_bin_op(parser->cur_tok);
    Precedence prec = op_to_prec(op);

    // cur_tok is expr
    next_token(parser);

    Expression right_expr;
    ParseResult result = parse_expr1(parser, &right_expr, prec);

    if (result.success) {
      Expression *left_copy = heap_clone(left);
      Expression *right_copy = heap_clone(&right_expr);

      return (Expression){.kind = EXPR_BIN_OP,
                          .var = {.expr_bin_op = {.left = left_copy,
                                                  .right = right_copy,
                                                  .op = op}}};
    }
    fprintf(stderr, "Failed to parse right side of infix expr, error: %s\n",
            result.error_msg);
    exit(1);
  }
  default: {
    return *left;
  }
  }
}

// begin: cur_tok is TOKEN_DOT
static Expression parse_struct_access(Parser *parser, Expression expr) {
  printf("Parsing struct access\n");
  if (parser->peek_tok->kind == TOKEN_IDENT) {
    ExprStructAccess expr_access = {.struct_expr = heap_clone(&expr),
                                    .fields =
                                        array_new(Ident, &HEAP_ALLOCATOR)};
    do {
      // cur_tok is ident
      next_token(parser);

      array_add(expr_access.fields, parser->cur_tok->var.ident);

      if (parser->peek_tok->kind == TOKEN_DOT) {
        // cur_tok is next ident
        next_token(parser);
      } else {
        break;
      }
    } while (parser->peek_tok->kind == TOKEN_IDENT);

    char cur_tok_buf[128];
    lexer_tok_print(cur_tok_buf, parser->cur_tok);
    printf("Cur tok after access: %s\n", cur_tok_buf);

    return (Expression){.kind = EXPR_STRUCT_ACCESS,
                        .var = {.expr_struct_access = expr_access}};
  }
  EXPECTED_TOKEN_ERR(TOKEN_IDENT, parser->peek_tok);
}

static void token_debug_print(const Token *tok) {
  char tok_buf[128];
  lexer_tok_print(tok_buf, tok);
  printf("%s\n", tok_buf);
}

static Expression parse_array_access(Parser *parser, Expression expr) {
  // cur_tok is index expression
  next_token(parser);
  token_debug_print(parser->cur_tok);
  Expression index_expr;
  ParseResult result = parse_expr1(parser, &index_expr, PREC_LOWEST);

  if (parser->peek_tok->kind != TOKEN_RSQUARE) {
    EXPECTED_TOKEN_ERR(TOKEN_RSQUARE, parser->peek_tok);
  }

  // cur_tok is TOKEN_RSQUARE
  next_token(parser);

  if (result.success) {
    return (Expression){
        .kind = EXPR_ARRAY_ACCESS,
        .var = {.expr_array_access = {.array_expr = bump_clone(&parser->ast_arena, &expr),
                                      .index_expr = bump_clone(&parser->ast_arena, &index_expr)}}};
  }
  fprintf(stderr,
          "Failed to parse expression for array access, Error message: %s",
          result.error_msg);
  exit(1);
}

static ParseResult parse_expr1(Parser *parser, Expression *expr,
                               Precedence prec) {
  Expression expr1 = {0};
  ParseResult result = parse_expr(parser, &expr1);

  if (!result.success)
    return result;

  Expression left_expr = expr1;

  // if (parser->peek_tok->kind == TOKEN_DOT) {
  //  cur_tok is TOKEN_DOT
  // next_token(parser);
  // left_expr = parse_struct_access(parser, left_expr);
  /*} else*/ if (parser->peek_tok->kind == TOKEN_LSQUARE) {
    // cur_tok is TOKEN_LSQUARE
    next_token(parser);
    left_expr = parse_array_access(parser, left_expr);
  }

  // char left_expr_buf[512];
  // expr_print(left_expr_buf, &left_expr);
  // log_debug("Left expr: %s", left_expr_buf);

  while (tok_is_op(parser->peek_tok) &&
         prec < op_to_prec(tok_to_bin_op(parser->peek_tok))) {
    // cur_tok is op
    next_token(parser);

    left_expr = parse_infix_expr(parser, &left_expr);
  }

  *expr = left_expr;
  return PARSE_RESULT({.success = true});
}

static TypeExpr parse_type_expr(Parser *parser) {
  if (parser->cur_tok->kind == TOKEN_IDENT &&
      hashmap_contains(&parser->custom_functions,
                       &parser->cur_tok->var.ident)) {
    token_debug_print(parser->peek_tok);
    Ident *idents = array_new(Ident, &HEAP_ALLOCATOR);
    while (parser->cur_tok->kind == TOKEN_IDENT) {
      array_add(idents, parser->cur_tok->var.ident);
      if (parser->peek_tok->kind == TOKEN_COMMA) {
        // cur_tok is comma
        next_token(parser);
        if (parser->peek_tok->kind == TOKEN_IDENT) {
          // cur_tok is next ident
          next_token(parser);
        } else {
          break;
        }
      } else {
        break;
      }
    }
    return (TypeExpr){.kind = TYPE_EXPR_OVERLOAD_SET,
                      .var = {.type_expr_overload_set = {.functions = idents}}};
  } else if (parser->cur_tok->kind == TOKEN_STRUCT) {
    if (parser->peek_tok->kind == TOKEN_LCURLY) {
      // cur_tok is TOKEN_LCURLY
      next_token(parser);
      // cur_tok is first ident of fields
      next_token(parser);
      TypedIdent *fields = parse_typed_ident_list(parser, TOKEN_RCURLY);
      return (TypeExpr){
          .kind = TYPE_EXPR_STRUCT,
          .var = {.type_expr_struct = {.generics = NULL, .fields = fields}}};
    } else {
      EXPECTED_TOKEN_ERR(TOKEN_LCURLY, parser->peek_tok);
    }
  } else {
    EXPECTED_TOKEN_ERR(TOKEN_IDENT | TOKEN_STRUCT, parser->peek_tok);
  }
}

static ExpressionVariant parse_expr_var(Parser *parser) {
  if (parser->cur_tok == TOKEN_IDENT &&
      hashmap_contains(&parser->custom_functions,
                       &parser->cur_tok->var.ident)) {
    TypeExpr ty_expr = parse_type_expr(parser);
    return EXPR_VAR_TYPE(ty_expr);
  } else if (parser->cur_tok->kind == TOKEN_STRUCT) {
    TypeExpr ty_expr = parse_type_expr(parser);
    return EXPR_VAR_TYPE(ty_expr);
  } else {
    Expression expr;
    ParseResult result = parse_expr1(parser, &expr, PREC_LOWEST);
    if (result.success) {
      return EXPR_VAR_EXPR(expr);
    }
    fprintf(stderr, "Failed to parse expression variant, error message: %s\n",
            result.error_msg);
    exit(1);
  }
}

static StmtDecl parse_decl_stmt(Parser *parser, bool typed) {
  StmtDecl stmt_decl = {0};
  stmt_decl.name = parser->cur_tok->var.ident;

  if (typed) {
    // cur_tok is colon
    next_token(parser);
    // cur_tok is first token of type
    next_token(parser);
    stmt_decl.type =
        (OptionalType){.type = parse_type(parser), .present = true};

    if (parser->peek_tok->kind == TOKEN_ASSIGN ||
        parser->peek_tok->kind == TOKEN_COLON) {
      // cur_tok is assign/colon
      next_token(parser);

      stmt_decl.mut = parser->cur_tok->kind == TOKEN_ASSIGN;
    } else {
      EXPECTED_TOKEN_ERR(TOKEN_ASSIGN | TOKEN_COLON, parser->peek_tok);
    }

    next_token(parser);
    Expression value;
    ParseResult result = parse_expr1(parser, &value, PREC_LOWEST);
    if (result.success) {
      stmt_decl.value = (ExpressionVariant){
          .kind = EXPR_VAR_REG_EXPR, .var = {.expr_var_reg_expr = value}};
    } else {
      fprintf(stderr, "Failed to parse decl stmt value, error message: %s",
              result.error_msg);
      exit(1);
    }
  } else {
    bool mutable = parser->peek_tok->kind == TOKEN_DECL_VAR;
    stmt_decl.mut = mutable;
    // cur token is DECL
    next_token(parser);
    // cur token is EXPR
    next_token(parser);

    ExpressionVariant expr_var = parse_expr_var(parser);
    stmt_decl.value = expr_var;

    switch (expr_var.kind) {
    case EXPR_VAR_TYPE_EXPR: {
      hashmap_insert(&parser->custom_types, &stmt_decl.name,
                     &expr_var.var.expr_var_type_expr);
      break;
    }
    case EXPR_VAR_REG_EXPR: {
      if (expr_var.var.expr_var_reg_expr.kind == EXPR_FUNCTION) {
        ModulePath module_path = module_path_copy(&parser->path, &parser->ast_arena_allocator);
        array_add(module_path.path, stmt_decl.name);

        if (debug_flags.print_parse_info) {
          log_debug("Parser Module path: %s",
                    module_path_fmt(&module_path).string);
        }

        if (array_len(module_path.path) > 0 &&
            !strv_eq(module_path.path[0], "main")) {
          hashmap_insert(
              &parser->module.functions, &module_path,
              &expr_var.var.expr_var_reg_expr.var.expr_function.desc);
          Ident mangled_function = mangle_function_name(&module_path);
          hashmap_insert(&mangled_functions, &module_path, &mangled_function);
          if (debug_flags.print_parse_info) {
            log_debug("Mangled function mod path len: %zu, %s",
                      array_len(module_path.path), module_path.path[0]);
            log_info("[PARSER] Mangled function: %s, mangled name: %s",
                     module_path_fmt(&module_path).string, mangled_function);
          }
        }
      } else {
        array_add(parser->module.decls,
                  (TypedIdent){.ident = stmt_decl.name,
                               .type = stmt_decl.type.present
                                           ? stmt_decl.type.type
                                           : (Type){.kind = TYPE_UNIT}});
      }
      break;
    }
    }
  }
  return stmt_decl;
}

static bool expr_is_comptime(const Parser *parser, const Expression *expr) {
  switch (expr->kind) {
  case EXPR_BIN_OP: {
    ExprBinOp bin_op = expr->var.expr_bin_op;
    if (!expr_is_comptime(parser, bin_op.left))
      return false;
    if (!expr_is_comptime(parser, bin_op.right))
      return false;
    return true;
  }
  case EXPR_BOOLEAN_LIT:
  case EXPR_INTEGER_LIT:
  case EXPR_STRING_LIT: {
    return true;
  }
  default:
    return false;
  }
}

static PpDirective parse_pp_dir(Parser *parser) {
  // cur_tok: First token of pp directive after '#'
  next_token(parser);

  if (parser->cur_tok->kind == TOKEN_COMPTIME) {
    return (PpDirective){.kind = PP_DIR_COMPTIME};
  } else if (parser->cur_tok->kind == TOKEN_IF) {
    log_debug("[PARSER] Found conditional preprocessor directive in line %d.",
              parser->cur_tok->line);

    // cur_tok is first token of condition expr
    next_token(parser);

    log_debug("cur tok:");
    token_debug_print(parser->cur_tok);

    Expression expr;
    ParseResult result = parse_expr1(parser, &expr, PREC_LOWEST);
    if (!result.success) {
      log_error("[PARSER] Failed to parse expression for #if condition");
      exit(1);
    }

    if (!expr_is_comptime(parser, &expr)) {
      log_error(
          "[PARSER] Condition expression for #if is not comptime compatible");
      exit(1);
    }

    if (parser->peek_tok->kind == TOKEN_LCURLY) {
      next_token(parser);
    } else {
      log_error("[PARSER] Expected left curly after condition expression");
      exit(1);
    }

    array_add(parser->pp_dir_conditionals,
              array_len(parser->pp_dir_conditionals));
    return (PpDirective){.kind = PP_DIR_IF,
                         .var = {.pp_dir_if = {.condition = expr}}};
  }

  log_error("[PARSER] Failed to parse preprocessor directive");
  exit(1);
}

static char *_exec_dir_path;

static char *get_exec_dir(const char *exec_filename) {
  if (_exec_dir_path == NULL) {
    const char *const exec_filename_only = strrchr(exec_filename, '/');
    if (exec_filename_only != NULL) {
      size_t exec_dir_path_length = exec_filename_only - exec_filename + 1;
      _exec_dir_path = malloc(exec_dir_path_length + 1);
      strncpy(_exec_dir_path, exec_filename, exec_dir_path_length);
    } else {
      _exec_dir_path = malloc(3);
      _exec_dir_path[0] = '.';
      _exec_dir_path[1] = '/';
      _exec_dir_path[2] = '\0';
    }
  }

  return _exec_dir_path;
}

static Statement parse_stmt(Parser *parser) {
  switch (parser->cur_tok->kind) {
  case TOKEN_RETURN: {
    // cur_tok is first token of expression of return value
    next_token(parser);

    Expression expr;
    ParseResult result = parse_expr1(parser, &expr, PREC_LOWEST);
    if (result.success) {
      return (Statement){
          .kind = STMT_RETURN,
          .var = {.stmt_return = {.ret_val = expr, .has_ret_val = true}}};
    }
    fprintf(stderr,
            "Encountered error while parsing return value expression\n");
    exit(1);
  }
  case TOKEN_IDENT: {
    TokenKind peek_kind = parser->peek_tok->kind;
    bool typed = peek_kind == TOKEN_COLON;

    if (peek_kind == TOKEN_DECL_CONST || peek_kind == TOKEN_DECL_VAR || typed) {
      StmtDecl stmt_decl = parse_decl_stmt(parser, typed);
      return (Statement){.kind = STMT_DECL, .var = {.stmt_decl = stmt_decl}};
    } else {
      goto parse_expr;
    }
    exit(1);
  }
  case TOKEN_FOREIGN: {
    if (parser->peek_tok->kind != TOKEN_IDENT) {
      log_error("Expected function name after TOKEN_FOREIGN");
      exit(1);
    }
    // Cur token is ident
    next_token(parser);
    ModulePath mod_path = parse_module_path(parser);
    // Cur tok is first token of func desc
    next_token(parser);
    FuncDescriptor desc = {0};
    parse_func_desc(parser, &desc);
    array_add(parser->foreign_functions, mod_path);
    return (Statement){
        .kind = STMT_FOREIGN,
        .var = {.stmt_foreign = {.name = mod_path, .desc = desc}}};
  }
  case TOKEN_IF:
  case TOKEN_IT:
  case TOKEN_FOR:
  case TOKEN_CAST:
  case TOKEN_LSQUARE:
  case TOKEN_AMPERSAND:
  case TOKEN_TILDE:
  case TOKEN_STRING:
  case TOKEN_INT:
  case TOKEN_BOOL:
  parse_expr: {
    Expression expr;
    ParseResult result = parse_expr1(parser, &expr, PREC_LOWEST);
    if (result.success) {
      if ((expr.kind == EXPR_IDENT || expr.kind == EXPR_STRUCT_ACCESS) &&
          parser->peek_tok->kind == TOKEN_ASSIGN) {
        // cur_tok is TOKEN_ASSIGN
        next_token(parser);
        // cur_tok is right expr
        next_token(parser);
        Expression right_expr;
        ParseResult right_result =
            parse_expr1(parser, &right_expr, PREC_LOWEST);
        if (!right_result.success) {
          log_error("Failed to parse right-hand expression of StmtAssign, "
                    "error: %s",
                    right_result.error_msg);
          exit(1);
        }
        // TODO: Fix module path
        return (Statement){
            .kind = STMT_ASSIGN,
            .var = {
                .stmt_assign = {
                    .left_ident_kind = expr.kind == EXPR_IDENT
                                           ? ACCESS_TYPE_IDENT
                                           : ACCESS_TYPE_STRUCT_ACCESS,
                    .left_ident = {.ident = expr.var.expr_ident.ident.path[0]},
                    .right_expr = right_expr,
                    .assign_kind = ASSIGN_REGULAR}}};
      }
      return (Statement){.kind = STMT_EXPR,
                         .var = {.stmt_expr = {.expr = expr}}};
    }
    fprintf(stderr, "Failed to parse expression statement, error msg: %s\n",
            result.error_msg);
    exit(1);
  }
  case TOKEN_HASH: {
    size_t line = parser->cur_tok->line;
    if (parser->peek_tok->kind == TOKEN_COMPTIME) {
      // cur_tok is 'comptime'
      next_token(parser);
      // cur_tok is first token of stmt
      next_token(parser);

      Statement stmt = parse_stmt(parser);
      PpDirective pp_dir = {.kind = PP_DIR_COMPTIME,
                            .var = {.pp_dir_comptime = {.stmt = stmt}}};
      array_add(parser->pp_dirs, pp_dir);
      return stmt;
    } else if (parser->peek_tok->kind == TOKEN_IDENT) {
      if (strv_eq(parser->peek_tok->var.ident, "import")) {
        // cur_tok is 'import' ident
        next_token(parser);
        if (parser->peek_tok->kind != TOKEN_STRING) {
          log_error("[PREPROCESSOR] Import directive requires the module name "
                    "as a string");
          exit(1);
        }

        // cur_tok is the string for the path
        next_token(parser);

        char *module_name = parser->cur_tok->var.string;
        char *exec_file_dir_path = get_exec_dir(parser->filename);
        dyn_string_t path = {0};
        dyn_string_init(&path, &HEAP_ALLOCATOR);

        if (strncmp(module_name, "core/", 5) == 0) {
          dyn_string_printf(&path, "%s/%s.goo", getenv(CORE_LIB_PATH),
                            module_name + 5);
        } else {
          dyn_string_printf(&path, "%s%s.goo", exec_file_dir_path, module_name);
        }

        FILE *f = fopen(path.string, "r");

        if (f == NULL) {
          log_error("[PREPROCESSOR] Cannot find module for import directive, "
                    "module: %s, path: %s. Execution path: %s",
                    module_name, path.string, parser->filename);
          exit(1);
        }

        ModulePath mod_path = parse_module_path_from_string(module_name);

        array_add(parser->imported_modules, mod_path);

        // TODO: Make dynamic
        char *source_buf = malloc(4096);
        fread(source_buf, 1, 4096, f);

        if (debug_flags.print_parse_info) {
          log_info("[PARSER] Loaded imported module %s",
                   module_path_fmt(&mod_path).string);
        }

        Module mod = parser_parse_module(source_buf, path.string, mod_path);

        hashmap_foreach(
            &mod.functions, ModulePath * key, FuncDescriptor * val,
            { hashmap_insert(&parser->imported_functions, key, val); });

        // Parse and return next stmt, effectively removing the pp dir from
        // source code cur_tok is first token of stmt
        next_token(parser);
        Statement stmt = parse_stmt(parser);
        return stmt;
      }
    } else if (parser->peek_tok->kind == TOKEN_RCURLY) {
      size_t last_pp_cond_idx =
          parser
              ->pp_dir_conditionals[array_len(parser->pp_dir_conditionals) - 1];
      PpDirective *pp_dir = &parser->pp_dirs[last_pp_cond_idx];
      pp_dir->var.pp_dir_if.lines_amount = line - pp_dir->line;

      log_debug("[PARSER] Found end of conditional pre processor directive in "
                "line %zu. Spans %zu lines.",
                line, pp_dir->var.pp_dir_if.lines_amount);

      // cur_tok is 'right curly'
      next_token(parser);
      // cur_tok is first token of stmt
      next_token(parser);
      Statement stmt = parse_stmt(parser);
      return stmt;
    }
    PpDirective pp_dir = parse_pp_dir(parser);
    pp_dir.line = line;
    array_add(parser->pp_dirs, pp_dir);
    exit(1);
  }
  default: {
    char cur_tok_buf[32];
    lexer_tok_print(cur_tok_buf, parser->cur_tok);
    printf("%s:%d:%d Illegal Token %s at beginning of statement\n",
           parser->filename, parser->cur_tok->line, parser->cur_tok->begin_pos,
           cur_tok_buf);
    ErrorMessage msg = {.ctx_first_line = parser->cur_tok->line,
                        .ctx_lines_amount = 1,
                        .issue_line = parser->cur_tok->line,
                        .issue_pos = parser->cur_tok->begin_pos,
                        .issue_ctx_msg = cur_tok_buf};
    printf("%s\n", error_msg_fmt(parser, &msg).string);
    exit(1);
  } break;
  }
}

void parser_parse(Parser *parser) {
  parser->cur_tok = parser->tokens;
  parser->peek_tok = parser->tokens + 1;

  if (debug_flags.print_parse_info) {
    log_info("[Parser] Start parsing file %s", parser->filename);
  }

  while (parser->cur_tok->kind != TOKEN_EOF) {
    Statement stmt = parse_stmt(parser);
    array_add(parser->statements, stmt);
    next_token(parser);
  }
}

inline Module parser_parse_module_ex(Parser *parser, const char *source,
                                     const char *filename) {
  parser_parse(parser);
  return parser->module;
}

Module parser_parse_module(const char *source, const char *filename,
                           ModulePath path) {
  Lexer lexer = {0};
  lexer_init(&lexer);
  lexer_tokenize(&lexer, source, filename);
  array_add(lexer.tokens, (Token){.kind = TOKEN_EOF});
  Parser parser = {0};
  parser_init(&parser, lexer.tokens, source, filename, path);
  parser.lines = lexer.lines;
  parser_parse(&parser);
  return parser.module;
}
