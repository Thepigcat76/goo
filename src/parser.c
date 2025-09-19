#include "../include/parser.h"
#include "lilc/array.h"
#include <lilc/alloc.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define EXPECTED_TOKEN_ERR(expected, received_ptr)                             \
  do {                                                                         \
    char print_buf[64];                                                        \
    lexer_tok_print(print_buf, received_ptr);                                  \
    fprintf(stderr, "Expected " #expected ", received: %s", print_buf);        \
    exit(1);                                                                    \
  } while (0)

#define ILLEGAL_TOKEN_ERR(tok)                                                 \
  fprintf(stderr, "Illegal " #tok " at beginning of stmt");                    \
  exit(1)

const Expression UNIT_EXPR = {.type = EXPR_UNIT};
const OptionalType OPT_TYPE_EMPTY = {.present = false};

Parser parser_new(Token *tokens) {
  return (Parser){
    .tokens = tokens,
    .statements = array_new(Statement, &HEAP_ALLOCATOR),
  };
}

static void next_token(Parser *parser) {
  parser->cur_tok = parser->peek_tok;
  parser->peek_tok++;
}

static void type_print_as_ident(char *buf, const Type *type) {
  switch (type->type) {
  case TYPE_IDENT: {
    sprintf(buf, "i%s", type->var.type_ident);
    break;
  }
  case TYPE_ARRAY: {
    char type_buf[128];
    type_print_as_ident(type_buf, type->var.type_array.type);
    sprintf(buf, "a%s", type_buf);
    break;
  }
  case TYPE_FUNCTION: {
    break;
  }
  case TYPE_TUPLE: {
    break;
  }
  case TYPE_UNIT: {
    sprintf(buf, "u");
    break;
  }
  }
}

static void generic_print(char *buf, const Generic *generic);

static void func_signature_print(char *buf, const FuncSignature *desc) {
  char generics_buf[256] = {'\0'};
  if (desc->generics != NULL) {
    for (size_t i = 0; i < array_len(desc->generics); i++) {
      char generic_buf[128];
      generic_print(generic_buf, &desc->generics[i]);
      strcat(generics_buf, generic_buf);
      strcat(generics_buf, ", ");
    }
    if (array_len(desc->generics) >= 1) {
      generics_buf[strlen(generics_buf) - 2] = '\0';
    }
  }
  char args_buf[256] = {'\0'};
  if (desc->arg_types != NULL) {
    for (size_t i = 0; i < array_len(desc->arg_types); i++) {
      char arg_buf[64];
      char type_buf[512];
      type_print(type_buf, &desc->arg_types[i]);
      sprintf(arg_buf, "Type{type=%s}", type_buf);
      strcat(args_buf, arg_buf);
      strcat(args_buf, ", ");
    }
    if (array_len(desc->arg_types) >= 1) {
      args_buf[strlen(args_buf) - 2] = '\0';
    }
  }
  char type_buf[512];
  type_print(type_buf, &desc->ret_type);
  sprintf(buf, "FuncSignature{name=%s, generics=[%s], args=[%s], ret_type=%s}",
          desc->name, generics_buf, args_buf, type_buf);
}

static void generic_print(char *buf, const Generic *generic) {
  char bounds_buf[512] = {'\0'};
  if (generic->bounds != NULL) {
    for (size_t i = 0; i < array_len(generic->bounds); i++) {
      char bound_buf[128] = {'\0'};
      func_signature_print(bound_buf, &generic->bounds[i]);
      strcat(bounds_buf, bound_buf);
      strcat(bounds_buf, ", ");
    }
    bounds_buf[strlen(bounds_buf) - 2] = '\0';
  }
  sprintf(buf, "Generic{name=%s, bounds=[%s]}", generic->name, bounds_buf);
}

static void typed_ident_print(char *buf, const TypedIdent *ident) {
  char type_buf[512];
  type_print(type_buf, &ident->type);
  sprintf(buf, "TypedIdent{ident=%s, type=%s}", ident->ident, type_buf);
}

void func_desc_print(char *buf, const FuncDescriptor *desc) {
  char generics_buf[512] = {'\0'};
  if (desc->generics != NULL) {
    for (size_t i = 0; i < array_len(desc->generics); i++) {
      char generic_buf[256] = {'\0'};
      generic_print(generic_buf, &desc->generics[i]);
      strcat(generics_buf, generic_buf);
      strcat(generics_buf, ", ");
    }
    if (array_len(desc->generics) >= 1) {
      generics_buf[strlen(generics_buf) - 2] = '\0';
    }
  }
  char args_buf[256] = {'\0'};
  if (desc->args != NULL) {
    for (size_t i = 0; i < array_len(desc->args); i++) {
      char arg_buf[64];
      typed_ident_print(arg_buf, &desc->args[i]);
      strcat(args_buf, arg_buf);
      strcat(args_buf, ", ");
    }
    if (array_len(desc->args) >= 1) {
      args_buf[strlen(args_buf) - 2] = '\0';
    }
  }
  char type_buf[512];
  type_print(type_buf, &desc->ret_type);
  sprintf(buf, "FuncDescriptor{generics=[%s], args=[%s], ret_type=%s}",
          generics_buf, args_buf, type_buf);
}

static void expr_print(char *buf, const Expression *expr) {
  switch (expr->type) {
  case EXPR_FUNCTION: {
    char func_desc_buf[512] = {'\0'};
    func_desc_print(func_desc_buf, &expr->var.expr_function.desc);
    char block_buf[4096] = {'\0'};
    if (expr->var.expr_function.block != NULL) {
      Statement *stmts = expr->var.expr_function.block->statements;
      if (stmts != NULL) {
        for (size_t i = 0; i < array_len(stmts); i++) {
          char stmt_buf[512];
          parser_stmt_print(stmt_buf, &stmts[i]);
          strcat(block_buf, stmt_buf);
          strcat(block_buf, ", ");
        }
        if (array_len(stmts) >= 1) {
          block_buf[strlen(block_buf) - 2] = '\0';
        }
      }
    }
    sprintf(buf, "ExprFunction{func_desc=%s, block=[%s]}", func_desc_buf,
            block_buf);
    break;
  }
  case EXPR_STRING_LIT: {
    sprintf(buf, "StringLiteral{value=\"%s\"}",
            expr->var.expr_string_literal.string);
    break;
  }
  case EXPR_INTEGER_LIT: {
    sprintf(buf, "IntegerLiteral{value=%d}",
            expr->var.expr_integer_literal.integer);
    break;
  }
  case EXPR_CALL: {
    char args_buf[512] = {'\0'};
    if (expr->var.expr_call.args != NULL) {
      for (size_t i = 0; i < array_len(expr->var.expr_call.args); i++) {
        char arg_buf[128];
        Expression arg_expr = expr->var.expr_call.args[i];
        expr_print(arg_buf, &arg_expr);
        strcat(args_buf, arg_buf);
        strcat(args_buf, ", ");
      }
      if (array_len(expr->var.expr_call.args) >= 1) {
        args_buf[strlen(args_buf) - 2] = '\0';
      }
    }
    sprintf(buf, "ExprCall{function=%s, args=[%s]}",
            expr->var.expr_call.function, args_buf);
    break;
  }
  case EXPR_GENERIC_CALL: {
    ExprGenericCall generic_call = expr->var.expr_generic_call;
    char print_buf[1024];
    Expression call_expr = {.type = EXPR_CALL,
                            .var = {.expr_call = generic_call.expr_call}};
    expr_print(print_buf, &call_expr);
    sprintf(buf, "ExprGenericCall{generic_ident=%s, call_expr=%s}",
            generic_call.generic, print_buf);
    break;
  }
  case EXPR_BLOCK: {
    char block_buf[4096] = {'\0'};
    Statement *stmts = expr->var.expr_block.statements;
    if (stmts != NULL) {
      for (size_t i = 0; i < array_len(stmts); i++) {
        char stmt_buf[512];
        parser_stmt_print(stmt_buf, &stmts[i]);
        strcat(block_buf, stmt_buf);
        strcat(block_buf, ", ");
      }
      if (array_len(expr->var.expr_block.statements) >= 1) {
        block_buf[strlen(block_buf) - 2] = '\0';
      }
    }
    sprintf(buf, "%s", block_buf);
    break;
  }
  case EXPR_IDENT: {
    sprintf(buf, "ExprIdent{ident=%s}", expr->var.expr_ident.ident);
    break;
  }
  case EXPR_ARRAY: {
    Type type = {.type = TYPE_ARRAY,
                 .var = {.type_array = expr->var.expr_array.type}};
    char type_buf[128];
    type_print(type_buf, &type);
    char exprs_buf[512] = {'\0'};
    for (size_t i = 0; i < array_len(expr->var.expr_array.items); i++) {
      char expr_buf[128];
      expr_print(expr_buf, &expr->var.expr_array.items[i]);
      strcat(exprs_buf, expr_buf);
      strcat(exprs_buf, ", ");
    }
    if (array_len(expr->var.expr_array.items) > 0) {
      exprs_buf[strlen(exprs_buf) - 2] = '\0';
    }
    sprintf(buf, "ExprArray{type=%s, items=%s}", type_buf, exprs_buf);
    break;
  }
  case EXPR_CAST: {
    char type_buf[128];
    type_print(type_buf, &expr->var.expr_cast.type);
    char expr_buf[128];
    expr_print(expr_buf, expr->var.expr_cast.expr);
    sprintf(buf, "ExprCast{type=%s, expr=%s}", type_buf, expr_buf);
    break;
  }
  case EXPR_UNIT: {
    sprintf(buf, "ExprUnit");
    break;
  }
  default: {
    fprintf(stderr, "No type found: %d", expr->type);
    exit(1);
  }
  }
}

void parser_stmt_print(char *buf, const Statement *stmt) {
  switch (stmt->type) {
  case STMT_DECL: {
    char expr_buf[1024] = {'\0'};
    if (stmt->var.stmt_decl.value.type == EXPR_VAR_REG_EXPR) {
      expr_print(expr_buf, &stmt->var.stmt_decl.value.var.expr_var_reg_expr);
    } else {
      strcpy(expr_buf, "ExprVariantType{...}");
    }
    char type_buf[512] = {'\0'};
    if (stmt->var.stmt_decl.type.present) {
      type_print(type_buf, &stmt->var.stmt_decl.type.type);
    }
    sprintf(buf, "StmtDecl{name=%s, type=%s, mutable=%s, value=%s}",
            stmt->var.stmt_decl.name, type_buf,
            stmt->var.stmt_decl.mutable ? "true" : "false", expr_buf);
    break;
  }
  case STMT_EXPR: {
    char expr_buf[1024];
    expr_print(expr_buf, &stmt->var.stmt_expr.expr);
    sprintf(buf, "StmtExpr{expr=%s}", expr_buf);
    break;
  }
  }
}

static Statement parse_stmt(Parser *parser);

// begin: cur_tok must be first token of type
// end: cur_tok is last token of type
static Type parse_type(Parser *parser) {
  switch (parser->cur_tok->type) {
  case TOKEN_IDENT: {
    return (Type){.type = TYPE_IDENT,
                  .var = {.type_ident = parser->cur_tok->var.ident}};
  }
  case TOKEN_LPAREN: {
    if (parser->peek_tok->type == TOKEN_RPAREN) {
      // cur_tok is right parenthesis
      next_token(parser);
      return (Type){.type = TYPE_UNIT};
    }
    Type *types = array_new(Type, &HEAP_ALLOCATOR);
    while (parser->peek_tok->type != TOKEN_RPAREN) {
      // cur_tok is first token of type
      next_token(parser);
      Type type = parse_type(parser);
      array_add(types, type);
      if (parser->peek_tok->type == TOKEN_COMMA) {
        // cur_tok is comma
        next_token(parser);
      }
    }
    return (Type){.type = TYPE_TUPLE, .var = {.type_tuple = {.types = types}}};
  }
  case TOKEN_LSQUARE: {
    TypeArray type_array = {};
    if (parser->peek_tok->type == TOKEN_IDENT &&
        strcmp(parser->peek_tok->var.ident, "dyn") == 0) {
      type_array.variant = TYPE_ARRAY_VARIANT_DYNAMIC;
      // cur_tok is ident
      next_token(parser);
    } else if (parser->peek_tok->type == TOKEN_INT) {
      type_array.variant = TYPE_ARRAY_VARIANT_SIZED;
      type_array.size = parser->peek_tok->var.integer;
      // cur_tok is int
      next_token(parser);
    } else if (parser->peek_tok->type == TOKEN_RSQUARE) {
      type_array.variant = TYPE_ARRAY_VARIANT_SIZE_UNKNOWN;
    }
    // cur_tok is right parenthesis
    next_token(parser);
    // cur_tok is first token of type
    next_token(parser);
    type_array.type = malloc(sizeof(Type));
    Type type = parse_type(parser);
    memcpy(type_array.type, &type, sizeof(Type));
    return (Type){.type = TYPE_ARRAY, .var = {.type_array = type_array}};
  }
  // case TOKEN_LANGLE: {
  //   break;
  // }
  default: {
    printf("Type parsing nyi for type\n");
    exit(1);
  }
  }
}

// begin: cur_tok must be first ident or end
// end: cur_tok is end
static TypedIdent *parse_typed_ident_list(Parser *parser, TokenType end) {
  TypedIdent *idents = array_new_capacity(TypedIdent, 8, &HEAP_ALLOCATOR);
  while (parser->cur_tok->type != end) {
    TypedIdent ti;
    if (parser->cur_tok->type == TOKEN_IDENT) {
      ti.ident = parser->cur_tok->var.ident;
    }
    // cur_tok is colon
    next_token(parser);
    if (parser->cur_tok->type != TOKEN_COLON) {
      EXPECTED_TOKEN_ERR(TOKEN_COLON, parser->cur_tok);
    }
    // cur_tok is type
    next_token(parser);
    if (parser->cur_tok->type == TOKEN_IDENT) {
      ti.type = parse_type(parser);
    }

    if (parser->peek_tok->type == TOKEN_COMMA) {
      // cur_tok is comma
      next_token(parser);
      // cur_tok is ident or end
      next_token(parser);
    } else if (parser->peek_tok->type == end) {
      // cur_tok is end
      next_token(parser);
    }
    array_add(idents, ti);
  }
  return idents;
}

// begin: cur_tok must be first type or end
// end: cur_tok is end
static Type *parse_type_list(Parser *parser, TokenType end) {
  Type *types = array_new_capacity(Type, 8, &HEAP_ALLOCATOR);
  while (parser->cur_tok->type != end) {
    Type t = {};
    if (parser->cur_tok->type == TOKEN_IDENT) {
      t = parse_type(parser);
    } else {
      char print_buf[64];
      lexer_tok_print(print_buf, parser->cur_tok);
      fprintf(stderr, "Expected type, received tok: %s", print_buf);
      exit(1);
    }

    if (parser->peek_tok->type == TOKEN_COMMA) {
      // cur_tok is comma
      next_token(parser);
      // cur_tok is ident or end
      next_token(parser);
    } else if (parser->peek_tok->type == end) {
      // cur_tok is end
      next_token(parser);
    }
    array_add(types, t);
  }
  return types;
}

// begin: cur_tok must be first token of first statement
// end: cur_tok is end
static Statement *parse_block_statements(Parser *parser, TokenType end) {
  Statement *stmts = array_new_capacity(Statement, 16, &HEAP_ALLOCATOR);
  while (parser->cur_tok->type != end) {
    Statement stmt = parse_stmt(parser);
    array_add(stmts, stmt);
    next_token(parser);
  }
  return stmts;
}

static Expression parse_expr(Parser *parser);

static Expression *parse_expr_list(Parser *parser, TokenType end) {
  Expression *exprs = array_new_capacity(Expression, 8, &HEAP_ALLOCATOR);
  while (parser->cur_tok->type != end) {
    Expression expr = parse_expr(parser);
    if (parser->peek_tok->type == TOKEN_COMMA) {
      // cur_tok is comma
      next_token(parser);
    }
    array_add(exprs, expr);
    // cur_tok is next expr
    next_token(parser);
  }
  return exprs;
}

// TODO: Generic functions
// begin: cur_tok must be left parenthesis
// end: cur_tok is return_type ident or right parenthesis
static FuncDescriptor parse_func_desc(Parser *parser);

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
  if (parser->peek_tok->type == TOKEN_ARROW) {
    // cur_tok is arrow
    next_token(parser);

    if (parser->peek_tok->type == TOKEN_IDENT) {
      // cur_tok is ident
      next_token(parser);
      signature.ret_type = parse_type(parser);
    } else {
      EXPECTED_TOKEN_ERR(TOKEN_IDENT, parser->peek_tok);
    }
  }

  return signature;
}

// begin: cur_tok must be generic name
// end: cur_tok is end of func descriptor or generic ident
static Generic parse_generic(Parser *parser) {
  Generic generic = {.name = parser->cur_tok->var.ident};
  if (parser->peek_tok->type == TOKEN_COLON) {
    // cur_tok is colon
    next_token(parser);
    // cur_tok is first tok of func descriptor
    next_token(parser);
    generic.bounds = array_new(FuncSignature, &HEAP_ALLOCATOR);
    while (parser->cur_tok->type != TOKEN_COMMA &&
           parser->cur_tok->type != TOKEN_RANGLE) {
      FuncSignature signature = parse_func_signature(parser);
      array_add(generic.bounds, signature);

      if (parser->peek_tok->type == TOKEN_PLUS) {
        // cur_tok is plus
        next_token(parser);
      } else if (parser->peek_tok->type == TOKEN_RANGLE) {
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
static FuncDescriptor parse_func_desc(Parser *parser) {
  FuncDescriptor desc = {};
  // cur_tok is first ident or end of args
  next_token(parser);
  desc.args = parse_typed_ident_list(parser, TOKEN_RPAREN);
  if (parser->peek_tok->type == TOKEN_ARROW) {
    // cur_tok is arrow
    next_token(parser);

    if (parser->peek_tok->type == TOKEN_IDENT) {
      // cur_tok is ident
      next_token(parser);
      desc.ret_type = parse_type(parser);
    } else {
      EXPECTED_TOKEN_ERR(TOKEN_IDENT, parser->peek_tok);
    }
  }

  return desc;
}

static Expression parse_expr(Parser *parser) {
  switch (parser->cur_tok->type) {
  case TOKEN_STRING: {
    return (Expression){
        .type = EXPR_STRING_LIT,
        .var = {.expr_string_literal = parser->cur_tok->var.string}};
  }
  case TOKEN_LPAREN: {
    FuncDescriptor desc = parse_func_desc(parser);
    ExprBlock *block_expr = malloc(sizeof(ExprBlock));

    if (parser->peek_tok->type == TOKEN_LCURLY) {
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
    return (Expression){
        .type = EXPR_FUNCTION,
        .var = {.expr_function = {.desc = desc, .block = block_expr}}};
  }
  case TOKEN_LCURLY: {
    // cur_tok is first tok of first stmt of block
    next_token(parser);
    Statement *stmts = parse_block_statements(parser, TOKEN_RCURLY);
    return (Expression){.type = EXPR_BLOCK,
                        .var = {.expr_block = {.statements = stmts}}};
  }
  case TOKEN_IDENT: {
    Ident ident = parser->cur_tok->var.ident;
    if (parser->peek_tok->type == TOKEN_LPAREN) {
      // cur_tok is left parenthesis
      next_token(parser);
      // cur_tok is first expr
      next_token(parser);

      Expression *exprs = parse_expr_list(parser, TOKEN_RPAREN);
      // end: right parenthesis
      return (Expression){
          .type = EXPR_CALL,
          .var = {.expr_call = {.function = ident, .args = exprs}}};
    } else if (parser->peek_tok->type == TOKEN_DOT) {
      // cur_tok is dot
      next_token(parser);
      // cur_tok is call name
      next_token(parser);

      Ident call_name = parser->cur_tok->var.ident;

      // cur_tok is left parenthesis
      next_token(parser);
      // cur_tok is first token of first expr
      next_token(parser);

      Expression *exprs = parse_expr_list(parser, TOKEN_RPAREN);
      // end: right parenthesis
      return (Expression){
          .type = EXPR_GENERIC_CALL,
          .var = {.expr_generic_call = {
                      .generic = ident,
                      .expr_call = {.function = call_name, .args = exprs}}}};
    }
    return (Expression){.type = EXPR_IDENT,
                        .var = {.expr_ident = {.ident = ident}}};
  }
  case TOKEN_INT: {
    return (Expression){.type = EXPR_INTEGER_LIT,
                        .var = {.expr_integer_literal = {
                                    .integer = parser->cur_tok->var.integer}}};
  }
  case TOKEN_LANGLE: {
    Generic *generics;
    if (parser->peek_tok->type == TOKEN_RANGLE) {
      generics = NULL;
    } else {
      generics = array_new(Generic, &HEAP_ALLOCATOR);
      if (parser->peek_tok->type == TOKEN_IDENT) {
        // cur_tok is generic name
        next_token(parser);

        while (parser->cur_tok->type != TOKEN_RANGLE) {
          Generic generic = parse_generic(parser);
          array_add(generics, generic);
          if (parser->peek_tok->type == TOKEN_COMMA) {
            // cur_tok is comma
            next_token(parser);
            if (parser->peek_tok->type == TOKEN_IDENT) {
              // cur_tok is ident
              next_token(parser);
            } else if (parser->peek_tok->type == TOKEN_RANGLE) {
              break;
            }
          } else if (parser->peek_tok->type == TOKEN_RANGLE) {
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
    FuncDescriptor desc = parse_func_desc(parser);
    desc.generics = generics;
    ExprBlock *block_expr = malloc(sizeof(ExprBlock));

    if (parser->peek_tok->type == TOKEN_LCURLY) {
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
    return (Expression){
        .type = EXPR_FUNCTION,
        .var = {.expr_function = {.desc = desc, .block = block_expr}}};
  }
  case TOKEN_LSQUARE: {
    Type type = parse_type(parser);
    if (parser->peek_tok->type != TOKEN_LCURLY) {
      EXPECTED_TOKEN_ERR(TOKEN_LCURLY, parser->peek_tok);
    }
    // cur_tok is left curly
    next_token(parser);
    // cur_tok is first token of expr
    next_token(parser);
    Expression *exprs = array_new(Expression, &HEAP_ALLOCATOR);
    while (parser->cur_tok->type != TOKEN_RCURLY) {
      array_add(exprs, parse_expr(parser));
      if (parser->peek_tok->type == TOKEN_COMMA) {
        // cur_tok is comma
        next_token(parser);
      }
      // cur_tok is right parenthesis or next expr
      next_token(parser);
    }
    return (Expression){
        .type = EXPR_ARRAY,
        .var = {.expr_array = {.type = type.var.type_array, .items = exprs}}};
  }
  case TOKEN_CAST: {
    if (parser->peek_tok->type != TOKEN_LANGLE) {
      EXPECTED_TOKEN_ERR(TOKEN_LPAREN, parser->peek_tok);
    }
    // cur_tok is left angle
    next_token(parser);
    // cur_tok is first token of type
    next_token(parser);
    Type type = parse_type(parser);

    if (parser->peek_tok->type != TOKEN_RANGLE) {
      EXPECTED_TOKEN_ERR(TOKEN_RANGLE, parser->peek_tok);
    }
    // cur_tok is right angle
    next_token(parser);

    if (parser->peek_tok->type != TOKEN_LPAREN) {
      EXPECTED_TOKEN_ERR(TOKEN_LPAREN, parser->peek_tok);
    }
    // cur_tok is left parenthesis
    next_token(parser);
    // cur_tok is first token of expr
    next_token(parser);
    Expression expr = parse_expr(parser);

    if (parser->peek_tok->type != TOKEN_RPAREN) {
      EXPECTED_TOKEN_ERR(TOKEN_RPAREN, parser->peek_tok);
    }

    // cur_tok is right parenthesis
    next_token(parser);

    ExprCast expr_cast = {.type = type, .expr = malloc(sizeof(Expression))};
    memcpy(expr_cast.expr, &expr, sizeof(Expression));
    return (Expression){.type = EXPR_CAST, .var = {.expr_cast = expr_cast}};
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
  case TOKEN_ASSIGN:
  case TOKEN_RSQUARE:
  case TOKEN_ILLEGAL: {
    char print_buf[64];
    lexer_tok_print(print_buf, parser->cur_tok);
    printf("nyi/illegal token: %s\n", print_buf);
    exit(1);
  }
  }
}

static Statement parse_stmt(Parser *parser) {
  switch (parser->cur_tok->type) {
  case TOKEN_IDENT: {
    if (parser->peek_tok->type == TOKEN_DECL_CONST ||
        parser->peek_tok->type == TOKEN_DECL_VAR) {
      Ident name = parser->cur_tok->var.ident;
      bool mutable = parser->peek_tok->type == TOKEN_DECL_VAR;
      // cur token is DECL
      next_token(parser);
      // cur token is EXPR
      next_token(parser);
      Statement stmt;
      if (parser->cur_tok->type == TOKEN_IDENT &&
          !(parser->peek_tok->type == TOKEN_LPAREN ||
            parser->peek_tok->type == TOKEN_DOT)) {
        Ident *idents = array_new(Ident, &HEAP_ALLOCATOR);
        while (parser->cur_tok->type == TOKEN_IDENT) {
          array_add(idents, parser->cur_tok->var.ident);
          if (parser->peek_tok->type == TOKEN_COMMA) {
            // cur_tok is comma
            next_token(parser);
            if (parser->peek_tok->type == TOKEN_IDENT) {
              // cur_tok is next ident
              next_token(parser);
            } else {
              break;
            }
          } else {
            break;
          }
        }
        stmt = (Statement){
            .type = STMT_DECL,
            .var = {.stmt_decl = {
                        .name = name,
                        .mutable = mutable,
                        .value = (ExpressionVariant){
                            .type = EXPR_VAR_TYPE_EXPR,
                            .var = {.expr_var_type_expr = {
                                        .type = TYPE_EXPR_OVERLOAD_SET,
                                        .var = {.type_expr_overload_set = {
                                                    .functions = idents}}}}}}}};
      } else {
        Expression value = parse_expr(parser);
        stmt = (Statement){
            .type = STMT_DECL,
            .var = {.stmt_decl = {.name = name,
                                  .mutable = mutable,
                                  .value = (ExpressionVariant){
                                      .type = EXPR_VAR_REG_EXPR,
                                      .var = {.expr_var_reg_expr = value}}}}};
      }
      return stmt;
    } else if (parser->peek_tok->type == TOKEN_COLON) {
      StmtDecl stmt_decl = {0};
      stmt_decl.name = parser->cur_tok->var.ident;
      // cur_tok is colon
      next_token(parser);
      // cur_tok is first token of type
      next_token(parser);
      stmt_decl.type =
          (OptionalType){.type = parse_type(parser), .present = true};

      if (parser->peek_tok->type == TOKEN_ASSIGN ||
          parser->peek_tok->type == TOKEN_COLON) {
        // cur_tok is assign/colon
        next_token(parser);

        stmt_decl.mutable = parser->cur_tok->type == TOKEN_ASSIGN;
      } else {
        EXPECTED_TOKEN_ERR(TOKEN_ASSIGN | TOKEN_COLON, parser->peek_tok);
      }

      next_token(parser);
      Expression value = parse_expr(parser);
      stmt_decl.value = (ExpressionVariant){
          .type = EXPR_VAR_REG_EXPR, .var = {.expr_var_reg_expr = value}};
      return (Statement){.type = STMT_DECL, .var = {.stmt_decl = stmt_decl}};
    } else {
      goto parse_expr;
    }
    exit(1);
  }
  case TOKEN_CAST:
  case TOKEN_LSQUARE:
  case TOKEN_STRING:
  case TOKEN_INT:
  parse_expr: {
    Expression expr = parse_expr(parser);
    return (Statement){.type = STMT_EXPR, .var = {.stmt_expr = {.expr = expr}}};
  }
  case TOKEN_DECL_CONST: {
    ILLEGAL_TOKEN_ERR(TOKEN_DECL_CONST);
  }
  case TOKEN_DECL_VAR: {
    ILLEGAL_TOKEN_ERR(TOKEN_DECL_VAR);
  }
  case TOKEN_COLON: {
    ILLEGAL_TOKEN_ERR(TOKEN_COLON);
  }
  case TOKEN_LPAREN: {
    ILLEGAL_TOKEN_ERR(TOKEN_LPAREN);
  }
  case TOKEN_RPAREN: {
    ILLEGAL_TOKEN_ERR(TOKEN_RPAREN);
  }
  case TOKEN_LCURLY: {
    ILLEGAL_TOKEN_ERR(TOKEN_LCURLY);
  }
  case TOKEN_RCURLY: {
    ILLEGAL_TOKEN_ERR(TOKEN_RCURLY);
  }
  case TOKEN_LANGLE: {
    ILLEGAL_TOKEN_ERR(TOKEN_LANGLE);
  }
  case TOKEN_RANGLE: {
    ILLEGAL_TOKEN_ERR(TOKEN_RANGLE);
  }
  case TOKEN_ARROW: {
    ILLEGAL_TOKEN_ERR(TOKEN_ARROW);
  }
  case TOKEN_COMMA: {
    ILLEGAL_TOKEN_ERR(TOKEN_COMMA);
  }
  case TOKEN_DOT: {
    ILLEGAL_TOKEN_ERR(TOKEN_DOT);
  }
  case TOKEN_PLUS: {
    ILLEGAL_TOKEN_ERR(TOKEN_PLUS);
  }
  case TOKEN_MINUS: {
    ILLEGAL_TOKEN_ERR(TOKEN_MINUS);
  }
  case TOKEN_EOF: {
    ILLEGAL_TOKEN_ERR(TOKEN_EOF);
  }
  case TOKEN_ILLEGAL: {
    ILLEGAL_TOKEN_ERR(TOKEN_ILLEGAL);
  }
  case TOKEN_ASSIGN: {
    ILLEGAL_TOKEN_ERR(TOKEN_ASSIGN);
    break;
  }
  case TOKEN_RSQUARE: {
    ILLEGAL_TOKEN_ERR(TOKEN_RSQUARE);
    break;
  }
  }
}

void parser_parse(Parser *parser) {
  parser->cur_tok = parser->tokens;
  parser->peek_tok = parser->tokens + 1;

  while (parser->cur_tok->type != TOKEN_EOF) {
    Statement stmt = parse_stmt(parser);
    array_add(parser->statements, stmt);
    next_token(parser);
  }
}