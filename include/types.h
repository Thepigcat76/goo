#pragma once

#include <stdbool.h>
#include <stdlib.h>

typedef char *Ident;

typedef enum {
  TYPE_ARRAY_VARIANT_DYNAMIC,
  TYPE_ARRAY_VARIANT_SIZED,
  TYPE_ARRAY_VARIANT_SIZE_UNKNOWN,
} TypeArrayVariant;

typedef struct {
  TypeArrayVariant variant;
  size_t size;
  struct _type *type;
} TypeArray;

typedef struct {
  struct _generic *generics;
  struct _type *arg_types;
  struct _type *ret_type;
} TypeFunc;

typedef struct {
  struct _type *types;
} TypeTuple;

typedef struct {
  struct _typed_ident *fields;
} TypeStruct;

typedef struct _type {
  enum {
    TYPE_IDENT,
    TYPE_ARRAY,
    TYPE_FUNCTION,
    TYPE_TUPLE,
    // unit is just an empty tuple and used as the "void" type
    TYPE_UNIT,
    TYPE_STRUCT,
  } type;
  union {
    Ident type_ident;
    TypeArray type_array;
    TypeFunc type_func;
    TypeTuple type_tuple;
    TypeStruct type_struct;
  } var;
} Type;

typedef struct {
  Ident name;
  struct _generic *generics;
  Type *arg_types;
  Type ret_type;
} FuncSignature;

typedef struct _generic {
  Ident name;
  FuncSignature *bounds;
} Generic;

extern const Type UNIT_BUILTIN_TYPE;
extern const Type STRING_BUILTIN_TYPE;
extern const Type INT_BUILTIN_TYPE;

typedef struct _typed_ident {
  Ident ident;
  Type type;
} TypedIdent;

bool type_eq(const Type *a, const Type *b);

void type_print(char *buf, const Type *type);
