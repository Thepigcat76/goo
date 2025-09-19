#pragma once

#include "parser.h"

extern Expression PRINTLN_FUNCTION_EXPR;
extern Expression EXIT_FUNCTION_EXPR;

void builtin_functions_init(TypeTable *global_table);
