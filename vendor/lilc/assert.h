#pragma once

#include "panic.h"

#define ASSERT(cond, fmt, ...) do {\
  if (!(cond)) panic(fmt, __VA_ARGS__);\
} while (0)
