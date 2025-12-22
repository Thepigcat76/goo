#include <stdio.h>
#include <raylib.h>

void draw_rect(int x, int y, int width, int height) {
  DrawRectangle(x, y, width, height, RED);
}

void print_int(int i) {
  printf("%d\n", i);
}

void print_int_ptr(int *ip) {
  printf("%d\n", *ip);
}