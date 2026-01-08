#include <limits.h>
#include <stdio.h>
#include <raylib.h>

void draw_rect(int x, int y, int width, int height) {
  DrawRectangle(x, y, width, height, WHITE);
}

void draw_white_rect() {
  DrawRectangle(0, 0, 100, 100, WHITE);
}

void print_int(int i) {
  INT_MAX
  printf("%d\n", i);
}

int is_mouse_button_released(int button) {
  return IsMouseButtonReleased(button) ? 1 : 0;
}

void print_int_ptr(int *ip) {
  printf("%d\n", *ip);
}