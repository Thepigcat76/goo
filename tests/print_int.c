#include <limits.h>
#include <stdio.h>
#include <raylib.h>
#include <stdint.h>

void draw_rect(int x, int y, int width, int height) {
  DrawRectangle(x, y, width, height, WHITE);
}

void draw_white_rect() {
  DrawRectangle(0, 0, 100, 100, WHITE);
}

void draw_circle(int x, int y, int radius) {
  DrawCircle(x, y, radius, WHITE);
}

void print_int(int i) {
  printf("%d\n", i);
}

int is_key_down(int key) {
  return IsKeyDown(key);
}

void print_int_ptr(int *ip) {
  printf("%d\n", *ip);
}

void print_u8(uint8_t byte) {
  printf("%d\n", byte);
}

void print_u16(uint16_t s) {
  printf("%d\n", s);
}

void print_bool(bool s) {
  printf("%s\n", s ? "True" : "False");
}

void add_random_num(int *i) {
  *i += 20;
}
