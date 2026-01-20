#include "raylib.h"
#include "print_int.c"

int main() {
    InitWindow(100, 100, "Hello");
    for (;;) {
        BeginDrawing();
        print_int(is_key_down(KEY_S));
        EndDrawing();
    }

}