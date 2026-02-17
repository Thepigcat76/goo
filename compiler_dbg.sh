#gurd r && objdump -d output/out.o && gcc output/out.o -lraylib print_int.a -o output/bin && objdump -d output/bin &&#
gurd r tests/files.goo -o output/files.o
gurd r tests/modules.goo -o output/modules.o
gcc output/modules.o output/files.o -o output/bin
./output/bin