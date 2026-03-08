#gurd r && objdump -d output/out.o && gcc output/out.o -lraylib print_int.a -o output/bin && objdump -d output/bin &&#
#gurd r goo-libs/core/io/files.goo -di -o output/files.o -mp core.io.files
#gurd r goo-libs/core/io.goo -di -o output/io.o -mp core.io
#gurd r tests/modules.goo -di -o output/modules.o
#gcc output/modules.o output/files.o output/io.o -o output/bin
#./output/bin

gurd r tests/modules.goo -di
gcc output/out.o -lraylib print_int.a -o ./output/bin # This just links the program, it doesnt have anything to do with compilation
./output/bin
