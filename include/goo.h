#pragma once

// clang-format off

/*                                                                                 -- THE PIPELINE --                                                                           */

/* [Parser] --Statements-> [Preprocessor] --Statements-> [Checker] --Statements->                               --Statements-> [Compiler] --Instructions-> [Codegen] -> Binary  */
/*                                        -------Comptime-Param-Functions-------> [Comptime Function Processor] ^                                                               */
