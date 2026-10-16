arm-none-eabi-as test_function_arm.s -o test_arm.o
arm-none-eabi-objcopy test_arm.o -O binary test_arm.bin

mv test_arm.bin src/tests/

# RL78: llvm-mc and llvm-objcopy from an LLVM with the RL78 backend.
llvm-mc --triple=rl78 -filetype=obj test_function_rl78.s -o test_rl78.o
llvm-objcopy test_rl78.o -O binary test_rl78.bin

mv test_rl78.bin src/tests/
