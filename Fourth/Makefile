all:
		nasm -f elf execve-stack.nasm
		ld execve-stack.o -o execve-stack
		nasm -f elf insertion-decoder.nasm
		ld insertion-decoder.o -o insertion-decoder	
		gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
clean:
		rm *.o
