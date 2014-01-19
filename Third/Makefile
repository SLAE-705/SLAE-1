all:
		nasm -f elf egghunter.asm
		ld egghunter.o -o egghunter
		gcc -ggdb -fno-stack-protector -z execstack shellcode.c -o shellcode
clean:
		rm *.o
