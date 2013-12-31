all:
		nasm -f elf shell_bind_tcp.asm
		ld shell_bind_tcp.o -o shell_bind_tcp
		gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
clean:
		rm *.o
