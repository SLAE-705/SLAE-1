all:
		nasm -f elf reverse_shell_bind_tcp.asm
		ld reverse_shell_bind_tcp.o -o reverse_shell_bind_tcp
		gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
clean:
		rm *.o
