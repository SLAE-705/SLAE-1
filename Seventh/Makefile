all:
		gcc -ggdb -o encrypt encrypt.c -lcrypto
		gcc -ggdb -fno-stack-protector -z execstack decrypt.c -o decrypt -lcrypto
clean:
		rm encrypt decrypt
