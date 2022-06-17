#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define LEN 25144

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	unsigned char *iv, unsigned char *plaintext);
void handleErrors(void);

int main (void)
{
	unsigned char key[LEN][16]; //= { "example#########" , "love############" };

	unsigned char iv[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
    				0x09, 0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

	unsigned char *plaintext =
		(unsigned char *)"This is CS445.";

	unsigned char expectedciphertext[] = 
		"3fc871ad620f701700a9e343036c573b";

	unsigned char ciphertext[128];

	//file biz
	
	FILE* file = fopen("words.txt", "r");
	char line[16];
	
	int p = 0;


	int ciphertext_len;
	
	for (int i = 0; i < LEN; i++)
	{
		ciphertext_len = encrypt(plaintext, strlen ((char *)plaintext), key[i], iv, ciphertext);
		//more file biz
		// read a line
		fscanf(file, "%[^\n]", line);

		// for line length
		for (p = 0; p <= 16; p++)
		{		//if not alphanumeric; then char = '#'	
			if(isalnum(line[p]) == 0)
				line[p] = 35; //ascii '#'
		}
				printf("LINE: %s", line);
return 0;
		strcpy(key[i], line);
		printf("Data from line: %s\n", line);

		char *buffer = malloc(2*ciphertext_len + 1);
		char *bufptr = buffer;
		for (int i = 0; i < ciphertext_len; i++)
			bufptr += sprintf(bufptr, "%02x", ciphertext[i]);
		*(bufptr + 1) = '\0';

		printf("Key: ");
		for (int j = 0; j < 16; j++)
			printf("%c", key[i][j]);
		printf("Ciphertext in hex: %s\n", buffer);

		if (!strcmp((const char *) buffer, (const char *) expectedciphertext))
		{
			printf("MATCH!\n");
			fclose(file);
			return 0;
		}
		else
			printf("Not match!\n");
			printf("I: %d\n", i);
	}
	fclose(file);
	return 0;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. 
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. 
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}
