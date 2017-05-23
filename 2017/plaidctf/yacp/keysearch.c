#include <stdio.h>
#include <openssl/evp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

unsigned char *newkey()
{
	char *data = NULL;
	int fd = 0;

	fd = open("/dev/urandom", O_RDONLY);

	if ( fd <= 0 ) {
		printf("[ERROR] Failed to open /dev/urandom");
		exit(1);
	}

	data = malloc(32);

	if ( data == NULL ) {
		printf("[ERROR] Failed to malloc data\n");
		close(fd);
		exit(1);
	}

	if ( read( fd, data, 32) != 32 ) {
		printf("[ERROR] Failed to read random data\n");
		close(fd);
		free(data);
		exit(1);
	}

	close(fd);
	return data;	
}

int main()
{
	const EVP_CIPHER *evpc = NULL;
	EVP_CIPHER_CTX cc;
	char iv[16];
	char plaintext[2048];
	unsigned char *key = NULL;
	int success = 0;
	char enc_data[2064];
	int *array = NULL;
	int outl = 0;
	int outlm = 0;
	
	OpenSSL_add_all_algorithms();

	while (!success) {
		memset(iv, 0, 16);
		memset(plaintext, 0x41, 2048);
		memset(enc_data, 0, 2064);

		evpc = EVP_get_cipherbyname("aes-256-cbc");
	
		if ( evpc == NULL ) {
			printf("[ERROR] Get cipher by name aes-256-cbc failed\n");
			exit(1);
		}

		key = newkey();

		EVP_CIPHER_CTX_init(&cc);

		EVP_CipherInit_ex(&cc, evpc, 0, key, iv, 1);
		EVP_CipherUpdate(&cc, enc_data, &outl, plaintext, 2048);
  		EVP_CipherFinal_ex(&cc, &enc_data[outl], &outlm);
  		if ( EVP_CIPHER_CTX_cleanup(&cc) == 0 ) {
			printf("[ERROR] Cipher cleanup failed.\n");
			free(key);
			exit(1);
		}
 
		/// Cast the encrypted data as an integer to check the sizes
		array = (int*)enc_data;

		// The size I need to find for an overwrite:
		/// So max is 4388 (0x1124) and min is 2340 (0x924)
		for ( int i = 512; i < 516; i++) {
			if ( array[i] >= 2340 && array[i] <= 4388 ) {
				printf("[INFO] Found %d in index %d\n", array[i], i);
				success = 1;
			}
		}

		if ( !success ) {
			free(key);
		} 
	}

	for ( int i = 0; i < 32; i++) {
		printf("%.2x ", key[i]);
	}
	printf("\n");

	free(key);
	return 0;	
}
