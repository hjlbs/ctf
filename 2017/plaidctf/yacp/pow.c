#include <stdio.h>
#include <openssl/evp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	const EVP_MD *md = NULL;
	EVP_MD_CTX *mdctx;
	int i = 0;
	int rfd; 
	int success = 0;
	char plain[33];
	unsigned char md_value[EVP_MAX_MD_SIZE];
    int md_len;
	
	OpenSSL_add_all_digests();

	memset(plain, 0, 33);
	memcpy( plain, argv[1], 16);
	md = EVP_get_digestbyname("sha256");

	if ( md == NULL ) {
		printf("[ERROR] Get digest by name sha256 failed\n");
		exit(1);
	}

	mdctx = EVP_MD_CTX_create();

	rfd = open("/dev/urandom", O_RDONLY);

	if ( rfd <= 0 ) {
		printf("[ERROR] Failed to open random\n");
		exit(1);
	}

	while (!success) {
		if ( read( rfd, plain+16, 16) != 16 ) {
			printf("[ERROR] Failed to read random\n");
			close(rfd);
			exit(1);
		}
		
        EVP_DigestInit_ex(mdctx, md, NULL);
        EVP_DigestUpdate(mdctx, plain, 32);
        EVP_DigestFinal_ex(mdctx, md_value, &md_len);
        

        if ( md_value[0] != 0xff) {
        	continue;
        }

        if (md_value[1] != 0xff) {
        	continue;
        }

        if (md_value[2] != 0xff) {
        	continue;
        }

        if (md_value[3] <= 0xef) {
        	continue;
        }

        success = 1;
	}

	EVP_MD_CTX_destroy(mdctx);

	printf("[INFO] SUCCESS\n");
	i = open("plain.txt", O_RDWR | O_CREAT, S_IRUSR | S_IRGRP | S_IROTH);

	if ( i <= 0 ) {
		printf("[ERROR] Failed to open output file\n");
		exit(1);
	}

	write(i, plain, 32);
	close(i);

	EVP_cleanup();
	return 0;	
}
