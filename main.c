#include <stdio.h>
#include <string.h>
#include <memory.h>

#include "sha256.h"


void pretty_print(BYTE *preimage, BYTE *buffer, BYTE *target, int pass) {
    
    printf("input:            \"");
    for (int i = 0; i < strlen(preimage); i++)
        printf("%c", preimage[i]);
    printf("\"\n");

    printf("target digest:    ");
    for(int i = 0; i < 32; i++)
        printf("%02x", target[i]);
    printf("\n");

    printf("computed digest:  ");
    for(int i = 0; i < 32; i++)
        printf("%02x", buffer[i]);
    printf("\n");

    if (pass)
        printf("status:           PASS");
    else
        printf("status:           FAIL");

    printf("\n\n\n");
}


void run_tests() {

	BYTE preimage1[] =         {""};
	BYTE digest1[BLOCK_SIZE] = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
                                0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                                0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                                0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

	BYTE preimage2[] =         {"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"};
	BYTE digest2[BLOCK_SIZE] = {0xa6, 0xd7, 0x2b, 0xaa, 0x3d, 0xb9, 0x00, 0xb0, 
                                0x3e, 0x70, 0xdf, 0x88, 0x0e, 0x50, 0x3e, 0x91, 
                                0x64, 0x01, 0x3b, 0x4d, 0x9a, 0x47, 0x08, 0x53,
                                0xed, 0xc1, 0x15, 0x77, 0x63, 0x23, 0xa0, 0x98};


	BYTE preimage3[] =         {"It ain't what you don't know that gets you into trouble. It's what you know for sure that just ain't so."};
	BYTE digest3[BLOCK_SIZE] = {0xa0, 0x98, 0x23, 0xe3, 0x8e, 0x8b, 0x7a, 0xfa,
                                0xe3, 0x85, 0xb5, 0xe5, 0x64, 0xb3, 0x00, 0x99,
                                0xf4, 0x53, 0xd3, 0x24, 0x2a, 0x2a, 0x31, 0x74,
                                0x5f, 0xb2, 0xf1, 0x63, 0xaa, 0x31, 0x91, 0xf9};


	SHA256_CTX ctx;
	BYTE buffer[BLOCK_SIZE];

	sha256_init(&ctx);
	sha256_update(&ctx, preimage1, strlen(preimage1));
	sha256_final(&ctx, buffer);
	int pass1 = !memcmp(digest1, buffer, BLOCK_SIZE);
    pretty_print(preimage1, buffer, digest1, pass1);


	sha256_init(&ctx);
	sha256_update(&ctx, preimage2, strlen(preimage2));
	sha256_final(&ctx, buffer);
	int pass2 = !memcmp(digest2, buffer, BLOCK_SIZE);
    pretty_print(preimage2, buffer, digest2, pass2);


	sha256_init(&ctx);
	sha256_update(&ctx, preimage3, strlen(preimage3));
	sha256_final(&ctx, buffer);
	int pass3 = !memcmp(digest3, buffer, BLOCK_SIZE);
    pretty_print(preimage3, buffer, digest3, pass3);
}


void digest_string() {
    // increase if desired
    BYTE input[8192];

    printf("input:            ");

    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = '\0';

    BYTE bytes[strlen(input)];

    for (int i = 0; i < strlen(input); i++)
        bytes[i] = input[i];

    SHA256_CTX ctx;
	BYTE buffer[BLOCK_SIZE];

	sha256_init(&ctx);
	sha256_update(&ctx, bytes, strlen(bytes));
	sha256_final(&ctx, buffer);

    printf("digest:           ");
    for (int i = 0; i < BLOCK_SIZE; i++)
        printf("%02x", buffer[i]);
    printf("\n\n\n");
}


int main() {

    printf("SHA-256 HASHING ALGORITHM\n\n");

    run_tests();

    while (1)
        digest_string();

	return 0;
}
