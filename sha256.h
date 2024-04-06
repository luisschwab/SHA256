#ifndef SHA256_H
#define SHA256_H

#define BLOCK_SIZE 32          // 32 bytes

#include <stddef.h>


typedef unsigned char BYTE;    // 1 byte = 8 bits
typedef unsigned int  WORD;    // 1 word = 32 bits


typedef struct {
    BYTE data[64];              // 64 bytes * 8-bit byte = 512 bit block

    WORD datalen;

    unsigned long long bitlen;  // SHA256 has a max input value of 2^64

    WORD state[8];              // H_i values in the paper

} SHA256_CTX;


void sha256_init(SHA256_CTX *ctx);
void sha256_transform(SHA256_CTX *ctx, const BYTE data[]);
void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len);
void sha256_final(SHA256_CTX *ctx, BYTE digest[]);


#endif 