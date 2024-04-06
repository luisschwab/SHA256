// implementing SHA-256 for kicks
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
// used openssl's code as a reference

#include <string.h>
#include "sha256.h"


#define w 32                                            // 32 bit word

#define ROTLEFT(x,n)  ( (x << n) | (x >> (w - n)) )     // Rotate Left, or Circular Left Shift
#define ROTRIGHT(x,n) ( (x >> n) | (x << (w - n)) )     // Rotate Right, or Circular Right Shift

#define SHR(x,n) ( x >> n )                             // Shift Right

#define CH(x,y,z)  ( (x & y) ^ (~x & z) )               // Choose: bit-to-bit, the value of x determines if the output is y or z (2:1 multiplexer)
#define MAJ(x,y,z) ( (x & y) ^ (x & z) ^ (y & z) )      // Majority: bit-to-bit, the output is the majority of x,y,z
                                                        // ie: 110 -> 1 \ 001 -> 0 \ 101 -> 1 \ 000 -> 0

#define EP0(x) ( ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22) )  // SIGMA0
#define EP1(x) ( ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25) )  // SIGMA1

#define SIG0(x) ( ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ SHR(x,3) )       // sigma0
#define SIG1(x) ( ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ SHR(x,10) )     // sigma1


// these values are the first 32 bits of the fractional parts of the 
// cube roots of the first 64 primes (these are 'nothing-up-my-sleeve' numbers)
static const WORD k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,    // 002,003,005,007,011,013,017,019
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,    // 023,029,031,037,041,043,047,053
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,    // 059,061,067,071,073,079,083,089
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,    // 097,101,103,107,109,113,127,131
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,    // 137,139,149,151,157,163,167,173
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,    // 179,181,191,193,197,199,211,223
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,    // 227,229,233,239,241,251,257,263
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,    // 269,271,277,281,283,293,307,311
};

// this function initializes a context for the hashing operation
// it stores H_i values during operations on all 512-bit blocks
void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;

    // here we set the initial hash values (also 'nothing-up-my-sleeve' numbers)
    // they correspond to the first 32 bits of the fractional parts of the square roots of the first 8 primes
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

// this function receives an 512-bit block and performs computation on it, modifying the context's state[]
void sha256_transform(SHA256_CTX *ctx, const BYTE data[]) {
    // working variables
    WORD a, b, c, d, e, f, g, h;

    // temp variables
    WORD t1, t2;

    // index variables
    WORD i, j;

    // ?
    WORD m[64];

    // ok, so according to the paper, each sha256_transform() has 64 rounds
    // from rounds 0 to 15, one operation is done; from rounds 15 to 63, another

    // 0 to 15
    for (i = 0, j = 0; i < 16; i++, j += 4) {
        // concatenate 4 8-bit BYTEs into a 32-bit word
        m[i] = (data[j] << 24) | (data[j+1] << 16) | (data[j+2] << 8) | (data[j+3]);
    }

    // 16 to 63
    for ( ; i < 64; i++) {
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    }

    // initialize the working variables with the hash values from ctx->state[i], ie current state
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    // now, we do some operations that I dont really understand
    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];

        t2 = EP0(a) + MAJ(a,b,c);

        // notice we are kind of shifting everything right, with some OPs in between
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // now add the working variables to the current state
    ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

// this will split data[] into 512-bit blocks and feed them to sha256_transform() 
void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len) {

    for (WORD i = 0; i < len; i++) {
        // ctx->data[] only holds 512 bits, it's overwritten on every block
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;

        // if it's an even 512 bits:
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);

            // increase input lenght
            ctx->bitlen += (8 * ctx->datalen);

            // reset block lenght
            ctx->datalen = 0;
        }
    }
}


/*
     message                  k zeroes             len(message) as long long
|----------------|1|----------------------------||---------------------------|

k = 448 - 1 - len(message)

*/

// this function will pad any remaining input and run it through sha256_transform(), then write the digest to hash[]
void sha256_final(SHA256_CTX *ctx, BYTE digest[]) {

    WORD i = ctx->datalen;

    if (ctx->datalen < 56) {        // 56 * 8 = 448 bits, leaves 64 bits for the message lenght value
        ctx->data[i++] = 0x80;      // 1000000

        while (i < 56) {
            ctx->data[i++] = 0x00;  // 00000000
        }

    } else {
        ctx->data[i++] = 0x80;

        while (i < 64) {
            ctx->data[i++] = 0x00;
        }

        sha256_transform(ctx, ctx->data);

        memset(ctx->data, 0, 56);    // empty the data array
    }


	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;

	sha256_transform(ctx, ctx->data);


    // reverse endianess (LE->BE)
    for (i = 0; i < 4; i++) {
        digest[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}
