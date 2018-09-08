/*
  Copyright (c) 2016
  Author: Jeff Weisberg <jaw @ tcp4me.com>
  Created: 2016-Jan-09 14:17 (EST)
  Function: crypto functions

*/

#include <conf.h>
#include <alloc.h>
#include <proc.h>
#include <gpio.h>
#include <pwm.h>
#include <ioctl.h>
#include <userint.h>
#include <crypto.h>

#define SHA1LEN		20
#define AESLEN		32

static u_long randbuf[8], randkey[8], randctr[8] ATTR_ALIGNED;

void
hmac_sha1(const u_char *src, int srclen, const u_char *key, int keylen, u_char *out, int outlen){

    hmac_sha1_start(key, keylen);
    hash_add(src, srclen);
    hmac_finish(out, outlen);
}


// IEEE Std 802.11-2007 H.4.2 Reference implementation
      /*
       * F(P, S, c, i) = U1 xor U2 xor ... Uc
       * U1 = PRF(P, S || Int(i))
       * U2 = PRF(P, U1)
       * Uc = PRF(P, Uc-1)
       */
void
pbkdf2_hmacsha1(const u_char *pass, const u_char *salt, int saltlen, u_char *out, int outlen, int iter){
    u_char digest1[SHA1LEN];
    int i, j;
    int count;

    u_char *digest = malloc( saltlen + 4 );
    short passlen = strlen(pass);
    short steps   = (outlen + SHA1LEN - 1) / SHA1LEN;	// ceil

    for(count=1; count<=steps; count++){
        short olen = (SHA1LEN > outlen) ? outlen : SHA1LEN;

        /* U1 = PRF(P, S || int(i)) */
        memcpy(digest, salt, saltlen);
        digest[saltlen]   = (unsigned char)((count>>24) & 0xff);
        digest[saltlen+1] = (unsigned char)((count>>16) & 0xff);
        digest[saltlen+2] = (unsigned char)((count>>8) & 0xff);
        digest[saltlen+3] = (unsigned char)(count & 0xff);

        hmac_sha1(digest, saltlen+4, pass, passlen, digest1, SHA1LEN);

        /* output = U1 */
        memcpy(out, digest1, olen);

        for (i=1; i<iter; i++) {

            /* Un = PRF(P, Un-1) */
            hmac_sha1(digest1, SHA1LEN, pass, passlen, digest, SHA1LEN);
            memcpy(digest1, digest, SHA1LEN);

            /* output = output xor Un */
            for (j=0; j<olen; j++) {
                out[j] ^= digest[j];
            }
        }

        out    += SHA1LEN;
        outlen -= SHA1LEN;
    }

    zfree(digest, saltlen + 4);
}

/****************************************************************/
// constant time memcmp
int
crypto_memcmp(u_long *a, u_long *b, int len){
    int r = 0;
    len >>= 2;

    for(;len; len--)
        r |= *a++ - *b++;
    return r;
}

/****************************************************************/
void
crypto_rand_init(void){
    int i;

    // seed from hardware rng
    for(i=0; i<8; i++){
        randbuf[i] ^= rng_get();
        randkey[i] ^= rng_get();
        randctr[i] ^= rng_get();
    }
}


// generate 16 random bytes
void
crypto_rand16(u_long *dst){

    // the hardware random number generator is almost certainly perfectly fine.
    // *almost* certainly.
    // debias + whiten

    // out = aes_ctr( hwrng )

    int i;
    for(i=0; i<4; i++){
        randbuf[i] = rng_get();
    }

    crypto_encrypt_start( CRYPTO_ALG_AES_CTR, randkey, AESLEN, randctr, AESLEN, randbuf, AESLEN );
    crypto_add( randbuf, AESLEN );
    crypto_final( );

    // incr counter
    int inc = 1;
    for(i=0; i<8; i++){
        randctr[i] += inc;
        if( randctr[i] != 0 ) inc = 0;
    }

    memcpy(dst, randbuf, 16);
}

void
crypto_add_entropy(u_long *src, int len){
    int i;

    // key = hash( key || input ) ^ randbuf
    hash_sha1_start();
    hash_add( randbuf, AESLEN );
    hash_add( src, len );
    hash_add( randkey, AESLEN );
    hash_finish( randkey, SHA1LEN );

    for(i=0; i<8; i++)
        randkey[i] ^= randbuf[i];

}

/****************************************************************/

#ifdef KTESTING

void
crypto_rand_dump(const char *msg){

    printf("%s:\n", msg);
    printf("R: [%32,.8H]\n", randbuf);
    printf("K: [%32,.8H]\n", randkey);
    printf("C: [%32,.8H]\n", randctr);
    printf("\n");
}

DEFUN(randtest, "random test")
{
    char buf[16];

    crypto_rand_init();
    crypto_rand_dump("init");

    crypto_rand16(buf);
    crypto_rand_dump("rand");

    crypto_rand16(buf);
    crypto_rand_dump("rand");

    crypto_rand16(buf);
    crypto_rand_dump("rand");

    crypto_add_entropy("drink ovaltine", 14);
    crypto_rand_dump("entropy");

    crypto_rand16(buf);
    crypto_rand_dump("rand");


    return 0;
}

DEFUN(pbkdftest, "pbkdf2 test")
{
    u_char buf[32];

    // test vectors from RFC 6070

    // 0c 60 c8 0f 96 1f 0e 71 f3 a9 b5 24 af 60 12 06 2f e0 37 a6
    pbkdf2_hmacsha1( "password", "salt", 4, buf, 20, 1 );
    hexdump(buf, 20);

    // ea 6c 01 4d c7 2d 6f 8c cd 1e d9 2a ce 1d 41 f0 d8 de 89 57
    pbkdf2_hmacsha1( "password", "salt", 4, buf, 20, 2 );
    hexdump(buf, 20);

    // 4b 00 79 01 b7 65 48 9a be ad 49 d9 26 f7 21 d0 65 a4 29 c1
    pbkdf2_hmacsha1( "password", "salt", 4, buf, 20, 4096 );
    hexdump(buf, 20);

    return 0;
}

#endif
