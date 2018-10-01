/*
  Copyright (c) 2016
  Author: Jeff Weisberg <jaw @ tcp4me.com>
  Created: 2016-Jan-07 00:18 (EST)
  Function: encrypted block device

*/

#include <conf.h>
#include <proc.h>
#include <gpio.h>
#include <pwm.h>
#include <ioctl.h>
#include <userint.h>
#include <crypto.h>

#include "board.h"
#include "dazzle.h"

#define TRACE
#include <trace.h>

//#define USE_INTENTLOG

#define SHA1LEN		20
#define MD5LEN		16
#define AESBLKLEN	16
#define AESKEYLEN	32	// AES-256
#define KEYLEN		32
#define CRIVLEN		16
#define CRMACLEN	16

#define PBKDF2ITER	10000
#define SECTRESERVED	16

/*
  on disk:
  1st sector - config
  2+3 sector - intent log
  ...

  16 sectors data
   1 sector  cmdata (iv+mac)
   *
*/

typedef u_char bool;

int cgd_ioctl(FILE*, int, void*);
int cgd_bread(FILE*, char*, int, offset_t);
int cgd_bwrite(FILE*, const char*, int, offset_t);
int cgd_stat(FILE *, struct stat*);

const struct io_fs cgd_fs = {
    .bread  = cgd_bread,
    .bwrite = cgd_bwrite,
    .stat   = cgd_stat,
    .ioctl  = cgd_ioctl,
};

// on disk data
struct CGDwire {
    u_long	magic;
    u_long	version;
    u_long	encalg;
    u_long	nsect;		// total sectors
    u_long	rsect;		// reserved sectors
    u_long      dsect;		// sectors for user data
    u_char	syssa[KEYLEN];	// per card random value for salt
    u_char	sysiv[KEYLEN];	// per card random value for iv
    u_char	sysac[KEYLEN];	// authenticator - hmac(CGDwire, authkey)

#define MAGIC		0x6A6375F5
#define VERSION		0x1
#define ALG_AESCGD	0x1
};

struct CGDconf {
    u_char	key1[KEYLEN];	// data encr
    u_char	key2[KEYLEN];	// hmac

};

// on disk crypto metadata
struct CGDcrd {
    u_char	iv[CRIVLEN];
    u_char	mac[CRMACLEN];
};

// on disk intent log
struct CGDilog {
    int		n;
    struct {
        u_long	block;
        u_char	iv[CRIVLEN];
        u_char	mac[CRMACLEN];
    } crd[];
};


struct CGDinfo {
    lock_t		lock;
    FILE 		file;
    FILE 		*fsd;
    const struct io_fs *sd_fs;

    offset_t		offset;
    bool		isconfig;
    bool		isformat;

    struct CGDwire	wcf;
    struct CGDconf	scf;

} cgdinfo;

static u_char buf1[512], buf2[512], ibuf[1024], dbuf[16 * 512], ivbuf[CRIVLEN], acbuf[CRMACLEN];


void
cgd_init(void){
    struct CGDinfo *ii = &cgdinfo;

    bzero(ii, sizeof(cgdinfo));
    finit( & ii->file );
    ii->file.d   = (void*)ii;
    ii->file.fs  = & cgd_fs;

    // open sd card
    ii->fsd = fopen( "dev:sd0", "r" );
    if( ! ii->fsd ){
        kprintf("cgd: cannot open dev:sd0\n");
        return;
    }
    ii->sd_fs = ii->fsd->fs;

    trace_init();
    crypto_rand_init();
    bootmsg("cgd at sd0\n");

    // mount
    devmount( & ii->file, "cgd" );

#if 0
    // for testing
    fmount( & ii->file, "cgd:", "fatfs" );
    bootmsg( "cgd mounted on cgd: type fatfs\n" );
#endif
}

int
cgd_isready(void){
    return cgdinfo.isconfig;
}

static void
cgd_effect_active(){
    set_blinky( BLINK_ACTIVE );
    play(volume, "a4a4c+4a3");
}

static void
cgd_effect_inactive(){
    set_blinky( BLINK_INACTIVE );
    play(volume, "a4c+4a4g3");
}


static void
cgd_make_keys(const char *pass){
    struct CGDinfo *ii = &cgdinfo;

    // salt1 = syssa || 1*
    // salt2 = syssa || 2*
    // key1  = pbkdf2( passphrase, salt1 )
    // key2  = pbkdf2( passphrase, salt2 )

    memcpy(buf2, ii->wcf.syssa, KEYLEN);
    memset(buf2 + KEYLEN, 0x01, KEYLEN);
    pbkdf2_hmacsha1( pass, buf2, 2*KEYLEN, ii->scf.key1, KEYLEN, PBKDF2ITER );

    memcpy(buf2, ii->wcf.syssa, KEYLEN);
    memset(buf2 + KEYLEN, 0x02, KEYLEN);
    pbkdf2_hmacsha1( pass, buf2, 2*KEYLEN, ii->scf.key2, KEYLEN, PBKDF2ITER );

}

// result in acbuf
static void
cgd_mac(u_char *d, u_long block){
    struct CGDinfo *ii = &cgdinfo;

    // hmac( blockno || ciphertext || per-block-iv || sysac, key2 )
    hmac_sha1_start( ii->scf.key2, KEYLEN );
    hash_add( &block, sizeof(block) );
    hash_add( d, 512 );
    hash_add( ivbuf, CRIVLEN );
    hash_add( ii->wcf.sysac, KEYLEN );
    hmac_finish( acbuf, CRMACLEN );
}

static void
cgd_new_iv(void){
    crypto_rand16( (u_long*)ivbuf );
}

static void
cgd_getkey(bool asktwice){
    struct CGDinfo *ii = &cgdinfo;
    short i;

    printf("SECRET KEY: ");
    bzero(buf1, sizeof(buf1));
    getpass((char *)buf1, sizeof(buf1)-1);

    if( asktwice ){
        printf(" AND AGAIN: ");
        bzero(buf2, sizeof(buf1));
        getpass((char *)buf2, sizeof(buf2)-1);

        // do they match?
        if( strcmp(buf1, buf2) ){
            printf("ERROR. key mismatch!\n");
            return;
        }
    }

    cgd_make_keys( buf1 );

    // overwrite plaintext secret
    bzero(buf1, sizeof(buf1));
}

DEFUN(cgdkey, "set crypto secret key")
DEFALIAS(cgdkey, key)
{
    struct CGDinfo *ii = &cgdinfo;

    crypto_addmix_entropy( &systime, sizeof(systime));

    // read wire conf - 1st disk sector
    bzero(buf1, 512);
    ii->sd_fs->bread( ii->fsd, buf1, 512, 0 );
    memcpy( & ii->wcf, buf1, sizeof(struct CGDwire) );

    if( ii->wcf.magic == MAGIC && ii->wcf.version == VERSION ){
        ii->offset   = ii->wcf.rsect * 512;
        ii->isformat = 1;
    }else{
        ii->isformat = 0;
    }

    ii->isconfig = 0;

    if( ! ii->isformat ){
        printf("card not formatted as cgd. 'cgdinit' to format card.\n");
        return 0;
    }

    if( argc == 2 )
        cgd_make_keys( argv[1] );
    else
        cgd_getkey(0);

    // validate the authenticator (sysac)
    hmac_sha1( & ii->wcf, sizeof(struct CGDwire) - KEYLEN, ii->scf.key2, KEYLEN, buf1, SHA1LEN );
    if( crypto_memcmp(buf1, ii->wcf.sysac, SHA1LEN) ){
        // invalid secret or corrupt disk
        printf("validation check failed.\n");
        bzero(buf1, 512);
        bzero(& ii->scf, sizeof(struct CGDconf));
        play(volume, "d4d4d4z3d4d4d4");
        return 0;
    }

    cgd_fsck();
    cgd_effect_active();

    ii->isconfig = 1;

    return 0;
}

DEFUN(cgdinit, "initialize crypto on new sd card")
DEFALIAS(cgdinit, init)
// -f  force
{
    struct CGDinfo *ii = &cgdinfo;
    struct stat s;
    short i, optf=0;

    crypto_addmix_entropy( &systime, sizeof(systime));

    ii->sd_fs->stat( ii->fsd, &s );

    if( argc > 1 && ! strncmp("-f", argv[1], 2) ) optf = 1;

    if( !optf ){
        // already formatted?
        bzero(buf1, 512);
        ii->sd_fs->bread( ii->fsd, buf1, 512, 0 );
        struct CGDwire *w = (struct CGDwire*)buf1;

        if( ii->isformat || w->magic == MAGIC ){
            printf("card already contains a valid format. -f to overwrite\nwill wipe all contents of card\n");
            return 0;
        }
    }

    u_long blocks = s.size >> 9;

    // build wire conf
    bzero( & ii->wcf, sizeof(struct CGDwire) );

    ii->wcf.magic   = MAGIC;
    ii->wcf.version = VERSION;
    ii->wcf.encalg  = ALG_AESCGD;
    ii->wcf.nsect   = blocks;
    ii->wcf.dsect   = ((blocks - SECTRESERVED) / 17) * 16;
    ii->wcf.rsect   = SECTRESERVED;
    ii->offset      = SECTRESERVED * 512;

    crypto_rand16( ii->wcf.syssa );
    crypto_rand16( ii->wcf.syssa + 16 );
    crypto_rand16( ii->wcf.sysiv );
    crypto_rand16( ii->wcf.sysiv + 16 );

    cgd_getkey(1);

    // calculate sysac: hmac( wirecf, key2 )
    hmac_sha1( & ii->wcf, sizeof(struct CGDwire) - KEYLEN, ii->scf.key2, KEYLEN, ii->wcf.sysac, SHA1LEN );

    // write to device
    bzero(buf1, 512);
    memcpy(buf1, & ii->wcf, sizeof(struct CGDwire) );
    ii->sd_fs->bwrite( ii->fsd, buf1, 512, 0 );

    // QQQ - zero metadata blocks
    // no,...so...slow....

    cgd_effect_active();
    ii->isformat = 1;
    ii->isconfig = 1;

    return 0;
}


void
cgd_unconfig(void){
    struct CGDinfo *ii = &cgdinfo;

    ii->isconfig = 0;
    ii->isformat = 0;
    bzero( & ii->scf, sizeof(struct CGDconf) );
    bzero( & ii->wcf, sizeof(struct CGDwire) );

    cgd_effect_inactive();
}

DEFUN(cgdclear, "unconfigure crypto keys")
DEFALIAS(cgdclear, rescind)
{
    cgd_unconfig();
    return 0;
}

// RSN - card removed irq - unconfigure
void
ext_irq(void){
    cgd_unconfig();
    // disengage usb/msc
}

/****************************************************************/

void
cgd_fsck(void){

    // replay intent log

}



/****************************************************************/

u_long
cgd_size_blocks(void){
    struct CGDinfo *ii = &cgdinfo;

    return ii->wcf.nsect;
}

int
cgd_stat(FILE *f, struct stat *s){
    struct CGDinfo *ii = f->d;

    int r = ii->sd_fs->stat( ii->fsd, s );
    s->size = (offset_t)ii->wcf.dsect << 9;
    return r;
}

int
cgd_ioctl(FILE*f, int s, void*d){}

/****************************************************************/

static int
cgd_decrypt_block(u_char *src, u_char *dst, u_long block, u_char *m){
    struct CGDinfo *ii = &cgdinfo;
    struct CGDcrd  *md = (struct CGDcrd*)m + (block & 0xF);

    // validate mac
    memcpy(ivbuf, md->iv, CRIVLEN);
    cgd_mac(src, block);

    if( crypto_memcmp(acbuf, md->mac, CRMACLEN) ){
        // mac mismatch
        // NB - init does not populate disk with valid macs
        // coerce into zeroed block
        // kprintf("mac !=\n");
        bzero(dst, 512);
        return 1;
    }

    // decrypt
    crypto_decrypt_start( CRYPTO_ALG_AES_CBC, ii->scf.key1, KEYLEN, md->iv, CRIVLEN, dst, 512 );
    crypto_add( src, 512 );
    crypto_final( );

    // undiffuse
    elephant_dec(dst);

    return 1;
}

static int
cgd_encrypt_block(u_char *src, u_char *dst, u_long block, u_char *m){
    struct CGDinfo *ii = &cgdinfo;
    struct CGDcrd  *md = (struct CGDcrd*)m + (block & 0xF);
    struct CGDilog *il = (struct CGDilog *)ibuf;

    // every write gets a new iv
    cgd_new_iv();

    // diffuse
    elephant_enc(src);

    // encrypt
    crypto_encrypt_start( CRYPTO_ALG_AES_CBC, ii->scf.key1, KEYLEN, ivbuf, CRIVLEN, dst, 512 );
    crypto_add( src, 512 );
    crypto_final( );

    // calc mac
    cgd_mac(dst, block);

    // update metadata
    memcpy(md->iv,  ivbuf, CRIVLEN);
    memcpy(md->mac, acbuf, CRMACLEN);

    // add to intent log
    short n = il->n ++;
    memcpy(il->crd[block & 0xF].iv,  ivbuf, CRIVLEN);
    memcpy(il->crd[block & 0xF].mac, acbuf, CRIVLEN);

    return 1;
}

// 16 data blocks followed by 1 metadata block

// data block is located here
static inline u_long
cgd_block_no(offset_t pos){
    u_long b = pos >> 9;
    return (b * 17) >> 4;
}

// mdata is in this block
static inline u_long
cgd_mblock_no(offset_t pos){
    u_long b = pos >> 9;
    return ((b>>4) + 1) * 17 - 1;
}

static int
read_error(int blk){
    kprintf("disk read error blk %d\n", blk);
    return -1;
}

int
cgd_bread(FILE*f, char*d, int len, offset_t pos){
    struct CGDinfo *ii = &cgdinfo;
    // struct CGDinfo *ii = f->d;
    int ret = len;
    utime_t t0 = get_hrtime();

    if( ! ii->isconfig ) return -1;

    trace_crumb2("cgd", "read", (int)pos, len);
    crypto_add_entropy(&pos, sizeof(pos));
    crypto_addmix_entropy( &t0, sizeof(t0));

    while( len > 0 ){
        // read largest possible contiguous chunk
        u_long   b = pos >> 9;
        offset_t p = cgd_block_no( pos );
        offset_t m = cgd_mblock_no( pos );
        int      l = len >> 9;
        int      x = 16 - (b & 0xF);	// this many in same cmdata block

        if( l > x ) l = x;
        int size   = l << 9;

        //kprintf("cgd read pos=%x p=%x, m=%x, b=%x i=%x l=%d\n", (int)pos, (int)p, (int)m, b, (int)ii->offset, l);

        // read data
        trace_crumb1("cgd", "rdda", size);
        int s = ii->sd_fs->bread( ii->fsd, dbuf, size, (p<<9) + ii->offset );
        if( s < 1 ) return read_error(p);

        // read cmdata
        trace_crumb1("cgd", "rdcm", (int)m);
        s = ii->sd_fs->bread( ii->fsd, buf1, 512, (m<<9) + ii->offset );
        if( s < 1 ) return read_error(m);

        // decrypt
        trace_crumb1("cgd", "dec", l);
        short i;
        for(i=0; i<l; i++){
            s = cgd_decrypt_block(dbuf + (i<<9), d + (i<<9), b+i, buf1);
            if( !s ) return -1;
        }

        pos += size;
        len -= size;
        d   += size;
    }

    trace_crumb1("cgd", "ret", ret);
    t0 = get_hrtime();
    crypto_add_entropy( &t0, sizeof(t0));
    return ret;
}

static int
write_error(int blk){
    kprintf("disk write error blk %d\n", blk);
    return -1;
}

int
cgd_bwrite(FILE*f, const char*d, int len, offset_t pos){
    struct CGDinfo *ii = &cgdinfo;
    // struct CGDinfo *ii = f->d;
    struct CGDilog *il = (struct CGDilog *)ibuf;
    utime_t t0 = get_hrtime();
    int ret = len;
    int s;

    if( ! ii->isconfig ) return -1;

    // kprintf("cgd write pos=%x, len=%d\n", (int)(pos>>9), len);

    trace_crumb2("cgd", "write", (int)pos, len);
    crypto_add_entropy(&pos, sizeof(pos));
    crypto_addmix_entropy( &t0, sizeof(t0));

    while( len > 0 ){
        // write largest possible contiguous chunk
        u_long   b = pos >> 9;
        offset_t p = cgd_block_no( pos );
        offset_t m = cgd_mblock_no( pos );
        int      l = len >> 9;
        int      x = 16 - (b & 0xF);	// this many in same cmdata block

        if( l > x ) l = x;
        int size   = l << 9;

        // kprintf("  cgd write p=%x, m=%x, b=%x, l=%d\n", (int)p, (int)m, b, l);

        il->n = 0;	// reset intent log

        trace_crumb1("cgd", "rdcm", (int)m);

        // read cmdata
        if( l == 16 )
            bzero(buf1, 512);
        else{
            s = ii->sd_fs->bread( ii->fsd, buf1, 512, (m<<9) + ii->offset );
            if( s < 1 ) return read_error(m);
        }

        trace_crumb1("cgd", "enc", l);

        // encrypt
        short i;
        for(i=0; i<l; i++)
            cgd_encrypt_block(d + (i<<9), dbuf + (i<<9), b+i, buf1);

#ifdef USE_INTENTLOG
        trace_crumb0("cgd", "wril");

        // write intent log
        s = ii->sd_fs->bwrite( ii->fsd, ibuf, 1024, 512 );
        if( s < 1 ) return write_error(1);
#endif

        // write data
        trace_crumb1("cgd", "wrda", size);
        s = ii->sd_fs->bwrite( ii->fsd, dbuf, size, (p<<9) + ii->offset );
        if( s < 1 ) return write_error(p);

        // write cmdata
        trace_crumb0("cgd", "wrcm");
        s = ii->sd_fs->bwrite( ii->fsd, buf1, 512, (m<<9) + ii->offset );
        if( s < 1 ) return write_error(m);

        pos += size;
        len -= size;
        d   += size;
    }

    trace_crumb1("cgd", "ret", ret);
    t0 = get_hrtime();
    crypto_add_entropy( &t0, sizeof(t0));
    return ret;
}

#ifdef KTESTING

DEFUN(cgdblock, "dump disk block")
{
    struct CGDinfo *ii = &cgdinfo;

    if( argc < 2 ) return -1;

    offset_t pos  = atoi(argv[1]) << 9;
    int s = ii->sd_fs->bread( ii->fsd, buf1, 512, pos );
    hexdump(buf1, 512);

    return 0;
}

DEFUN(cgddump, "dump cgd info")
{
    struct CGDinfo *ii = &cgdinfo;
    struct CGDwire *c = (struct CGDwire *)buf1;
    ii->sd_fs->bread( ii->fsd, buf1, 512, 0 );

    printf("magic  %X (%s)\n", c->magic, (c->magic == MAGIC) ? "ok" : "invalid" );
    printf("versn  %X\n", c->version);
    printf("algor  %X\n", c->encalg);
    printf("nsect  %d\n", c->nsect);
    printf("resvd  %d\n", c->rsect);
    printf("syssa  [%32,.8H]\n", c->syssa);
    printf("sysiv  [%32,.8H]\n", c->sysiv);
    printf("sysac  [%20,.8H]\n", c->sysac);

    return 0;
}


static u_char tbuf[512];

DEFUN(cgdtest, "test cgd")
{
    struct CGDinfo *ii = &cgdinfo;
    FILE *f = & ii->file;

    memset(tbuf, random() & 0xFF, 512);
    hexdump(tbuf, 16 );

#if 0
    cgd_encrypt_block(buf1, 32, buf2);

    hexdump(buf1, 16);
    hexdump(buf2, 32);

    printf("decrypt\n");
    cgd_decrypt_block(buf1, 32, buf2);
    hexdump(buf1, 16);
#endif
#if 1
    int blk = (argc > 1) ? atoi(argv[1]) : 0x32;
    
    // write + read back
    cgd_bwrite( f, tbuf, 512, blk<<9 );

    ii->sd_fs->bread( ii->fsd, tbuf, 512, cgd_block_no(blk)<<9 + ii->offset );
    printf("disk\n");
    hexdump( tbuf, 16 );

    ii->sd_fs->bread( ii->fsd, tbuf, 512, cgd_mblock_no(blk)<<9 + ii->offset );
    printf("mdisk\n");
    hexdump( tbuf, 16 );

    printf("decrypt\n");
    cgd_bread(  f, tbuf, 512, blk<<9 );
    hexdump( tbuf, 16 );
#endif



    return 0;
}

#endif
