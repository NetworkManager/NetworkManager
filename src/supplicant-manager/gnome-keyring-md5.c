/*
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 *
 * To compute the message digest of a chunk of bytes, declare an
 * GnomeKeyringMD5Context structure, pass it to gnome_keyring_md5_init, call
 * gnome_keyring_md5_update as needed on buffers full of bytes, and then call
 * gnome_keyring_md5_final, which will fill a supplied 32-byte array with the
 * digest in ascii form. 
 *
 */

#include "gnome-keyring-md5.h"
#include <string.h>

static void gnome_keyring_md5_transform (guint32                 buf[4],
					 guint32 const           in[16]);

void
gnome_keyring_md5_string (const char *string, unsigned char digest[16])
{
  struct GnomeKeyringMD5Context md5_context;
  
  gnome_keyring_md5_init (&md5_context);
  gnome_keyring_md5_update (&md5_context, (const unsigned char *)string, strlen (string));
  gnome_keyring_md5_final (digest, &md5_context);
}

#if G_BYTE_ORDER == G_LITTLE_ENDIAN
#define byteReverse(buf, len)	/* Nothing */
#else

/*
 * Note: this code is harmless on little-endian machines.
 */
static void
byteReverse(unsigned char *buf, unsigned longs)
{
    guint32 t;
    do {
	t = (guint32) ((unsigned) buf[3] << 8 | buf[2]) << 16 |
	    ((unsigned) buf[1] << 8 | buf[0]);
	*(guint32 *) buf = t;
	buf += 4;
    } while (--longs);
}

#endif

char *
gnome_keyring_md5_digest_to_ascii (unsigned char digest[16])
{
  static char hex_digits[] = "0123456789abcdef";
  char *res;
  int i;
  
  res = g_malloc (33);
  
  for (i = 0; i < 16; i++) {
    res[2*i] = hex_digits[digest[i] >> 4];
    res[2*i+1] = hex_digits[digest[i] & 0xf];
  }
  
  res[32] = 0;
  
  return res;
}


/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
void 
gnome_keyring_md5_init (struct GnomeKeyringMD5Context *ctx)
{
    ctx->buf[0] = 0x67452301;
    ctx->buf[1] = 0xefcdab89;
    ctx->buf[2] = 0x98badcfe;
    ctx->buf[3] = 0x10325476;

    ctx->bits[0] = 0;
    ctx->bits[1] = 0;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
void 
gnome_keyring_md5_update (struct GnomeKeyringMD5Context *ctx,
			  unsigned char const *buf,
			  unsigned len)
{
    guint32 t;

    /* Update bitcount */

    t = ctx->bits[0];
    if ((ctx->bits[0] = t + ((guint32) len << 3)) < t)
	ctx->bits[1]++;		/* Carry from low to high */
    ctx->bits[1] += len >> 29;

    t = (t >> 3) & 0x3f;	/* Bytes already in shsInfo->data */

    /* Handle any leading odd-sized chunks */

    if (t) {
	unsigned char *p = (unsigned char *) ctx->in + t;

	t = 64 - t;
	if (len < t) {
	    memcpy (p, buf, len);
	    return;
	}
	memcpy (p, buf, t);
	byteReverse (ctx->in, 16);
	gnome_keyring_md5_transform (ctx->buf, (guint32 *) ctx->in);
	buf += t;
	len -= t;
    }

    /* Process data in 64-byte chunks */

    while (len >= 64) {
	memcpy (ctx->in, buf, 64);
	byteReverse (ctx->in, 16);
	gnome_keyring_md5_transform (ctx->buf, (guint32 *) ctx->in);
	buf += 64;
	len -= 64;
    }

    /* Handle any remaining bytes of data. */

    memcpy(ctx->in, buf, len);
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern 
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
void 
gnome_keyring_md5_final (unsigned char digest[16], struct GnomeKeyringMD5Context *ctx)
{
    unsigned count;
    unsigned char *p;

    /* Compute number of bytes mod 64 */
    count = (ctx->bits[0] >> 3) & 0x3F;

    /* Set the first char of padding to 0x80.  This is safe since there is
       always at least one byte free */
    p = ctx->in + count;
    *p++ = 0x80;

    /* Bytes of padding needed to make 64 bytes */
    count = 64 - 1 - count;

    /* Pad out to 56 mod 64 */
    if (count < 8) {
	/* Two lots of padding:  Pad the first block to 64 bytes */
	memset (p, 0, count);
	byteReverse (ctx->in, 16);
	gnome_keyring_md5_transform (ctx->buf, (guint32 *) ctx->in);

	/* Now fill the next block with 56 bytes */
	memset(ctx->in, 0, 56);
    } else {
	/* Pad block to 56 bytes */
	memset(p, 0, count - 8);
    }
    byteReverse(ctx->in, 14);

    /* Append length in bits and transform */
    ((guint32 *) ctx->in)[14] = ctx->bits[0];
    ((guint32 *) ctx->in)[15] = ctx->bits[1];

    gnome_keyring_md5_transform (ctx->buf, (guint32 *) ctx->in);
    byteReverse ((unsigned char *) ctx->buf, 4);
    memcpy (digest, ctx->buf, 16);
    memset (ctx, 0, sizeof(ctx));	/* In case it's sensitive */
}


/* The four core functions - F1 is optimized somewhat */

#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1 (z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#define gnome_keyring_md5_step(f, w, x, y, z, data, s) \
	( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  GnomeKeyringMD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */
static void 
gnome_keyring_md5_transform (guint32 buf[4], guint32 const in[16])
{
    register guint32 a, b, c, d;

    a = buf[0];
    b = buf[1];
    c = buf[2];
    d = buf[3];

    gnome_keyring_md5_step(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
    gnome_keyring_md5_step(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
    gnome_keyring_md5_step(F1, c, d, a, b, in[2] + 0x242070db, 17);
    gnome_keyring_md5_step(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
    gnome_keyring_md5_step(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
    gnome_keyring_md5_step(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
    gnome_keyring_md5_step(F1, c, d, a, b, in[6] + 0xa8304613, 17);
    gnome_keyring_md5_step(F1, b, c, d, a, in[7] + 0xfd469501, 22);
    gnome_keyring_md5_step(F1, a, b, c, d, in[8] + 0x698098d8, 7);
    gnome_keyring_md5_step(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
    gnome_keyring_md5_step(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
    gnome_keyring_md5_step(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
    gnome_keyring_md5_step(F1, a, b, c, d, in[12] + 0x6b901122, 7);
    gnome_keyring_md5_step(F1, d, a, b, c, in[13] + 0xfd987193, 12);
    gnome_keyring_md5_step(F1, c, d, a, b, in[14] + 0xa679438e, 17);
    gnome_keyring_md5_step(F1, b, c, d, a, in[15] + 0x49b40821, 22);
		
    gnome_keyring_md5_step(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
    gnome_keyring_md5_step(F2, d, a, b, c, in[6] + 0xc040b340, 9);
    gnome_keyring_md5_step(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
    gnome_keyring_md5_step(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
    gnome_keyring_md5_step(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
    gnome_keyring_md5_step(F2, d, a, b, c, in[10] + 0x02441453, 9);
    gnome_keyring_md5_step(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
    gnome_keyring_md5_step(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
    gnome_keyring_md5_step(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
    gnome_keyring_md5_step(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
    gnome_keyring_md5_step(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
    gnome_keyring_md5_step(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
    gnome_keyring_md5_step(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
    gnome_keyring_md5_step(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
    gnome_keyring_md5_step(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
    gnome_keyring_md5_step(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);
		
    gnome_keyring_md5_step(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
    gnome_keyring_md5_step(F3, d, a, b, c, in[8] + 0x8771f681, 11);
    gnome_keyring_md5_step(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
    gnome_keyring_md5_step(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
    gnome_keyring_md5_step(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
    gnome_keyring_md5_step(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
    gnome_keyring_md5_step(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
    gnome_keyring_md5_step(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
    gnome_keyring_md5_step(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
    gnome_keyring_md5_step(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
    gnome_keyring_md5_step(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
    gnome_keyring_md5_step(F3, b, c, d, a, in[6] + 0x04881d05, 23);
    gnome_keyring_md5_step(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
    gnome_keyring_md5_step(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
    gnome_keyring_md5_step(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
    gnome_keyring_md5_step(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);
		
    gnome_keyring_md5_step(F4, a, b, c, d, in[0] + 0xf4292244, 6);
    gnome_keyring_md5_step(F4, d, a, b, c, in[7] + 0x432aff97, 10);
    gnome_keyring_md5_step(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
    gnome_keyring_md5_step(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
    gnome_keyring_md5_step(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
    gnome_keyring_md5_step(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
    gnome_keyring_md5_step(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
    gnome_keyring_md5_step(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
    gnome_keyring_md5_step(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
    gnome_keyring_md5_step(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
    gnome_keyring_md5_step(F4, c, d, a, b, in[6] + 0xa3014314, 15);
    gnome_keyring_md5_step(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
    gnome_keyring_md5_step(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
    gnome_keyring_md5_step(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
    gnome_keyring_md5_step(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
    gnome_keyring_md5_step(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

    buf[0] += a;
    buf[1] += b;
    buf[2] += c;
    buf[3] += d;
}

