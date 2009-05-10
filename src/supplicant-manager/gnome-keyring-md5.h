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

#ifndef GNOME_KEYRING_MD5_H
#define GNOME_KEYRING_MD5_H

#include <glib.h>

struct GnomeKeyringMD5Context {
	guint32 buf[4];
	guint32 bits[2];
	unsigned char in[64];
};

char *gnome_keyring_md5_digest_to_ascii (unsigned char                  digest[16]);
void  gnome_keyring_md5_string          (const char                    *string,
					 unsigned char                  digest[16]);
void  gnome_keyring_md5_init            (struct GnomeKeyringMD5Context *ctx);
void  gnome_keyring_md5_update          (struct GnomeKeyringMD5Context *ctx,
					 unsigned char const           *buf,
					 unsigned                       len);
void  gnome_keyring_md5_final           (unsigned char                  digest[16],
					 struct GnomeKeyringMD5Context *ctx);

#endif /* GNOME_KEYRING_MD5_H */
