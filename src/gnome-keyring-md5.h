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
