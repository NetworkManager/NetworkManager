/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2005 - 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-utils.h"

#include <stdlib.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <uuid/uuid.h>
#include <libintl.h>
#include <gmodule.h>
#include <sys/stat.h>
#include <net/if.h>
#include <linux/pkt_sched.h>

#if WITH_JSON_VALIDATION
#include "nm-json.h"
#endif

#include "nm-glib-aux/nm-enum-utils.h"
#include "nm-glib-aux/nm-time-utils.h"
#include "nm-glib-aux/nm-secret-utils.h"
#include "systemd/nm-sd-utils-shared.h"
#include "nm-libnm-core-intern/nm-common-macros.h"
#include "nm-utils-private.h"
#include "nm-setting-private.h"
#include "nm-crypto.h"
#include "nm-setting-bond.h"
#include "nm-setting-bridge.h"
#include "nm-setting-bridge-port.h"
#include "nm-setting-infiniband.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-team.h"
#include "nm-setting-vlan.h"
#include "nm-setting-wired.h"
#include "nm-setting-wireless.h"

/**
 * SECTION:nm-utils
 * @short_description: Utility functions
 *
 * A collection of utility functions for working with SSIDs, IP addresses, Wi-Fi
 * access points and devices, among other things.
 */

/*****************************************************************************/

struct _NMSockAddrEndpoint {
	const char *host;
	guint16 port;
	guint refcount;
	char endpoint[];
};

static gboolean
NM_IS_SOCK_ADDR_ENDPOINT (const NMSockAddrEndpoint *self)
{
	return self && self->refcount > 0;
}

static const char *
_parse_endpoint (char *str,
                 guint16 *out_port)
{
	char *s;
	const char *s_port;
	gint16 port;

	/* Like
	 * - https://git.zx2c4.com/WireGuard/tree/src/tools/config.c?id=5e99a6d43fe2351adf36c786f5ea2086a8fe7ab8#n192
	 * - https://github.com/systemd/systemd/blob/911649fdd43f3a9158b847947724a772a5a45c34/src/network/netdev/wireguard.c#L614
	 */

	g_strstrip (str);

	if (!str[0])
		return NULL;

	if (str[0] == '[') {
		str++;
		s = strchr (str, ']');
		if (!s)
			return NULL;
		if (s == str)
			return NULL;
		if (s[1] != ':')
			return NULL;
		if (!s[2])
			return NULL;
		*s = '\0';
		s_port = &s[2];
	} else {
		s = strrchr (str, ':');
		if (!s)
			return NULL;
		if (s == str)
			return NULL;
		if (!s[1])
			return NULL;
		*s = '\0';
		s_port = &s[1];
	}

	if (!NM_STRCHAR_ALL (s_port, ch, (ch >= '0' && ch <= '9')))
		return NULL;

	port = _nm_utils_ascii_str_to_int64 (s_port, 10, 1, G_MAXUINT16, 0);
	if (port == 0)
		return NULL;

	*out_port = port;
	return str;
}

/**
 * nm_sock_addr_endpoint_new:
 * @endpoint: the endpoint string.
 *
 * This function cannot fail, even if the @endpoint is invalid.
 * The reason is to allow NMSockAddrEndpoint also to be used
 * for tracking invalid endpoints. Use nm_sock_addr_endpoint_get_host()
 * to determine whether the endpoint is valid.
 *
 * Returns: (transfer full): the new #NMSockAddrEndpoint endpoint.
 */
NMSockAddrEndpoint *
nm_sock_addr_endpoint_new (const char *endpoint)
{
	NMSockAddrEndpoint *ep;
	gsize l_endpoint;
	gsize l_host = 0;
	gsize i;
	gs_free char *host_clone = NULL;
	const char *host;
	guint16 port;

	g_return_val_if_fail (endpoint, NULL);

	l_endpoint = strlen (endpoint) + 1;

	host = _parse_endpoint (nm_strndup_a (200, endpoint, l_endpoint - 1, &host_clone),
	                        &port);

	if (host)
		l_host = strlen (host) + 1;

	ep = g_malloc (sizeof (NMSockAddrEndpoint) + l_endpoint + l_host);
	ep->refcount = 1;
	memcpy (ep->endpoint, endpoint, l_endpoint);
	if (host) {
		i = l_endpoint;
		memcpy (&ep->endpoint[i], host, l_host);
		ep->host = &ep->endpoint[i];
		ep->port = port;
	} else {
		ep->host = NULL;
		ep->port = 0;
	}
	return ep;
}

/**
 * nm_sock_addr_endpoint_ref:
 * @self: (allow-none): the #NMSockAddrEndpoint
 */
NMSockAddrEndpoint *
nm_sock_addr_endpoint_ref (NMSockAddrEndpoint *self)
{
	if (!self)
		return NULL;

	g_return_val_if_fail (NM_IS_SOCK_ADDR_ENDPOINT (self), NULL);

	nm_assert (self->refcount < G_MAXUINT);

	self->refcount++;
	return self;
}

/**
 * nm_sock_addr_endpoint_unref:
 * @self: (allow-none): the #NMSockAddrEndpoint
 */
void
nm_sock_addr_endpoint_unref (NMSockAddrEndpoint *self)
{
	if (!self)
		return;

	g_return_if_fail (NM_IS_SOCK_ADDR_ENDPOINT (self));

	if (--self->refcount == 0)
		g_free (self);
}

/**
 * nm_sock_addr_endpoint_get_endpoint:
 * @self: the #NMSockAddrEndpoint
 *
 * Gives the endpoint string. Since #NMSockAddrEndpoint's only
 * information is the endpoint string, this can be used for comparing
 * to instances for equality and order them lexically.
 *
 * Returns: (transfer none): the endpoint.
 */
const char *
nm_sock_addr_endpoint_get_endpoint (NMSockAddrEndpoint *self)
{
	g_return_val_if_fail (NM_IS_SOCK_ADDR_ENDPOINT (self), NULL);

	return self->endpoint;
}

/**
 * nm_sock_addr_endpoint_get_host:
 * @self: the #NMSockAddrEndpoint
 *
 * Returns: (transfer none): the parsed host part of the endpoint.
 *   If the endpoint is invalid, %NULL will be returned.
 */
const char *
nm_sock_addr_endpoint_get_host (NMSockAddrEndpoint *self)
{
	g_return_val_if_fail (NM_IS_SOCK_ADDR_ENDPOINT (self), NULL);

	return self->host;
}

/**
 * nm_sock_addr_endpoint_get_port:
 * @self: the #NMSockAddrEndpoint
 *
 * Returns: the parsed port part of the endpoint (the service).
 *   If the endpoint is invalid, -1 will be returned.
 */
gint32
nm_sock_addr_endpoint_get_port (NMSockAddrEndpoint *self)
{
	g_return_val_if_fail (NM_IS_SOCK_ADDR_ENDPOINT (self), -1);

	return self->host ? (int) self->port : -1;
}

gboolean
nm_sock_addr_endpoint_get_fixed_sockaddr (NMSockAddrEndpoint *self,
                                          gpointer sockaddr)
{
	int addr_family;
	NMIPAddr addrbin;
	const char *s;
	guint scope_id = 0;

	g_return_val_if_fail (NM_IS_SOCK_ADDR_ENDPOINT (self), FALSE);
	g_return_val_if_fail (sockaddr, FALSE);

	if (!self->host)
		return FALSE;

	if (nm_utils_parse_inaddr_bin (AF_UNSPEC, self->host, &addr_family, &addrbin))
		goto good;

	/* See if there is an IPv6 scope-id...
	 *
	 * Note that it does not make sense to persist connection profiles to disk,
	 * that refenrence a scope-id (because the interface's ifindex changes on
	 * reboot). However, we also support runtime only changes like `nmcli device modify`
	 * where nothing is persisted to disk. At least in that case, passing a scope-id
	 * might be reasonable. So, parse that too. */
	s = strchr (self->host, '%');
	if (!s)
		return FALSE;

	if (   s[1] == '\0'
	    || !NM_STRCHAR_ALL (&s[1], ch, (ch >= '0' && ch <= '9')))
		return FALSE;

	scope_id = _nm_utils_ascii_str_to_int64 (&s[1], 10, 0, G_MAXINT32, G_MAXUINT);
	if (scope_id == G_MAXUINT && errno)
		return FALSE;

	{
		gs_free char *tmp_str = NULL;
		const char *host_part;

		host_part = nm_strndup_a (200, self->host, s - self->host, &tmp_str);
		if (nm_utils_parse_inaddr_bin (AF_INET6, host_part, &addr_family, &addrbin))
			goto good;
	}

	return FALSE;

good:
	switch (addr_family) {
	case AF_INET:
		*((struct sockaddr_in *) sockaddr) = (struct sockaddr_in) {
			.sin_family = AF_INET,
			.sin_addr   = addrbin.addr4_struct,
			.sin_port   = htons (self->port),
		};
		return TRUE;
	case AF_INET6:
		*((struct sockaddr_in6 *) sockaddr) = (struct sockaddr_in6) {
			.sin6_family   = AF_INET6,
			.sin6_addr     = addrbin.addr6,
			.sin6_port     = htons (self->port),
			.sin6_scope_id = scope_id,
			.sin6_flowinfo = 0,
		};
		return TRUE;
	}

	return FALSE;
}

/*****************************************************************************/

struct IsoLangToEncodings
{
	const char *lang;
	const char *const *encodings;
};

#define LANG_ENCODINGS(l, ...) { .lang = l, .encodings = NM_MAKE_STRV (__VA_ARGS__), }

/* 5-letter language codes */
static const struct IsoLangToEncodings isoLangEntries5[] =
{
	/* Simplified Chinese */
	LANG_ENCODINGS ("zh_cn",   "euc-cn", "gb2312", "gb18030"),         /* PRC */
	LANG_ENCODINGS ("zh_sg",   "euc-cn", "gb2312", "gb18030"),         /* Singapore */

	/* Traditional Chinese */
	LANG_ENCODINGS ("zh_tw",   "big5", "euc-tw"),                      /* Taiwan */
	LANG_ENCODINGS ("zh_hk",   "big5", "euc-tw", "big5-hkcs"),         /* Hong Kong */
	LANG_ENCODINGS ("zh_mo",   "big5", "euc-tw"),                      /* Macau */

	LANG_ENCODINGS (NULL, NULL)
};

/* 2-letter language codes; we don't care about the other 3 in this table */
static const struct IsoLangToEncodings isoLangEntries2[] =
{
	/* Japanese */
	LANG_ENCODINGS ("ja",      "euc-jp", "shift_jis", "iso-2022-jp"),

	/* Korean */
	LANG_ENCODINGS ("ko",      "euc-kr", "iso-2022-kr", "johab"),

	/* Thai */
	LANG_ENCODINGS ("th",      "iso-8859-11", "windows-874"),

	/* Central European */
	LANG_ENCODINGS ("hu",      "iso-8859-2", "windows-1250"),          /* Hungarian */
	LANG_ENCODINGS ("cs",      "iso-8859-2", "windows-1250"),          /* Czech */
	LANG_ENCODINGS ("hr",      "iso-8859-2", "windows-1250"),          /* Croatian */
	LANG_ENCODINGS ("pl",      "iso-8859-2", "windows-1250"),          /* Polish */
	LANG_ENCODINGS ("ro",      "iso-8859-2", "windows-1250"),          /* Romanian */
	LANG_ENCODINGS ("sk",      "iso-8859-2", "windows-1250"),          /* Slovakian */
	LANG_ENCODINGS ("sl",      "iso-8859-2", "windows-1250"),          /* Slovenian */
	LANG_ENCODINGS ("sh",      "iso-8859-2", "windows-1250"),          /* Serbo-Croatian */

	/* Cyrillic */
	LANG_ENCODINGS ("ru",      "koi8-r", "windows-1251","iso-8859-5"), /* Russian */
	LANG_ENCODINGS ("be",      "koi8-r", "windows-1251","iso-8859-5"), /* Belorussian */
	LANG_ENCODINGS ("bg",      "windows-1251","koi8-r", "iso-8859-5"), /* Bulgarian */
	LANG_ENCODINGS ("mk",      "koi8-r", "windows-1251", "iso-8859-5"),/* Macedonian */
	LANG_ENCODINGS ("sr",      "koi8-r", "windows-1251", "iso-8859-5"),/* Serbian */
	LANG_ENCODINGS ("uk",      "koi8-u", "koi8-r", "windows-1251"),    /* Ukrainian */

	/* Arabic */
	LANG_ENCODINGS ("ar",      "iso-8859-6","windows-1256"),

	/* Baltic */
	LANG_ENCODINGS ("et",      "iso-8859-4", "windows-1257"),          /* Estonian */
	LANG_ENCODINGS ("lt",      "iso-8859-4", "windows-1257"),          /* Lithuanian */
	LANG_ENCODINGS ("lv",      "iso-8859-4", "windows-1257"),          /* Latvian */

	/* Greek */
	LANG_ENCODINGS ("el",      "iso-8859-7","windows-1253"),

	/* Hebrew */
	LANG_ENCODINGS ("he",      "iso-8859-8", "windows-1255"),
	LANG_ENCODINGS ("iw",      "iso-8859-8", "windows-1255"),

	/* Turkish */
	LANG_ENCODINGS ("tr",      "iso-8859-9", "windows-1254"),

	/* Table end */
	LANG_ENCODINGS (NULL, NULL)
};

static GHashTable * langToEncodings5 = NULL;
static GHashTable * langToEncodings2 = NULL;

static void
init_lang_to_encodings_hash (void)
{
	struct IsoLangToEncodings *enc;

	if (G_UNLIKELY (langToEncodings5 == NULL)) {
		/* Five-letter codes */
		enc = (struct IsoLangToEncodings *) &isoLangEntries5[0];
		langToEncodings5 = g_hash_table_new (nm_str_hash, g_str_equal);
		while (enc->lang) {
			g_hash_table_insert (langToEncodings5, (gpointer) enc->lang,
			                     (gpointer) enc->encodings);
			enc++;
		}
	}

	if (G_UNLIKELY (langToEncodings2 == NULL)) {
		/* Two-letter codes */
		enc = (struct IsoLangToEncodings *) &isoLangEntries2[0];
		langToEncodings2 = g_hash_table_new (nm_str_hash, g_str_equal);
		while (enc->lang) {
			g_hash_table_insert (langToEncodings2, (gpointer) enc->lang,
			                     (gpointer) enc->encodings);
			enc++;
		}
	}
}

static gboolean
get_encodings_for_lang (const char *lang, const char *const **encodings)
{
	gs_free char *tmp_lang = NULL;

	g_return_val_if_fail (lang, FALSE);
	g_return_val_if_fail (encodings, FALSE);

	init_lang_to_encodings_hash ();

	if ((*encodings = g_hash_table_lookup (langToEncodings5, lang)))
		return TRUE;

	/* Truncate tmp_lang to length of 2 */
	if (strlen (lang) > 2) {
		tmp_lang = g_strdup (lang);
		tmp_lang[2] = '\0';
		if ((*encodings = g_hash_table_lookup (langToEncodings2, tmp_lang)))
			return TRUE;
	}

	return FALSE;
}

static const char *const *
get_system_encodings (void)
{
	static const char *const *cached_encodings;
	static char *default_encodings[4];
	const char *const *encodings = NULL;
	char *lang;

	if (cached_encodings)
		return cached_encodings;

	/* Use environment variables as encoding hint */
	lang = getenv ("LC_ALL");
	if (!lang)
		lang = getenv ("LC_CTYPE");
	if (!lang)
		lang = getenv ("LANG");
	if (lang) {
		char *dot;

		lang = g_ascii_strdown (lang, -1);
		if ((dot = strchr (lang, '.')))
			*dot = '\0';

		get_encodings_for_lang (lang, &encodings);
		g_free (lang);
	}
	if (!encodings) {
		g_get_charset ((const char **) &default_encodings[0]);
		default_encodings[1] = "iso-8859-1";
		default_encodings[2] = "windows-1251";
		default_encodings[3] = NULL;
		encodings = (const char *const *) default_encodings;
	}

	cached_encodings = encodings;
	return cached_encodings;
}

/*****************************************************************************/

static void __attribute__((constructor))
_nm_utils_init (void)
{
	static int initialized = 0;

	if (g_atomic_int_get (&initialized) != 0)
		return;

	/* we don't expect this code to run multiple times, nor on multiple threads.
	 *
	 * In practice, it would not be a problem if two threads concurrently try to
	 * run the initialization code below, all code below itself is thread-safe,
	 * Hence, a poor-man guard "initialized" above is more than sufficient,
	 * although it does not guarantee that the code is not run concurrently. */

	bindtextdomain (GETTEXT_PACKAGE, NMLOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");

	_nm_dbus_errors_init ();

	g_atomic_int_set (&initialized, 1);
}

/*****************************************************************************/

gboolean _nm_utils_is_manager_process;

/* ssid helpers */

/**
 * nm_utils_ssid_to_utf8:
 * @ssid: (array length=len): pointer to a buffer containing the SSID data
 * @len: length of the SSID data in @ssid
 *
 * Wi-Fi SSIDs are byte arrays, they are _not_ strings.  Thus, an SSID may
 * contain embedded NULLs and other unprintable characters.  Often it is
 * useful to print the SSID out for debugging purposes, but that should be the
 * _only_ use of this function.  Do not use this function for any persistent
 * storage of the SSID, since the printable SSID returned from this function
 * cannot be converted back into the real SSID of the access point.
 *
 * This function does almost everything humanly possible to convert the input
 * into a printable UTF-8 string, using roughly the following procedure:
 *
 * 1) if the input data is already UTF-8 safe, no conversion is performed
 * 2) attempts to get the current system language from the LANG environment
 *    variable, and depending on the language, uses a table of alternative
 *    encodings to try.  For example, if LANG=hu_HU, the table may first try
 *    the ISO-8859-2 encoding, and if that fails, try the Windows-1250 encoding.
 *    If all fallback encodings fail, replaces non-UTF-8 characters with '?'.
 * 3) If the system language was unable to be determined, falls back to the
 *    ISO-8859-1 encoding, then to the Windows-1251 encoding.
 * 4) If step 3 fails, replaces non-UTF-8 characters with '?'.
 *
 * Again, this function should be used for debugging and display purposes
 * _only_.
 *
 * Returns: (transfer full): an allocated string containing a UTF-8
 * representation of the SSID, which must be freed by the caller using g_free().
 * Returns %NULL on errors.
 **/
char *
nm_utils_ssid_to_utf8 (const guint8 *ssid, gsize len)
{
	const char *const *encodings;
	const char *const *e;
	char *converted = NULL;

	g_return_val_if_fail (ssid != NULL, NULL);

	if (g_utf8_validate ((const char *) ssid, len, NULL))
		return g_strndup ((const char *) ssid, len);

	encodings = get_system_encodings ();

	for (e = encodings; *e; e++) {
		converted = g_convert ((const char *) ssid, len, "UTF-8", *e, NULL, NULL, NULL);
		if (converted)
			break;
	}

	if (!converted) {
		converted = g_convert_with_fallback ((const char *) ssid, len,
		                                     "UTF-8", encodings[0], "?", NULL, NULL, NULL);
	}

	if (!converted) {
		/* If there is still no converted string, the SSID probably
		 * contains characters not valid in the current locale. Convert
		 * the string to ASCII instead.
		 */

		/* Use the printable range of 0x20-0x7E */
		char *valid_chars = " !\"#$%&'()*+,-./0123456789:;<=>?@"
		                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
		                     "abcdefghijklmnopqrstuvwxyz{|}~";

		converted = g_strndup ((const char *) ssid, len);
		g_strcanon (converted, valid_chars, '?');
	}

	return converted;
}

char *
_nm_utils_ssid_to_utf8 (GBytes *ssid)
{
	const guint8 *p;
	gsize l;

	g_return_val_if_fail (ssid, NULL);

	p = g_bytes_get_data (ssid, &l);
	return nm_utils_ssid_to_utf8 (p, l);
}

/* Shamelessly ripped from the Linux kernel ieee80211 stack */
/**
 * nm_utils_is_empty_ssid:
 * @ssid: (array length=len): pointer to a buffer containing the SSID data
 * @len: length of the SSID data in @ssid
 *
 * Different manufacturers use different mechanisms for not broadcasting the
 * AP's SSID.  This function attempts to detect blank/empty SSIDs using a
 * number of known SSID-cloaking methods.
 *
 * Returns: %TRUE if the SSID is "empty", %FALSE if it is not
 **/
gboolean
nm_utils_is_empty_ssid (const guint8 *ssid, gsize len)
{
	/* Single white space is for Linksys APs */
	if (len == 1 && ssid[0] == ' ')
		return TRUE;

	/* Otherwise, if the entire ssid is 0, we assume it is hidden */
	while (len--) {
		if (ssid[len] != '\0')
			return FALSE;
	}
	return TRUE;
}

gboolean
_nm_utils_is_empty_ssid (GBytes *ssid)
{
	const guint8 *p;
	gsize l;

	g_return_val_if_fail (ssid, FALSE);

	p = g_bytes_get_data (ssid, &l);
	return nm_utils_is_empty_ssid (p, l);
}

#define ESSID_MAX_SIZE 32

/**
 * nm_utils_escape_ssid:
 * @ssid: (array length=len): pointer to a buffer containing the SSID data
 * @len: length of the SSID data in @ssid
 *
 * This function does a quick printable character conversion of the SSID, simply
 * replacing embedded NULLs and non-printable characters with the hexadecimal
 * representation of that character.  Intended for debugging only, should not
 * be used for display of SSIDs.
 *
 * Returns: pointer to the escaped SSID, which uses an internal static buffer
 * and will be overwritten by subsequent calls to this function
 **/
const char *
nm_utils_escape_ssid (const guint8 *ssid, gsize len)
{
	static char escaped[ESSID_MAX_SIZE * 2 + 1];
	const guint8 *s = ssid;
	char *d = escaped;

	if (nm_utils_is_empty_ssid (ssid, len)) {
		memcpy (escaped, "<hidden>", sizeof ("<hidden>"));
		return escaped;
	}

	len = MIN (len, (guint32) ESSID_MAX_SIZE);
	while (len--) {
		if (*s == '\0') {
			*d++ = '\\';
			*d++ = '0';
			s++;
		} else {
			*d++ = *s++;
		}
	}
	*d = '\0';
	return escaped;
}

char *
_nm_utils_ssid_to_string_arr (const guint8 *ssid, gsize len)
{
	gs_free char *s_copy = NULL;
	const char *s_cnst;

	if (len == 0)
		return g_strdup ("(empty)");

	s_cnst = nm_utils_buf_utf8safe_escape (ssid, len, NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL, &s_copy);
	nm_assert (s_cnst);

	if (nm_utils_is_empty_ssid (ssid, len))
		return g_strdup_printf ("\"%s\" (hidden)", s_cnst);

	return g_strdup_printf ("\"%s\"", s_cnst);
}

char *
_nm_utils_ssid_to_string (GBytes *ssid)
{
	gconstpointer p;
	gsize l;

	if (!ssid)
		return g_strdup ("(none)");

	p = g_bytes_get_data (ssid, &l);
	return _nm_utils_ssid_to_string_arr (p, l);
}

/**
 * nm_utils_same_ssid:
 * @ssid1: (array length=len1): the first SSID to compare
 * @len1: length of the SSID data in @ssid1
 * @ssid2: (array length=len2): the second SSID to compare
 * @len2: length of the SSID data in @ssid2
 * @ignore_trailing_null: %TRUE to ignore one trailing NULL byte
 *
 * Earlier versions of the Linux kernel added a NULL byte to the end of the
 * SSID to enable easy printing of the SSID on the console or in a terminal,
 * but this behavior was problematic (SSIDs are simply byte arrays, not strings)
 * and thus was changed.  This function compensates for that behavior at the
 * cost of some compatibility with odd SSIDs that may legitimately have trailing
 * NULLs, even though that is functionally pointless.
 *
 * Returns: %TRUE if the SSIDs are the same, %FALSE if they are not
 **/
gboolean
nm_utils_same_ssid (const guint8 *ssid1, gsize len1,
                    const guint8 *ssid2, gsize len2,
                    gboolean ignore_trailing_null)
{
	g_return_val_if_fail (ssid1 != NULL || len1 == 0, FALSE);
	g_return_val_if_fail (ssid2 != NULL || len2 == 0, FALSE);

	if (ssid1 == ssid2 && len1 == len2)
		return TRUE;
	if (!ssid1 || !ssid2)
		return FALSE;

	if (ignore_trailing_null) {
		if (len1 && ssid1[len1 - 1] == '\0')
			len1--;
		if (len2 && ssid2[len2 - 1] == '\0')
			len2--;
	}

	if (len1 != len2)
		return FALSE;

	return memcmp (ssid1, ssid2, len1) == 0 ? TRUE : FALSE;
}

gboolean
_nm_utils_string_slist_validate (GSList *list, const char **valid_values)
{
	GSList *iter;

	for (iter = list; iter; iter = iter->next) {
		if (!g_strv_contains (valid_values, (char *) iter->data))
			return FALSE;
	}

	return TRUE;
}

/**
 * _nm_utils_hash_values_to_slist:
 * @hash: a #GHashTable
 *
 * Utility function to iterate over a hash table and return
 * its values as a #GSList.
 *
 * Returns: (element-type gpointer) (transfer container): a newly allocated #GSList
 * containing the values of the hash table. The caller must free the
 * returned list with g_slist_free(). The hash values are not owned
 * by the returned list.
 **/
GSList *
_nm_utils_hash_values_to_slist (GHashTable *hash)
{
	GSList *list = NULL;
	GHashTableIter iter;
	void *value;

	g_return_val_if_fail (hash, NULL);

	g_hash_table_iter_init (&iter, hash);
	while (g_hash_table_iter_next (&iter, NULL, &value))
		 list = g_slist_prepend (list, value);

	return list;
}

GVariant *
_nm_utils_strdict_to_dbus (const GValue *prop_value)
{
	GHashTable *hash;
	GHashTableIter iter;
	const char *key, *value;
	GVariantBuilder builder;
	guint i, len;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{ss}"));

	hash = g_value_get_boxed (prop_value);
	if (!hash)
		goto out;
	len = g_hash_table_size (hash);
	if (!len)
		goto out;

	g_hash_table_iter_init (&iter, hash);
	if (!g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &value))
		nm_assert_not_reached ();

	if (len == 1)
		g_variant_builder_add (&builder, "{ss}", key, value);
	else {
		gs_free NMUtilsNamedValue *idx = NULL;

		idx = g_new (NMUtilsNamedValue, len);
		i = 0;
		do {
			idx[i].name = key;
			idx[i].value_str = value;
			i++;
		} while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &value));
		nm_assert (i == len);

		nm_utils_named_value_list_sort (idx, len, NULL, NULL);

		for (i = 0; i < len; i++)
			g_variant_builder_add (&builder, "{ss}", idx[i].name, idx[i].value_str);
	}

out:
	return g_variant_builder_end (&builder);
}

void
_nm_utils_strdict_from_dbus (GVariant *dbus_value,
                             GValue *prop_value)
{
	GVariantIter iter;
	const char *key, *value;
	GHashTable *hash;

	hash = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, g_free);
	g_variant_iter_init (&iter, dbus_value);
	while (g_variant_iter_next (&iter, "{&s&s}", &key, &value))
		g_hash_table_insert (hash, g_strdup (key), g_strdup (value));

	g_value_take_boxed (prop_value, hash);
}

GHashTable *
_nm_utils_copy_strdict (GHashTable *strdict)
{
	GHashTable *copy;
	GHashTableIter iter;
	gpointer key, value;

	copy = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, g_free);
	if (strdict) {
		g_hash_table_iter_init (&iter, strdict);
		while (g_hash_table_iter_next (&iter, &key, &value))
			g_hash_table_insert (copy, g_strdup (key), g_strdup (value));
	}
	return copy;
}

GPtrArray *
_nm_utils_copy_array (const GPtrArray *array,
                      NMUtilsCopyFunc copy_func,
                      GDestroyNotify free_func)
{
	GPtrArray *copy;
	int i;

	if (!array)
		return g_ptr_array_new_with_free_func (free_func);

	copy = g_ptr_array_new_full (array->len, free_func);
	for (i = 0; i < array->len; i++)
		g_ptr_array_add (copy, copy_func (array->pdata[i]));
	return copy;
}

GPtrArray *
_nm_utils_copy_object_array (const GPtrArray *array)
{
	return _nm_utils_copy_array (array, g_object_ref, g_object_unref);
}

gssize
_nm_utils_ptrarray_find_first (gconstpointer *list, gssize len, gconstpointer needle)
{
	gssize i;

	if (len == 0)
		return -1;

	if (len > 0) {
		g_return_val_if_fail (list, -1);
		for (i = 0; i < len; i++) {
			if (list[i] == needle)
				return i;
		}
	} else {
		g_return_val_if_fail (needle, -1);
		for (i = 0; list && list[i]; i++) {
			if (list[i] == needle)
				return i;
		}
	}
	return -1;
}

void
_nm_utils_bytes_from_dbus (GVariant *dbus_value,
                           GValue *prop_value)
{
	GBytes *bytes;

	if (g_variant_n_children (dbus_value)) {
		gconstpointer data;
		gsize length;

		data = g_variant_get_fixed_array (dbus_value, &length, 1);
		bytes = g_bytes_new (data, length);
	} else
		bytes = NULL;
	g_value_take_boxed (prop_value, bytes);
}

/*****************************************************************************/

GSList *
_nm_utils_strv_to_slist (char **strv, gboolean deep_copy)
{
	GSList *list = NULL;
	gsize i;

	if (!strv)
		return NULL;

	if (deep_copy) {
		for (i = 0; strv[i]; i++)
			list = g_slist_prepend (list, g_strdup (strv[i]));
	} else {
		for (i = 0; strv[i]; i++)
			list = g_slist_prepend (list, strv[i]);
	}
	return g_slist_reverse (list);
}

char **
_nm_utils_slist_to_strv (const GSList *slist, gboolean deep_copy)
{
	const GSList *iter;
	char **strv;
	guint len, i;

	if (!slist)
		return NULL;

	len = g_slist_length ((GSList *) slist);

	strv = g_new (char *, len + 1);

	if (deep_copy) {
		for (i = 0, iter = slist; iter; iter = iter->next, i++) {
			nm_assert (iter->data);
			strv[i] = g_strdup (iter->data);
		}
	} else {
		for (i = 0, iter = slist; iter; iter = iter->next, i++) {
			nm_assert (iter->data);
			strv[i] = iter->data;
		}
	}
	strv[i] = NULL;

	return strv;
}

GPtrArray *
_nm_utils_strv_to_ptrarray (char **strv)
{
	GPtrArray *ptrarray;
	gsize i, l;

	l = NM_PTRARRAY_LEN (strv);

	ptrarray = g_ptr_array_new_full (l, g_free);

	if (strv) {
		for (i = 0; strv[i]; i++)
			g_ptr_array_add (ptrarray, g_strdup (strv[i]));
	}

	return ptrarray;
}

char **
_nm_utils_ptrarray_to_strv (const GPtrArray *ptrarray)
{
	char **strv;
	guint i;

	if (!ptrarray)
		return g_new0 (char *, 1);

	strv = g_new (char *, ptrarray->len + 1);

	for (i = 0; i < ptrarray->len; i++)
		strv[i] = g_strdup (ptrarray->pdata[i]);
	strv[i] = NULL;

	return strv;
}

/*****************************************************************************/

static gboolean
device_supports_ap_ciphers (guint32 dev_caps,
                            guint32 ap_flags,
                            gboolean static_wep)
{
	gboolean have_pair = FALSE;
	gboolean have_group = FALSE;
	/* Device needs to support at least one pairwise and one group cipher */

	/* Pairwise */
	if (static_wep) {
		/* Static WEP only uses group ciphers */
		have_pair = TRUE;
	} else {
		if (dev_caps & NM_WIFI_DEVICE_CAP_CIPHER_WEP40)
			if (ap_flags & NM_802_11_AP_SEC_PAIR_WEP40)
				have_pair = TRUE;
		if (dev_caps & NM_WIFI_DEVICE_CAP_CIPHER_WEP104)
			if (ap_flags & NM_802_11_AP_SEC_PAIR_WEP104)
				have_pair = TRUE;
		if (dev_caps & NM_WIFI_DEVICE_CAP_CIPHER_TKIP)
			if (ap_flags & NM_802_11_AP_SEC_PAIR_TKIP)
				have_pair = TRUE;
		if (dev_caps & NM_WIFI_DEVICE_CAP_CIPHER_CCMP)
			if (ap_flags & NM_802_11_AP_SEC_PAIR_CCMP)
				have_pair = TRUE;
	}

	/* Group */
	if (dev_caps & NM_WIFI_DEVICE_CAP_CIPHER_WEP40)
		if (ap_flags & NM_802_11_AP_SEC_GROUP_WEP40)
			have_group = TRUE;
	if (dev_caps & NM_WIFI_DEVICE_CAP_CIPHER_WEP104)
		if (ap_flags & NM_802_11_AP_SEC_GROUP_WEP104)
			have_group = TRUE;
	if (!static_wep) {
		if (dev_caps & NM_WIFI_DEVICE_CAP_CIPHER_TKIP)
			if (ap_flags & NM_802_11_AP_SEC_GROUP_TKIP)
				have_group = TRUE;
		if (dev_caps & NM_WIFI_DEVICE_CAP_CIPHER_CCMP)
			if (ap_flags & NM_802_11_AP_SEC_GROUP_CCMP)
				have_group = TRUE;
	}

	return (have_pair && have_group);
}

/**
 * nm_utils_ap_mode_security_valid:
 * @type: the security type to check device capabilities against,
 * e.g. #NMU_SEC_STATIC_WEP
 * @wifi_caps: bitfield of the capabilities of the specific Wi-Fi device, e.g.
 * #NM_WIFI_DEVICE_CAP_CIPHER_WEP40
 *
 * Given a set of device capabilities, and a desired security type to check
 * against, determines whether the combination of device capabilities and
 * desired security type are valid for AP/Hotspot connections.
 *
 * Returns: %TRUE if the device capabilities are compatible with the desired
 * @type, %FALSE if they are not.
 **/
gboolean
nm_utils_ap_mode_security_valid (NMUtilsSecurityType type,
                                 NMDeviceWifiCapabilities wifi_caps)
{
	if (!(wifi_caps & NM_WIFI_DEVICE_CAP_AP))
		return FALSE;

	/* Return TRUE for any security that wpa_supplicant's lightweight AP
	 * mode can handle: which is open, WEP, and WPA/WPA2 PSK.
	 */
	switch (type) {
	case NMU_SEC_NONE:
	case NMU_SEC_STATIC_WEP:
	case NMU_SEC_WPA_PSK:
	case NMU_SEC_WPA2_PSK:
		return TRUE;
	default:
		break;
	}
	return FALSE;
}

/**
 * nm_utils_security_valid:
 * @type: the security type to check AP flags and device capabilities against,
 * e.g. #NMU_SEC_STATIC_WEP
 * @wifi_caps: bitfield of the capabilities of the specific Wi-Fi device, e.g.
 * #NM_WIFI_DEVICE_CAP_CIPHER_WEP40
 * @have_ap: whether the @ap_flags, @ap_wpa, and @ap_rsn arguments are valid
 * @adhoc: whether the capabilities being tested are from an Ad-Hoc AP (IBSS)
 * @ap_flags: bitfield of AP capabilities, e.g. #NM_802_11_AP_FLAGS_PRIVACY
 * @ap_wpa: bitfield of AP capabilities derived from the AP's WPA beacon,
 * e.g. (#NM_802_11_AP_SEC_PAIR_TKIP | #NM_802_11_AP_SEC_KEY_MGMT_PSK)
 * @ap_rsn: bitfield of AP capabilities derived from the AP's RSN/WPA2 beacon,
 * e.g. (#NM_802_11_AP_SEC_PAIR_CCMP | #NM_802_11_AP_SEC_PAIR_TKIP)
 *
 * Given a set of device capabilities, and a desired security type to check
 * against, determines whether the combination of device, desired security
 * type, and AP capabilities intersect.
 *
 * NOTE: this function cannot handle checking security for AP/Hotspot mode;
 * use nm_utils_ap_mode_security_valid() instead.
 *
 * Returns: %TRUE if the device capabilities and AP capabilities intersect and are
 * compatible with the desired @type, %FALSE if they are not
 **/
gboolean
nm_utils_security_valid (NMUtilsSecurityType type,
                         NMDeviceWifiCapabilities wifi_caps,
                         gboolean have_ap,
                         gboolean adhoc,
                         NM80211ApFlags ap_flags,
                         NM80211ApSecurityFlags ap_wpa,
                         NM80211ApSecurityFlags ap_rsn)
{
	gboolean good = TRUE;

	if (!have_ap) {
		if (type == NMU_SEC_NONE)
			return TRUE;
		if (   (type == NMU_SEC_STATIC_WEP)
		    || ((type == NMU_SEC_DYNAMIC_WEP) && !adhoc)
		    || ((type == NMU_SEC_LEAP) && !adhoc)) {
			if (wifi_caps & (NM_WIFI_DEVICE_CAP_CIPHER_WEP40 | NM_WIFI_DEVICE_CAP_CIPHER_WEP104))
				return TRUE;
			else
				return FALSE;
		}
	}

	switch (type) {
	case NMU_SEC_NONE:
		g_assert (have_ap);
		if (ap_flags & NM_802_11_AP_FLAGS_PRIVACY)
			return FALSE;
		if (ap_wpa || ap_rsn)
			return FALSE;
		break;
	case NMU_SEC_LEAP: /* require PRIVACY bit for LEAP? */
		if (adhoc)
			return FALSE;
		/* fall through */
	case NMU_SEC_STATIC_WEP:
		g_assert (have_ap);
		if (!(ap_flags & NM_802_11_AP_FLAGS_PRIVACY))
			return FALSE;
		if (ap_wpa || ap_rsn) {
			if (!device_supports_ap_ciphers (wifi_caps, ap_wpa, TRUE))
				if (!device_supports_ap_ciphers (wifi_caps, ap_rsn, TRUE))
					return FALSE;
		}
		break;
	case NMU_SEC_DYNAMIC_WEP:
		if (adhoc)
			return FALSE;
		g_assert (have_ap);
		if (ap_rsn || !(ap_flags & NM_802_11_AP_FLAGS_PRIVACY))
			return FALSE;
		/* Some APs broadcast minimal WPA-enabled beacons that must be handled */
		if (ap_wpa) {
			if (!(ap_wpa & NM_802_11_AP_SEC_KEY_MGMT_802_1X))
				return FALSE;
			if (!device_supports_ap_ciphers (wifi_caps, ap_wpa, FALSE))
				return FALSE;
		}
		break;
	case NMU_SEC_WPA_PSK:
		if (adhoc)
			return FALSE;  /* FIXME: Kernel WPA Ad-Hoc support is buggy */
		if (!(wifi_caps & NM_WIFI_DEVICE_CAP_WPA))
			return FALSE;
		if (have_ap) {
			/* Ad-Hoc WPA APs won't necessarily have the PSK flag set, and
			 * they don't have any pairwise ciphers. */
			if (adhoc) {
				/* coverity[dead_error_line] */
				if (   (ap_wpa & NM_802_11_AP_SEC_GROUP_TKIP)
				    && (wifi_caps & NM_WIFI_DEVICE_CAP_CIPHER_TKIP))
					return TRUE;
				if (   (ap_wpa & NM_802_11_AP_SEC_GROUP_CCMP)
				    && (wifi_caps & NM_WIFI_DEVICE_CAP_CIPHER_CCMP))
					return TRUE;
			} else {
				if (ap_wpa & NM_802_11_AP_SEC_KEY_MGMT_PSK) {
					if (   (ap_wpa & NM_802_11_AP_SEC_PAIR_TKIP)
					    && (wifi_caps & NM_WIFI_DEVICE_CAP_CIPHER_TKIP))
						return TRUE;
					if (   (ap_wpa & NM_802_11_AP_SEC_PAIR_CCMP)
					    && (wifi_caps & NM_WIFI_DEVICE_CAP_CIPHER_CCMP))
						return TRUE;
				}
			}
			return FALSE;
		}
		break;
	case NMU_SEC_WPA2_PSK:
		if (adhoc)
			return FALSE;  /* FIXME: Kernel WPA Ad-Hoc support is buggy */
		if (!(wifi_caps & NM_WIFI_DEVICE_CAP_RSN))
			return FALSE;
		if (have_ap) {
			/* Ad-Hoc WPA APs won't necessarily have the PSK flag set, and
			 * they don't have any pairwise ciphers, nor any RSA flags yet. */
			if (adhoc) {
				/* coverity[dead_error_line] */
				if (wifi_caps & NM_WIFI_DEVICE_CAP_CIPHER_TKIP)
					return TRUE;
				if (wifi_caps & NM_WIFI_DEVICE_CAP_CIPHER_CCMP)
					return TRUE;
			} else {
				if (ap_rsn & NM_802_11_AP_SEC_KEY_MGMT_PSK) {
					if (   (ap_rsn & NM_802_11_AP_SEC_PAIR_TKIP)
					    && (wifi_caps & NM_WIFI_DEVICE_CAP_CIPHER_TKIP))
						return TRUE;
					if (   (ap_rsn & NM_802_11_AP_SEC_PAIR_CCMP)
					    && (wifi_caps & NM_WIFI_DEVICE_CAP_CIPHER_CCMP))
						return TRUE;
				}
			}
			return FALSE;
		}
		break;
	case NMU_SEC_WPA_ENTERPRISE:
		if (adhoc)
			return FALSE;
		if (!(wifi_caps & NM_WIFI_DEVICE_CAP_WPA))
			return FALSE;
		if (have_ap) {
			if (!(ap_wpa & NM_802_11_AP_SEC_KEY_MGMT_802_1X))
				return FALSE;
			/* Ensure at least one WPA cipher is supported */
			if (!device_supports_ap_ciphers (wifi_caps, ap_wpa, FALSE))
				return FALSE;
		}
		break;
	case NMU_SEC_WPA2_ENTERPRISE:
		if (adhoc)
			return FALSE;
		if (!(wifi_caps & NM_WIFI_DEVICE_CAP_RSN))
			return FALSE;
		if (have_ap) {
			if (!(ap_rsn & NM_802_11_AP_SEC_KEY_MGMT_802_1X))
				return FALSE;
			/* Ensure at least one WPA cipher is supported */
			if (!device_supports_ap_ciphers (wifi_caps, ap_rsn, FALSE))
				return FALSE;
		}
		break;
	default:
		good = FALSE;
		break;
	}

	return good;
}

/**
 * nm_utils_wep_key_valid:
 * @key: a string that might be a WEP key
 * @wep_type: the #NMWepKeyType type of the WEP key
 *
 * Checks if @key is a valid WEP key
 *
 * Returns: %TRUE if @key is a WEP key, %FALSE if not
 */
gboolean
nm_utils_wep_key_valid (const char *key, NMWepKeyType wep_type)
{
	int keylen, i;

	if (!key)
		return FALSE;

	if (wep_type == NM_WEP_KEY_TYPE_UNKNOWN) {
		return nm_utils_wep_key_valid (key, NM_WEP_KEY_TYPE_KEY) ||
		       nm_utils_wep_key_valid (key, NM_WEP_KEY_TYPE_PASSPHRASE);
	}

	keylen = strlen (key);
	if (wep_type == NM_WEP_KEY_TYPE_KEY) {
		if (keylen == 10 || keylen == 26) {
			/* Hex key */
			for (i = 0; i < keylen; i++) {
				if (!g_ascii_isxdigit (key[i]))
					return FALSE;
			}
		} else if (keylen == 5 || keylen == 13) {
			/* ASCII key */
			for (i = 0; i < keylen; i++) {
				if (!g_ascii_isprint (key[i]))
					return FALSE;
			}
		} else
			return FALSE;
	} else if (wep_type == NM_WEP_KEY_TYPE_PASSPHRASE) {
		if (!keylen || keylen > 64)
			return FALSE;
	}

	return TRUE;
}

/**
 * nm_utils_wpa_psk_valid:
 * @psk: a string that might be a WPA PSK
 *
 * Checks if @psk is a valid WPA PSK
 *
 * Returns: %TRUE if @psk is a WPA PSK, %FALSE if not
 */
gboolean
nm_utils_wpa_psk_valid (const char *psk)
{
	int psklen, i;

	if (!psk)
		return FALSE;

	psklen = strlen (psk);
	if (psklen < 8 || psklen > 64)
		return FALSE;

	if (psklen == 64) {
		/* Hex PSK */
		for (i = 0; i < psklen; i++) {
			if (!g_ascii_isxdigit (psk[i]))
				return FALSE;
		}
	}

	return TRUE;
}

/**
 * nm_utils_ip4_dns_to_variant:
 * @dns: (type utf8): an array of IP address strings
 *
 * Utility function to convert an array of IP address strings int a #GVariant of
 * type 'au' representing an array of IPv4 addresses.
 *
 * Returns: (transfer none): a new floating #GVariant representing @dns.
 **/
GVariant *
nm_utils_ip4_dns_to_variant (char **dns)
{
	GVariantBuilder builder;
	int i;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("au"));

	if (dns) {
		for (i = 0; dns[i]; i++) {
			guint32 ip = 0;

			inet_pton (AF_INET, dns[i], &ip);
			g_variant_builder_add (&builder, "u", ip);
		}
	}

	return g_variant_builder_end (&builder);
}

/**
 * nm_utils_ip4_dns_from_variant:
 * @value: a #GVariant of type 'au'
 *
 * Utility function to convert a #GVariant of type 'au' representing a list of
 * IPv4 addresses into an array of IP address strings.
 *
 * Returns: (transfer full) (type utf8): a %NULL-terminated array of IP address strings.
 **/
char **
nm_utils_ip4_dns_from_variant (GVariant *value)
{
	const guint32 *array;
	gsize length;
	char **dns;
	int i;

	g_return_val_if_fail (g_variant_is_of_type (value, G_VARIANT_TYPE ("au")), NULL);

	array = g_variant_get_fixed_array (value, &length, sizeof (guint32));
	dns = g_new (char *, length + 1);

	for (i = 0; i < length; i++)
		dns[i] = nm_utils_inet4_ntop_dup (array[i]);
	dns[i] = NULL;

	return dns;
}

/**
 * nm_utils_ip4_addresses_to_variant:
 * @addresses: (element-type NMIPAddress): an array of #NMIPAddress objects
 * @gateway: (allow-none): the gateway IP address
 *
 * Utility function to convert a #GPtrArray of #NMIPAddress objects representing
 * IPv4 addresses into a #GVariant of type 'aau' representing an array of
 * NetworkManager IPv4 addresses (which are tuples of address, prefix, and
 * gateway). The "gateway" field of the first address will get the value of
 * @gateway (if non-%NULL). In all of the other addresses, that field will be 0.
 *
 * Returns: (transfer none): a new floating #GVariant representing @addresses.
 **/
GVariant *
nm_utils_ip4_addresses_to_variant (GPtrArray *addresses, const char *gateway)
{
	GVariantBuilder builder;
	int i;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aau"));

	if (addresses) {
		for (i = 0; i < addresses->len; i++) {
			NMIPAddress *addr = addresses->pdata[i];
			guint32 array[3];

			if (nm_ip_address_get_family (addr) != AF_INET)
				continue;

			nm_ip_address_get_address_binary (addr, &array[0]);
			array[1] = nm_ip_address_get_prefix (addr);
			if (i == 0 && gateway)
				inet_pton (AF_INET, gateway, &array[2]);
			else
				array[2] = 0;

			g_variant_builder_add (&builder, "@au",
			                       g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
			                                                  array, 3, sizeof (guint32)));
		}
	}

	return g_variant_builder_end (&builder);
}

/**
 * nm_utils_ip4_addresses_from_variant:
 * @value: a #GVariant of type 'aau'
 * @out_gateway: (out) (allow-none) (transfer full): on return, will contain the IP gateway
 *
 * Utility function to convert a #GVariant of type 'aau' representing a list of
 * NetworkManager IPv4 addresses (which are tuples of address, prefix, and
 * gateway) into a #GPtrArray of #NMIPAddress objects. The "gateway" field of
 * the first address (if set) will be returned in @out_gateway; the "gateway" fields
 * of the other addresses are ignored.
 *
 * Returns: (transfer full) (element-type NMIPAddress): a newly allocated
 *   #GPtrArray of #NMIPAddress objects
 **/
GPtrArray *
nm_utils_ip4_addresses_from_variant (GVariant *value, char **out_gateway)
{
	GPtrArray *addresses;
	GVariantIter iter;
	GVariant *addr_var;

	g_return_val_if_fail (g_variant_is_of_type (value, G_VARIANT_TYPE ("aau")), NULL);

	if (out_gateway)
		*out_gateway = NULL;

	g_variant_iter_init (&iter, value);
	addresses = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_address_unref);

	while (g_variant_iter_next (&iter, "@au", &addr_var)) {
		const guint32 *addr_array;
		gsize length;
		NMIPAddress *addr;
		GError *error = NULL;

		addr_array = g_variant_get_fixed_array (addr_var, &length, sizeof (guint32));
		if (length < 3) {
			g_warning ("Ignoring invalid IP4 address");
			g_variant_unref (addr_var);
			continue;
		}

		addr = nm_ip_address_new_binary (AF_INET, &addr_array[0], addr_array[1], &error);
		if (addr) {
			g_ptr_array_add (addresses, addr);

			if (addr_array[2] && out_gateway && !*out_gateway)
				*out_gateway = nm_utils_inet4_ntop_dup (addr_array[2]);
		} else {
			g_warning ("Ignoring invalid IP4 address: %s", error->message);
			g_clear_error (&error);
		}

		g_variant_unref (addr_var);
	}

	return addresses;
}

/**
 * nm_utils_ip4_routes_to_variant:
 * @routes: (element-type NMIPRoute): an array of #NMIP4Route objects
 *
 * Utility function to convert a #GPtrArray of #NMIPRoute objects representing
 * IPv4 routes into a #GVariant of type 'aau' representing an array of
 * NetworkManager IPv4 routes (which are tuples of route, prefix, next hop, and
 * metric).
 *
 * Returns: (transfer none): a new floating #GVariant representing @routes.
 **/
GVariant *
nm_utils_ip4_routes_to_variant (GPtrArray *routes)
{
	GVariantBuilder builder;
	int i;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aau"));

	if (routes) {
		for (i = 0; i < routes->len; i++) {
			NMIPRoute *route = routes->pdata[i];
			guint32 array[4];

			if (nm_ip_route_get_family (route) != AF_INET)
				continue;

			nm_ip_route_get_dest_binary (route, &array[0]);
			array[1] = nm_ip_route_get_prefix (route);
			nm_ip_route_get_next_hop_binary (route, &array[2]);
			/* The old routes format uses "0" for default, not "-1" */
			array[3] = MAX (0, nm_ip_route_get_metric (route));

			g_variant_builder_add (&builder, "@au",
			                       g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
			                                                  array, 4, sizeof (guint32)));
		}
	}

	return g_variant_builder_end (&builder);
}

/**
 * nm_utils_ip4_routes_from_variant:
 * @value: #GVariant of type 'aau'
 *
 * Utility function to convert a #GVariant of type 'aau' representing an array
 * of NetworkManager IPv4 routes (which are tuples of route, prefix, next hop,
 * and metric) into a #GPtrArray of #NMIPRoute objects.
 *
 * Returns: (transfer full) (element-type NMIPRoute): a newly allocated
 *   #GPtrArray of #NMIPRoute objects
 **/
GPtrArray *
nm_utils_ip4_routes_from_variant (GVariant *value)
{
	GVariantIter iter;
	GVariant *route_var;
	GPtrArray *routes;

	g_return_val_if_fail (g_variant_is_of_type (value, G_VARIANT_TYPE ("aau")), NULL);

	g_variant_iter_init (&iter, value);
	routes = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_route_unref);

	while (g_variant_iter_next (&iter, "@au", &route_var)) {
		const guint32 *route_array;
		gsize length;
		NMIPRoute *route;
		GError *error = NULL;

		route_array = g_variant_get_fixed_array (route_var, &length, sizeof (guint32));
		if (length < 4) {
			g_warning ("Ignoring invalid IP4 route");
			g_variant_unref (route_var);
			continue;
		}

		route = nm_ip_route_new_binary (AF_INET,
		                                &route_array[0],
		                                route_array[1],
		                                &route_array[2],
		                                /* The old routes format uses "0" for default, not "-1" */
		                                route_array[3] ? (gint64) route_array[3] : -1,
		                                &error);
		if (route)
			g_ptr_array_add (routes, route);
		else {
			g_warning ("Ignoring invalid IP4 route: %s", error->message);
			g_clear_error (&error);
		}
		g_variant_unref (route_var);
	}

	return routes;
}

/**
 * nm_utils_ip4_netmask_to_prefix:
 * @netmask: an IPv4 netmask in network byte order
 *
 * Returns: the CIDR prefix represented by the netmask
 **/
guint32
nm_utils_ip4_netmask_to_prefix (guint32 netmask)
{
	G_STATIC_ASSERT_EXPR (__SIZEOF_INT__   == 4);
	G_STATIC_ASSERT_EXPR (sizeof (int)     == 4);
	G_STATIC_ASSERT_EXPR (sizeof (netmask) == 4);

	return  (  (netmask != 0)
	         ? (32 - __builtin_ctz (ntohl (netmask)))
	         : 0);
}

/**
 * nm_utils_ip4_prefix_to_netmask:
 * @prefix: a CIDR prefix
 *
 * Returns: the netmask represented by the prefix, in network byte order
 **/
guint32
nm_utils_ip4_prefix_to_netmask (guint32 prefix)
{
	return _nm_utils_ip4_prefix_to_netmask (prefix);
}

/**
 * nm_utils_ip4_get_default_prefix:
 * @ip: an IPv4 address (in network byte order)
 *
 * When the Internet was originally set up, various ranges of IP addresses were
 * segmented into three network classes: A, B, and C.  This function will return
 * a prefix that is associated with the IP address specified defining where it
 * falls in the predefined classes.
 *
 * Returns: the default class prefix for the given IP
 **/
/* The function is originally from ipcalc.c of Red Hat's initscripts. */
guint32
nm_utils_ip4_get_default_prefix (guint32 ip)
{
	return _nm_utils_ip4_get_default_prefix (ip);
}

/**
 * nm_utils_ip6_dns_to_variant:
 * @dns: (type utf8): an array of IP address strings
 *
 * Utility function to convert an array of IP address strings int a #GVariant of
 * type 'aay' representing an array of IPv6 addresses.
 *
 * Returns: (transfer none): a new floating #GVariant representing @dns.
 **/
GVariant *
nm_utils_ip6_dns_to_variant (char **dns)
{
	GVariantBuilder builder;
	int i;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aay"));

	if (dns) {
		for (i = 0; dns[i]; i++) {
			struct in6_addr ip;

			inet_pton (AF_INET6, dns[i], &ip);
			g_variant_builder_add (&builder, "@ay",
			                       g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
			                                                  &ip, sizeof (ip), 1));
		}
	}

	return g_variant_builder_end (&builder);
}

/**
 * nm_utils_ip6_dns_from_variant:
 * @value: a #GVariant of type 'aay'
 *
 * Utility function to convert a #GVariant of type 'aay' representing a list of
 * IPv6 addresses into an array of IP address strings.
 *
 * Returns: (transfer full) (type utf8): a %NULL-terminated array of IP address strings.
 **/
char **
nm_utils_ip6_dns_from_variant (GVariant *value)
{
	GVariantIter iter;
	GVariant *ip_var;
	char **dns;
	int i;

	g_return_val_if_fail (g_variant_is_of_type (value, G_VARIANT_TYPE ("aay")), NULL);

	dns = g_new (char *, g_variant_n_children (value) + 1);

	g_variant_iter_init (&iter, value);
	i = 0;
	while (g_variant_iter_next (&iter, "@ay", &ip_var)) {
		gsize length;
		const struct in6_addr *ip = g_variant_get_fixed_array (ip_var, &length, 1);

		if (length != sizeof (struct in6_addr)) {
			g_warning ("%s: ignoring invalid IP6 address of length %d",
			           __func__, (int) length);
			g_variant_unref (ip_var);
			continue;
		}

		dns[i++] = nm_utils_inet6_ntop_dup (ip);
		g_variant_unref (ip_var);
	}
	dns[i] = NULL;

	return dns;
}

/**
 * nm_utils_ip6_addresses_to_variant:
 * @addresses: (element-type NMIPAddress): an array of #NMIPAddress objects
 * @gateway: (allow-none): the gateway IP address
 *
 * Utility function to convert a #GPtrArray of #NMIPAddress objects representing
 * IPv6 addresses into a #GVariant of type 'a(ayuay)' representing an array of
 * NetworkManager IPv6 addresses (which are tuples of address, prefix, and
 * gateway).  The "gateway" field of the first address will get the value of
 * @gateway (if non-%NULL). In all of the other addresses, that field will be
 * all 0s.
 *
 * Returns: (transfer none): a new floating #GVariant representing @addresses.
 **/
GVariant *
nm_utils_ip6_addresses_to_variant (GPtrArray *addresses, const char *gateway)
{
	GVariantBuilder builder;
	int i;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a(ayuay)"));

	if (addresses) {
		for (i = 0; i < addresses->len; i++) {
			NMIPAddress *addr = addresses->pdata[i];
			struct in6_addr ip_bytes, gateway_bytes;
			GVariant *ip_var, *gateway_var;
			guint32 prefix;

			if (nm_ip_address_get_family (addr) != AF_INET6)
				continue;

			nm_ip_address_get_address_binary (addr, &ip_bytes);
			ip_var = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, &ip_bytes, 16, 1);

			prefix = nm_ip_address_get_prefix (addr);

			if (i == 0 && gateway)
				inet_pton (AF_INET6, gateway, &gateway_bytes);
			else
				memset (&gateway_bytes, 0, sizeof (gateway_bytes));
			gateway_var = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, &gateway_bytes, 16, 1);

			g_variant_builder_add (&builder, "(@ayu@ay)", ip_var, prefix, gateway_var);
		}
	}

	return g_variant_builder_end (&builder);
}

/**
 * nm_utils_ip6_addresses_from_variant:
 * @value: a #GVariant of type 'a(ayuay)'
 * @out_gateway: (out) (allow-none) (transfer full): on return, will contain the IP gateway
 *
 * Utility function to convert a #GVariant of type 'a(ayuay)' representing a
 * list of NetworkManager IPv6 addresses (which are tuples of address, prefix,
 * and gateway) into a #GPtrArray of #NMIPAddress objects. The "gateway" field
 * of the first address (if set) will be returned in @out_gateway; the "gateway"
 * fields of the other addresses are ignored.
 *
 * Returns: (transfer full) (element-type NMIPAddress): a newly allocated
 *   #GPtrArray of #NMIPAddress objects
 **/
GPtrArray *
nm_utils_ip6_addresses_from_variant (GVariant *value, char **out_gateway)
{
	GVariantIter iter;
	GVariant *addr_var, *gateway_var;
	guint32 prefix;
	GPtrArray *addresses;

	g_return_val_if_fail (g_variant_is_of_type (value, G_VARIANT_TYPE ("a(ayuay)")), NULL);

	if (out_gateway)
		*out_gateway = NULL;

	g_variant_iter_init (&iter, value);
	addresses = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_address_unref);

	while (g_variant_iter_next (&iter, "(@ayu@ay)", &addr_var, &prefix, &gateway_var)) {
		NMIPAddress *addr;
		const struct in6_addr *addr_bytes, *gateway_bytes;
		gsize addr_len, gateway_len;
		GError *error = NULL;

		if (   !g_variant_is_of_type (addr_var, G_VARIANT_TYPE_BYTESTRING)
		    || !g_variant_is_of_type (gateway_var, G_VARIANT_TYPE_BYTESTRING)) {
			g_warning ("%s: ignoring invalid IP6 address structure", __func__);
			goto next;
		}

		addr_bytes = g_variant_get_fixed_array (addr_var, &addr_len, 1);
		if (addr_len != 16) {
			g_warning ("%s: ignoring invalid IP6 address of length %d",
			           __func__, (int) addr_len);
			goto next;
		}

		addr = nm_ip_address_new_binary (AF_INET6, addr_bytes, prefix, &error);
		if (addr) {
			g_ptr_array_add (addresses, addr);

			if (out_gateway && !*out_gateway) {
				gateway_bytes = g_variant_get_fixed_array (gateway_var, &gateway_len, 1);
				if (gateway_len != 16) {
					g_warning ("%s: ignoring invalid IP6 address of length %d",
					           __func__, (int) gateway_len);
					goto next;
				}
				if (!IN6_IS_ADDR_UNSPECIFIED (gateway_bytes))
					*out_gateway = nm_utils_inet6_ntop_dup (gateway_bytes);
			}
		} else {
			g_warning ("Ignoring invalid IP6 address: %s", error->message);
			g_clear_error (&error);
		}

	next:
		g_variant_unref (addr_var);
		g_variant_unref (gateway_var);
	}

	return addresses;
}

/**
 * nm_utils_ip6_routes_to_variant:
 * @routes: (element-type NMIPRoute): an array of #NMIPRoute objects
 *
 * Utility function to convert a #GPtrArray of #NMIPRoute objects representing
 * IPv6 routes into a #GVariant of type 'a(ayuayu)' representing an array of
 * NetworkManager IPv6 routes (which are tuples of route, prefix, next hop, and
 * metric).
 *
 * Returns: (transfer none): a new floating #GVariant representing @routes.
 **/
GVariant *
nm_utils_ip6_routes_to_variant (GPtrArray *routes)
{
	GVariantBuilder builder;
	int i;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a(ayuayu)"));

	if (routes) {
		for (i = 0; i < routes->len; i++) {
			NMIPRoute *route = routes->pdata[i];
			struct in6_addr dest_bytes, next_hop_bytes;
			GVariant *dest, *next_hop;
			guint32 prefix, metric;

			if (nm_ip_route_get_family (route) != AF_INET6)
				continue;

			nm_ip_route_get_dest_binary (route, &dest_bytes);
			dest = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, &dest_bytes, 16, 1);
			prefix = nm_ip_route_get_prefix (route);
			nm_ip_route_get_next_hop_binary (route, &next_hop_bytes);
			next_hop = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, &next_hop_bytes, 16, 1);
			/* The old routes format uses "0" for default, not "-1" */
			metric = MAX (0, nm_ip_route_get_metric (route));

			g_variant_builder_add (&builder, "(@ayu@ayu)", dest, prefix, next_hop, metric);
		}
	}

	return g_variant_builder_end (&builder);
}

/**
 * nm_utils_ip6_routes_from_variant:
 * @value: #GVariant of type 'a(ayuayu)'
 *
 * Utility function to convert a #GVariant of type 'a(ayuayu)' representing an
 * array of NetworkManager IPv6 routes (which are tuples of route, prefix, next
 * hop, and metric) into a #GPtrArray of #NMIPRoute objects.
 *
 * Returns: (transfer full) (element-type NMIPRoute): a newly allocated
 *   #GPtrArray of #NMIPRoute objects
 **/
GPtrArray *
nm_utils_ip6_routes_from_variant (GVariant *value)
{
	GPtrArray *routes;
	GVariantIter iter;
	GVariant *dest_var, *next_hop_var;
	const struct in6_addr *dest, *next_hop;
	gsize dest_len, next_hop_len;
	guint32 prefix, metric;

	g_return_val_if_fail (g_variant_is_of_type (value, G_VARIANT_TYPE ("a(ayuayu)")), NULL);

	routes = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_route_unref);

	g_variant_iter_init (&iter, value);
	while (g_variant_iter_next (&iter, "(@ayu@ayu)", &dest_var, &prefix, &next_hop_var, &metric)) {
		NMIPRoute *route;
		GError *error = NULL;

		if (   !g_variant_is_of_type (dest_var, G_VARIANT_TYPE_BYTESTRING)
		    || !g_variant_is_of_type (next_hop_var, G_VARIANT_TYPE_BYTESTRING)) {
			g_warning ("%s: ignoring invalid IP6 address structure", __func__);
			goto next;
		}

		dest = g_variant_get_fixed_array (dest_var, &dest_len, 1);
		if (dest_len != 16) {
			g_warning ("%s: ignoring invalid IP6 address of length %d",
			           __func__, (int) dest_len);
			goto next;
		}

		next_hop = g_variant_get_fixed_array (next_hop_var, &next_hop_len, 1);
		if (next_hop_len != 16) {
			g_warning ("%s: ignoring invalid IP6 address of length %d",
			           __func__, (int) next_hop_len);
			goto next;
		}

		route = nm_ip_route_new_binary (AF_INET6, dest, prefix, next_hop,
		                                metric ? (gint64) metric : -1,
		                                &error);
		if (route)
			g_ptr_array_add (routes, route);
		else {
			g_warning ("Ignoring invalid IP6 route: %s", error->message);
			g_clear_error (&error);
		}

	next:
		g_variant_unref (dest_var);
		g_variant_unref (next_hop_var);
	}

	return routes;
}

/**
 * nm_utils_ip_addresses_to_variant:
 * @addresses: (element-type NMIPAddress): an array of #NMIPAddress objects
 *
 * Utility function to convert a #GPtrArray of #NMIPAddress objects representing
 * IPv4 or IPv6 addresses into a #GVariant of type 'aa{sv}' representing an
 * array of new-style NetworkManager IP addresses. All addresses will include
 * "address" (an IP address string), and "prefix" (a uint). Some addresses may
 * include additional attributes.
 *
 * Returns: (transfer none): a new floating #GVariant representing @addresses.
 **/
GVariant *
nm_utils_ip_addresses_to_variant (GPtrArray *addresses)
{
	GVariantBuilder builder;
	guint i;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aa{sv}"));

	if (addresses) {
		for (i = 0; i < addresses->len; i++) {
			NMIPAddress *addr = addresses->pdata[i];
			GVariantBuilder addr_builder;
			gs_free const char **names = NULL;
			guint j, len;

			g_variant_builder_init (&addr_builder, G_VARIANT_TYPE ("a{sv}"));
			g_variant_builder_add (&addr_builder, "{sv}",
			                       "address",
			                       g_variant_new_string (nm_ip_address_get_address (addr)));
			g_variant_builder_add (&addr_builder, "{sv}",
			                       "prefix",
			                       g_variant_new_uint32 (nm_ip_address_get_prefix (addr)));

			names = _nm_ip_address_get_attribute_names (addr, TRUE, &len);
			for (j = 0; j < len; j++) {
				g_variant_builder_add (&addr_builder, "{sv}",
				                       names[j],
				                       nm_ip_address_get_attribute (addr, names[j]));
			}

			g_variant_builder_add (&builder, "a{sv}", &addr_builder);
		}
	}

	return g_variant_builder_end (&builder);
}

/**
 * nm_utils_ip_addresses_from_variant:
 * @value: a #GVariant of type 'aa{sv}'
 * @family: an IP address family
 *
 * Utility function to convert a #GVariant representing a list of new-style
 * NetworkManager IPv4 or IPv6 addresses (as described in the documentation for
 * nm_utils_ip_addresses_to_variant()) into a #GPtrArray of #NMIPAddress
 * objects.
 *
 * Returns: (transfer full) (element-type NMIPAddress): a newly allocated
 *   #GPtrArray of #NMIPAddress objects
 **/
GPtrArray *
nm_utils_ip_addresses_from_variant (GVariant *value,
                                    int family)
{
	GPtrArray *addresses;
	GVariantIter iter, attrs_iter;
	GVariant *addr_var;
	const char *ip;
	guint32 prefix;
	const char *attr_name;
	GVariant *attr_val;
	NMIPAddress *addr;
	GError *error = NULL;

	g_return_val_if_fail (g_variant_is_of_type (value, G_VARIANT_TYPE ("aa{sv}")), NULL);

	g_variant_iter_init (&iter, value);
	addresses = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_address_unref);

	while (g_variant_iter_next (&iter, "@a{sv}", &addr_var)) {
		if (   !g_variant_lookup (addr_var, "address", "&s", &ip)
		    || !g_variant_lookup (addr_var, "prefix", "u", &prefix)) {
			g_warning ("Ignoring invalid address");
			g_variant_unref (addr_var);
			continue;
		}

		addr = nm_ip_address_new (family, ip, prefix, &error);
		if (!addr) {
			g_warning ("Ignoring invalid address: %s", error->message);
			g_clear_error (&error);
			g_variant_unref (addr_var);
			continue;
		}

		g_variant_iter_init (&attrs_iter, addr_var);
		while (g_variant_iter_next (&attrs_iter, "{&sv}", &attr_name, &attr_val)) {
			if (   strcmp (attr_name, "address") != 0
			    && strcmp (attr_name, "prefix") != 0)
				nm_ip_address_set_attribute (addr, attr_name, attr_val);
			g_variant_unref (attr_val);
		}

		g_variant_unref (addr_var);
		g_ptr_array_add (addresses, addr);
	}

	return addresses;
}

/**
 * nm_utils_ip_routes_to_variant:
 * @routes: (element-type NMIPRoute): an array of #NMIPRoute objects
 *
 * Utility function to convert a #GPtrArray of #NMIPRoute objects representing
 * IPv4 or IPv6 routes into a #GVariant of type 'aa{sv}' representing an array
 * of new-style NetworkManager IP routes (which are tuples of destination,
 * prefix, next hop, metric, and additional attributes).
 *
 * Returns: (transfer none): a new floating #GVariant representing @routes.
 **/
GVariant *
nm_utils_ip_routes_to_variant (GPtrArray *routes)
{
	GVariantBuilder builder;
	int i;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aa{sv}"));

	if (routes) {
		for (i = 0; i < routes->len; i++) {
			NMIPRoute *route = routes->pdata[i];
			GVariantBuilder route_builder;
			gs_free const char **names = NULL;
			guint j, len;

			g_variant_builder_init (&route_builder, G_VARIANT_TYPE ("a{sv}"));
			g_variant_builder_add (&route_builder, "{sv}",
			                       "dest",
			                       g_variant_new_string (nm_ip_route_get_dest (route)));
			g_variant_builder_add (&route_builder, "{sv}",
			                       "prefix",
			                       g_variant_new_uint32 (nm_ip_route_get_prefix (route)));
			if (nm_ip_route_get_next_hop (route)) {
				g_variant_builder_add (&route_builder, "{sv}",
				                       "next-hop",
				                       g_variant_new_string (nm_ip_route_get_next_hop (route)));
			}
			if (nm_ip_route_get_metric (route) != -1) {
				g_variant_builder_add (&route_builder, "{sv}",
				                       "metric",
				                       g_variant_new_uint32 ((guint32) nm_ip_route_get_metric (route)));
			}

			names = _nm_ip_route_get_attribute_names (route, TRUE, &len);
			for (j = 0; j < len; j++) {
				g_variant_builder_add (&route_builder, "{sv}",
				                       names[j],
				                       nm_ip_route_get_attribute (route, names[j]));
			}

			g_variant_builder_add (&builder, "a{sv}", &route_builder);
		}
	}

	return g_variant_builder_end (&builder);
}

/**
 * nm_utils_ip_routes_from_variant:
 * @value: a #GVariant of type 'aa{sv}'
 * @family: an IP address family
 *
 * Utility function to convert a #GVariant representing a list of new-style
 * NetworkManager IPv4 or IPv6 addresses (which are tuples of destination,
 * prefix, next hop, metric, and additional attributes) into a #GPtrArray of
 * #NMIPRoute objects.
 *
 * Returns: (transfer full) (element-type NMIPRoute): a newly allocated
 *   #GPtrArray of #NMIPRoute objects
 **/
GPtrArray *
nm_utils_ip_routes_from_variant (GVariant *value,
                                 int family)
{
	GPtrArray *routes;
	GVariantIter iter, attrs_iter;
	GVariant *route_var;
	const char *dest, *next_hop;
	guint32 prefix, metric32;
	gint64 metric;
	const char *attr_name;
	GVariant *attr_val;
	NMIPRoute *route;
	GError *error = NULL;

	g_return_val_if_fail (g_variant_is_of_type (value, G_VARIANT_TYPE ("aa{sv}")), NULL);

	g_variant_iter_init (&iter, value);
	routes = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_route_unref);

	while (g_variant_iter_next (&iter, "@a{sv}", &route_var)) {
		if (   !g_variant_lookup (route_var, "dest", "&s", &dest)
		    || !g_variant_lookup (route_var, "prefix", "u", &prefix)) {
			g_warning ("Ignoring invalid address");
			goto next;
		}
		if (!g_variant_lookup (route_var, "next-hop", "&s", &next_hop))
			next_hop = NULL;
		if (g_variant_lookup (route_var, "metric", "u", &metric32))
			metric = metric32;
		else
			metric = -1;

		route = nm_ip_route_new (family, dest, prefix, next_hop, metric, &error);
		if (!route) {
			g_warning ("Ignoring invalid route: %s", error->message);
			g_clear_error (&error);
			goto next;
		}

		g_variant_iter_init (&attrs_iter, route_var);
		while (g_variant_iter_next (&attrs_iter, "{&sv}", &attr_name, &attr_val)) {
			if (   strcmp (attr_name, "dest") != 0
			    && strcmp (attr_name, "prefix") != 0
			    && strcmp (attr_name, "next-hop") != 0
			    && strcmp (attr_name, "metric") != 0)
				nm_ip_route_set_attribute (route, attr_name, attr_val);
			g_variant_unref (attr_val);
		}

		g_ptr_array_add (routes, route);
next:
		g_variant_unref (route_var);
	}

	return routes;
}

/*****************************************************************************/

static void
_string_append_tc_handle (GString *string, guint32 handle)
{
	g_string_append_printf (string, "%x:", TC_H_MAJ (handle) >> 16);
	if (TC_H_MIN (handle) != TC_H_UNSPEC)
		g_string_append_printf (string, "%x", TC_H_MIN (handle));
}

/**
 * _nm_utils_string_append_tc_parent:
 * @string: the string to write the parent handle to
 * @prefix: optional prefix for the numeric handle
 * @parent: the parent handle
 *
 * This is used to either write out the parent handle to the tc qdisc string
 * or to pretty-format (use symbolic name for root) the key in keyfile.
 * The presence of prefix determnines which one is the case.
 *
 * Private API due to general ugliness and overall uselessness for anything
 * sensible.
 */
void
_nm_utils_string_append_tc_parent (GString *string, const char *prefix, guint32 parent)
{
	if (parent == TC_H_ROOT) {
		g_string_append (string, "root");
	} else {
		if (prefix) {
			if (parent == TC_H_INGRESS)
				return;
			g_string_append_printf (string, "%s ", prefix);
		}
		_string_append_tc_handle (string, parent);
	}

	if (prefix)
		g_string_append_c (string, ' ');
}

/**
 * _nm_utils_parse_tc_handle:
 * @str: the string representation of a qdisc handle
 * @error: location of the error
 *
 * Parses tc style handle number into a numeric representation.
 * Don't use this, use nm_utils_tc_qdisc_from_str() instead.
 */
guint32
_nm_utils_parse_tc_handle (const char *str, GError **error)
{
	gint64 maj;
	gint64 min = 0;
	const char *sep;

	nm_assert (str);

	maj = g_ascii_strtoll (str, (char **) &sep, 0x10);
	if (sep == str)
		goto fail;

	sep = nm_str_skip_leading_spaces (sep);

	if (sep[0] == ':') {
		const char *str2 = &sep[1];

		min = g_ascii_strtoll (str2, (char **) &sep, 0x10);
		sep = nm_str_skip_leading_spaces (sep);
		if (sep[0] != '\0')
			goto fail;
	} else if (sep[0] != '\0')
		goto fail;

	if (   maj <= 0
	    || maj > 0xffff
	    || min < 0
	    || min > 0xffff
	    || !NM_STRCHAR_ALL (str, ch, (   g_ascii_isxdigit (ch)
	                                  || ch == ':'
	                                  || g_ascii_isspace (ch)))) {
		goto fail;
	}

	return TC_H_MAKE (((guint32) maj) << 16, (guint32) min);
fail:
	nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN, _("'%s' is not a valid handle."), str);
	return TC_H_UNSPEC;
}

static const NMVariantAttributeSpec *const tc_object_attribute_spec[] = {
	NM_VARIANT_ATTRIBUTE_SPEC_DEFINE ("root",   G_VARIANT_TYPE_BOOLEAN, .no_value = TRUE,                                         ),
	NM_VARIANT_ATTRIBUTE_SPEC_DEFINE ("parent", G_VARIANT_TYPE_STRING,                                           .str_type = 'a', ),
	NM_VARIANT_ATTRIBUTE_SPEC_DEFINE ("handle", G_VARIANT_TYPE_STRING,                                           .str_type = 'a', ),
	NM_VARIANT_ATTRIBUTE_SPEC_DEFINE ("kind",   G_VARIANT_TYPE_STRING,  .no_value = TRUE,                        .str_type = 'a', ),
	NM_VARIANT_ATTRIBUTE_SPEC_DEFINE ("",       G_VARIANT_TYPE_STRING,  .no_value = TRUE, .consumes_rest = TRUE, .str_type = 'a', ),
	NULL,
};

static const NMVariantAttributeSpec *const tc_qdisc_fq_codel_spec[] = {
	NM_VARIANT_ATTRIBUTE_SPEC_DEFINE ("limit",        G_VARIANT_TYPE_UINT32,                    ),
	NM_VARIANT_ATTRIBUTE_SPEC_DEFINE ("flows",        G_VARIANT_TYPE_UINT32,                    ),
	NM_VARIANT_ATTRIBUTE_SPEC_DEFINE ("target",       G_VARIANT_TYPE_UINT32,                    ),
	NM_VARIANT_ATTRIBUTE_SPEC_DEFINE ("interval",     G_VARIANT_TYPE_UINT32,                    ),
	NM_VARIANT_ATTRIBUTE_SPEC_DEFINE ("quantum",      G_VARIANT_TYPE_UINT32,                    ),

	/* 0x83126E97u is not a valid value (it means "disabled"). We should reject that
	 * value. Or alternatively, reject all values >= MAX_INT(32). */
	NM_VARIANT_ATTRIBUTE_SPEC_DEFINE ("ce_threshold", G_VARIANT_TYPE_UINT32,                    ),

	/* kernel clamps the value at 2^31. Possibly such values should be rejected from configuration
	 * as they cannot be configured. Leaving the attribute unspecified causes kernel to choose
	 * a default (currently 32MB). */
	NM_VARIANT_ATTRIBUTE_SPEC_DEFINE ("memory_limit", G_VARIANT_TYPE_UINT32,                    ),

	NM_VARIANT_ATTRIBUTE_SPEC_DEFINE ("ecn",          G_VARIANT_TYPE_BOOLEAN, .no_value = TRUE, ),
	NULL,
};

typedef struct {
	const char *kind;
	const NMVariantAttributeSpec *const *attrs;
} NMQdiscAttributeSpec;

static const NMQdiscAttributeSpec *const tc_qdisc_attribute_spec[] = {
	&(const NMQdiscAttributeSpec) { "fq_codel", tc_qdisc_fq_codel_spec },
	NULL,
};

/*****************************************************************************/

/**
 * _nm_utils_string_append_tc_qdisc_rest:
 * @string: the string to write the formatted qdisc to
 * @qdisc: the %NMTCQdisc
 *
 * This formats the rest of the qdisc string but the parent. Useful to format
 * the keyfile value and nowhere else.
 * Use nm_utils_tc_qdisc_to_str() that also includes the parent instead.
 */
void
_nm_utils_string_append_tc_qdisc_rest (GString *string, NMTCQdisc *qdisc)
{
	guint32 handle = nm_tc_qdisc_get_handle (qdisc);
	const char *kind = nm_tc_qdisc_get_kind (qdisc);
	gs_free char *str = NULL;

	if (handle != TC_H_UNSPEC && strcmp (kind, "ingress") != 0) {
		g_string_append (string, "handle ");
		_string_append_tc_handle (string, handle);
		g_string_append_c (string, ' ');
	}

	g_string_append (string, kind);

	str = nm_utils_format_variant_attributes (_nm_tc_qdisc_get_attributes (qdisc),
	                                          ' ', ' ');
	if (str) {
		g_string_append_c (string, ' ');
		g_string_append (string, str);
	}
}

/**
 * nm_utils_tc_qdisc_to_str:
 * @qdisc: the %NMTCQdisc
 * @error: location of the error
 *
 * Turns the %NMTCQdisc into a tc style string representation of the queueing
 * discipline.
 *
 * Returns: formatted string or %NULL
 *
 * Since: 1.12
 */
char *
nm_utils_tc_qdisc_to_str (NMTCQdisc *qdisc, GError **error)
{
	GString *string;

	string = g_string_sized_new (60);

	_nm_utils_string_append_tc_parent (string, "parent",
	                                   nm_tc_qdisc_get_parent (qdisc));
	_nm_utils_string_append_tc_qdisc_rest (string, qdisc);

	return g_string_free (string, FALSE);
}

static gboolean
_tc_read_common_opts (const char *str,
                      guint32 *handle,
                      guint32 *parent,
                      char **kind,
                      char **rest,
                      GError **error)
{
	gs_unref_hashtable GHashTable *ht = NULL;
	GVariant *variant;

	ht = nm_utils_parse_variant_attributes (str,
	                                        ' ', ' ', FALSE,
	                                        tc_object_attribute_spec,
	                                        error);
	if (!ht)
		return FALSE;

	if (g_hash_table_contains (ht, "root"))
		*parent = TC_H_ROOT;

	variant = g_hash_table_lookup (ht, "parent");
	if (variant) {
		if (*parent != TC_H_UNSPEC) {
			g_set_error (error, 1, 0,
			             _("'%s' unexpected: parent already specified."),
			             g_variant_get_string (variant, NULL));
			return FALSE;
		}
		*parent = _nm_utils_parse_tc_handle (g_variant_get_string (variant, NULL), error);
		if (*parent == TC_H_UNSPEC)
			return FALSE;
	}

	variant = g_hash_table_lookup (ht, "handle");
	if (variant) {
		*handle = _nm_utils_parse_tc_handle (g_variant_get_string (variant, NULL), error);
		if (*handle == TC_H_UNSPEC)
			return FALSE;
		if (TC_H_MIN (*handle)) {
			g_set_error (error, 1, 0,
			             _("invalid handle: '%s'"),
			             g_variant_get_string (variant, NULL));
			return FALSE;
		}
	}

	variant = g_hash_table_lookup (ht, "kind");
	if (variant) {
		*kind = g_variant_dup_string (variant, NULL);
		if (strcmp (*kind, "ingress") == 0) {
			if (*parent == TC_H_UNSPEC)
				*parent = TC_H_INGRESS;
			if (*handle == TC_H_UNSPEC)
				*handle = TC_H_MAKE (TC_H_INGRESS, 0);
		}
	}

	if (*parent == TC_H_UNSPEC) {
		if (*kind) {
			g_free (*kind);
			*kind = NULL;
		}
		g_set_error_literal (error, 1, 0, _("parent not specified."));
		return FALSE;
	}

	variant = g_hash_table_lookup (ht, "");
	if (variant)
		*rest = g_variant_dup_string (variant, NULL);

	return TRUE;
}

/**
 * nm_utils_tc_qdisc_from_str:
 * @str: the string representation of a qdisc
 * @error: location of the error
 *
 * Parses the tc style string qdisc representation of the queueing
 * discipline to a %NMTCQdisc instance. Supports a subset of the tc language.
 *
 * Returns: the %NMTCQdisc or %NULL
 *
 * Since: 1.12
 */
NMTCQdisc *
nm_utils_tc_qdisc_from_str (const char *str, GError **error)
{
	guint32 handle = TC_H_UNSPEC;
	guint32 parent = TC_H_UNSPEC;
	gs_free char *kind = NULL;
	gs_free char *rest = NULL;
	NMTCQdisc *qdisc = NULL;
	gs_unref_hashtable GHashTable *options = NULL;
	GHashTableIter iter;
	gpointer key, value;
	guint i;

	nm_assert (str);
	nm_assert (!error || !*error);

	if (!_tc_read_common_opts (str, &handle, &parent, &kind, &rest, error))
		return NULL;

	for (i = 0; rest && tc_qdisc_attribute_spec[i]; i++) {
		if (strcmp (tc_qdisc_attribute_spec[i]->kind, kind) == 0) {
			options = nm_utils_parse_variant_attributes (rest,
			                                             ' ', ' ', FALSE,
			                                             tc_qdisc_attribute_spec[i]->attrs,
			                                             error);
			if (!options)
				return NULL;
			break;
		}
	}
	nm_clear_pointer (&rest, g_free);

	if (options) {
		value = g_hash_table_lookup (options, "");
		if (value)
			rest = g_variant_dup_string (value, NULL);
	}

	if (rest) {
		g_set_error (error, 1, 0, _("unsupported qdisc option: '%s'."), rest);
		return NULL;
	}

	qdisc = nm_tc_qdisc_new (kind, parent, error);
	if (!qdisc)
		return NULL;

	nm_tc_qdisc_set_handle (qdisc, handle);

	if (options) {
		g_hash_table_iter_init (&iter, options);
		while (g_hash_table_iter_next (&iter, &key, &value))
			nm_tc_qdisc_set_attribute (qdisc, key, g_variant_ref_sink (value));
	}

	return qdisc;
}

/*****************************************************************************/

static const NMVariantAttributeSpec *const tc_action_simple_attribute_spec[] = {
	NM_VARIANT_ATTRIBUTE_SPEC_DEFINE ("sdata", G_VARIANT_TYPE_BYTESTRING, ),
	NULL,
};

static const NMVariantAttributeSpec *const tc_action_mirred_attribute_spec[] = {
	NM_VARIANT_ATTRIBUTE_SPEC_DEFINE ("egress",   G_VARIANT_TYPE_BOOLEAN, .no_value = TRUE,                  ),
	NM_VARIANT_ATTRIBUTE_SPEC_DEFINE ("ingress",  G_VARIANT_TYPE_BOOLEAN, .no_value = TRUE,                  ),
	NM_VARIANT_ATTRIBUTE_SPEC_DEFINE ("mirror",   G_VARIANT_TYPE_BOOLEAN, .no_value = TRUE,                  ),
	NM_VARIANT_ATTRIBUTE_SPEC_DEFINE ("redirect", G_VARIANT_TYPE_BOOLEAN, .no_value = TRUE,                  ),
	NM_VARIANT_ATTRIBUTE_SPEC_DEFINE ("dev",      G_VARIANT_TYPE_STRING,  .no_value = TRUE, .str_type = 'a', ),
	NULL,
};

static const NMVariantAttributeSpec *const tc_action_attribute_spec[] = {
	NM_VARIANT_ATTRIBUTE_SPEC_DEFINE ("kind",    G_VARIANT_TYPE_STRING, .no_value = TRUE,                        .str_type = 'a', ),
	NM_VARIANT_ATTRIBUTE_SPEC_DEFINE ("",        G_VARIANT_TYPE_STRING, .no_value = TRUE, .consumes_rest = TRUE, .str_type = 'a', ),
	NULL,
};

static gboolean
_string_append_tc_action (GString *string, NMTCAction *action, GError **error)
{
	const char *kind = nm_tc_action_get_kind (action);
	gs_free char *str = NULL;

	g_string_append (string, kind);

	str = nm_utils_format_variant_attributes (_nm_tc_action_get_attributes (action),
	                                          ' ', ' ');
	if (str) {
		g_string_append_c (string, ' ');
		g_string_append (string, str);
	}

	return TRUE;
}

/**
 * nm_utils_tc_action_to_str:
 * @action: the %NMTCAction
 * @error: location of the error
 *
 * Turns the %NMTCAction into a tc style string representation of the queueing
 * discipline.
 *
 * Returns: formatted string or %NULL
 *
 * Since: 1.12
 */
char *
nm_utils_tc_action_to_str (NMTCAction *action, GError **error)
{
	GString *string;

	string = g_string_sized_new (60);
	if (!_string_append_tc_action (string, action, error)) {
		g_string_free (string, TRUE);
		return NULL;
	}

	return g_string_free (string, FALSE);
}

/**
 * nm_utils_tc_action_from_str:
 * @str: the string representation of a action
 * @error: location of the error
 *
 * Parses the tc style string action representation of the queueing
 * discipline to a %NMTCAction instance. Supports a subset of the tc language.
 *
 * Returns: the %NMTCAction or %NULL
 *
 * Since: 1.12
 */
NMTCAction *
nm_utils_tc_action_from_str (const char *str, GError **error)
{
	const char *kind = NULL;
	const char *rest = NULL;
	NMTCAction *action = NULL;
	gs_unref_hashtable GHashTable *ht = NULL;
	gs_unref_hashtable GHashTable *options = NULL;
	GVariant *variant;
	const NMVariantAttributeSpec *const *attrs;

	nm_assert (str);
	nm_assert (!error || !*error);

	ht = nm_utils_parse_variant_attributes (str,
	                                        ' ', ' ', FALSE,
	                                        tc_action_attribute_spec,
	                                        error);
	if (!ht)
		return FALSE;

	variant = g_hash_table_lookup (ht, "kind");
	if (variant) {
		kind = g_variant_get_string (variant, NULL);
	} else {
		g_set_error_literal (error, 1, 0, _("action name missing."));
		return NULL;
	}

	kind = g_variant_get_string (variant, NULL);
	if (strcmp (kind, "simple") == 0)
		attrs = tc_action_simple_attribute_spec;
	else if (strcmp (kind, "mirred") == 0)
		attrs = tc_action_mirred_attribute_spec;
	else
		attrs = NULL;

	variant = g_hash_table_lookup (ht, "");
	if (variant)
		rest = g_variant_get_string (variant, NULL);

	action = nm_tc_action_new (kind, error);
	if (!action)
		return NULL;

	if (rest) {
		GHashTableIter iter;
		gpointer key, value;

		if (!attrs) {
			nm_tc_action_unref (action);
			g_set_error (error, 1, 0, _("unsupported action option: '%s'."), rest);
			return NULL;
		}

		options = nm_utils_parse_variant_attributes (rest,
		                                             ' ', ' ', FALSE,
		                                             attrs,
		                                             error);
		if (!options) {
			nm_tc_action_unref (action);
			return NULL;
		}

		g_hash_table_iter_init (&iter, options);
		while (g_hash_table_iter_next (&iter, &key, &value))
			nm_tc_action_set_attribute (action, key, g_variant_ref_sink (value));
	}

	return action;
}

/*****************************************************************************/

/**
 * _nm_utils_string_append_tc_tfilter_rest:
 * @string: the string to write the formatted tfilter to
 * @tfilter: the %NMTCTfilter
 *
 * This formats the rest of the tfilter string but the parent. Useful to format
 * the keyfile value and nowhere else.
 * Use nm_utils_tc_tfilter_to_str() that also includes the parent instead.
 */
gboolean
_nm_utils_string_append_tc_tfilter_rest (GString *string, NMTCTfilter *tfilter, GError **error)
{
	guint32 handle = nm_tc_tfilter_get_handle (tfilter);
	const char *kind = nm_tc_tfilter_get_kind (tfilter);
	NMTCAction *action;

	if (handle != TC_H_UNSPEC) {
		g_string_append (string, "handle ");
		_string_append_tc_handle (string, handle);
		g_string_append_c (string, ' ');
	}

	g_string_append (string, kind);

	action = nm_tc_tfilter_get_action (tfilter);
	if (action) {
		g_string_append (string, " action ");
		if (!_string_append_tc_action (string, action, error))
			return FALSE;
	}

	return TRUE;
}

/**
 * nm_utils_tc_tfilter_to_str:
 * @tfilter: the %NMTCTfilter
 * @error: location of the error
 *
 * Turns the %NMTCTfilter into a tc style string representation of the queueing
 * discipline.
 *
 * Returns: formatted string or %NULL
 *
 * Since: 1.12
 */
char *
nm_utils_tc_tfilter_to_str (NMTCTfilter *tfilter, GError **error)
{
	GString *string;

	string = g_string_sized_new (60);

	_nm_utils_string_append_tc_parent (string, "parent",
	                                   nm_tc_tfilter_get_parent (tfilter));
	if (!_nm_utils_string_append_tc_tfilter_rest (string, tfilter, error)) {
		g_string_free (string, TRUE);
		return NULL;
	}

	return g_string_free (string, FALSE);
}

static const NMVariantAttributeSpec *const tc_tfilter_attribute_spec[] = {
	NM_VARIANT_ATTRIBUTE_SPEC_DEFINE ("action", G_VARIANT_TYPE_BOOLEAN, .no_value = TRUE,                                         ),
	NM_VARIANT_ATTRIBUTE_SPEC_DEFINE ("",       G_VARIANT_TYPE_STRING,  .no_value = TRUE, .consumes_rest = TRUE, .str_type = 'a', ),
	NULL,
};

/**
 * nm_utils_tc_tfilter_from_str:
 * @str: the string representation of a tfilter
 * @error: location of the error
 *
 * Parses the tc style string tfilter representation of the queueing
 * discipline to a %NMTCTfilter instance. Supports a subset of the tc language.
 *
 * Returns: the %NMTCTfilter or %NULL
 *
 * Since: 1.12
 */
NMTCTfilter *
nm_utils_tc_tfilter_from_str (const char *str, GError **error)
{
	guint32 handle = TC_H_UNSPEC;
	guint32 parent = TC_H_UNSPEC;
	gs_free char *kind = NULL;
	gs_free char *rest = NULL;
	NMTCAction *action = NULL;
	const char *extra_opts = NULL;
	NMTCTfilter *tfilter = NULL;
	gs_unref_hashtable GHashTable *ht = NULL;
	GVariant *variant;

	nm_assert (str);
	nm_assert (!error || !*error);

	if (!_tc_read_common_opts (str, &handle, &parent, &kind, &rest, error))
		return NULL;

	if (rest) {
		ht = nm_utils_parse_variant_attributes (rest,
		                                        ' ', ' ', FALSE,
		                                        tc_tfilter_attribute_spec,
		                                        error);
		if (!ht)
			return NULL;

		variant = g_hash_table_lookup (ht, "");
		if (variant)
			extra_opts = g_variant_get_string (variant, NULL);

		if (g_hash_table_contains (ht, "action")) {
			action = nm_utils_tc_action_from_str (extra_opts, error);
			if (!action) {
				g_prefix_error (error, _("invalid action: "));
				return NULL;
			}
		} else {
			g_set_error (error, 1, 0, _("unsupported tfilter option: '%s'."), rest);
			return NULL;
		}
	}

	tfilter = nm_tc_tfilter_new (kind, parent, error);
	if (!tfilter)
		return NULL;

	nm_tc_tfilter_set_handle (tfilter, handle);
	if (action) {
		nm_tc_tfilter_set_action (tfilter, action);
		nm_tc_action_unref (action);
	}

	return tfilter;
}

/*****************************************************************************/

extern const NMVariantAttributeSpec *const _nm_sriov_vf_attribute_spec[];

/**
 * nm_utils_sriov_vf_to_str:
 * @vf: the %NMSriovVF
 * @omit_index: if %TRUE, the VF index will be omitted from output string
 * @error: (out) (allow-none): location to store the error on failure
 *
 * Converts a SR-IOV virtual function object to its string representation.
 *
 * Returns: a newly allocated string or %NULL on error
 *
 * Since: 1.14
 */
char *
nm_utils_sriov_vf_to_str (const NMSriovVF *vf, gboolean omit_index, GError **error)
{
	gs_free NMUtilsNamedValue *values = NULL;
	gs_free const char **names = NULL;
	const guint *vlan_ids;
	guint num_vlans, num_attrs;
	guint i;
	GString *str;

	str = g_string_new ("");
	if (!omit_index)
		g_string_append_printf (str, "%u", nm_sriov_vf_get_index (vf));

	names = nm_sriov_vf_get_attribute_names (vf);
	num_attrs = names ? g_strv_length ((char **) names) : 0;
	values = g_new0 (NMUtilsNamedValue, num_attrs);

	for (i = 0; i < num_attrs; i++) {
		values[i].name = names[i];
		values[i].value_ptr = nm_sriov_vf_get_attribute (vf, names[i]);
	}

	if (num_attrs > 0) {
		if (!omit_index)
			g_string_append_c (str, ' ');
		_nm_utils_format_variant_attributes_full (str, values, num_attrs, ' ', '=');
	}

	vlan_ids = nm_sriov_vf_get_vlan_ids (vf, &num_vlans);
	if (num_vlans != 0) {
		g_string_append (str, " vlans");
		for (i = 0; i < num_vlans; i++) {
			guint32 qos;
			NMSriovVFVlanProtocol protocol;

			qos = nm_sriov_vf_get_vlan_qos (vf, vlan_ids[i]);
			protocol = nm_sriov_vf_get_vlan_protocol (vf, vlan_ids[i]);

			g_string_append_c (str, i == 0 ? '=' : ';');

			g_string_append_printf (str, "%u", vlan_ids[i]);

			if (   qos != 0
			    || protocol != NM_SRIOV_VF_VLAN_PROTOCOL_802_1Q) {
				g_string_append_printf (str,
				                        ".%u%s",
				                        (unsigned) qos,
				                        protocol == NM_SRIOV_VF_VLAN_PROTOCOL_802_1Q ? "" : ".ad");
			}
		}
	}

	return g_string_free (str, FALSE);
}

gboolean
_nm_sriov_vf_parse_vlans (NMSriovVF *vf, const char *str, GError **error)
{
	gs_free const char **vlans = NULL;
	guint i;

	vlans = nm_utils_strsplit_set (str, ";");
	if (!vlans) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_FAILED,
		                     "empty VF VLAN");
		return FALSE;
	}

	for (i = 0; vlans[i]; i++) {
		gs_strfreev char **params = NULL;
		guint id = G_MAXUINT;
		gint64 qos = -1;

		/* we accept leading/trailing whitespace around vlans[1]. Hence
		 * the nm_str_skip_leading_spaces() and g_strchomp() below.
		 *
		 * However, we don't accept any whitespace inside the specifier.
		 * Hence the NM_STRCHAR_ALL() checks. */

		params = g_strsplit (nm_str_skip_leading_spaces (vlans[i]), ".", 3);
		if (!params || !params[0] || *params[0] == '\0') {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_FAILED,
			                     "empty VF VLAN");
			return FALSE;
		}

		if (!params[1])
			g_strchomp (params[0]);
		if (NM_STRCHAR_ALL (params[0], ch, ch == 'x' || g_ascii_isdigit (ch)))
			id = _nm_utils_ascii_str_to_int64 (params[0], 0, 0, 4095, G_MAXUINT);
		if (id == G_MAXUINT) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_FAILED,
			             "invalid VF VLAN id '%s'",
			             params[0]);
			return FALSE;
		}
		if (!nm_sriov_vf_add_vlan (vf, id)) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_FAILED,
			             "duplicate VLAN id %u",
			             id);
			return FALSE;
		}

		if (!params[1])
			continue;

		if (!params[2])
			g_strchomp (params[1]);
		if (NM_STRCHAR_ALL (params[1], ch, ch == 'x' || g_ascii_isdigit (ch)))
			qos = _nm_utils_ascii_str_to_int64 (params[1], 0, 0, G_MAXUINT32, -1);
		if (qos == -1) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_FAILED,
			             "invalid VF VLAN QoS '%s'",
			             params[1]);
			return FALSE;
		}
		nm_sriov_vf_set_vlan_qos (vf, id, qos);

		if (!params[2])
			continue;

		g_strchomp (params[2]);

		if (nm_streq (params[2], "ad"))
			nm_sriov_vf_set_vlan_protocol (vf, id, NM_SRIOV_VF_VLAN_PROTOCOL_802_1AD);
		else if (nm_streq (params[2], "q"))
			nm_sriov_vf_set_vlan_protocol (vf, id, NM_SRIOV_VF_VLAN_PROTOCOL_802_1Q);
		else {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_FAILED,
			             "invalid VF VLAN protocol '%s'",
			             params[2]);
			return FALSE;
		}
	}

	return TRUE;
}

/**
 * nm_utils_sriov_vf_from_str:
 * @str: the input string
 * @error: (out) (allow-none): location to store the error on failure
 *
 * Converts a string to a SR-IOV virtual function object.
 *
 * Returns: (transfer full): the virtual function object
 *
 * Since: 1.14
 */
NMSriovVF *
nm_utils_sriov_vf_from_str (const char *str, GError **error)
{
	gs_free char *index_free = NULL;
	const char *detail;

	g_return_val_if_fail (str, NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	while (*str == ' ')
		str++;

	detail = strchr (str, ' ');
	if (detail) {
		str = nm_strndup_a (200, str, detail - str, &index_free);
		detail++;
	}

	return _nm_utils_sriov_vf_from_strparts (str, detail, FALSE, error);
}

NMSriovVF *
_nm_utils_sriov_vf_from_strparts (const char *index,
                                  const char *detail,
                                  gboolean ignore_unknown,
                                  GError **error)
{
	NMSriovVF *vf;
	guint32 n_index;
	GHashTableIter iter;
	char *key;
	GVariant *variant;
	gs_unref_hashtable GHashTable *ht = NULL;

	n_index = _nm_utils_ascii_str_to_int64 (index, 10, 0, G_MAXUINT32, 0);
	if (errno) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_FAILED,
		                     "invalid index");
		return NULL;
	}

	vf = nm_sriov_vf_new (n_index);
	if (detail) {
		ht = nm_utils_parse_variant_attributes (detail,
		                                        ' ',
		                                        '=',
		                                        ignore_unknown,
		                                        _nm_sriov_vf_attribute_spec,
		                                        error);
		if (!ht) {
			nm_sriov_vf_unref (vf);
			return NULL;
		}

		if ((variant = g_hash_table_lookup (ht, "vlans"))) {
			if (!_nm_sriov_vf_parse_vlans (vf, g_variant_get_string (variant, NULL), error)) {
				nm_sriov_vf_unref (vf);
				return NULL;
			}
			g_hash_table_remove (ht, "vlans");
		}

		g_hash_table_iter_init (&iter, ht);
		while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &variant))
			nm_sriov_vf_set_attribute (vf, key, g_variant_ref_sink (variant));
	}

	return vf;
}

/*****************************************************************************/

NMUuid *
_nm_utils_uuid_parse (const char *str,
                      NMUuid *out_uuid)
{
	nm_assert (str);
	nm_assert (out_uuid);

	if (uuid_parse (str, out_uuid->uuid) != 0)
		return NULL;
	return out_uuid;
}

char *
_nm_utils_uuid_unparse (const NMUuid *uuid,
                        char *out_str /*[37]*/)
{
	nm_assert (uuid);

	if (!out_str) {
		/* for convenience, allow %NULL to indicate that a new
		 * string should be allocated. */
		out_str = g_malloc (37);
	}
	uuid_unparse_lower (uuid->uuid, out_str);
	return out_str;
}

NMUuid *
_nm_utils_uuid_generate_random (NMUuid *out_uuid)
{
	nm_assert (out_uuid);

	uuid_generate_random (out_uuid->uuid);
	return out_uuid;
}

gboolean
nm_utils_uuid_is_null (const NMUuid *uuid)
{
	int i;

	if (!uuid)
		return TRUE;

	for (i = 0; i < G_N_ELEMENTS (uuid->uuid); i++) {
		if (uuid->uuid[i])
			return FALSE;
	}
	return TRUE;
}

/**
 * nm_utils_uuid_generate_buf_:
 * @buf: input buffer, must contain at least 37 bytes
 *
 * Returns: generates a new random UUID, writes it to @buf and returns @buf.
 **/
char *
nm_utils_uuid_generate_buf_ (char *buf)
{
	NMUuid uuid;

	nm_assert (buf);

	_nm_utils_uuid_generate_random (&uuid);
	return _nm_utils_uuid_unparse (&uuid, buf);
}

/**
 * nm_utils_uuid_generate:
 *
 * Returns: a newly allocated UUID suitable for use as the #NMSettingConnection
 * object's #NMSettingConnection:id: property.  Should be freed with g_free()
 **/
char *
nm_utils_uuid_generate (void)
{
	return nm_utils_uuid_generate_buf_ (g_malloc (37));
}

/**
 * nm_utils_uuid_generate_from_string_bin:
 * @uuid: the UUID to update inplace. This function cannot
 *   fail to succeed.
 * @s: a string to use as the seed for the UUID
 * @slen: if negative, treat @s as zero terminated C string.
 *   Otherwise, assume the length as given (and allow @s to be
 *   non-null terminated or contain '\0').
 * @uuid_type: a type identifier which UUID format to generate.
 * @type_args: additional arguments, depending on the uuid_type
 *
 * For a given @s, this function will always return the same UUID.
 *
 * Returns: the input @uuid. This function cannot fail.
 **/
NMUuid *
nm_utils_uuid_generate_from_string_bin (NMUuid *uuid, const char *s, gssize slen, int uuid_type, gpointer type_args)
{
	g_return_val_if_fail (uuid, FALSE);
	g_return_val_if_fail (slen == 0 || s, FALSE);

	if (slen < 0)
		slen = s ? strlen (s) : 0;

	switch (uuid_type) {
	case NM_UTILS_UUID_TYPE_LEGACY:
		g_return_val_if_fail (!type_args, NULL);
		nm_crypto_md5_hash (NULL,
		                    0,
		                    (guint8 *) s,
		                    slen,
		                    (guint8 *) uuid,
		                    sizeof (*uuid));
		break;
	case NM_UTILS_UUID_TYPE_VERSION3:
	case NM_UTILS_UUID_TYPE_VERSION5: {
		NMUuid ns_uuid = { };

		if (type_args) {
			/* type_args can be a name space UUID. Interpret it as (char *) */
			if (!_nm_utils_uuid_parse (type_args, &ns_uuid))
				g_return_val_if_reached (NULL);
		}

		if (uuid_type == NM_UTILS_UUID_TYPE_VERSION3) {
			nm_crypto_md5_hash ((guint8 *) s,
			                    slen,
			                    (guint8 *) &ns_uuid,
			                    sizeof (ns_uuid),
			                    (guint8 *) uuid,
			                    sizeof (*uuid));
		} else {
			nm_auto_free_checksum GChecksum *sum = NULL;
			union {
				guint8 sha1[NM_UTILS_CHECKSUM_LENGTH_SHA1];
				NMUuid uuid;
			} digest;

			sum = g_checksum_new (G_CHECKSUM_SHA1);
			g_checksum_update (sum, (guchar *) &ns_uuid, sizeof (ns_uuid));
			g_checksum_update (sum, (guchar *) s, slen);
			nm_utils_checksum_get_digest (sum, digest.sha1);

			G_STATIC_ASSERT_EXPR (sizeof (digest.sha1) > sizeof (digest.uuid));
			*uuid = digest.uuid;
		}

		uuid->uuid[6] = (uuid->uuid[6] & 0x0F) | (uuid_type << 4);
		uuid->uuid[8] = (uuid->uuid[8] & 0x3F) | 0x80;
		break;
	}
	default:
		g_return_val_if_reached (NULL);
	}

	return uuid;
}

/**
 * nm_utils_uuid_generate_from_string:
 * @s: a string to use as the seed for the UUID
 * @slen: if negative, treat @s as zero terminated C string.
 *   Otherwise, assume the length as given (and allow @s to be
 *   non-null terminated or contain '\0').
 * @uuid_type: a type identifier which UUID format to generate.
 * @type_args: additional arguments, depending on the uuid_type
 *
 * For a given @s, this function will always return the same UUID.
 *
 * Returns: a newly allocated UUID suitable for use as the #NMSettingConnection
 * object's #NMSettingConnection:id: property
 **/
char *
nm_utils_uuid_generate_from_string (const char *s, gssize slen, int uuid_type, gpointer type_args)
{
	NMUuid uuid;

	nm_utils_uuid_generate_from_string_bin (&uuid, s, slen, uuid_type, type_args);
	return _nm_utils_uuid_unparse (&uuid, NULL);
}

/**
 * _nm_utils_uuid_generate_from_strings:
 * @string1: a variadic list of strings. Must be NULL terminated.
 *
 * Returns a variant3 UUID based on the concatenated C strings.
 * It does not simply concatenate them, but also includes the
 * terminating '\0' character. For example "a", "b", gives
 * "a\0b\0".
 *
 * This has the advantage, that the following invocations
 * all give different UUIDs: (NULL), (""), ("",""), ("","a"), ("a",""),
 * ("aa"), ("aa", ""), ("", "aa"), ...
 */
char *
_nm_utils_uuid_generate_from_strings (const char *string1, ...)
{
	GString *str;
	va_list args;
	const char *s;
	char *uuid;

	if (!string1)
		return nm_utils_uuid_generate_from_string (NULL, 0, NM_UTILS_UUID_TYPE_VERSION3, NM_UTILS_UUID_NS);

	str = g_string_sized_new (120); /* effectively allocates power of 2 (128)*/

	g_string_append_len (str, string1, strlen (string1) + 1);

	va_start (args, string1);
	s = va_arg (args, const char *);
	while (s) {
		g_string_append_len (str, s, strlen (s) + 1);
		s = va_arg (args, const char *);
	}
	va_end (args);

	uuid = nm_utils_uuid_generate_from_string (str->str, str->len, NM_UTILS_UUID_TYPE_VERSION3, NM_UTILS_UUID_NS);

	g_string_free (str, TRUE);
	return uuid;
}

/*****************************************************************************/

static gboolean
file_has_extension (const char *filename, const char *extensions[])
{
	const char *ext;
	int i;

	ext = strrchr (filename, '.');
	if (!ext)
		return FALSE;

	for (i = 0; extensions[i]; i++) {
		if (!g_ascii_strcasecmp (ext, extensions[i]))
			return TRUE;
	}

	return FALSE;
}

/**
 * nm_utils_file_is_certificate:
 * @filename: name of the file to test
 *
 * Tests if @filename has a valid extension for an X.509 certificate file
 * (".cer", ".crt", ".der", or ".pem"), and contains a certificate in a format
 * recognized by NetworkManager.
 *
 * Returns: %TRUE if the file is a certificate, %FALSE if it is not
 **/
gboolean
nm_utils_file_is_certificate (const char *filename)
{
	const char *extensions[] = { ".der", ".pem", ".crt", ".cer", NULL };
	NMCryptoFileFormat file_format;

	g_return_val_if_fail (filename != NULL, FALSE);

	if (!file_has_extension (filename, extensions))
		return FALSE;

	if (!nm_crypto_load_and_verify_certificate (filename, &file_format, NULL, NULL))
		return FALSE;
	return file_format = NM_CRYPTO_FILE_FORMAT_X509;
}

/**
 * nm_utils_file_is_private_key:
 * @filename: name of the file to test
 * @out_encrypted: (out): on return, whether the file is encrypted
 *
 * Tests if @filename has a valid extension for an X.509 private key file
 * (".der", ".key", ".pem", or ".p12"), and contains a private key in a format
 * recognized by NetworkManager.
 *
 * Returns: %TRUE if the file is a private key, %FALSE if it is not
 **/
gboolean
nm_utils_file_is_private_key (const char *filename, gboolean *out_encrypted)
{
	const char *extensions[] = { ".der", ".pem", ".p12", ".key", NULL };

	g_return_val_if_fail (filename != NULL, FALSE);

	NM_SET_OUT (out_encrypted, FALSE);
	if (!file_has_extension (filename, extensions))
		return FALSE;

	return nm_crypto_verify_private_key (filename, NULL, out_encrypted, NULL) != NM_CRYPTO_FILE_FORMAT_UNKNOWN;
}

/**
 * nm_utils_file_is_pkcs12:
 * @filename: name of the file to test
 *
 * Tests if @filename is a PKCS#<!-- -->12 file.
 *
 * Returns: %TRUE if the file is PKCS#<!-- -->12, %FALSE if it is not
 **/
gboolean
nm_utils_file_is_pkcs12 (const char *filename)
{
	g_return_val_if_fail (filename != NULL, FALSE);

	return nm_crypto_is_pkcs12_file (filename, NULL);
}

/*****************************************************************************/

gboolean
_nm_utils_check_file (const char *filename,
                      gint64 check_owner,
                      NMUtilsCheckFilePredicate check_file,
                      gpointer user_data,
                      struct stat *out_st,
                      GError **error)
{
	struct stat st_backup;

	if (!out_st)
		out_st = &st_backup;

	if (stat (filename, out_st) != 0) {
		int errsv = errno;

		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_FAILED,
		             _("failed stat file %s: %s"), filename, nm_strerror_native (errsv));
		return FALSE;
	}

	/* ignore non-files. */
	if (!S_ISREG (out_st->st_mode)) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_FAILED,
		             _("not a file (%s)"), filename);
		return FALSE;
	}

	/* with check_owner enabled, check that the file belongs to the
	 * owner or root. */
	if (   check_owner >= 0
	    && (out_st->st_uid != 0 && (gint64) out_st->st_uid != check_owner)) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_FAILED,
		             _("invalid file owner %d for %s"), out_st->st_uid, filename);
		return FALSE;
	}

	/* with check_owner enabled, check that the file cannot be modified
	 * by other users (except root). */
	if (   check_owner >= 0
	    && NM_FLAGS_ANY (out_st->st_mode, S_IWGRP | S_IWOTH | S_ISUID)) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_FAILED,
		             _("file permissions for %s"), filename);
		return FALSE;
	}

	if (    check_file
	    && !check_file (filename, out_st, user_data, error)) {
		if (error && !*error) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_FAILED,
			             _("reject %s"), filename);
		}
		return FALSE;
	}

	return TRUE;
}

gboolean
_nm_utils_check_module_file (const char *name,
                             int check_owner,
                             NMUtilsCheckFilePredicate check_file,
                             gpointer user_data,
                             GError **error)
{
	if (!g_path_is_absolute (name)) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_FAILED,
		             _("path is not absolute (%s)"), name);
		return FALSE;
	}

	/* Set special error code if the file doesn't exist.
	 * The VPN package might be split into separate packages,
	 * so it could be correct that the plugin file is missing.
	 *
	 * Note that nm-applet checks for this error code to fail
	 * gracefully. */
	if (!g_file_test (name, G_FILE_TEST_EXISTS)) {
		g_set_error (error,
		             G_FILE_ERROR,
		             G_FILE_ERROR_NOENT,
		             _("Plugin file does not exist (%s)"), name);
		return FALSE;
	}

	if (!g_file_test (name, G_FILE_TEST_IS_REGULAR)) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_FAILED,
		             _("Plugin is not a valid file (%s)"), name);
		return FALSE;
	}

	if (g_str_has_suffix (name, ".la")) {
		/* g_module_open() treats files that end with .la special.
		 * We don't want to parse the libtool archive. Just error out. */
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_FAILED,
		             _("libtool archives are not supported (%s)"), name);
		return FALSE;
	}

	return _nm_utils_check_file (name,
	                             check_owner,
	                             check_file,
	                             user_data,
	                             NULL,
	                             error);
}

/*****************************************************************************/

/**
 * nm_utils_file_search_in_paths:
 * @progname: the helper program name, like "iptables"
 *   Must be a non-empty string, without path separator (/).
 * @try_first: (allow-none): a custom path to try first before searching.
 *   It is silently ignored if it is empty or not an absolute path.
 * @paths: (allow-none): a %NULL terminated list of search paths.
 *   Can be empty or %NULL, in which case only @try_first is checked.
 * @file_test_flags: the flags passed to g_file_test() when searching
 *   for @progname. Set it to 0 to skip the g_file_test().
 * @predicate: (scope call): if given, pass the file name to this function
 *   for additional checks. This check is performed after the check for
 *   @file_test_flags. You cannot omit both @file_test_flags and @predicate.
 * @user_data: (closure) (allow-none): user data for @predicate function.
 * @error: (allow-none): on failure, set a "not found" error %G_IO_ERROR %G_IO_ERROR_NOT_FOUND.
 *
 * Searches for a @progname file in a list of search @paths.
 *
 * Returns: (transfer none): the full path to the helper, if found, or %NULL if not found.
 *   The returned string is not owned by the caller, but later
 *   invocations of the function might overwrite it.
 */
const char *
nm_utils_file_search_in_paths (const char *progname,
                               const char *try_first,
                               const char *const *paths,
                               GFileTest file_test_flags,
                               NMUtilsFileSearchInPathsPredicate predicate,
                               gpointer user_data,
                               GError **error)
{
	GString *tmp;
	const char *ret;

	g_return_val_if_fail (!error || !*error, NULL);
	g_return_val_if_fail (progname && progname[0] && !strchr (progname, '/'), NULL);
	g_return_val_if_fail (file_test_flags || predicate, NULL);

	/* Only consider @try_first if it is a valid, absolute path. This makes
	 * it simpler to pass in a path from configure checks. */
	if (   try_first
	    && try_first[0] == '/'
	    && (file_test_flags == 0 || g_file_test (try_first, file_test_flags))
	    && (!predicate || predicate (try_first, user_data)))
		return g_intern_string (try_first);

	if (!paths || !*paths)
		goto NOT_FOUND;

	tmp = g_string_sized_new (50);
	for (; *paths; paths++) {
		if (!*paths)
			continue;
		g_string_append (tmp, *paths);
		if (tmp->str[tmp->len - 1] != '/')
			g_string_append_c (tmp, '/');
		g_string_append (tmp, progname);
		if (   (file_test_flags == 0 || g_file_test (tmp->str, file_test_flags))
		    && (!predicate || predicate (tmp->str, user_data))) {
			ret = g_intern_string (tmp->str);
			g_string_free (tmp, TRUE);
			return ret;
		}
		g_string_set_size (tmp, 0);
	}
	g_string_free (tmp, TRUE);

NOT_FOUND:
	g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND, _("Could not find \"%s\" binary"), progname);
	return NULL;
}

/*****************************************************************************/

/* Band, channel/frequency stuff for wireless */
struct cf_pair {
	guint32 chan;
	guint32 freq;
};

static struct cf_pair a_table[] = {
	/* A band */
	{  7, 5035 },
	{  8, 5040 },
	{  9, 5045 },
	{ 11, 5055 },
	{ 12, 5060 },
	{ 16, 5080 },
	{ 34, 5170 },
	{ 36, 5180 },
	{ 38, 5190 },
	{ 40, 5200 },
	{ 42, 5210 },
	{ 44, 5220 },
	{ 46, 5230 },
	{ 48, 5240 },
	{ 50, 5250 },
	{ 52, 5260 },
	{ 56, 5280 },
	{ 58, 5290 },
	{ 60, 5300 },
	{ 64, 5320 },
	{ 100, 5500 },
	{ 104, 5520 },
	{ 108, 5540 },
	{ 112, 5560 },
	{ 116, 5580 },
	{ 120, 5600 },
	{ 124, 5620 },
	{ 128, 5640 },
	{ 132, 5660 },
	{ 136, 5680 },
	{ 140, 5700 },
	{ 149, 5745 },
	{ 152, 5760 },
	{ 153, 5765 },
	{ 157, 5785 },
	{ 160, 5800 },
	{ 161, 5805 },
	{ 165, 5825 },
	{ 183, 4915 },
	{ 184, 4920 },
	{ 185, 4925 },
	{ 187, 4935 },
	{ 188, 4945 },
	{ 192, 4960 },
	{ 196, 4980 },
	{ 0, -1 }
};

static struct cf_pair bg_table[] = {
	/* B/G band */
	{ 1, 2412 },
	{ 2, 2417 },
	{ 3, 2422 },
	{ 4, 2427 },
	{ 5, 2432 },
	{ 6, 2437 },
	{ 7, 2442 },
	{ 8, 2447 },
	{ 9, 2452 },
	{ 10, 2457 },
	{ 11, 2462 },
	{ 12, 2467 },
	{ 13, 2472 },
	{ 14, 2484 },
	{ 0, -1 }
};

/**
 * nm_utils_wifi_freq_to_channel:
 * @freq: frequency
 *
 * Utility function to translate a Wi-Fi frequency to its corresponding channel.
 *
 * Returns: the channel represented by the frequency or 0
 **/
guint32
nm_utils_wifi_freq_to_channel (guint32 freq)
{
	int i = 0;

	if (freq > 4900) {
		while (a_table[i].chan && (a_table[i].freq != freq))
			i++;
		return a_table[i].chan;
	} else {
		while (bg_table[i].chan && (bg_table[i].freq != freq))
			i++;
		return bg_table[i].chan;
	}

	return 0;
}

/**
 * nm_utils_wifi_freq_to_band:
 * @freq: frequency
 *
 * Utility function to translate a Wi-Fi frequency to its corresponding band.
 *
 * Returns: the band containing the frequency or NULL if freq is invalid
 **/
const char *
nm_utils_wifi_freq_to_band (guint32 freq)
{
	if (freq >= 4915 && freq <= 5825)
		return "a";
	else if (freq >= 2412 && freq <= 2484)
		return "bg";

	return NULL;
}

/**
 * nm_utils_wifi_channel_to_freq:
 * @channel: channel
 * @band: frequency band for wireless ("a" or "bg")
 *
 * Utility function to translate a Wi-Fi channel to its corresponding frequency.
 *
 * Returns: the frequency represented by the channel of the band,
 *          or -1 when the freq is invalid, or 0 when the band
 *          is invalid
 **/
guint32
nm_utils_wifi_channel_to_freq (guint32 channel, const char *band)
{
	int i = 0;

	if (!strcmp (band, "a")) {
		while (a_table[i].chan && (a_table[i].chan != channel))
			i++;
		return a_table[i].freq;
	} else if (!strcmp (band, "bg")) {
		while (bg_table[i].chan && (bg_table[i].chan != channel))
			i++;
		return bg_table[i].freq;
	}

	return 0;
}

/**
 * nm_utils_wifi_find_next_channel:
 * @channel: current channel
 * @direction: whether going downward (0 or less) or upward (1 or more)
 * @band: frequency band for wireless ("a" or "bg")
 *
 * Utility function to find out next/previous Wi-Fi channel for a channel.
 *
 * Returns: the next channel in the specified direction or 0
 **/
guint32
nm_utils_wifi_find_next_channel (guint32 channel, int direction, char *band)
{
	size_t a_size = sizeof (a_table) / sizeof (struct cf_pair);
	size_t bg_size = sizeof (bg_table) / sizeof (struct cf_pair);
	struct cf_pair *pair = NULL;

	if (!strcmp (band, "a")) {
		if (channel < a_table[0].chan)
			return a_table[0].chan;
		if (channel > a_table[a_size - 2].chan)
			return a_table[a_size - 2].chan;
		pair = &a_table[0];
	} else if (!strcmp (band, "bg")) {
		if (channel < bg_table[0].chan)
			return bg_table[0].chan;
		if (channel > bg_table[bg_size - 2].chan)
			return bg_table[bg_size - 2].chan;
		pair = &bg_table[0];
	} else {
		g_assert_not_reached ();
		return 0;
	}

	while (pair->chan) {
		if (channel == pair->chan)
			return channel;
		if ((channel < (pair+1)->chan) && (channel > pair->chan)) {
			if (direction > 0)
				return (pair+1)->chan;
			else
				return pair->chan;
		}
		pair++;
	}
	return 0;
}

/**
 * nm_utils_wifi_is_channel_valid:
 * @channel: channel
 * @band: frequency band for wireless ("a" or "bg")
 *
 * Utility function to verify Wi-Fi channel validity.
 *
 * Returns: %TRUE or %FALSE
 **/
gboolean
nm_utils_wifi_is_channel_valid (guint32 channel, const char *band)
{
	struct cf_pair *table = NULL;
	int i = 0;

	if (!strcmp (band, "a"))
		table = a_table;
	else if (!strcmp (band, "bg"))
		table = bg_table;
	else
		return FALSE;

	while (table[i].chan && (table[i].chan != channel))
		i++;

	if (table[i].chan != 0)
		return TRUE;
	else
		return FALSE;
}

static const guint *
_wifi_freqs (gboolean bg_band)
{
	static guint *freqs_2ghz = NULL;
	static guint *freqs_5ghz = NULL;
	guint *freqs;

	freqs = bg_band ? freqs_2ghz : freqs_5ghz;
	if (G_UNLIKELY (freqs == NULL)) {
		struct cf_pair *table;
		int i;

		table = bg_band ? bg_table : a_table;
		freqs = g_new0 (guint, bg_band ? G_N_ELEMENTS (bg_table) : G_N_ELEMENTS (a_table));
		for (i = 0; table[i].chan; i++)
			freqs[i] = table[i].freq;
		freqs[i] = 0;
		if (bg_band)
			freqs_2ghz = freqs;
		else
			freqs_5ghz = freqs;
	}
	return freqs;
}

/**
 * nm_utils_wifi_2ghz_freqs:
 *
 * Utility function to return 2.4 GHz Wi-Fi frequencies (802.11bg band).
 *
 * Returns: zero-terminated array of frequencies numbers (in MHz)
 *
 * Since: 1.2
 **/
const guint *
nm_utils_wifi_2ghz_freqs (void)
{
	return _wifi_freqs (TRUE);
}

/**
 * nm_utils_wifi_5ghz_freqs:
 *
 * Utility function to return 5 GHz Wi-Fi frequencies (802.11a band).
 *
 * Returns: zero-terminated array of frequencies numbers (in MHz)
 *
 * Since: 1.2
 **/
const guint *
nm_utils_wifi_5ghz_freqs (void)
{
	return _wifi_freqs (FALSE);
}

/**
 * nm_utils_wifi_strength_bars:
 * @strength: the access point strength, from 0 to 100
 *
 * Converts @strength into a 4-character-wide graphical representation of
 * strength suitable for printing to stdout.
 *
 * Previous versions used to take a guess at the terminal type and possibly
 * return a wide UTF-8 encoded string. Now it always returns a 7-bit
 * clean strings of one to 0 to 4 asterisks. Users that actually need
 * the functionality are encouraged to make their implementations instead.
 *
 * Returns: the graphical representation of the access point strength
 */
const char *
nm_utils_wifi_strength_bars (guint8 strength)
{
	if (strength > 80)
		return "****";
	else if (strength > 55)
		return "*** ";
	else if (strength > 30)
		return "**  ";
	else if (strength > 5)
		return "*   ";
	else
		return "    ";
}

/**
 * nm_utils_hwaddr_len:
 * @type: the type of address; either <literal>ARPHRD_ETHER</literal> or
 * <literal>ARPHRD_INFINIBAND</literal>
 *
 * Returns the length in octets of a hardware address of type @type.
 *
 * It is an error to call this function with any value other than
 * <literal>ARPHRD_ETHER</literal> or <literal>ARPHRD_INFINIBAND</literal>.
 *
 * Return value: the length.
 */
gsize
nm_utils_hwaddr_len (int type)
{
	if (type == ARPHRD_ETHER)
		return ETH_ALEN;
	else if (type == ARPHRD_INFINIBAND)
		return INFINIBAND_ALEN;

	g_return_val_if_reached (0);
}

/**
 * nm_utils_hexstr2bin:
 * @hex: a string of hexadecimal characters with optional ':' separators
 *
 * Converts a hexadecimal string @hex into an array of bytes.  The optional
 * separator ':' may be used between single or pairs of hexadecimal characters,
 * eg "00:11" or "0:1".  Any "0x" at the beginning of @hex is ignored.  @hex
 * may not start or end with ':'.
 *
 * Return value: (transfer full): the converted bytes, or %NULL on error
 */
GBytes *
nm_utils_hexstr2bin (const char *hex)
{
	guint8 *buffer;
	gsize len;

	buffer = nm_utils_hexstr2bin_alloc (hex, TRUE, FALSE, ":", 0, &len);
	if (!buffer)
		return NULL;
	buffer = g_realloc (buffer, len);
	return g_bytes_new_take (buffer, len);
}

#define hwaddr_aton(asc, buffer, buffer_len, out_len) nm_utils_hexstr2bin_full ((asc), FALSE, TRUE, ":-", 0, (buffer), (buffer_len), (out_len))

/**
 * nm_utils_hwaddr_atoba:
 * @asc: the ASCII representation of a hardware address
 * @length: the expected length in bytes of the result
 *
 * Parses @asc and converts it to binary form in a #GByteArray. See
 * nm_utils_hwaddr_aton() if you don't want a #GByteArray.
 *
 * Return value: (transfer full): a new #GByteArray, or %NULL if @asc couldn't
 * be parsed
 */
GByteArray *
nm_utils_hwaddr_atoba (const char *asc, gsize length)
{
	GByteArray *ba;
	gsize l;

	g_return_val_if_fail (asc, NULL);
	g_return_val_if_fail (length > 0 && length <= NM_UTILS_HWADDR_LEN_MAX, NULL);

	ba = g_byte_array_sized_new (length);
	g_byte_array_set_size (ba, length);
	if (!hwaddr_aton (asc, ba->data, length, &l))
		goto fail;
	if (length != l)
		goto fail;

	return ba;
fail:
	g_byte_array_unref (ba);
	return NULL;
}

/**
 * _nm_utils_hwaddr_aton:
 * @asc: the ASCII representation of a hardware address
 * @buffer: buffer to store the result into. Must have
 *   at least a size of @buffer_length.
 * @buffer_length: the length of the input buffer @buffer.
 *   The result must fit into that buffer, otherwise
 *   the function fails and returns %NULL.
 * @out_length: the output length in case of success.
 *
 * Parses @asc and converts it to binary form in @buffer.
 * Bytes in @asc can be sepatared by colons (:), or hyphens (-), but not mixed.
 *
 * It is like nm_utils_hwaddr_aton(), but contrary to that it
 * can parse addresses of any length. That is, you don't need
 * to know the length before-hand.
 *
 * Return value: @buffer, or %NULL if @asc couldn't be parsed.
 */
guint8 *
_nm_utils_hwaddr_aton (const char *asc, gpointer buffer, gsize buffer_length, gsize *out_length)
{
	g_return_val_if_fail (asc, NULL);
	g_return_val_if_fail (buffer, NULL);
	g_return_val_if_fail (buffer_length > 0, NULL);
	g_return_val_if_fail (out_length, NULL);

	return hwaddr_aton (asc, buffer, buffer_length, out_length);
}

/**
 * nm_utils_hwaddr_aton:
 * @asc: the ASCII representation of a hardware address
 * @buffer: (type guint8) (array length=length): buffer to store the result into
 * @length: the expected length in bytes of the result and
 * the size of the buffer in bytes.
 *
 * Parses @asc and converts it to binary form in @buffer.
 * Bytes in @asc can be sepatared by colons (:), or hyphens (-), but not mixed.
 *
 * Return value: @buffer, or %NULL if @asc couldn't be parsed
 *   or would be shorter or longer than @length.
 */
guint8 *
nm_utils_hwaddr_aton (const char *asc, gpointer buffer, gsize length)
{
	gsize l;

	g_return_val_if_fail (asc, NULL);
	g_return_val_if_fail (buffer, NULL);
	g_return_val_if_fail (length > 0 && length <= NM_UTILS_HWADDR_LEN_MAX, NULL);

	if (!hwaddr_aton (asc, buffer, length, &l))
		return NULL;
	if (length != l)
		return NULL;
	return buffer;
}



/**
 * nm_utils_bin2hexstr:
 * @src: (type guint8) (array length=len): an array of bytes
 * @len: the length of the @src array
 * @final_len: an index where to cut off the returned string, or -1
 *
 * Converts the byte array @src into a hexadecimal string. If @final_len is
 * greater than -1, the returned string is terminated at that index
 * (returned_string[final_len] == '\0'),
 *
 * Return value: (transfer full): the textual form of @bytes
 */
char *
nm_utils_bin2hexstr (gconstpointer src, gsize len, int final_len)
{
	char *result;
	gsize buflen = (len * 2) + 1;

	g_return_val_if_fail (src != NULL, NULL);
	g_return_val_if_fail (len > 0 && (buflen - 1) / 2 == len, NULL);
	g_return_val_if_fail (final_len < 0 || (gsize) final_len < buflen, NULL);

	result = g_malloc (buflen);

	nm_utils_bin2hexstr_full (src, len, '\0', FALSE, result);

	/* Cut converted key off at the correct length for this cipher type */
	if (final_len >= 0 && (gsize) final_len < buflen)
		result[final_len] = '\0';

	return result;
}

/**
 * nm_utils_hwaddr_ntoa:
 * @addr: (type guint8) (array length=length): a binary hardware address
 * @length: the length of @addr
 *
 * Converts @addr to textual form.
 *
 * Return value: (transfer full): the textual form of @addr
 */
char *
nm_utils_hwaddr_ntoa (gconstpointer addr, gsize length)
{
	g_return_val_if_fail (addr, g_strdup (""));
	g_return_val_if_fail (length > 0, g_strdup (""));

	return nm_utils_bin2hexstr_full (addr, length, ':', TRUE, NULL);
}

const char *
nm_utils_hwaddr_ntoa_buf (gconstpointer addr, gsize addr_len, gboolean upper_case, char *buf, gsize buf_len)
{
	g_return_val_if_fail (addr, NULL);
	g_return_val_if_fail (addr_len > 0, NULL);
	g_return_val_if_fail (buf, NULL);
	if (buf_len < addr_len * 3)
		g_return_val_if_reached (NULL);

	return nm_utils_bin2hexstr_full (addr, addr_len, ':', upper_case, buf);
}

/**
 * nm_utils_hwaddr_valid:
 * @asc: the ASCII representation of a hardware address
 * @length: the length of address that @asc is expected to convert to
 *   (or -1 to accept any length up to %NM_UTILS_HWADDR_LEN_MAX)
 *
 * Parses @asc to see if it is a valid hardware address of the given
 * length.
 *
 * Return value: %TRUE if @asc appears to be a valid hardware address
 *   of the indicated length, %FALSE if not.
 */
gboolean
nm_utils_hwaddr_valid (const char *asc, gssize length)
{
	guint8 buf[NM_UTILS_HWADDR_LEN_MAX];
	gsize l;

	g_return_val_if_fail (asc != NULL, FALSE);

	if (length > 0 && length <= NM_UTILS_HWADDR_LEN_MAX) {
		if (!hwaddr_aton (asc, buf, length, &l))
			return FALSE;
		return length == l;
	} else if (length == -1)
		return !!hwaddr_aton (asc, buf, sizeof (buf), &l);
	else if (length == 0)
		return FALSE;
	else
		g_return_val_if_reached (FALSE);
}

/**
 * nm_utils_hwaddr_canonical:
 * @asc: the ASCII representation of a hardware address
 * @length: the length of address that @asc is expected to convert to
 *   (or -1 to accept any length up to %NM_UTILS_HWADDR_LEN_MAX)
 *
 * Parses @asc to see if it is a valid hardware address of the given
 * length, and if so, returns it in canonical form (uppercase, with
 * leading 0s as needed, and with colons rather than hyphens).
 *
 * Return value: (transfer full): the canonicalized address if @asc appears to
 *   be a valid hardware address of the indicated length, %NULL if not.
 */
char *
nm_utils_hwaddr_canonical (const char *asc, gssize length)
{
	guint8 buf[NM_UTILS_HWADDR_LEN_MAX];
	gsize l;

	g_return_val_if_fail (asc, NULL);
	g_return_val_if_fail (length == -1 || (length > 0 && length <= NM_UTILS_HWADDR_LEN_MAX), NULL);

	if (length > 0 && length <= NM_UTILS_HWADDR_LEN_MAX) {
		if (!hwaddr_aton (asc, buf, length, &l))
			return NULL;
		if (l != length)
			return NULL;
	} else if (length == -1) {
		if (!hwaddr_aton (asc, buf, NM_UTILS_HWADDR_LEN_MAX, &l))
			return NULL;
	} else
		g_return_val_if_reached (NULL);

	return nm_utils_hwaddr_ntoa (buf, l);
}

/* This is used to possibly canonicalize values passed to MAC address property
 * setters. Unlike nm_utils_hwaddr_canonical(), it accepts %NULL, and if you
 * pass it an invalid MAC address, it just returns that string rather than
 * returning %NULL (so that we can return a proper error from verify() later).
 */
char *
_nm_utils_hwaddr_canonical_or_invalid (const char *mac, gssize length)
{
	char *canonical;

	if (!mac)
		return NULL;

	canonical = nm_utils_hwaddr_canonical (mac, length);
	if (canonical)
		return canonical;
	else
		return g_strdup (mac);
}

/**
 * nm_utils_hwaddr_matches:
 * @hwaddr1: (nullable): pointer to a binary or ASCII hardware address, or %NULL
 * @hwaddr1_len: size of @hwaddr1, or -1 if @hwaddr1 is ASCII
 * @hwaddr2: (nullable): pointer to a binary or ASCII hardware address, or %NULL
 * @hwaddr2_len: size of @hwaddr2, or -1 if @hwaddr2 is ASCII
 *
 * Generalized hardware address comparison function. Tests if @hwaddr1 and
 * @hwaddr2 "equal" (or more precisely, "equivalent"), with several advantages
 * over a simple memcmp():
 *
 *   1. If @hwaddr1_len or @hwaddr2_len is -1, then the corresponding address is
 *      assumed to be ASCII rather than binary, and will be converted to binary
 *      before being compared.
 *
 *   2. If @hwaddr1 or @hwaddr2 is %NULL, it is treated instead as though it was
 *      a zero-filled buffer @hwaddr1_len or @hwaddr2_len bytes long.
 *
 *   3. If @hwaddr1 and @hwaddr2 are InfiniBand hardware addresses (that is, if
 *      they are <literal>INFINIBAND_ALEN</literal> bytes long in binary form)
 *      then only the last 8 bytes are compared, since those are the only bytes
 *      that actually identify the hardware. (The other 12 bytes will change
 *      depending on the configuration of the InfiniBand fabric that the device
 *      is connected to.)
 *
 * If a passed-in ASCII hardware address cannot be parsed, or would parse to an
 * address larger than %NM_UTILS_HWADDR_LEN_MAX, then it will silently fail to
 * match. (This means that externally-provided address strings do not need to be
 * sanity-checked before comparing them against known good addresses; they are
 * guaranteed to not match if they are invalid.)
 *
 * Return value: %TRUE if @hwaddr1 and @hwaddr2 are equivalent, %FALSE if they are
 *   different (or either of them is invalid).
 */
gboolean
nm_utils_hwaddr_matches (gconstpointer hwaddr1,
                         gssize        hwaddr1_len,
                         gconstpointer hwaddr2,
                         gssize        hwaddr2_len)
{
	guint8 buf1[NM_UTILS_HWADDR_LEN_MAX], buf2[NM_UTILS_HWADDR_LEN_MAX];
	gsize l;

	if (hwaddr1_len == -1) {
		g_return_val_if_fail (hwaddr1 != NULL, FALSE);

		if (!hwaddr_aton (hwaddr1, buf1, sizeof (buf1), &l)) {
			g_return_val_if_fail ((hwaddr2_len == -1 && hwaddr2) || (hwaddr2_len > 0 && hwaddr2_len <= NM_UTILS_HWADDR_LEN_MAX), FALSE);
			return FALSE;
		}
		hwaddr1 = buf1;
		hwaddr1_len = l;
	} else {
		g_return_val_if_fail (hwaddr1_len > 0 && hwaddr1_len <= NM_UTILS_HWADDR_LEN_MAX, FALSE);

		if (!hwaddr1) {
			memset (buf1, 0, hwaddr1_len);
			hwaddr1 = buf1;
		}
	}

	if (hwaddr2_len == -1) {
		g_return_val_if_fail (hwaddr2 != NULL, FALSE);

		if (!hwaddr_aton (hwaddr2, buf2, sizeof (buf2), &l))
			return FALSE;
		if (l != hwaddr1_len)
			return FALSE;
		hwaddr2 = buf2;
	} else {
		g_return_val_if_fail (hwaddr2_len > 0 && hwaddr2_len <= NM_UTILS_HWADDR_LEN_MAX, FALSE);

		if (hwaddr2_len != hwaddr1_len)
			return FALSE;

		if (!hwaddr2) {
			memset (buf2, 0, hwaddr2_len);
			hwaddr2 = buf2;
		}
	}

	if (hwaddr1_len == INFINIBAND_ALEN) {
		hwaddr1 = (guint8 *)hwaddr1 + INFINIBAND_ALEN - 8;
		hwaddr2 = (guint8 *)hwaddr2 + INFINIBAND_ALEN - 8;
		hwaddr1_len = 8;
	}

	return !memcmp (hwaddr1, hwaddr2, hwaddr1_len);
}

/*****************************************************************************/

static GVariant *
_nm_utils_hwaddr_to_dbus_impl (const char *str)
{
	guint8 buf[NM_UTILS_HWADDR_LEN_MAX];
	gsize len;

	if (!str)
		return NULL;
	if (!hwaddr_aton (str, buf, sizeof (buf), &len))
		return NULL;

	return g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, buf, len, 1);
}

GVariant *
_nm_utils_hwaddr_cloned_get (const NMSettInfoSetting *sett_info,
                             guint property_idx,
                             NMConnection *connection,
                             NMSetting *setting,
                             NMConnectionSerializationFlags flags,
                             const NMConnectionSerializationOptions *options)
{
	gs_free char *addr = NULL;

	nm_assert (nm_streq (sett_info->property_infos[property_idx].name, "cloned-mac-address"));

	g_object_get (setting, "cloned-mac-address", &addr, NULL);
	return _nm_utils_hwaddr_to_dbus_impl (addr);
}

gboolean
_nm_utils_hwaddr_cloned_set (NMSetting     *setting,
                             GVariant      *connection_dict,
                             const char    *property,
                             GVariant      *value,
                             NMSettingParseFlags parse_flags,
                             GError       **error)
{
	gsize length;
	const guint8 *array;
	char *str;

	nm_assert (nm_streq0 (property, "cloned-mac-address"));

	if (!_nm_setting_use_legacy_property (setting, connection_dict, "cloned-mac-address", "assigned-mac-address"))
		return TRUE;

	length = 0;
	array = g_variant_get_fixed_array (value, &length, 1);

	if (!length)
		return TRUE;

	str = nm_utils_hwaddr_ntoa (array, length);
	g_object_set (setting,
	              "cloned-mac-address",
	              str,
	              NULL);
	g_free (str);
	return TRUE;
}

gboolean
_nm_utils_hwaddr_cloned_not_set (NMSetting *setting,
                                 GVariant      *connection_dict,
                                 const char    *property,
                                 NMSettingParseFlags parse_flags,
                                 GError       **error)
{
	nm_assert (nm_streq0 (property, "cloned-mac-address"));
	return TRUE;
}

GVariant *
_nm_utils_hwaddr_cloned_data_synth (const NMSettInfoSetting *sett_info,
                                    guint property_idx,
                                    NMConnection *connection,
                                    NMSetting *setting,
                                    NMConnectionSerializationFlags flags,
                                    const NMConnectionSerializationOptions *options)
{
	gs_free char *addr = NULL;

	if (flags & NM_CONNECTION_SERIALIZE_ONLY_SECRETS)
		return NULL;

	nm_assert (nm_streq0 (sett_info->property_infos[property_idx].name, "assigned-mac-address"));

	g_object_get (setting,
	              "cloned-mac-address",
	              &addr,
	              NULL);

	/* Before introducing the extended "cloned-mac-address" (and its D-Bus
	 * field "assigned-mac-address"), libnm's _nm_utils_hwaddr_to_dbus()
	 * would drop invalid values as it was unable to serialize them.
	 *
	 * Now, we would like to send invalid values as "assigned-mac-address"
	 * over D-Bus and let the server reject them.
	 *
	 * However, clients used to set the cloned-mac-address property
	 * to "" and it just worked as the value was not serialized in
	 * an ill form.
	 *
	 * To preserve that behavior, serialize "" as NULL.
	 */

	return addr && addr[0]
	       ? g_variant_new_take_string (g_steal_pointer (&addr))
	       : NULL;
}

gboolean
_nm_utils_hwaddr_cloned_data_set (NMSetting *setting,
                                  GVariant *connection_dict,
                                  const char *property,
                                  GVariant *value,
                                  NMSettingParseFlags parse_flags,
                                  GError **error)
{
	nm_assert (nm_streq0 (property, "assigned-mac-address"));

	if (_nm_setting_use_legacy_property (setting, connection_dict, "cloned-mac-address", "assigned-mac-address"))
		return TRUE;

	g_object_set (setting,
	              "cloned-mac-address",
	              nm_str_not_empty (g_variant_get_string (value, NULL)),
	              NULL);
	return TRUE;
}

GVariant *
_nm_utils_hwaddr_to_dbus (const GValue *prop_value)
{
	return _nm_utils_hwaddr_to_dbus_impl (g_value_get_string (prop_value));
}

void
_nm_utils_hwaddr_from_dbus (GVariant *dbus_value,
                            GValue *prop_value)
{
	gsize length = 0;
	const guint8 *array = g_variant_get_fixed_array (dbus_value, &length, 1);
	char *str;

	str = length ? nm_utils_hwaddr_ntoa (array, length) : NULL;
	g_value_take_string (prop_value, str);
}

/*****************************************************************************/

/* Validate secret-flags. Most settings don't validate them, which is a bug.
 * But we possibly cannot enforce a strict validation now.
 *
 * For new settings, they shall validate the secret-flags strictly. */
gboolean
_nm_utils_secret_flags_validate (NMSettingSecretFlags secret_flags,
                                 const char *setting_name,
                                 const char *property_name,
                                 NMSettingSecretFlags disallowed_flags,
                                 GError **error)
{
	if (secret_flags == NM_SETTING_SECRET_FLAG_NONE)
		return TRUE;

	if (NM_FLAGS_ANY (secret_flags, ~NM_SETTING_SECRET_FLAG_ALL)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("unknown secret flags"));
		if (setting_name)
			g_prefix_error (error, "%s.%s: ", setting_name, property_name);
		return FALSE;
	}

	if (!nm_utils_is_power_of_two (secret_flags)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("conflicting secret flags"));
		if (setting_name)
			g_prefix_error (error, "%s.%s: ", setting_name, property_name);
		return FALSE;
	}

	if (NM_FLAGS_ANY (secret_flags, disallowed_flags)) {
		if (NM_FLAGS_HAS (secret_flags, NM_SETTING_SECRET_FLAG_NOT_REQUIRED)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("secret flags must not be \"not-required\""));
			if (setting_name)
				g_prefix_error (error, "%s.%s: ", setting_name, property_name);
			return FALSE;
		}
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("unsupported secret flags"));
		if (setting_name)
			g_prefix_error (error, "%s.%s: ", setting_name, property_name);
		return FALSE;
	}

	return TRUE;
}

gboolean
_nm_utils_wps_method_validate (NMSettingWirelessSecurityWpsMethod wps_method,
                               const char *setting_name,
                               const char *property_name,
                               gboolean wps_required,
                               GError **error)
{
	if (wps_method > NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_PIN) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", setting_name, property_name);
		return FALSE;
	}

	if (NM_FLAGS_HAS (wps_method, NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_DISABLED)) {
		if (wps_method != NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_DISABLED) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("can't be simultaneously disabled and enabled"));
			g_prefix_error (error, "%s.%s: ", setting_name, property_name);
			return FALSE;
		}
		if (wps_required) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("WPS is required"));
			g_prefix_error (error, "%s.%s: ", setting_name, property_name);
			return FALSE;
		}
	}

	return TRUE;
}

/*****************************************************************************/

static char *
_split_word (char *s)
{
	/* takes @s and truncates the string on the first white-space.
	 * then it returns the first word afterwards (again seeking
	 * over leading white-space). */
	for (; s[0]; s++) {
		if (g_ascii_isspace (s[0])) {
			s[0] = '\0';
			s++;
			while (g_ascii_isspace (s[0]))
				s++;
			return s;
		}
	}
	return s;
}

gboolean
_nm_utils_generate_mac_address_mask_parse (const char *value,
                                           struct ether_addr *out_mask,
                                           struct ether_addr **out_ouis,
                                           gsize *out_ouis_len,
                                           GError **error)
{
	gs_free char *s_free = NULL;
	char *s, *s_next;
	struct ether_addr mask;
	gs_unref_array GArray *ouis = NULL;

	g_return_val_if_fail (!error || !*error, FALSE);

	if (!value || !*value)  {
		/* NULL and "" are valid values and both mean the default
		 * "q */
		if (out_mask) {
			memset (out_mask, 0, sizeof (*out_mask));
			out_mask->ether_addr_octet[0] |= 0x02;
		}
		NM_SET_OUT (out_ouis, NULL);
		NM_SET_OUT (out_ouis_len, 0);
		return TRUE;
	}

	s_free = g_strdup (value);
	s = s_free;

	/* skip over leading whitespace */
	while (g_ascii_isspace (s[0]))
		s++;

	/* parse the first mask */
	s_next = _split_word (s);
	if (!nm_utils_hwaddr_aton (s, &mask, ETH_ALEN)) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             _("not a valid ethernet MAC address for mask at position %lld"),
		             (long long) (s - s_free));
		return FALSE;
	}

	if (s_next[0]) {
		ouis = g_array_sized_new (FALSE, FALSE, sizeof (struct ether_addr), 4);

		do {
			s = s_next;
			s_next = _split_word (s);

			g_array_set_size (ouis, ouis->len + 1);
			if (!nm_utils_hwaddr_aton (s, &g_array_index (ouis, struct ether_addr, ouis->len - 1), ETH_ALEN)) {
				g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
				             _("not a valid ethernet MAC address #%u at position %lld"),
				             ouis->len, (long long) (s - s_free));
				return FALSE;
			}
		} while (s_next[0]);
	}

	NM_SET_OUT (out_mask, mask);
	NM_SET_OUT (out_ouis_len, ouis ? ouis->len : 0);
	NM_SET_OUT (out_ouis, ouis ? ((struct ether_addr *) g_array_free (g_steal_pointer (&ouis), FALSE)) : NULL);
	return TRUE;
}

/*****************************************************************************/

gboolean
nm_utils_is_valid_iface_name_utf8safe (const char *utf8safe_name)
{
	gs_free gpointer bin_to_free = NULL;
	gconstpointer bin;
	gsize len;

	g_return_val_if_fail (utf8safe_name, FALSE);

	bin = nm_utils_buf_utf8safe_unescape (utf8safe_name, &len, &bin_to_free);

	if (bin_to_free) {
		/* some unescaping happened... */

		if (len != strlen (bin)) {
			/* there are embedded NUL chars. Invalid. */
			return FALSE;
		}
	}

	return nm_utils_is_valid_iface_name (bin, NULL);
}

/**
 * nm_utils_is_valid_iface_name:
 * @name: (allow-none): Name of interface
 * @error: location to store the error occurring, or %NULL to ignore
 *
 * Validate the network interface name.
 *
 * This function is a 1:1 copy of the kernel's interface validation
 * function in net/core/dev.c.
 *
 * Returns: %TRUE if interface name is valid, otherwise %FALSE is returned.
 *
 * Before 1.20, this function did not accept %NULL as @name argument. If you
 *   want to run against older versions of libnm, don't pass %NULL.
 */
gboolean
nm_utils_is_valid_iface_name (const char *name, GError **error)
{
	int i;

	if (!name) {
		g_set_error_literal (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		                     _("interface name is missing"));
		return FALSE;
	}

	if (name[0] == '\0') {
		g_set_error_literal (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		                     _("interface name is too short"));
		return FALSE;
	}

	if (   name[0] == '.'
	    && (   name[1] == '\0'
	        || (   name[1] == '.'
	            && name[2] == '\0'))) {
		g_set_error_literal (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		                     _("interface name is reserved"));
		return FALSE;
	}

	for (i = 0; i < IFNAMSIZ; i++) {
		char ch = name[i];

		if (ch == '\0')
			return TRUE;
		if (   NM_IN_SET (ch, '/', ':')
		    || g_ascii_isspace (ch)) {
			g_set_error_literal (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
			                     _("interface name contains an invalid character"));
			return FALSE;
		}
	}

	g_set_error_literal (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
	                     _("interface name is longer than 15 characters"));
	return FALSE;
}

/**
 * nm_utils_iface_valid_name:
 * @name: (allow-none): Name of interface
 *
 * Validate the network interface name.
 *
 * Deprecated: 1.6: use nm_utils_is_valid_iface_name() instead, with better error reporting.
 *
 * Returns: %TRUE if interface name is valid, otherwise %FALSE is returned.
 *
 * Before 1.20, this function did not accept %NULL as @name argument. If you
 *   want to run against older versions of libnm, don't pass %NULL.
 */
gboolean
nm_utils_iface_valid_name (const char *name)
{
	return nm_utils_is_valid_iface_name (name, NULL);
}

/**
 * nm_utils_is_uuid:
 * @str: (allow-none): a string that might be a UUID
 *
 * Checks if @str is a UUID
 *
 * Returns: %TRUE if @str is a UUID, %FALSE if not
 *
 * In older versions, nm_utils_is_uuid() did not accept %NULL as @str
 * argument. Don't pass %NULL if you run against older versions of libnm.
 */
gboolean
nm_utils_is_uuid (const char *str)
{
	const char *p = str;
	int num_dashes = 0;

	if (!p)
		return FALSE;

	while (*p) {
		if (*p == '-')
			num_dashes++;
		else if (!g_ascii_isxdigit (*p))
			return FALSE;
		p++;
	}

	if ((num_dashes == 4) && (p - str == 36))
		return TRUE;

	/* Backwards compat for older configurations */
	if ((num_dashes == 0) && (p - str == 40))
		return TRUE;

	return FALSE;
}

static char _nm_utils_inet_ntop_buffer[NM_UTILS_INET_ADDRSTRLEN];

const char *
nm_utils_inet_ntop (int addr_family, gconstpointer addr, char *dst)
{
	const char *s;

	nm_assert_addr_family (addr_family);
	nm_assert (addr);
	nm_assert (dst);

	s = inet_ntop (addr_family,
	               addr,
	               dst,
	               addr_family == AF_INET6 ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN);
	nm_assert (s);
	return s;
}

/**
 * nm_utils_inet4_ntop: (skip)
 * @inaddr: the address that should be converted to string.
 * @dst: the destination buffer, it must contain at least
 *  <literal>INET_ADDRSTRLEN</literal> or %NM_UTILS_INET_ADDRSTRLEN
 *  characters. If set to %NULL, it will return a pointer to an internal, static
 *  buffer (shared with nm_utils_inet6_ntop()).  Beware, that the internal
 *  buffer will be overwritten with ever new call of nm_utils_inet4_ntop() or
 *  nm_utils_inet6_ntop() that does not provide its own @dst buffer. Also,
 *  using the internal buffer is not thread safe. When in doubt, pass your own
 *  @dst buffer to avoid these issues.
 *
 * Wrapper for inet_ntop.
 *
 * Returns: the input buffer @dst, or a pointer to an
 *  internal, static buffer. This function cannot fail.
 **/
const char *
nm_utils_inet4_ntop (in_addr_t inaddr, char *dst)
{
	/* relying on the static buffer (by leaving @dst as %NULL) is discouraged.
	 * Don't do that!
	 *
	 * However, still support it to be lenient against mistakes and because
	 * this is public API of libnm. */
	return inet_ntop (AF_INET, &inaddr, dst ?: _nm_utils_inet_ntop_buffer,
	                  INET_ADDRSTRLEN);
}

/**
 * nm_utils_inet6_ntop: (skip)
 * @in6addr: the address that should be converted to string.
 * @dst: the destination buffer, it must contain at least
 *  <literal>INET6_ADDRSTRLEN</literal> or %NM_UTILS_INET_ADDRSTRLEN
 *  characters. If set to %NULL, it will return a pointer to an internal, static
 *  buffer (shared with nm_utils_inet4_ntop()).  Beware, that the internal
 *  buffer will be overwritten with ever new call of nm_utils_inet4_ntop() or
 *  nm_utils_inet6_ntop() that does not provide its own @dst buffer. Also,
 *  using the internal buffer is not thread safe. When in doubt, pass your own
 *  @dst buffer to avoid these issues.
 *
 * Wrapper for inet_ntop.
 *
 * Returns: the input buffer @dst, or a pointer to an
 *  internal, static buffer. %NULL is not allowed as @in6addr,
 *  otherwise, this function cannot fail.
 **/
const char *
nm_utils_inet6_ntop (const struct in6_addr *in6addr, char *dst)
{
	/* relying on the static buffer (by leaving @dst as %NULL) is discouraged.
	 * Don't do that!
	 *
	 * However, still support it to be lenient against mistakes and because
	 * this is public API of libnm. */
	g_return_val_if_fail (in6addr, NULL);
	return inet_ntop (AF_INET6, in6addr, dst ?: _nm_utils_inet_ntop_buffer,
	                  INET6_ADDRSTRLEN);
}

/**
 * nm_utils_ipaddr_valid:
 * @family: <literal>AF_INET</literal> or <literal>AF_INET6</literal>, or
 *   <literal>AF_UNSPEC</literal> to accept either
 * @ip: an IP address
 *
 * Checks if @ip contains a valid IP address of the given family.
 *
 * Return value: %TRUE or %FALSE
 */
gboolean
nm_utils_ipaddr_valid (int family, const char *ip)
{
	guint8 buf[sizeof (struct in6_addr)];

	g_return_val_if_fail (family == AF_INET || family == AF_INET6 || family == AF_UNSPEC, FALSE);

	if (!ip)
		return FALSE;

	if (family == AF_UNSPEC)
		family = strchr (ip, ':') ? AF_INET6 : AF_INET;

	return inet_pton (family, ip, buf) == 1;
}

/**
 * nm_utils_iinet6_is_token:
 * @in6addr: the AF_INET6 address structure
 *
 * Checks if only the bottom 64bits of the address are set.
 *
 * Return value: %TRUE or %FALSE
 */
gboolean
_nm_utils_inet6_is_token (const struct in6_addr *in6addr)
{
	if (   in6addr->s6_addr[0]
	    || in6addr->s6_addr[1]
	    || in6addr->s6_addr[2]
	    || in6addr->s6_addr[3]
	    || in6addr->s6_addr[4]
	    || in6addr->s6_addr[5]
	    || in6addr->s6_addr[6]
	    || in6addr->s6_addr[7])
		return FALSE;

	if (   in6addr->s6_addr[8]
	    || in6addr->s6_addr[9]
	    || in6addr->s6_addr[10]
	    || in6addr->s6_addr[11]
	    || in6addr->s6_addr[12]
	    || in6addr->s6_addr[13]
	    || in6addr->s6_addr[14]
	    || in6addr->s6_addr[15])
		return TRUE;

	return FALSE;
}

/**
 * _nm_utils_dhcp_duid_valid:
 * @duid: the candidate DUID
 *
 * Checks if @duid string contains either a special duid value ("ll",
 * "llt", "lease" or the "stable" variants) or a valid hex DUID.
 *
 * Return value: %TRUE or %FALSE
 */
gboolean
_nm_utils_dhcp_duid_valid (const char *duid, GBytes **out_duid_bin)
{
	guint8 duid_arr[128 + 2];
	gsize duid_len;

	NM_SET_OUT (out_duid_bin, NULL);

	if (!duid)
		return FALSE;

	if (NM_IN_STRSET (duid, "lease",
	                        "llt",
	                        "ll",
	                        "stable-llt",
	                        "stable-ll",
	                        "stable-uuid")) {
		return TRUE;
	}

	if (nm_utils_hexstr2bin_full (duid, FALSE, FALSE, ":", 0, duid_arr, sizeof (duid_arr), &duid_len)) {
		/* MAX DUID length is 128 octects + the type code (2 octects). */
		if (   duid_len > 2
		    && duid_len <= (128 + 2)) {
			NM_SET_OUT (out_duid_bin, g_bytes_new (duid_arr, duid_len));
			return TRUE;
		}
	}

	return FALSE;
}

/**
 * nm_utils_check_virtual_device_compatibility:
 * @virtual_type: a virtual connection type
 * @other_type: a connection type to test against @virtual_type
 *
 * Determines if a connection of type @virtual_type can (in the
 * general case) work with connections of type @other_type.
 *
 * If @virtual_type is %NM_TYPE_SETTING_VLAN, then this checks if
 * @other_type is a valid type for the parent of a VLAN.
 *
 * If @virtual_type is a "master" type (eg, %NM_TYPE_SETTING_BRIDGE),
 * then this checks if @other_type is a valid type for a slave of that
 * master.
 *
 * Note that even if this returns %TRUE it is not guaranteed that
 * <emphasis>every</emphasis> connection of type @other_type is
 * compatible with @virtual_type; it may depend on the exact
 * configuration of the two connections, or on the capabilities of an
 * underlying device driver.
 *
 * Returns: %TRUE or %FALSE
 */
gboolean
nm_utils_check_virtual_device_compatibility (GType virtual_type, GType other_type)
{
	g_return_val_if_fail (_nm_setting_type_get_base_type_priority (virtual_type) != NM_SETTING_PRIORITY_INVALID, FALSE);
	g_return_val_if_fail (_nm_setting_type_get_base_type_priority (other_type)   != NM_SETTING_PRIORITY_INVALID, FALSE);

	if (virtual_type == NM_TYPE_SETTING_BOND) {
		return (   other_type == NM_TYPE_SETTING_INFINIBAND
		        || other_type == NM_TYPE_SETTING_WIRED
		        || other_type == NM_TYPE_SETTING_BRIDGE
		        || other_type == NM_TYPE_SETTING_BOND
		        || other_type == NM_TYPE_SETTING_TEAM
		        || other_type == NM_TYPE_SETTING_VLAN);
	} else if (virtual_type == NM_TYPE_SETTING_BRIDGE) {
		return (   other_type == NM_TYPE_SETTING_WIRED
		        || other_type == NM_TYPE_SETTING_BOND
		        || other_type == NM_TYPE_SETTING_TEAM
		        || other_type == NM_TYPE_SETTING_VLAN);
	} else if (virtual_type == NM_TYPE_SETTING_TEAM) {
		return (   other_type == NM_TYPE_SETTING_WIRED
		        || other_type == NM_TYPE_SETTING_BRIDGE
		        || other_type == NM_TYPE_SETTING_BOND
		        || other_type == NM_TYPE_SETTING_TEAM
		        || other_type == NM_TYPE_SETTING_VLAN);
	} else if (virtual_type == NM_TYPE_SETTING_VLAN) {
		return (   other_type == NM_TYPE_SETTING_WIRED
		        || other_type == NM_TYPE_SETTING_WIRELESS
		        || other_type == NM_TYPE_SETTING_BRIDGE
		        || other_type == NM_TYPE_SETTING_BOND
		        || other_type == NM_TYPE_SETTING_TEAM
		        || other_type == NM_TYPE_SETTING_VLAN);
	} else {
		g_warn_if_reached ();
		return FALSE;
	}
}

typedef struct {
	const char *str;
	const char *num;
} BondMode;

static BondMode bond_mode_table[] = {
	[0] = { "balance-rr",    "0" },
	[1] = { "active-backup", "1" },
	[2] = { "balance-xor",   "2" },
	[3] = { "broadcast",     "3" },
	[4] = { "802.3ad",       "4" },
	[5] = { "balance-tlb",   "5" },
	[6] = { "balance-alb",   "6" },
};

/**
 * nm_utils_bond_mode_int_to_string:
 * @mode: bonding mode as a numeric value
 *
 * Convert bonding mode from integer value to descriptive name.
 * See https://www.kernel.org/doc/Documentation/networking/bonding.txt for
 * available modes.
 *
 * Returns: bonding mode string, or NULL on error
 *
 * Since: 1.2
 */
const char *
nm_utils_bond_mode_int_to_string (int mode)
{
	if (mode >= 0 && mode < G_N_ELEMENTS (bond_mode_table))
		return bond_mode_table[mode].str;
	return NULL;
}

/**
 * nm_utils_bond_mode_string_to_int:
 * @mode: bonding mode as string
 *
 * Convert bonding mode from string representation to numeric value.
 * See https://www.kernel.org/doc/Documentation/networking/bonding.txt for
 * available modes.
 * The @mode string can be either a descriptive name or a number (as string).
 *
 * Returns: numeric bond mode, or -1 on error
 *
 * Since: 1.2
 */
int
nm_utils_bond_mode_string_to_int (const char *mode)
{
	int i;

	if (!mode || !*mode)
		return -1;

	for (i = 0; i < G_N_ELEMENTS (bond_mode_table); i++) {
		if (   strcmp (mode, bond_mode_table[i].str) == 0
		    || strcmp (mode, bond_mode_table[i].num) == 0)
			return i;
	}
	return -1;
}

/*****************************************************************************/

#define STRSTRDICTKEY_V1_SET  0x01
#define STRSTRDICTKEY_V2_SET  0x02
#define STRSTRDICTKEY_ALL_SET 0x03

struct _NMUtilsStrStrDictKey {
	char type;
	char data[1];
};

guint
_nm_utils_strstrdictkey_hash (gconstpointer a)
{
	const NMUtilsStrStrDictKey *k = a;
	const char *p;
	NMHashState h;

	nm_hash_init (&h, 76642997u);
	if (k) {
		if (((int) k->type) & ~STRSTRDICTKEY_ALL_SET)
			g_return_val_if_reached (0);

		nm_hash_update_val (&h, k->type);
		if (k->type & STRSTRDICTKEY_ALL_SET) {
			p = strchr (k->data, '\0');
			if (k->type == STRSTRDICTKEY_ALL_SET) {
				/* the key contains two strings. Continue... */
				p = strchr (p + 1, '\0');
			}
			if (p != k->data)
				nm_hash_update (&h, k->data, p - k->data);
		}
	}
	return nm_hash_complete (&h);
}

gboolean
_nm_utils_strstrdictkey_equal  (gconstpointer a, gconstpointer b)
{
	const NMUtilsStrStrDictKey *k1 = a;
	const NMUtilsStrStrDictKey *k2 = b;

	if (k1 == k2)
		return TRUE;
	if (!k1 || !k2)
		return FALSE;

	if (k1->type != k2->type)
		return FALSE;

	if (k1->type & STRSTRDICTKEY_ALL_SET) {
		if (strcmp (k1->data, k2->data) != 0)
			return FALSE;

		if (k1->type == STRSTRDICTKEY_ALL_SET) {
			gsize l = strlen (k1->data) + 1;

			return strcmp (&k1->data[l], &k2->data[l]) == 0;
		}
	}

	return TRUE;
}

NMUtilsStrStrDictKey *
_nm_utils_strstrdictkey_create (const char *v1, const char *v2)
{
	char type = 0;
	gsize l1 = 0, l2 = 0;
	NMUtilsStrStrDictKey *k;

	if (!v1 && !v2)
		return g_malloc0 (1);

	/* we need to distinguish between ("",NULL) and (NULL,"").
	 * Thus, in @type we encode which strings we have present
	 * as not-NULL. */
	if (v1) {
		type |= STRSTRDICTKEY_V1_SET;
		l1 = strlen (v1) + 1;
	}
	if (v2) {
		type |= STRSTRDICTKEY_V2_SET;
		l2 = strlen (v2) + 1;
	}

	k = g_malloc (G_STRUCT_OFFSET (NMUtilsStrStrDictKey, data) + l1 + l2);
	k->type = type;
	if (v1)
		memcpy (&k->data[0], v1, l1);
	if (v2)
		memcpy (&k->data[l1], v2, l2);

	return k;
}

static gboolean
validate_dns_option (const char *name, gboolean numeric, gboolean ipv6,
                     const NMUtilsDNSOptionDesc *option_descs)
{
	const NMUtilsDNSOptionDesc *desc;

	if (!option_descs)
		return !!*name;

	for (desc = option_descs; desc->name; desc++) {
		if (!strcmp (name, desc->name) &&
		    numeric == desc->numeric &&
		    (!desc->ipv6_only || ipv6))
			return TRUE;
	}

	return FALSE;
}

/**
 * _nm_utils_dns_option_validate:
 * @option: option string
 * @out_name: (out) (allow-none): the option name
 * @out_value: (out) (allow-none): the option value
 * @ipv6: whether the option refers to a IPv6 configuration
 * @option_descs: (allow-none): an array of NMUtilsDNSOptionDesc which describes the
 * valid options
 *
 * Parses a DNS option in the form "name" or "name:number" and, if
 * @option_descs is not NULL, checks that the option conforms to one
 * of the provided descriptors. If @option_descs is NULL @ipv6 is
 * not considered.
 *
 * Returns: %TRUE when the parsing was successful and the option is valid,
 * %FALSE otherwise
 */
gboolean
_nm_utils_dns_option_validate (const char *option, char **out_name,
                               long *out_value, gboolean ipv6,
                               const NMUtilsDNSOptionDesc *option_descs)
{
	char **tokens, *ptr;
	gboolean ret = FALSE;

	g_return_val_if_fail (option != NULL, FALSE);

	if (out_name)
		*out_name = NULL;
	if (out_value)
		*out_value = -1;

	if (!option[0])
		return FALSE;

	tokens = g_strsplit (option, ":", 2);

	if (g_strv_length (tokens) == 1) {
		ret = validate_dns_option (tokens[0], FALSE, ipv6, option_descs);
		if (ret && out_name)
			*out_name = g_strdup (tokens[0]);
		goto out;
	}

	if (!tokens[1][0]) {
		ret = FALSE;
		goto out;
	}

	for (ptr = tokens[1]; *ptr; ptr++) {
		if (!g_ascii_isdigit (*ptr)) {
			ret = FALSE;
			goto out;
		}
	}

	ret = FALSE;
	if (validate_dns_option (tokens[0], TRUE, ipv6, option_descs)) {
		int value = _nm_utils_ascii_str_to_int64 (tokens[1], 10, 0, G_MAXINT32, -1);
		if (value >= 0) {
			if (out_name)
				*out_name = g_strdup (tokens[0]);
			if (out_value)
				*out_value = value;
			ret = TRUE;
		}
	}
out:
	g_strfreev (tokens);
	return ret;
}

/**
 * _nm_utils_dns_option_find_idx:
 * @array: an array of strings
 * @option: a dns option string
 *
 * Searches for an option in an array of strings. The match is
 * performed only the option name; the option value is ignored.
 *
 * Returns: the index of the option in the array or -1 if was not
 * found.
 */
gssize _nm_utils_dns_option_find_idx (GPtrArray *array, const char *option)
{
	gboolean ret;
	char *option_name, *tmp_name;
	guint i;

	if (!_nm_utils_dns_option_validate (option, &option_name, NULL, FALSE, NULL))
		return -1;

	for (i = 0; i < array->len; i++) {
		if (_nm_utils_dns_option_validate (array->pdata[i], &tmp_name, NULL, FALSE, NULL)) {
			ret = strcmp (tmp_name, option_name);
			g_free (tmp_name);
			if (!ret) {
				g_free (option_name);
				return i;
			}
		}

	}

	g_free (option_name);
	return -1;
}

/*****************************************************************************/

/**
 * nm_utils_enum_to_str:
 * @type: the %GType of the enum
 * @value: the value to be translated
 *
 * Converts an enum value to its string representation. If the enum is a
 * %G_TYPE_FLAGS the function returns a comma-separated list of matching values.
 * If the value has no corresponding string representation, it is converted
 * to a number. For enums it is converted to a decimal number, for flags
 * to an (unsigned) hex number.
 *
 * Returns: a newly allocated string or %NULL
 *
 * Since: 1.2
 */
char *
nm_utils_enum_to_str (GType type, int value)
{
	return _nm_utils_enum_to_str_full (type, value, ", ", NULL);
}

/**
 * nm_utils_enum_from_str:
 * @type: the %GType of the enum
 * @str: the input string
 * @out_value: (out) (allow-none): the output value
 * @err_token: (out) (allow-none) (transfer full): location to store the first unrecognized token
 *
 * Converts a string to the matching enum value.
 *
 * If the enum is a %G_TYPE_FLAGS the function returns the logical OR of values
 * matching the comma-separated tokens in the string; if an unknown token is found
 * the function returns %FALSE and stores a pointer to a newly allocated string
 * containing the unrecognized token in @err_token.
 *
 * Returns: %TRUE if the conversion was successful, %FALSE otherwise
 *
 * Since: 1.2
 */
gboolean
nm_utils_enum_from_str (GType type, const char *str,
                        int *out_value, char **err_token)
{
	return _nm_utils_enum_from_str_full (type, str, out_value, err_token, NULL);
}

/**
 * nm_utils_enum_get_values:
 * @type: the %GType of the enum
 * @from: the first element to be returned
 * @to: the last element to be returned
 *
 * Returns the list of possible values for a given enum.
 *
 * Returns: (transfer container): a NULL-terminated dynamically-allocated array of static strings
 * or %NULL on error
 *
 * Since: 1.2
 */
const char **nm_utils_enum_get_values (GType type, int from, int to)
{
	return _nm_utils_enum_get_values (type, from, to);
}

/*****************************************************************************/

static gboolean
_nm_utils_is_json_object_no_validation (const char *str, GError **error)
{
	nm_assert (str);

	/* libjansson also requires only utf-8 encoding. */
	if (!g_utf8_validate (str, -1, NULL)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("not valid utf-8"));
		return FALSE;
	}
	while (g_ascii_isspace (str[0]))
		str++;

	/* do some very basic validation to see if this might be a JSON object. */
	if (str[0] == '{') {
		gsize l;

		l = strlen (str) - 1;
		while (l > 0 && g_ascii_isspace (str[l]))
			l--;

		if (str[l] == '}')
			return TRUE;
	}

	g_set_error_literal (error,
	                     NM_CONNECTION_ERROR,
	                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
	                     _("is not a JSON object"));
	return FALSE;
}

/**
 * nm_utils_is_json_object:
 * @str: the JSON string to test
 * @error: optional error reason
 *
 * Returns: whether the passed string is valid JSON.
 *   If libnm is not compiled with libjansson support, this check will
 *   also return %TRUE for possibly invalid inputs. If that is a problem
 *   for you, you must validate the JSON yourself.
 *
 * Since: 1.6
 */
gboolean
nm_utils_is_json_object (const char *str, GError **error)
{
#if WITH_JSON_VALIDATION
	json_t *json;
	json_error_t jerror;

	g_return_val_if_fail (!error || !*error, FALSE);

	if (!str || !str[0]) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     str ? _("value is NULL") : _("value is empty"));
		return FALSE;
	}

	if (!nm_jansson_load ())
		return _nm_utils_is_json_object_no_validation (str, error);

	json = json_loads (str, JSON_REJECT_DUPLICATES, &jerror);
	if (!json) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("invalid JSON at position %d (%s)"),
		             jerror.position,
		             jerror.text);
		return FALSE;
	}

	/* valid JSON (depending on the definition) can also be a literal.
	 * Here we only allow objects. */
	if (!json_is_object (json)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("is not a JSON object"));
		return FALSE;
	}

	json_decref (json);
	return TRUE;
#else /* !WITH_JSON_VALIDATION */
	g_return_val_if_fail (!error || !*error, FALSE);

	if (!str || !str[0]) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     str ? _("value is NULL") : _("value is empty"));
		return FALSE;
	}

	return _nm_utils_is_json_object_no_validation (str, error);
#endif
}

static char *
attribute_escape (const char *src, char c1, char c2)
{
	char *ret, *dest;

	dest = ret = malloc (strlen (src) * 2 + 1);

	while (*src) {
		if (*src == c1 || *src == c2 || *src == '\\')
			*dest++ = '\\';
		*dest++ = *src++;
	}
	*dest++ = '\0';

	return ret;
}

static char *
attribute_unescape (const char *start, const char *end)
{
	char *ret, *dest;

	nm_assert (start <= end);
	dest = ret = g_malloc (end - start + 1);

	for (; start < end && *start; start++) {
		if (*start == '\\') {
			start++;
			if (!*start)
				break;
		}
		*dest++ = *start;
	}
	*dest = '\0';

	return ret;
}

/**
 * nm_utils_parse_variant_attributes:
 * @string: the input string
 * @attr_separator: the attribute separator character
 * @key_value_separator: character separating key and values
 * @ignore_unknown: whether unknown attributes should be ignored
 * @spec: the attribute format specifiers
 * @error: (out) (allow-none): location to store the error on failure
 *
 * Parse attributes from a string.
 *
 * Returns: (transfer full) (element-type utf8 GVariant): a #GHashTable mapping
 * attribute names to #GVariant values. Warning: the variant are still floating
 * references, owned by the hash table. If you take a reference, ensure to sink
 * the one of the hash table first.
 *
 * Since: 1.8
 */
GHashTable *
nm_utils_parse_variant_attributes (const char *string,
                                   char attr_separator,
                                   char key_value_separator,
                                   gboolean ignore_unknown,
                                   const NMVariantAttributeSpec *const *spec,
                                   GError **error)
{
	gs_unref_hashtable GHashTable *ht = NULL;
	const char *ptr = string, *start = NULL, *sep;
	GVariant *variant;
	const NMVariantAttributeSpec *const *s;

	g_return_val_if_fail (string, NULL);
	g_return_val_if_fail (attr_separator, NULL);
	g_return_val_if_fail (key_value_separator, NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	ht = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, (GDestroyNotify) g_variant_unref);

	while (TRUE) {
		gs_free char *name = NULL, *value = NULL;

		if (!start)
			start = ptr;
		if (*ptr == '\\') {
			ptr++;
			if (!*ptr) {
				g_set_error_literal (error,
				                     NM_CONNECTION_ERROR,
				                     NM_CONNECTION_ERROR_FAILED,
				                     _("unterminated escape sequence"));
				return NULL;
			}
			goto next;
		}
		if (*ptr == attr_separator || *ptr == '\0') {
			if (ptr == start) {
				/* multiple separators */
				start = NULL;
				goto next;
			}

			/* Find the key-value separator */
			for (sep = start; sep != ptr; sep++) {
				if (*sep == '\\') {
					sep++;
					if (!*sep) {
						g_set_error_literal (error,
						                     NM_CONNECTION_ERROR,
						                     NM_CONNECTION_ERROR_FAILED,
						                     _("unterminated escape sequence"));
						return NULL;
					}
				}
				if (*sep == key_value_separator)
					break;
			}

			name = attribute_unescape (start, sep);

			for (s = spec; *s; s++) {
				if (g_hash_table_contains (ht, (*s)->name))
					continue;
				if (nm_streq (name, (*s)->name))
					break;
				if (   (*s)->no_value
				    && g_variant_type_equal ((*s)->type, G_VARIANT_TYPE_STRING))
					break;
			}

			if (!*s) {
				if (ignore_unknown)
					goto next;
				else {
					g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
					             _("unknown attribute '%s'"), name);
					return NULL;
				}
			}

			if ((*s)->no_value) {
				if ((*s)->consumes_rest) {
					value = g_strdup (start);
					ptr = strchr (start, '\0');
				} else {
					value = g_steal_pointer (&name);
				}
			} else {
				if (*sep != key_value_separator) {
					g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
					             _("missing key-value separator '%c' after '%s'"), key_value_separator, name);
					return NULL;
				}

				/* The attribute and key/value separators are the same. Look for the next one. */
				if (ptr == sep)
					goto next;

				value = attribute_unescape (sep + 1, ptr);
			}

			if (g_variant_type_equal ((*s)->type, G_VARIANT_TYPE_UINT32)) {
				gint64 num = _nm_utils_ascii_str_to_int64 (value, 10, 0, G_MAXUINT32, -1);

				if (num == -1) {
					g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
					             _("invalid uint32 value '%s' for attribute '%s'"), value, (*s)->name);
					return NULL;
				}
				variant = g_variant_new_uint32 (num);
			} else if (g_variant_type_equal ((*s)->type, G_VARIANT_TYPE_BYTE)) {
				gint64 num = _nm_utils_ascii_str_to_int64 (value, 10, 0, G_MAXUINT8, -1);

				if (num == -1) {
					g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
					             _("invalid uint8 value '%s' for attribute '%s'"), value, (*s)->name);
					return NULL;
				}
				variant = g_variant_new_byte ((guchar) num);
			} else if (g_variant_type_equal ((*s)->type, G_VARIANT_TYPE_BOOLEAN)) {
				int b;

				b = (*s)->no_value ? TRUE :_nm_utils_ascii_str_to_bool (value, -1);
				if (b == -1) {
					g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
					             _("invalid boolean value '%s' for attribute '%s'"), value, (*s)->name);
					return NULL;
				}
				variant = g_variant_new_boolean (b);
			} else if (g_variant_type_equal ((*s)->type, G_VARIANT_TYPE_STRING)) {
				variant = g_variant_new_take_string (g_steal_pointer (&value));
			} else if (g_variant_type_equal ((*s)->type, G_VARIANT_TYPE_BYTESTRING)) {
				variant = g_variant_new_bytestring (value);
			} else {
				g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
				             _("unsupported attribute '%s' of type '%s'"), (*s)->name,
				             (char *) (*s)->type);
				return NULL;
			}

			g_hash_table_insert (ht, g_strdup ((*s)->name), variant);
			start = NULL;
		}
next:
		if (*ptr == '\0')
			break;
		ptr++;
	}

	return g_steal_pointer (&ht);
}

void
_nm_utils_format_variant_attributes_full (GString *str,
                                          const NMUtilsNamedValue *values,
                                          guint num_values,
                                          char attr_separator,
                                          char key_value_separator)
{
	const char *name, *value;
	GVariant *variant;
	char *escaped;
	char buf[64];
	char sep = 0;
	guint i;

	for (i = 0; i < num_values; i++) {
		name = values[i].name;
		variant = (GVariant *) values[i].value_ptr;
		value = NULL;

		if (g_variant_is_of_type (variant, G_VARIANT_TYPE_UINT32))
			value = nm_sprintf_buf (buf, "%u", g_variant_get_uint32 (variant));
		else if (g_variant_is_of_type (variant, G_VARIANT_TYPE_BYTE))
			value = nm_sprintf_buf (buf, "%hhu", g_variant_get_byte (variant));
		else if (g_variant_is_of_type (variant, G_VARIANT_TYPE_BOOLEAN))
			value = g_variant_get_boolean (variant) ? "true" : "false";
		else if (g_variant_is_of_type (variant, G_VARIANT_TYPE_STRING))
			value = g_variant_get_string (variant, NULL);
		else if (g_variant_is_of_type (variant, G_VARIANT_TYPE_BYTESTRING))
			value = g_variant_get_bytestring (variant);
		else
			continue;

		if (sep)
			g_string_append_c (str, sep);

		escaped = attribute_escape (name, attr_separator, key_value_separator);
		g_string_append (str, escaped);
		g_free (escaped);

		g_string_append_c (str, key_value_separator);

		escaped = attribute_escape (value, attr_separator, key_value_separator);
		g_string_append (str, escaped);
		g_free (escaped);

		sep = attr_separator;
	}
}

/*
 * nm_utils_format_variant_attributes:
 * @attributes: (element-type utf8 GVariant): a #GHashTable mapping attribute names to #GVariant values
 * @attr_separator: the attribute separator character
 * @key_value_separator: character separating key and values
 *
 * Format attributes to a string.
 *
 * Returns: (transfer full): the string representing attributes, or %NULL
 *    in case there are no attributes
 *
 * Since: 1.8
 */
char *
nm_utils_format_variant_attributes (GHashTable *attributes,
                                    char attr_separator,
                                    char key_value_separator)
{
	GString *str = NULL;
	gs_free NMUtilsNamedValue *values = NULL;
	guint len;

	g_return_val_if_fail (attr_separator, NULL);
	g_return_val_if_fail (key_value_separator, NULL);

	if (!attributes || !g_hash_table_size (attributes))
		return NULL;

	values = nm_utils_named_values_from_str_dict (attributes, &len);

	str = g_string_new ("");
	_nm_utils_format_variant_attributes_full (str,
	                                          values,
	                                          len,
	                                          attr_separator,
	                                          key_value_separator);
	return g_string_free (str, FALSE);
}

/*****************************************************************************/

/*
 * nm_utils_get_timestamp_msec():
 *
 * Gets current time in milliseconds of CLOCK_BOOTTIME.
 *
 * Returns: time in milliseconds
 *
 * Since: 1.12
 */
gint64
nm_utils_get_timestamp_msec (void)
{
	gint64 ts;

	ts = nm_utils_clock_gettime_ms (CLOCK_BOOTTIME);
	if (ts >= 0)
		return ts;

	if (ts == -EINVAL) {
		/* The fallback to CLOCK_MONOTONIC is taken only if we're running on a
		 * criminally old kernel, prior to 2.6.39 (released on 18 May, 2011).
		 * That happens during buildcheck on old builders, we don't expect to
		 * be actually runs on kernels that old. */
		ts = nm_utils_clock_gettime_ms (CLOCK_MONOTONIC);
		if (ts >= 0)
			return ts;
	}

	g_return_val_if_reached (-1);
}

/*****************************************************************************/

/**
 * nm_utils_version:
 *
 * Returns: the version ID of the libnm version. That is, the %NM_VERSION
 *   at runtime.
 *
 * Since: 1.6.0
 */
guint
nm_utils_version (void)
{
	return NM_VERSION;
}

/*****************************************************************************/

/**
 * nm_utils_base64secret_decode:
 * @base64_key: the (possibly invalid) base64 encode key.
 * @required_key_len: the expected (binary) length of the key after
 *   decoding. If the length does not match, the validation fails.
 * @out_key: (allow-none): (out): an optional output buffer for the binary
 *   key. If given, it will be filled with exactly @required_key_len
 *   bytes.
 *
 * Returns: %TRUE if the input key is a valid base64 encoded key
 *   with @required_key_len bytes.
 *
 * Since: 1.16
 */
gboolean
nm_utils_base64secret_decode (const char *base64_key,
                              gsize required_key_len,
                              guint8 *out_key)
{
	gs_free guint8 *bin_arr = NULL;
	gsize base64_key_len;
	gsize bin_len;
	int r;

	if (!base64_key)
		return FALSE;

	base64_key_len = strlen (base64_key);

	r = nm_sd_utils_unbase64mem (base64_key, base64_key_len, TRUE, &bin_arr, &bin_len);
	if (r < 0)
		return FALSE;
	if (bin_len != required_key_len) {
		nm_explicit_bzero (bin_arr, bin_len);
		return FALSE;
	}

	if (out_key)
		memcpy (out_key, bin_arr, required_key_len);

	nm_explicit_bzero (bin_arr, bin_len);
	return TRUE;
}

gboolean
nm_utils_base64secret_normalize (const char *base64_key,
                                 gsize required_key_len,
                                 char **out_base64_key_norm)
{
	gs_free guint8 *buf_free = NULL;
	guint8 buf_static[200];
	guint8 *buf;

	if (required_key_len > sizeof (buf_static)) {
		buf_free = g_new (guint8, required_key_len);
		buf = buf_free;
	} else
		buf = buf_static;

	if (!nm_utils_base64secret_decode (base64_key, required_key_len, buf)) {
		NM_SET_OUT (out_base64_key_norm, NULL);
		return FALSE;
	}

	NM_SET_OUT (out_base64_key_norm, g_base64_encode (buf, required_key_len));
	nm_explicit_bzero (buf, required_key_len);
	return TRUE;
}

GVariant *
_nm_utils_bridge_vlans_to_dbus (const NMSettInfoSetting *sett_info,
                                guint property_idx,
                                NMConnection *connection,
                                NMSetting *setting,
                                NMConnectionSerializationFlags flags,
                                const NMConnectionSerializationOptions *options)
{
	gs_unref_ptrarray GPtrArray *vlans = NULL;
	GVariantBuilder builder;
	guint i;
	const char *property_name = sett_info->property_infos[property_idx].name;

	nm_assert (property_name);

	g_object_get (setting, property_name, &vlans, NULL);
	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aa{sv}"));

	if (vlans) {
		for (i = 0; i < vlans->len; i++) {
			NMBridgeVlan *vlan = vlans->pdata[i];
			GVariantBuilder vlan_builder;
			guint16 vid_start, vid_end;

			nm_bridge_vlan_get_vid_range (vlan, &vid_start, &vid_end);

			g_variant_builder_init (&vlan_builder, G_VARIANT_TYPE_VARDICT);
			g_variant_builder_add (&vlan_builder, "{sv}", "vid-start",
			                       g_variant_new_uint16 (vid_start));
			g_variant_builder_add (&vlan_builder, "{sv}", "vid-end",
			                       g_variant_new_uint16 (vid_end));
			g_variant_builder_add (&vlan_builder, "{sv}", "pvid",
			                       g_variant_new_boolean (nm_bridge_vlan_is_pvid (vlan)));
			g_variant_builder_add (&vlan_builder, "{sv}", "untagged",
			                       g_variant_new_boolean (nm_bridge_vlan_is_untagged (vlan)));
			g_variant_builder_add (&builder, "a{sv}", &vlan_builder);
		}
	}

	return g_variant_builder_end (&builder);
}

gboolean
_nm_utils_bridge_vlans_from_dbus (NMSetting *setting,
                                  GVariant *connection_dict,
                                  const char *property,
                                  GVariant *value,
                                  NMSettingParseFlags parse_flags,
                                  GError **error)
{
	gs_unref_ptrarray GPtrArray *vlans = NULL;
	GVariantIter vlan_iter;
	GVariant *vlan_var;

	g_return_val_if_fail (g_variant_is_of_type (value, G_VARIANT_TYPE ("aa{sv}")), FALSE);

	vlans = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_bridge_vlan_unref);
	g_variant_iter_init (&vlan_iter, value);
	while (g_variant_iter_next (&vlan_iter, "@a{sv}", &vlan_var)) {
		_nm_unused gs_unref_variant GVariant *var_unref = vlan_var;
		NMBridgeVlan *vlan;
		guint16 vid_start, vid_end;
		gboolean pvid = FALSE, untagged = FALSE;

		if (!g_variant_lookup (vlan_var, "vid-start", "q", &vid_start))
			continue;
		if (   vid_start < NM_BRIDGE_VLAN_VID_MIN
		    || vid_start > NM_BRIDGE_VLAN_VID_MAX)
			continue;

		if (!g_variant_lookup (vlan_var, "vid-end", "q", &vid_end))
			continue;
		if (   vid_end < NM_BRIDGE_VLAN_VID_MIN
		    || vid_end > NM_BRIDGE_VLAN_VID_MAX)
			continue;
		if (vid_start > vid_end)
			continue;

		if (!g_variant_lookup (vlan_var, "pvid", "b", &pvid))
			pvid = FALSE;
		if (pvid && vid_start != vid_end)
			continue;
		if (!g_variant_lookup (vlan_var, "untagged", "b", &untagged))
			untagged = FALSE;

		vlan = nm_bridge_vlan_new (vid_start, vid_end);
		nm_bridge_vlan_set_untagged (vlan, untagged);
		nm_bridge_vlan_set_pvid (vlan, pvid);
		g_ptr_array_add (vlans, vlan);
	}

	g_object_set (setting, property, vlans, NULL);

	return TRUE;
}

gboolean
_nm_utils_bridge_vlan_verify_list (GPtrArray *vlans,
                                   gboolean check_normalizable,
                                   GError **error,
                                   const char *setting,
                                   const char *property)
{
	guint i;
	gs_unref_hashtable GHashTable *h = NULL;
	gboolean pvid_found = FALSE;

	if (   !vlans
	    || vlans->len <= 1)
		return TRUE;

	if (check_normalizable) {
		guint16 vid_prev_end, vid_start, vid_end;

		nm_assert (_nm_utils_bridge_vlan_verify_list (vlans, FALSE, NULL, setting, property));

		nm_bridge_vlan_get_vid_range (vlans->pdata[0], NULL, &vid_prev_end);
		for (i = 1; i < vlans->len; i++) {
			const NMBridgeVlan *vlan = vlans->pdata[i];

			nm_bridge_vlan_get_vid_range (vlan, &vid_start, &vid_end);

			if (vid_prev_end > vid_start) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("Bridge VLANs %d and %d are not sorted by ascending vid"),
				             vid_prev_end,
				             vid_start);
				g_prefix_error (error, "%s.%s: ", setting, property);
				return FALSE;
			}

			vid_prev_end = vid_end;
		}
		return TRUE;
	}

	h = g_hash_table_new (nm_direct_hash, NULL);
	for (i = 0; i < vlans->len; i++) {
		NMBridgeVlan *vlan = vlans->pdata[i];
		guint16 v, vid_start, vid_end;

		nm_bridge_vlan_get_vid_range (vlan, &vid_start, &vid_end);

		for (v = vid_start; v <= vid_end; v++) {
			if (!nm_g_hash_table_add (h, GUINT_TO_POINTER (v))) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("duplicate bridge VLAN vid %u"), v);
				g_prefix_error (error, "%s.%s: ", setting, property);
				return FALSE;
			}
		}

		if (nm_bridge_vlan_is_pvid (vlan)) {
			if (   vid_start != vid_end
			    || pvid_found) {
				g_set_error_literal (error,
				                     NM_CONNECTION_ERROR,
				                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
				                     _("only one VLAN can be the PVID"));
				g_prefix_error (error, "%s.%s: ", setting, property);
				return FALSE;
			}
			pvid_found = TRUE;
		}
	}

	return TRUE;
}

gboolean
nm_utils_connection_is_adhoc_wpa (NMConnection *connection)
{
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	const char *key_mgmt;
	const char *mode;

	s_wifi = nm_connection_get_setting_wireless (connection);
	if (!s_wifi)
		return FALSE;

	mode = nm_setting_wireless_get_mode (s_wifi);
	if (!nm_streq0 (mode, NM_SETTING_WIRELESS_MODE_ADHOC))
		return FALSE;

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	if (!s_wsec)
		return FALSE;

	key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wsec);
	if (!nm_streq0 (key_mgmt, "wpa-none"))
		return FALSE;

	return TRUE;
}
