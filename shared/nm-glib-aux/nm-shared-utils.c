// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2016 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-shared-utils.h"

#include <arpa/inet.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <glib-unix.h>
#include <net/if.h>

#include "nm-errno.h"
#include "nm-str-buf.h"

/*****************************************************************************/

const void *const _NM_PTRARRAY_EMPTY[1] = { NULL };

/*****************************************************************************/

const NMIPAddr nm_ip_addr_zero = { };

/* this initializes a struct in_addr/in6_addr and allows for untrusted
 * arguments (like unsuitable @addr_family or @src_len). It's almost safe
 * in the sense that it verifies input arguments strictly. Also, it
 * uses memcpy() to access @src, so alignment is not an issue.
 *
 * Only potential pitfalls:
 *
 * - it allows for @addr_family to be AF_UNSPEC. If that is the case (and the
 *   caller allows for that), the caller MUST provide @out_addr_family.
 * - when setting @dst to an IPv4 address, the trailing bytes are not touched.
 *   Meaning, if @dst is an NMIPAddr union, only the first bytes will be set.
 *   If that matter to you, clear @dst before. */
gboolean
nm_ip_addr_set_from_untrusted (int addr_family,
                               gpointer dst,
                               gconstpointer src,
                               gsize src_len,
                               int *out_addr_family)
{
	nm_assert (dst);

	switch (addr_family) {
	case AF_UNSPEC:
		if (!out_addr_family) {
			/* when the callers allow undefined @addr_family, they must provide
			 * an @out_addr_family argument. */
			nm_assert_not_reached ();
			return FALSE;
		}
		switch (src_len) {
		case sizeof (struct in_addr):  addr_family = AF_INET;  break;
		case sizeof (struct in6_addr): addr_family = AF_INET6; break;
		default:
			return FALSE;
		}
		break;
	case AF_INET:
		if (src_len != sizeof (struct in_addr))
			return FALSE;
		break;
	case AF_INET6:
		if (src_len != sizeof (struct in6_addr))
			return FALSE;
		break;
	default:
		/* when the callers allow undefined @addr_family, they must provide
		 * an @out_addr_family argument. */
		nm_assert (out_addr_family);
		return FALSE;
	}

	nm_assert (src);

	memcpy (dst, src, src_len);
	NM_SET_OUT (out_addr_family, addr_family);
	return TRUE;
}

/*****************************************************************************/

gsize
nm_utils_get_next_realloc_size (gboolean true_realloc, gsize requested)
{
	gsize n, x;

	/* https://doc.qt.io/qt-5/containers.html#growth-strategies */

	if (requested <= 40) {
		/* small allocations. Increase in small steps of 8 bytes.
		 *
		 * We get thus sizes of 8, 16, 32, 40. */
		if (requested <= 8)
			return 8;
		if (requested <= 16)
			return 16;
		if (requested <= 32)
			return 32;

		/* The return values for < 104 are essentially hard-coded, and the choice here is
		 * made without very strong reasons.
		 *
		 * We want to stay 24 bytes below the power-of-two border 64. Hence, return 40 here.
		 * However, the next step then is already 104 (128 - 24). It's a larger gap than in
		 * the steps before.
		 *
		 * It's not clear whether some of the steps should be adjusted (or how exactly). */
		return 40;
	}

	if (   requested <= 0x2000u - 24u
	    || G_UNLIKELY (!true_realloc)) {
		/* mid sized allocations. Return next power of two, minus 24 bytes extra space
		 * at the beginning.
		 * That means, we double the size as we grow.
		 *
		 * With !true_realloc, it means that the caller does not intend to call
		 * realloc() but instead clone the buffer. This is for example the case, when we
		 * want to nm_explicit_bzero() the old buffer. In that case we really want to grow
		 * the buffer exponentially every time and not increment in page sizes of 4K (below).
		 *
		 * We get thus sizes of 104, 232, 488, 1000, 2024, 4072, 8168... */

		if (G_UNLIKELY (requested > G_MAXSIZE / 2u - 24u))
			return G_MAXSIZE;

		x = requested + 24u;
		n = 128u;
		while (n < x) {
			n <<= 1;
			nm_assert (n > 128u);
		}

		nm_assert (n > 24u && n - 24u >= requested);
		return n - 24u;
	}

	if (G_UNLIKELY (requested > G_MAXSIZE - 0x1000u - 24u))
		return G_MAXSIZE;

	/* For large allocations (with !true_realloc) we allocate memory in chunks of
	 * 4K (- 24 bytes extra), assuming that the memory gets mmapped and thus
	 * realloc() is efficient by just reordering pages. */
	n = ((requested + (0x0FFFu + 24u)) & ~((gsize) 0x0FFFu)) - 24u;
	nm_assert (n >= requested);
	return n;
}

/*****************************************************************************/

pid_t
nm_utils_gettid (void)
{
	return (pid_t) syscall (SYS_gettid);
}

/* Used for asserting that this function is called on the main-thread.
 * The main-thread is determined by remembering the thread-id
 * of when the function was called the first time.
 *
 * When forking, the thread-id is again reset upon first call. */
gboolean
_nm_assert_on_main_thread (void)
{
	G_LOCK_DEFINE_STATIC (lock);
	static pid_t seen_tid;
	static pid_t seen_pid;
	pid_t tid;
	pid_t pid;
	gboolean success = FALSE;

	tid = nm_utils_gettid ();
	nm_assert (tid != 0);

	G_LOCK (lock);

	if (G_LIKELY (tid == seen_tid)) {
		/* we don't care about false positives (when the process forked, and the thread-id
		 * is accidentally re-used) . It's for assertions only. */
		success = TRUE;
	} else {
		pid = getpid ();
		nm_assert (pid != 0);

		if (   seen_tid == 0
			|| seen_pid != pid) {
			/* either this is the first time we call the function, or the process
			 * forked. In both cases, remember the thread-id. */
			seen_tid = tid;
			seen_pid = pid;
			success = TRUE;
		}
	}

	G_UNLOCK (lock);

	return success;
}

/*****************************************************************************/

void
nm_utils_strbuf_append_c (char **buf, gsize *len, char c)
{
	switch (*len) {
	case 0:
		return;
	case 1:
		(*buf)[0] = '\0';
		*len = 0;
		(*buf)++;
		return;
	default:
		(*buf)[0] = c;
		(*buf)[1] = '\0';
		(*len)--;
		(*buf)++;
		return;
	}
}

void
nm_utils_strbuf_append_bin (char **buf, gsize *len, gconstpointer str, gsize str_len)
{
	switch (*len) {
	case 0:
		return;
	case 1:
		if (str_len == 0) {
			(*buf)[0] = '\0';
			return;
		}
		(*buf)[0] = '\0';
		*len = 0;
		(*buf)++;
		return;
	default:
		if (str_len == 0) {
			(*buf)[0] = '\0';
			return;
		}
		if (str_len >= *len) {
			memcpy (*buf, str, *len - 1);
			(*buf)[*len - 1] = '\0';
			*buf = &(*buf)[*len];
			*len = 0;
		} else {
			memcpy (*buf, str, str_len);
			*buf = &(*buf)[str_len];
			(*buf)[0] = '\0';
			*len -= str_len;
		}
		return;
	}
}

void
nm_utils_strbuf_append_str (char **buf, gsize *len, const char *str)
{
	gsize src_len;

	switch (*len) {
	case 0:
		return;
	case 1:
		if (!str || !*str) {
			(*buf)[0] = '\0';
			return;
		}
		(*buf)[0] = '\0';
		*len = 0;
		(*buf)++;
		return;
	default:
		if (!str || !*str) {
			(*buf)[0] = '\0';
			return;
		}
		src_len = g_strlcpy (*buf, str, *len);
		if (src_len >= *len) {
			*buf = &(*buf)[*len];
			*len = 0;
		} else {
			*buf = &(*buf)[src_len];
			*len -= src_len;
		}
		return;
	}
}

void
nm_utils_strbuf_append (char **buf, gsize *len, const char *format, ...)
{
	char *p = *buf;
	va_list args;
	int retval;

	if (*len == 0)
		return;

	va_start (args, format);
	retval = g_vsnprintf (p, *len, format, args);
	va_end (args);

	if ((gsize) retval >= *len) {
		*buf = &p[*len];
		*len = 0;
	} else {
		*buf = &p[retval];
		*len -= retval;
	}
}

/**
 * nm_utils_strbuf_seek_end:
 * @buf: the input/output buffer
 * @len: the input/output length of the buffer.
 *
 * Commonly, one uses nm_utils_strbuf_append*(), to incrementally
 * append strings to the buffer. However, sometimes we need to use
 * existing API to write to the buffer.
 * After doing so, we want to adjust the buffer counter.
 * Essentially,
 *
 *   g_snprintf (buf, len, ...);
 *   nm_utils_strbuf_seek_end (&buf, &len);
 *
 * is almost the same as
 *
 *   nm_utils_strbuf_append (&buf, &len, ...);
 *
 * The only difference is the behavior when the string got truncated:
 * nm_utils_strbuf_append() will recognize that and set the remaining
 * length to zero.
 *
 * In general, the behavior is:
 *
 *  - if *len is zero, do nothing
 *  - if the buffer contains a NUL byte within the first *len characters,
 *    the buffer is pointed to the NUL byte and len is adjusted. In this
 *    case, the remaining *len is always >= 1.
 *    In particular, that is also the case if the NUL byte is at the very last
 *    position ((*buf)[*len -1]). That happens, when the previous operation
 *    either fit the string exactly into the buffer or the string was truncated
 *    by g_snprintf(). The difference cannot be determined.
 *  - if the buffer contains no NUL bytes within the first *len characters,
 *    write NUL at the last position, set *len to zero, and point *buf past
 *    the NUL byte. This would happen with
 *
 *       strncpy (buf, long_str, len);
 *       nm_utils_strbuf_seek_end (&buf, &len).
 *
 *    where strncpy() does truncate the string and not NUL terminate it.
 *    nm_utils_strbuf_seek_end() would then NUL terminate it.
 */
void
nm_utils_strbuf_seek_end (char **buf, gsize *len)
{
	gsize l;
	char *end;

	nm_assert (len);
	nm_assert (buf && *buf);

	if (*len <= 1) {
		if (   *len == 1
		    && (*buf)[0])
			goto truncate;
		return;
	}

	end = memchr (*buf, 0, *len);
	if (end) {
		l = end - *buf;
		nm_assert (l < *len);

		*buf = end;
		*len -= l;
		return;
	}

truncate:
	/* hm, no NUL character within len bytes.
	 * Just NUL terminate the array and consume them
	 * all. */
	*buf += *len;
	(*buf)[-1] = '\0';
	*len = 0;
	return;
}

/*****************************************************************************/

/**
 * nm_utils_gbytes_equals:
 * @bytes: (allow-none): a #GBytes array to compare. Note that
 *   %NULL is treated like an #GBytes array of length zero.
 * @mem_data: the data pointer with @mem_len bytes
 * @mem_len: the length of the data pointer
 *
 * Returns: %TRUE if @bytes contains the same data as @mem_data. As a
 *   special case, a %NULL @bytes is treated like an empty array.
 */
gboolean
nm_utils_gbytes_equal_mem (GBytes *bytes,
                           gconstpointer mem_data,
                           gsize mem_len)
{
	gconstpointer p;
	gsize l;

	if (!bytes) {
		/* as a special case, let %NULL GBytes compare idential
		 * to an empty array. */
		return (mem_len == 0);
	}

	p = g_bytes_get_data (bytes, &l);
	return    l == mem_len
	       && (   mem_len == 0 /* allow @mem_data to be %NULL */
	           || memcmp (p, mem_data, mem_len) == 0);
}

GVariant *
nm_utils_gbytes_to_variant_ay (GBytes *bytes)
{
	const guint8 *p;
	gsize l;

	if (!bytes) {
		/* for convenience, accept NULL to return an empty variant */
		return g_variant_new_array (G_VARIANT_TYPE_BYTE, NULL, 0);
	}

	p = g_bytes_get_data (bytes, &l);
	return g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, p, l, 1);
}

/*****************************************************************************/

/* Convert a hash table with "char *" keys and values to an "a{ss}" GVariant.
 * The keys will be sorted asciibetically.
 * Returns a floating reference.
 */
GVariant *
nm_utils_strdict_to_variant_ass (GHashTable *strdict)
{
	GHashTableIter iter;
	const char *key, *value;
	GVariantBuilder builder;
	guint i, len;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{ss}"));

	if (!strdict)
		goto out;
	len = g_hash_table_size (strdict);
	if (!len)
		goto out;

	g_hash_table_iter_init (&iter, strdict);
	if (!g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &value))
		nm_assert_not_reached ();

	if (len == 1)
		g_variant_builder_add (&builder, "{ss}", key, value);
	else {
		gs_free NMUtilsNamedValue *idx_free = NULL;
		NMUtilsNamedValue *idx;

		if (len > 300 / sizeof (NMUtilsNamedValue)) {
			idx_free = g_new (NMUtilsNamedValue, len);
			idx = idx_free;
		} else
			idx = g_alloca (sizeof (NMUtilsNamedValue) * len);

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

/*****************************************************************************/

/**
 * nm_strquote:
 * @buf: the output buffer of where to write the quoted @str argument.
 * @buf_len: the size of @buf.
 * @str: (allow-none): the string to quote.
 *
 * Writes @str to @buf with quoting. The resulting buffer
 * is always NUL terminated, unless @buf_len is zero.
 * If @str is %NULL, it writes "(null)".
 *
 * If @str needs to be truncated, the closing quote is '^' instead
 * of '"'.
 *
 * This is similar to nm_strquote_a(), which however uses alloca()
 * to allocate a new buffer. Also, here @buf_len is the size of @buf,
 * while nm_strquote_a() has the number of characters to print. The latter
 * doesn't include the quoting.
 *
 * Returns: the input buffer with the quoted string.
 */
const char *
nm_strquote (char *buf, gsize buf_len, const char *str)
{
	const char *const buf0 = buf;

	if (!str) {
		nm_utils_strbuf_append_str (&buf, &buf_len, "(null)");
		goto out;
	}

	if (G_UNLIKELY (buf_len <= 2)) {
		switch (buf_len) {
		case 2:
			*(buf++) = '^';
			/* fall-through */
		case 1:
			*(buf++) = '\0';
			break;
		}
		goto out;
	}

	*(buf++) = '"';
	buf_len--;

	nm_utils_strbuf_append_str (&buf, &buf_len, str);

	/* if the string was too long we indicate truncation with a
	 * '^' instead of a closing quote. */
	if (G_UNLIKELY (buf_len <= 1)) {
		switch (buf_len) {
		case 1:
			buf[-1] = '^';
			break;
		case 0:
			buf[-2] = '^';
			break;
		default:
			nm_assert_not_reached ();
			break;
		}
	} else {
		nm_assert (buf_len >= 2);
		*(buf++) = '"';
		*(buf++) = '\0';
	}

out:
	return buf0;
}

/*****************************************************************************/

char _nm_utils_to_string_buffer[];

void
nm_utils_to_string_buffer_init (char **buf, gsize *len)
{
	if (!*buf) {
		*buf = _nm_utils_to_string_buffer;
		*len = sizeof (_nm_utils_to_string_buffer);
	}
}

gboolean
nm_utils_to_string_buffer_init_null (gconstpointer obj, char **buf, gsize *len)
{
	nm_utils_to_string_buffer_init (buf, len);
	if (!obj) {
		g_strlcpy (*buf, "(null)", *len);
		return FALSE;
	}
	return TRUE;
}

/*****************************************************************************/

const char *
nm_utils_flags2str (const NMUtilsFlags2StrDesc *descs,
                    gsize n_descs,
                    unsigned flags,
                    char *buf,
                    gsize len)
{
	gsize i;
	char *p;

#if NM_MORE_ASSERTS > 10
	nm_assert (descs);
	nm_assert (n_descs > 0);
	for (i = 0; i < n_descs; i++) {
		gsize j;

		nm_assert (descs[i].name && descs[i].name[0]);
		for (j = 0; j < i; j++)
			nm_assert (descs[j].flag != descs[i].flag);
	}
#endif

	nm_utils_to_string_buffer_init (&buf, &len);

	if (!len)
		return buf;

	buf[0] = '\0';
	p = buf;
	if (!flags) {
		for (i = 0; i < n_descs; i++) {
			if (!descs[i].flag) {
				nm_utils_strbuf_append_str (&p, &len, descs[i].name);
				break;
			}
		}
		return buf;
	}

	for (i = 0; flags && i < n_descs; i++) {
		if (   descs[i].flag
		    && NM_FLAGS_ALL (flags, descs[i].flag)) {
			flags &= ~descs[i].flag;

			if (buf[0] != '\0')
				nm_utils_strbuf_append_c (&p, &len, ',');
			nm_utils_strbuf_append_str (&p, &len, descs[i].name);
		}
	}
	if (flags) {
		if (buf[0] != '\0')
			nm_utils_strbuf_append_c (&p, &len, ',');
		nm_utils_strbuf_append (&p, &len, "0x%x", flags);
	}
	return buf;
};

/*****************************************************************************/

/**
 * _nm_utils_ip4_prefix_to_netmask:
 * @prefix: a CIDR prefix
 *
 * Returns: the netmask represented by the prefix, in network byte order
 **/
guint32
_nm_utils_ip4_prefix_to_netmask (guint32 prefix)
{
	return prefix < 32 ? ~htonl(0xFFFFFFFF >> prefix) : 0xFFFFFFFF;
}

gconstpointer
nm_utils_ipx_address_clear_host_address (int family, gpointer dst, gconstpointer src, guint8 plen)
{
	g_return_val_if_fail (dst, NULL);

	switch (family) {
	case AF_INET:
		g_return_val_if_fail (plen <= 32, NULL);

		if (!src) {
			/* allow "self-assignment", by specifying %NULL as source. */
			src = dst;
		}

		*((guint32 *) dst) = nm_utils_ip4_address_clear_host_address (*((guint32 *) src), plen);
		break;
	case AF_INET6:
		nm_utils_ip6_address_clear_host_address (dst, src, plen);
		break;
	default:
		g_return_val_if_reached (NULL);
	}
	return dst;
}

/* nm_utils_ip4_address_clear_host_address:
 * @addr: source ip6 address
 * @plen: prefix length of network
 *
 * returns: the input address, with the host address set to 0.
 */
in_addr_t
nm_utils_ip4_address_clear_host_address (in_addr_t addr, guint8 plen)
{
	return addr & _nm_utils_ip4_prefix_to_netmask (plen);
}

/* nm_utils_ip6_address_clear_host_address:
 * @dst: destination output buffer, will contain the network part of the @src address
 * @src: source ip6 address
 * @plen: prefix length of network
 *
 * Note: this function is self assignment safe, to update @src inplace, set both
 * @dst and @src to the same destination or set @src NULL.
 */
const struct in6_addr *
nm_utils_ip6_address_clear_host_address (struct in6_addr *dst, const struct in6_addr *src, guint8 plen)
{
	g_return_val_if_fail (plen <= 128, NULL);
	g_return_val_if_fail (dst, NULL);

	if (!src)
		src = dst;

	if (plen < 128) {
		guint nbytes = plen / 8;
		guint nbits = plen % 8;

		if (nbytes && dst != src)
			memcpy (dst, src, nbytes);
		if (nbits) {
			dst->s6_addr[nbytes] = (src->s6_addr[nbytes] & (0xFF << (8 - nbits)));
			nbytes++;
		}
		if (nbytes <= 15)
			memset (&dst->s6_addr[nbytes], 0, 16 - nbytes);
	} else if (src != dst)
		*dst = *src;

	return dst;
}

int
nm_utils_ip6_address_same_prefix_cmp (const struct in6_addr *addr_a, const struct in6_addr *addr_b, guint8 plen)
{
	int nbytes;
	guint8 va, vb, m;

	if (plen >= 128)
		NM_CMP_DIRECT_MEMCMP (addr_a, addr_b, sizeof (struct in6_addr));
	else {
		nbytes = plen / 8;
		if (nbytes)
			NM_CMP_DIRECT_MEMCMP (addr_a, addr_b, nbytes);

		plen = plen % 8;
		if (plen != 0) {
			m = ~((1 << (8 - plen)) - 1);
			va = ((((const guint8 *) addr_a))[nbytes]) & m;
			vb = ((((const guint8 *) addr_b))[nbytes]) & m;
			NM_CMP_DIRECT (va, vb);
		}
	}
	return 0;
}

/**
 * _nm_utils_ip4_get_default_prefix:
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
_nm_utils_ip4_get_default_prefix (guint32 ip)
{
	if (((ntohl (ip) & 0xFF000000) >> 24) <= 127)
		return 8;  /* Class A - 255.0.0.0 */
	else if (((ntohl (ip) & 0xFF000000) >> 24) <= 191)
		return 16;  /* Class B - 255.255.0.0 */

	return 24;  /* Class C - 255.255.255.0 */
}

gboolean
nm_utils_ip_is_site_local (int addr_family,
                           const void *address)
{
	in_addr_t addr4;

	switch (addr_family) {
	case AF_INET:
		/* RFC1918 private addresses
		 * 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 */
		addr4 = ntohl (*((const in_addr_t *) address));
		return    (addr4 & 0xff000000) == 0x0a000000
		       || (addr4 & 0xfff00000) == 0xac100000
		       || (addr4 & 0xffff0000) == 0xc0a80000;
	case AF_INET6:
		return IN6_IS_ADDR_SITELOCAL (address);
	default:
		g_return_val_if_reached (FALSE);
	}
}

/*****************************************************************************/

static gboolean
_parse_legacy_addr4 (const char *text, in_addr_t *out_addr, GError **error)
{
	gs_free char *s_free = NULL;
	struct in_addr a1;
	guint8 bin[sizeof (a1)];
	char *s;
	int i;

	if (inet_aton (text, &a1) != 1) {
		g_set_error_literal (error,
		                     NM_UTILS_ERROR,
		                     NM_UTILS_ERROR_INVALID_ARGUMENT,
		                     "address invalid according to inet_aton()");
		return FALSE;
	}

	/* OK, inet_aton() accepted the format. That's good, because we want
	 * to accept IPv4 addresses in octal format, like 255.255.000.000.
	 * That's what "legacy" means here. inet_pton() doesn't accept those.
	 *
	 * But inet_aton() also ignores trailing garbage and formats with fewer than
	 * 4 digits. That is just too crazy and we don't do that. Perform additional checks
	 * and reject some forms that inet_aton() accepted.
	 *
	 * Note that we still should (of course) accept everything that inet_pton()
	 * accepts. However this code never gets called if inet_pton() succeeds
	 * (see below, aside the assertion code). */

	if (NM_STRCHAR_ANY (text, ch, (   !(ch >= '0' && ch <= '9')
	                               && !NM_IN_SET (ch, '.', 'x')))) {
		/* We only accepts '.', digits, and 'x' for "0x". */
		g_set_error_literal (error,
		                     NM_UTILS_ERROR,
		                     NM_UTILS_ERROR_INVALID_ARGUMENT,
		                     "contains an invalid character");
		return FALSE;
	}

	s = nm_memdup_maybe_a (300, text, strlen (text) + 1, &s_free);

	for (i = 0; i < G_N_ELEMENTS (bin); i++) {
		char *current_token = s;
		gint32 v;

		s = strchr (s, '.');
		if (s) {
			s[0] = '\0';
			s++;
		}

		if ((i == G_N_ELEMENTS (bin) - 1) != (s == NULL)) {
			/* Exactly for the last digit, we expect to have no more following token.
			 * But this isn't the case. Abort. */
			g_set_error (error,
			             NM_UTILS_ERROR,
			             NM_UTILS_ERROR_INVALID_ARGUMENT,
			             "wrong number of tokens (index %d, token '%s')",
			             i, s);
			return FALSE;
		}

		v = _nm_utils_ascii_str_to_int64 (current_token, 0, 0, 0xFF, -1);
		if (v == -1) {
			int errsv = errno;

			/* we do accept octal and hex (even with leading "0x"). But something
			 * about this token is wrong. */
			g_set_error (error,
			             NM_UTILS_ERROR,
			             NM_UTILS_ERROR_INVALID_ARGUMENT,
			             "invalid token '%s': %s (%d)",
			             current_token,
			             nm_strerror_native (errsv),
			             errsv);
			return FALSE;
		}

		bin[i] = v;
	}

	if (memcmp (bin, &a1, sizeof (bin)) != 0) {
		/* our parsing did not agree with what inet_aton() gave. Something
		 * is wrong. Abort. */
		g_set_error (error,
		             NM_UTILS_ERROR,
		             NM_UTILS_ERROR_INVALID_ARGUMENT,
		             "inet_aton() result 0x%08x differs from computed value 0x%02hhx%02hhx%02hhx%02hhx",
		             a1.s_addr,
		             bin[0], bin[1], bin[2], bin[3]);
		return FALSE;
	}

	*out_addr = a1.s_addr;
	return TRUE;
}

gboolean
nm_utils_parse_inaddr_bin_full (int addr_family,
                                gboolean accept_legacy,
                                const char *text,
                                int *out_addr_family,
                                gpointer out_addr)
{
	NMIPAddr addrbin;

	g_return_val_if_fail (text, FALSE);

	if (addr_family == AF_UNSPEC) {
		g_return_val_if_fail (!out_addr || out_addr_family, FALSE);
		addr_family = strchr (text, ':') ? AF_INET6 : AF_INET;
	} else
		g_return_val_if_fail (NM_IN_SET (addr_family, AF_INET, AF_INET6), FALSE);

	if (inet_pton (addr_family, text, &addrbin) != 1) {
		if (   accept_legacy
		    && addr_family == AF_INET
		    && _parse_legacy_addr4 (text, &addrbin.addr4, NULL)) {
			/* The address is in some legacy format which inet_aton() accepts, but not inet_pton().
			 * Most likely octal digits (leading zeros). We accept the address. */
		} else
			return FALSE;
	}

#if NM_MORE_ASSERTS > 10
	if (addr_family == AF_INET) {
		gs_free_error GError *error = NULL;
		in_addr_t a;

		/* The legacy parser should accept everything that inet_pton() accepts too. Meaning,
		 * it should strictly parse *more* formats. And of course, parse it the same way. */
		if (!_parse_legacy_addr4 (text, &a, &error)) {
			char buf[INET_ADDRSTRLEN];

			g_error ("unexpected assertion failure: could parse \"%s\" as %s, but not accepted by legacy parser: %s",
			         text, _nm_utils_inet4_ntop (addrbin.addr4, buf), error->message);
		}
		nm_assert (addrbin.addr4 == a);
	}
#endif

	NM_SET_OUT (out_addr_family, addr_family);
	if (out_addr)
		nm_ip_addr_set (addr_family, out_addr, &addrbin);
	return TRUE;
}

gboolean
nm_utils_parse_inaddr (int addr_family,
                       const char *text,
                       char **out_addr)
{
	NMIPAddr addrbin;
	char addrstr_buf[MAX (INET_ADDRSTRLEN, INET6_ADDRSTRLEN)];

	g_return_val_if_fail (text, FALSE);

	if (addr_family == AF_UNSPEC)
		addr_family = strchr (text, ':') ? AF_INET6 : AF_INET;
	else
		g_return_val_if_fail (NM_IN_SET (addr_family, AF_INET, AF_INET6), FALSE);

	if (inet_pton (addr_family, text, &addrbin) != 1)
		return FALSE;

	NM_SET_OUT (out_addr, g_strdup (inet_ntop (addr_family, &addrbin, addrstr_buf, sizeof (addrstr_buf))));
	return TRUE;
}

gboolean
nm_utils_parse_inaddr_prefix_bin (int addr_family,
                                  const char *text,
                                  int *out_addr_family,
                                  gpointer out_addr,
                                  int *out_prefix)
{
	gs_free char *addrstr_free = NULL;
	int prefix = -1;
	const char *slash;
	const char *addrstr;
	NMIPAddr addrbin;

	g_return_val_if_fail (text, FALSE);

	if (addr_family == AF_UNSPEC) {
		g_return_val_if_fail (!out_addr || out_addr_family, FALSE);
		addr_family = strchr (text, ':') ? AF_INET6 : AF_INET;
	} else
		g_return_val_if_fail (NM_IN_SET (addr_family, AF_INET, AF_INET6), FALSE);

	slash = strchr (text, '/');
	if (slash)
		addrstr = addrstr_free = g_strndup (text, slash - text);
	else
		addrstr = text;

	if (inet_pton (addr_family, addrstr, &addrbin) != 1)
		return FALSE;

	if (slash) {
		/* For IPv4, `ip addr add` supports the prefix-length as a netmask. We don't
		 * do that. */
		prefix = _nm_utils_ascii_str_to_int64 (slash + 1, 10,
		                                       0,
		                                       addr_family == AF_INET ? 32 : 128,
		                                       -1);
		if (prefix == -1)
			return FALSE;
	}

	NM_SET_OUT (out_addr_family, addr_family);
	if (out_addr)
		nm_ip_addr_set (addr_family, out_addr, &addrbin);
	NM_SET_OUT (out_prefix, prefix);
	return TRUE;
}

gboolean
nm_utils_parse_inaddr_prefix (int addr_family,
                              const char *text,
                              char **out_addr,
                              int *out_prefix)
{
	NMIPAddr addrbin;
	char addrstr_buf[MAX (INET_ADDRSTRLEN, INET6_ADDRSTRLEN)];

	if (!nm_utils_parse_inaddr_prefix_bin (addr_family, text, &addr_family, &addrbin, out_prefix))
		return FALSE;
	NM_SET_OUT (out_addr, g_strdup (inet_ntop (addr_family, &addrbin, addrstr_buf, sizeof (addrstr_buf))));
	return TRUE;
}

/*****************************************************************************/

gboolean
nm_utils_ipaddr_is_valid (int addr_family,
                          const char *str_addr)
{
	nm_assert (NM_IN_SET (addr_family, AF_UNSPEC, AF_INET, AF_INET6));

	return    str_addr
	       && nm_utils_parse_inaddr_bin (addr_family,
	                                     str_addr,
	                                     NULL,
	                                     NULL);
}

gboolean
nm_utils_ipaddr_is_normalized (int addr_family,
                               const char *str_addr)
{
	NMIPAddr addr;
	char sbuf[NM_UTILS_INET_ADDRSTRLEN];

	nm_assert (NM_IN_SET (addr_family, AF_UNSPEC, AF_INET, AF_INET6));

	if (!str_addr)
		return FALSE;

	if (!nm_utils_parse_inaddr_bin (addr_family,
	                                str_addr,
	                                &addr_family,
	                                &addr))
		return FALSE;

	nm_utils_inet_ntop (addr_family, &addr, sbuf);
	return nm_streq (sbuf, str_addr);
}

/*****************************************************************************/

/**
 * nm_g_ascii_strtoll()
 * @nptr: the string to parse
 * @endptr: the pointer on the first invalid chars
 * @base: the base.
 *
 * This wraps g_ascii_strtoll() and should in almost all cases behave identical
 * to it.
 *
 * However, it seems there are situations where g_ascii_strtoll() might set
 * errno to some unexpected value EAGAIN. Possibly this is related to creating
 * the C locale during
 *
 *   #ifdef USE_XLOCALE
 *   return strtoll_l (nptr, endptr, base, get_C_locale ());
 *
 * This wrapper tries to workaround that condition.
 */
gint64
nm_g_ascii_strtoll (const char *nptr,
                    char **endptr,
                    guint base)
{
	int try_count = 2;
	gint64 v;
	const int errsv_orig = errno;
	int errsv;

	nm_assert (nptr);
	nm_assert (base == 0u || (base >= 2u && base <= 36u));

again:
	errno = 0;
	v = g_ascii_strtoll (nptr, endptr, base);
	errsv = errno;

	if (errsv == 0) {
		if (errsv_orig != 0)
			errno = errsv_orig;
		return v;
	}

	if (   errsv == ERANGE
	    && NM_IN_SET (v, G_MININT64, G_MAXINT64))
		return v;

	if (   errsv == EINVAL
	    && v == 0
	    && nptr
	    && nptr[0] == '\0')
		return v;

	if (try_count-- > 0)
		goto again;

#if NM_MORE_ASSERTS
	g_critical ("g_ascii_strtoll() for \"%s\" failed with errno=%d (%s) and v=%"G_GINT64_FORMAT,
	            nptr,
	            errsv,
	            nm_strerror_native (errsv),
	            v);
#endif

	return v;
}

/* See nm_g_ascii_strtoll() */
guint64
nm_g_ascii_strtoull (const char *nptr,
                     char **endptr,
                     guint base)
{
	int try_count = 2;
	guint64 v;
	const int errsv_orig = errno;
	int errsv;

	nm_assert (nptr);
	nm_assert (base == 0u || (base >= 2u && base <= 36u));

again:
	errno = 0;
	v = g_ascii_strtoull (nptr, endptr, base);
	errsv = errno;

	if (errsv == 0) {
		if (errsv_orig != 0)
			errno = errsv_orig;
		return v;
	}

	if (   errsv == ERANGE
	    && NM_IN_SET (v, G_MAXUINT64))
		return v;

	if (   errsv == EINVAL
	    && v == 0
	    && nptr
	    && nptr[0] == '\0')
		return v;

	if (try_count-- > 0)
		goto again;

#if NM_MORE_ASSERTS
	g_critical ("g_ascii_strtoull() for \"%s\" failed with errno=%d (%s) and v=%"G_GUINT64_FORMAT,
	            nptr,
	            errsv,
	            nm_strerror_native (errsv),
	            v);
#endif

	return v;
}

/* see nm_g_ascii_strtoll(). */
double
nm_g_ascii_strtod (const char *nptr,
                   char **endptr)
{
	int try_count = 2;
	double v;
	int errsv;

	nm_assert (nptr);

again:
	v = g_ascii_strtod (nptr, endptr);
	errsv = errno;

	if (errsv == 0)
		return v;

	if (errsv == ERANGE)
		return v;

	if (try_count-- > 0)
		goto again;

#if NM_MORE_ASSERTS
	g_critical ("g_ascii_strtod() for \"%s\" failed with errno=%d (%s) and v=%f",
	            nptr,
	            errsv,
	            nm_strerror_native (errsv),
	            v);
#endif

	/* Not really much else to do. Return the parsed value and leave errno set
	 * to the unexpected value. */
	return v;
}

/* _nm_utils_ascii_str_to_int64:
 *
 * A wrapper for g_ascii_strtoll, that checks whether the whole string
 * can be successfully converted to a number and is within a given
 * range. On any error, @fallback will be returned and %errno will be set
 * to a non-zero value. On success, %errno will be set to zero, check %errno
 * for errors. Any trailing or leading (ascii) white space is ignored and the
 * functions is locale independent.
 *
 * The function is guaranteed to return a value between @min and @max
 * (inclusive) or @fallback. Also, the parsing is rather strict, it does
 * not allow for any unrecognized characters, except leading and trailing
 * white space.
 **/
gint64
_nm_utils_ascii_str_to_int64 (const char *str, guint base, gint64 min, gint64 max, gint64 fallback)
{
	gint64 v;
	const char *s = NULL;

	str = nm_str_skip_leading_spaces (str);
	if (!str || !str[0]) {
		errno = EINVAL;
		return fallback;
	}

	errno = 0;
	v = nm_g_ascii_strtoll (str, (char **) &s, base);

	if (errno != 0)
		return fallback;

	if (s[0] != '\0') {
		s = nm_str_skip_leading_spaces (s);
		if (s[0] != '\0') {
			errno = EINVAL;
			return fallback;
		}
	}
	if (v > max || v < min) {
		errno = ERANGE;
		return fallback;
	}

	return v;
}

guint64
_nm_utils_ascii_str_to_uint64 (const char *str, guint base, guint64 min, guint64 max, guint64 fallback)
{
	guint64 v;
	const char *s = NULL;

	if (str) {
		while (g_ascii_isspace (str[0]))
			str++;
	}
	if (!str || !str[0]) {
		errno = EINVAL;
		return fallback;
	}

	errno = 0;
	v = nm_g_ascii_strtoull (str, (char **) &s, base);

	if (errno != 0)
		return fallback;
	if (s[0] != '\0') {
		while (g_ascii_isspace (s[0]))
			s++;
		if (s[0] != '\0') {
			errno = EINVAL;
			return fallback;
		}
	}
	if (v > max || v < min) {
		errno = ERANGE;
		return fallback;
	}

	if (   v != 0
	    && str[0] == '-') {
		/* As documented, g_ascii_strtoull() accepts negative values, and returns their
		 * absolute value. We don't. */
		errno = ERANGE;
		return fallback;
	}

	return v;
}

/*****************************************************************************/

int
nm_strcmp_with_data (gconstpointer a, gconstpointer b, gpointer user_data)
{
	const char *s1 = a;
	const char *s2 = b;

	return strcmp (s1, s2);
}

/* like nm_strcmp_p(), suitable for g_ptr_array_sort_with_data().
 * g_ptr_array_sort() just casts nm_strcmp_p() to a function of different
 * signature. I guess, in glib there are knowledgeable people that ensure
 * that this additional argument doesn't cause problems due to different ABI
 * for every architecture that glib supports.
 * For NetworkManager, we'd rather avoid such stunts.
 **/
int
nm_strcmp_p_with_data (gconstpointer a, gconstpointer b, gpointer user_data)
{
	const char *s1 = *((const char **) a);
	const char *s2 = *((const char **) b);

	return strcmp (s1, s2);
}

int
nm_strcmp0_p_with_data (gconstpointer a, gconstpointer b, gpointer user_data)
{
	const char *s1 = *((const char **) a);
	const char *s2 = *((const char **) b);

	return nm_strcmp0 (s1, s2);
}

int
nm_cmp_uint32_p_with_data (gconstpointer p_a, gconstpointer p_b, gpointer user_data)
{
	const guint32 a = *((const guint32 *) p_a);
	const guint32 b = *((const guint32 *) p_b);

	if (a < b)
		return -1;
	if (a > b)
		return 1;
	return 0;
}

int
nm_cmp_int2ptr_p_with_data (gconstpointer p_a, gconstpointer p_b, gpointer user_data)
{
	/* p_a and p_b are two pointers to a pointer, where the pointer is
	 * interpreted as a integer using GPOINTER_TO_INT().
	 *
	 * That is the case of a hash-table that uses GINT_TO_POINTER() to
	 * convert integers as pointers, and the resulting keys-as-array
	 * array. */
	const int a = GPOINTER_TO_INT (*((gconstpointer *) p_a));
	const int b = GPOINTER_TO_INT (*((gconstpointer *) p_b));

	if (a < b)
		return -1;
	if (a > b)
		return 1;
	return 0;
}

/*****************************************************************************/

const char *
nm_utils_dbus_path_get_last_component (const char *dbus_path)
{
	if (dbus_path) {
		dbus_path = strrchr (dbus_path, '/');
		if (dbus_path)
			return dbus_path + 1;
	}
	return NULL;
}

static gint64
_dbus_path_component_as_num (const char *p)
{
	gint64 n;

	/* no odd stuff. No leading zeros, only a non-negative, decimal integer.
	 *
	 * Otherwise, there would be multiple ways to encode the same number "10"
	 * and "010". That is just confusing. A number has no leading zeros,
	 * if it has, it's not a number (as far as we are concerned here). */
	if (p[0] == '0') {
		if (p[1] != '\0')
			return -1;
		else
			return 0;
	}
	if (!(p[0] >= '1' && p[0] <= '9'))
		return -1;
	if (!NM_STRCHAR_ALL (&p[1], ch, (ch >= '0' && ch <= '9')))
		return -1;
	n = _nm_utils_ascii_str_to_int64 (p, 10, 0, G_MAXINT64, -1);
	nm_assert (n == -1 || nm_streq0 (p, nm_sprintf_bufa (100, "%"G_GINT64_FORMAT, n)));
	return n;
}

int
nm_utils_dbus_path_cmp (const char *dbus_path_a, const char *dbus_path_b)
{
	const char *l_a, *l_b;
	gsize plen;
	gint64 n_a, n_b;

	/* compare function for two D-Bus paths. It behaves like
	 * strcmp(), except, if both paths have the same prefix,
	 * and both end in a (positive) number, then the paths
	 * will be sorted by number. */

	NM_CMP_SELF (dbus_path_a, dbus_path_b);

	/* if one or both paths have no slash (and no last component)
	 * compare the full paths directly. */
	if (   !(l_a = nm_utils_dbus_path_get_last_component (dbus_path_a))
	    || !(l_b = nm_utils_dbus_path_get_last_component (dbus_path_b)))
		goto comp_full;

	/* check if both paths have the same prefix (up to the last-component). */
	plen = l_a - dbus_path_a;
	if (plen != (l_b - dbus_path_b))
		goto comp_full;
	NM_CMP_RETURN (strncmp (dbus_path_a, dbus_path_b, plen));

	n_a = _dbus_path_component_as_num (l_a);
	n_b = _dbus_path_component_as_num (l_b);
	if (n_a == -1 && n_b == -1)
		goto comp_l;

	/* both components must be convertiable to a number. If they are not,
	 * (and only one of them is), then we must always strictly sort numeric parts
	 * after non-numeric components. If we wouldn't, we wouldn't have
	 * a total order.
	 *
	 * An example of a not total ordering would be:
	 *   "8"   < "010"  (numeric)
	 *   "0x"  < "8"    (lexical)
	 *   "0x"  > "010"  (lexical)
	 * We avoid this, by forcing that a non-numeric entry "0x" always sorts
	 * before numeric entries.
	 *
	 * Additionally, _dbus_path_component_as_num() would also reject "010" as
	 * not a valid number.
	 */
	if (n_a == -1)
		return -1;
	if (n_b == -1)
		return 1;

	NM_CMP_DIRECT (n_a, n_b);
	nm_assert (nm_streq (dbus_path_a, dbus_path_b));
	return 0;

comp_full:
	NM_CMP_DIRECT_STRCMP0 (dbus_path_a, dbus_path_b);
	return 0;
comp_l:
	NM_CMP_DIRECT_STRCMP0 (l_a, l_b);
	nm_assert (nm_streq (dbus_path_a, dbus_path_b));
	return 0;
}

/*****************************************************************************/

static void
_char_lookup_table_set_one (guint8 lookup[static 256],
                             char ch)
{
	lookup[(guint8) ch] = 1;
}

static void
_char_lookup_table_set_all (guint8 lookup[static 256],
                            const char *candidates)
{
	while (candidates[0] != '\0')
		_char_lookup_table_set_one (lookup, (candidates++)[0]);
}

static void
_char_lookup_table_init (guint8 lookup[static 256],
                         const char *candidates)
{
	memset (lookup, 0, 256);
	if (candidates)
		_char_lookup_table_set_all (lookup, candidates);
}

static gboolean
_char_lookup_has (const guint8 lookup[static 256],
                  char ch)
{
	nm_assert (lookup[(guint8) '\0'] == 0);
	return lookup[(guint8) ch] != 0;
}

static gboolean
_char_lookup_has_all (const guint8 lookup[static 256],
                      const char *candidates)
{
	if (candidates) {
		while (candidates[0] != '\0') {
			if (!_char_lookup_has (lookup, (candidates++)[0]))
				return FALSE;
		}
	}
	return TRUE;
}

/**
 * nm_utils_strsplit_set_full:
 * @str: the string to split.
 * @delimiters: the set of delimiters.
 * @flags: additional flags for controlling the operation.
 *
 * This is a replacement for g_strsplit_set() which avoids copying
 * each word once (the entire strv array), but instead copies it once
 * and all words point into that internal copy.
 *
 * Note that for @str %NULL and "", this always returns %NULL too. That differs
 * from g_strsplit_set(), which would return an empty strv array for "".
 * This never returns an empty array.
 *
 * Returns: %NULL if @str is %NULL or "".
 *   If @str only contains delimiters and %NM_UTILS_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY
 *   is not set, it also returns %NULL.
 *   Otherwise, a %NULL terminated strv array containing the split words.
 *   (delimiter characters are removed).
 *   The strings to which the result strv array points to are allocated
 *   after the returned result itself. Don't free the strings themself,
 *   but free everything with g_free().
 *   It is however safe and allowed to modify the individual strings in-place,
 *   like "g_strstrip((char *) iter[0])".
 */
const char **
nm_utils_strsplit_set_full (const char *str,
                            const char *delimiters,
                            NMUtilsStrsplitSetFlags flags)
{
	const char **ptr;
	gsize num_tokens;
	gsize i_token;
	gsize str_len_p1;
	const char *c_str;
	char *s;
	guint8 ch_lookup[256];
	const gboolean f_escaped = NM_FLAGS_HAS (flags, NM_UTILS_STRSPLIT_SET_FLAGS_ESCAPED);
	const gboolean f_allow_escaping = f_escaped || NM_FLAGS_HAS (flags, NM_UTILS_STRSPLIT_SET_FLAGS_ALLOW_ESCAPING);
	const gboolean f_preserve_empty = NM_FLAGS_HAS (flags, NM_UTILS_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY);
	const gboolean f_strstrip = NM_FLAGS_HAS (flags, NM_UTILS_STRSPLIT_SET_FLAGS_STRSTRIP);

	if (!str)
		return NULL;

	if (!delimiters) {
		nm_assert_not_reached ();
		delimiters = " \t\n";
	}
	_char_lookup_table_init (ch_lookup, delimiters);

	nm_assert (   !f_allow_escaping
	           || !_char_lookup_has (ch_lookup, '\\'));

	if (!f_preserve_empty) {
		while (_char_lookup_has (ch_lookup, str[0]))
			str++;
	}

	if (!str[0]) {
		/* We return %NULL here, also with NM_UTILS_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY.
		 * That makes nm_utils_strsplit_set_full() with NM_UTILS_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY
		 * different from g_strsplit_set(), which would in this case return an empty array.
		 * If you need to handle %NULL, and "" specially, then check the input string first. */
		return NULL;
	}

#define _char_is_escaped(str_start, str_cur) \
	({ \
		const char *const _str_start = (str_start); \
		const char *const _str_cur = (str_cur); \
		const char *_str_i = (_str_cur); \
		\
		while (   _str_i > _str_start \
		       && _str_i[-1] == '\\') \
			_str_i--; \
		(((_str_cur - _str_i) % 2) != 0); \
	})

	num_tokens = 1;
	c_str = str;
	while (TRUE) {

		while (G_LIKELY (!_char_lookup_has (ch_lookup, c_str[0]))) {
			if (c_str[0] == '\0')
				goto done1;
			c_str++;
		}

		/* we assume escapings are not frequent. After we found
		 * this delimiter, check whether it was escaped by counting
		 * the backslashed before. */
		if (   f_allow_escaping
		    && _char_is_escaped (str, c_str)) {
			/* the delimiter is escaped. This was not an accepted delimiter. */
			c_str++;
			continue;
		}

		c_str++;

		/* if we drop empty tokens, then we now skip over all consecutive delimiters. */
		if (!f_preserve_empty) {
			while (_char_lookup_has (ch_lookup, c_str[0]))
				c_str++;
			if (c_str[0] == '\0')
				break;
		}

		num_tokens++;
	}

done1:

	nm_assert (c_str[0] == '\0');

	str_len_p1 = (c_str - str) + 1;

	nm_assert (str[str_len_p1 - 1] == '\0');

	ptr = g_malloc ((sizeof (const char *) * (num_tokens + 1)) + str_len_p1);
	s = (char *) &ptr[num_tokens + 1];
	memcpy (s, str, str_len_p1);

	i_token = 0;

	while (TRUE) {

		nm_assert (i_token < num_tokens);
		ptr[i_token++] = s;

		if (s[0] == '\0') {
			nm_assert (f_preserve_empty);
			goto done2;
		}
		nm_assert (   f_preserve_empty
		           || !_char_lookup_has (ch_lookup, s[0]));

		while (!_char_lookup_has (ch_lookup, s[0])) {
			if (G_UNLIKELY (   s[0] == '\\'
			                && f_allow_escaping)) {
				s++;
				if (s[0] == '\0')
					goto done2;
				s++;
			} else if (s[0] == '\0')
				goto done2;
			else
				s++;
		}

		nm_assert (_char_lookup_has (ch_lookup, s[0]));
		s[0] = '\0';
		s++;

		if (!f_preserve_empty) {
			while (_char_lookup_has (ch_lookup, s[0]))
				s++;
			if (s[0] == '\0')
				goto done2;
		}
	}

done2:
	nm_assert (i_token == num_tokens);
	ptr[i_token] = NULL;

	if (f_strstrip) {
		gsize i;

		i_token = 0;
		for (i = 0; ptr[i]; i++) {

			s = (char *) nm_str_skip_leading_spaces (ptr[i]);
			if (s[0] != '\0') {
				char *s_last;

				s_last = &s[strlen (s) - 1];
				while (   s_last > s
				       && g_ascii_isspace (s_last[0])
				       && (   ! f_allow_escaping
				           || !_char_is_escaped (s, s_last)))
					(s_last--)[0] = '\0';
			}

			if (   !f_preserve_empty
			    && s[0] == '\0')
				continue;

			ptr[i_token++] = s;
		}

		if (i_token == 0) {
			g_free (ptr);
			return NULL;
		}
		ptr[i_token] = NULL;
	}

	if (f_escaped) {
		gsize i, j;

		/* We no longer need ch_lookup for its original purpose. Modify it, so it
		 * can detect the delimiters, '\\', and (optionally) whitespaces. */
		_char_lookup_table_set_one (ch_lookup, '\\');
		if (f_strstrip)
			_char_lookup_table_set_all (ch_lookup, NM_ASCII_SPACES);

		for (i_token = 0; ptr[i_token]; i_token++) {
			s = (char *) ptr[i_token];
			j = 0;
			for (i = 0; s[i] != '\0'; ) {
				if (   s[i] == '\\'
				    && _char_lookup_has (ch_lookup, s[i + 1]))
					i++;
				s[j++] = s[i++];
			}
			s[j] = '\0';
		}
	}

	return ptr;
}

/*****************************************************************************/

const char *
nm_utils_escaped_tokens_escape_full (const char *str,
                                     const char *delimiters,
                                     const char *delimiters_as_needed,
                                     NMUtilsEscapedTokensEscapeFlags flags,
                                     char **out_to_free)
{
	guint8 ch_lookup[256];
	guint8 ch_lookup_as_needed[256];
	gboolean has_ch_lookup_as_needed = FALSE;
	char *ret;
	gsize str_len;
	gsize alloc_len;
	gsize n_escapes;
	gsize i, j;
	gboolean escape_leading_space;
	gboolean escape_trailing_space;
	gboolean escape_backslash_as_needed;

	nm_assert (   !delimiters_as_needed
	           || (   delimiters_as_needed[0]
	               && NM_FLAGS_HAS (flags, NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_BACKSLASH_AS_NEEDED)));

	if (!str || str[0] == '\0') {
		*out_to_free = NULL;
		return str;
	}

	str_len = strlen (str);

	_char_lookup_table_init (ch_lookup, delimiters);
	if (   !delimiters
	    || NM_FLAGS_HAS (flags, NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_SPACES)) {
		flags &= ~(  NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_LEADING_SPACE
		           | NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_TRAILING_SPACE);
		_char_lookup_table_set_all (ch_lookup, NM_ASCII_SPACES);
	}

	if (NM_FLAGS_HAS (flags, NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_BACKSLASH_ALWAYS)) {
		_char_lookup_table_set_one (ch_lookup, '\\');
		escape_backslash_as_needed = FALSE;
	} else if (_char_lookup_has (ch_lookup, '\\'))
		escape_backslash_as_needed = FALSE;
	else {
		escape_backslash_as_needed = NM_FLAGS_HAS (flags, NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_BACKSLASH_AS_NEEDED);
		if (escape_backslash_as_needed) {
			if (    NM_FLAGS_ANY (flags,   NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_LEADING_SPACE
			                             | NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_TRAILING_SPACE)
			    && !_char_lookup_has_all (ch_lookup, NM_ASCII_SPACES)) {
				/* ESCAPE_LEADING_SPACE and ESCAPE_TRAILING_SPACE implies that we escape backslash
				 * before whitespaces. */
				if (!has_ch_lookup_as_needed) {
					has_ch_lookup_as_needed = TRUE;
					_char_lookup_table_init (ch_lookup_as_needed, NULL);
				}
				_char_lookup_table_set_all (ch_lookup_as_needed, NM_ASCII_SPACES);
			}
			if (   delimiters_as_needed
			    && !_char_lookup_has_all (ch_lookup, delimiters_as_needed)) {
				if (!has_ch_lookup_as_needed) {
					has_ch_lookup_as_needed = TRUE;
					_char_lookup_table_init (ch_lookup_as_needed, NULL);
				}
				_char_lookup_table_set_all (ch_lookup_as_needed, delimiters_as_needed);
			}
		}
	}

	escape_leading_space =    NM_FLAGS_HAS (flags, NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_LEADING_SPACE)
	                       && g_ascii_isspace (str[0])
	                       && !_char_lookup_has (ch_lookup, str[0]);
	if (str_len == 1)
		escape_trailing_space = FALSE;
	else {
		escape_trailing_space =    NM_FLAGS_HAS (flags, NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_TRAILING_SPACE)
		                        && g_ascii_isspace (str[str_len - 1])
		                        && !_char_lookup_has (ch_lookup, str[str_len - 1]);
	}

	n_escapes = 0;
	for (i = 0; str[i] != '\0'; i++) {
		if (_char_lookup_has (ch_lookup, str[i]))
			n_escapes++;
		else if (   str[i] == '\\'
		         && escape_backslash_as_needed
		         && (   _char_lookup_has (ch_lookup, str[i + 1])
		             || NM_IN_SET (str[i + 1], '\0', '\\')
		             || (   has_ch_lookup_as_needed
		                 && _char_lookup_has (ch_lookup_as_needed, str[i + 1]))))
			n_escapes++;
	}
	if (escape_leading_space)
		n_escapes++;
	if (escape_trailing_space)
		n_escapes++;

	if (n_escapes == 0u) {
		*out_to_free = NULL;
		return str;
	}

	alloc_len = str_len + n_escapes + 1u;
	ret = g_new (char, alloc_len);

	j = 0;
	i = 0;

	if (escape_leading_space) {
		ret[j++] = '\\';
		ret[j++] = str[i++];
	}
	for (; str[i] != '\0'; i++) {
		if (_char_lookup_has (ch_lookup, str[i]))
			ret[j++] = '\\';
		else if (   str[i] == '\\'
		         && escape_backslash_as_needed
		         && (   _char_lookup_has (ch_lookup, str[i + 1])
		             || NM_IN_SET (str[i + 1], '\0', '\\')
		             || (   has_ch_lookup_as_needed
		                 && _char_lookup_has (ch_lookup_as_needed, str[i + 1]))))
			ret[j++] = '\\';
		ret[j++] = str[i];
	}
	if (escape_trailing_space) {
		nm_assert (   !_char_lookup_has (ch_lookup, ret[j - 1])
		           && g_ascii_isspace (ret[j - 1]));
		ret[j] = ret[j - 1];
		ret[j - 1] = '\\';
		j++;
	}

	nm_assert (j == alloc_len - 1);
	ret[j] = '\0';
	nm_assert (strlen (ret) == j);

	*out_to_free = ret;
	return ret;
}

/**
 * nm_utils_escaped_tokens_options_split:
 * @str: the src string. This string will be modified in-place.
 *   The output values will point into @str.
 * @out_key: (allow-none): the returned output key. This will always be set to @str
 *   itself. @str will be modified to contain only the unescaped, truncated
 *   key name.
 * @out_val: returns the parsed (and unescaped) value or %NULL, if @str contains
 *   no '=' delimiter.
 *
 * Honors backslash escaping to parse @str as "key=value" pairs. Optionally, if no '='
 * is present, @out_val will be returned as %NULL. Backslash can be used to escape
 * '=', ',', '\\', and ascii whitespace. Other backslash sequences are taken verbatim.
 *
 * For keys, '=' obviously must be escaped. For values, that is optional because an
 * unescaped '=' is just taken verbatim. For example, in a key, the sequence "\\="
 * must be escaped as "\\\\\\=". For the value, that works too, but "\\\\=" is also
 * accepted.
 *
 * Unescaped Space around the key and value are also removed. Space in general must
 * not be escaped, unless they are at the beginning or the end of key/value.
 */
void
nm_utils_escaped_tokens_options_split (char *str,
                                       const char **out_key,
                                       const char **out_val)
{
	const char *val = NULL;
	gsize i;
	gsize j;
	gsize last_space_idx;
	gboolean last_space_has;

	nm_assert (str);

	i = 0;
	while (g_ascii_isspace (str[i]))
		i++;

	j = 0;
	last_space_idx = 0;
	last_space_has = FALSE;
	while (str[i] != '\0') {
		if (g_ascii_isspace (str[i])) {
			if (!last_space_has) {
				last_space_has = TRUE;
				last_space_idx = j;
			}
		} else {
			if (str[i] == '\\') {
				if (   NM_IN_SET (str[i + 1u], '\\', ',', '=')
				    || g_ascii_isspace (str[i + 1u]))
					i++;
			} else if (str[i] == '=') {
				/* Encounter an unescaped '=' character. When we still parse the key, this
				 * is the separator we were waiting for. If we are parsing the value,
				 * we take the character verbatim. */
				if (!val) {
					if (last_space_has) {
						str[last_space_idx] = '\0';
						j = last_space_idx + 1;
						last_space_has = FALSE;
					} else
						str[j++] = '\0';
					val = &str[j];
					i++;
					while (g_ascii_isspace (str[i]))
						i++;
					continue;
				}
			}
			last_space_has = FALSE;
		}
		str[j++] = str[i++];
	}

	if (last_space_has)
		str[last_space_idx] = '\0';
	else
		str[j] = '\0';

	*out_key = str;
	*out_val = val;
}

/*****************************************************************************/

/**
 * nm_utils_strv_find_first:
 * @list: the strv list to search
 * @len: the length of the list, or a negative value if @list is %NULL terminated.
 * @needle: the value to search for. The search is done using strcmp().
 *
 * Searches @list for @needle and returns the index of the first match (based
 * on strcmp()).
 *
 * For convenience, @list has type 'char**' instead of 'const char **'.
 *
 * Returns: index of first occurrence or -1 if @needle is not found in @list.
 */
gssize
nm_utils_strv_find_first (char **list, gssize len, const char *needle)
{
	gssize i;

	if (len > 0) {
		g_return_val_if_fail (list, -1);

		if (!needle) {
			/* if we search a list with known length, %NULL is a valid @needle. */
			for (i = 0; i < len; i++) {
				if (!list[i])
					return i;
			}
		} else {
			for (i = 0; i < len; i++) {
				if (list[i] && !strcmp (needle, list[i]))
					return i;
			}
		}
	} else if (len < 0) {
		g_return_val_if_fail (needle, -1);

		if (list) {
			for (i = 0; list[i]; i++) {
				if (strcmp (needle, list[i]) == 0)
					return i;
			}
		}
	}
	return -1;
}

char **
_nm_utils_strv_cleanup (char **strv,
                        gboolean strip_whitespace,
                        gboolean skip_empty,
                        gboolean skip_repeated)
{
	guint i, j;

	if (!strv || !*strv)
		return strv;

	if (strip_whitespace) {
		/* we only modify the strings pointed to by @strv if @strip_whitespace is
		 * requested. Otherwise, the strings themselves are untouched. */
		for (i = 0; strv[i]; i++)
			g_strstrip (strv[i]);
	}
	if (!skip_empty && !skip_repeated)
		return strv;
	j = 0;
	for (i = 0; strv[i]; i++) {
		if (   (skip_empty && !*strv[i])
		    || (skip_repeated && nm_utils_strv_find_first (strv, j, strv[i]) >= 0))
			g_free (strv[i]);
		else
			strv[j++] = strv[i];
	}
	strv[j] = NULL;
	return strv;
}

/*****************************************************************************/

int
_nm_utils_ascii_str_to_bool (const char *str,
                             int default_value)
{
	gs_free char *str_free = NULL;

	if (!str)
		return default_value;

	str = nm_strstrip_avoid_copy_a (300, str, &str_free);
	if (str[0] == '\0')
		return default_value;

	if (   !g_ascii_strcasecmp (str, "true")
	    || !g_ascii_strcasecmp (str, "yes")
	    || !g_ascii_strcasecmp (str, "on")
	    || !g_ascii_strcasecmp (str, "1"))
		return TRUE;

	if (   !g_ascii_strcasecmp (str, "false")
	    || !g_ascii_strcasecmp (str, "no")
	    || !g_ascii_strcasecmp (str, "off")
	    || !g_ascii_strcasecmp (str, "0"))
		return FALSE;

	return default_value;
}

/*****************************************************************************/

NM_CACHED_QUARK_FCN ("nm-utils-error-quark", nm_utils_error_quark)

void
nm_utils_error_set_cancelled (GError **error,
                              gboolean is_disposing,
                              const char *instance_name)
{
	if (is_disposing) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_CANCELLED_DISPOSING,
		             "Disposing %s instance",
		             instance_name && *instance_name ? instance_name : "source");
	} else {
		g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CANCELLED,
		                     "Request cancelled");
	}
}

gboolean
nm_utils_error_is_cancelled_or_disposing (GError *error)
{
	if (error) {
		if (error->domain == G_IO_ERROR)
			return NM_IN_SET (error->code, G_IO_ERROR_CANCELLED);
		if (error->domain == NM_UTILS_ERROR)
			return NM_IN_SET (error->code, NM_UTILS_ERROR_CANCELLED_DISPOSING);
	}
	return FALSE;
}

gboolean
nm_utils_error_is_notfound (GError *error)
{
	if (error) {
		if (error->domain == G_IO_ERROR)
			return NM_IN_SET (error->code, G_IO_ERROR_NOT_FOUND);
		if (error->domain == G_FILE_ERROR)
			return NM_IN_SET (error->code, G_FILE_ERROR_NOENT);
	}
	return FALSE;
}

/*****************************************************************************/

/**
 * nm_g_object_set_property:
 * @object: the target object
 * @property_name: the property name
 * @value: the #GValue to set
 * @error: (allow-none): optional error argument
 *
 * A reimplementation of g_object_set_property(), but instead
 * returning an error instead of logging a warning. All g_object_set*()
 * versions in glib require you to not pass invalid types or they will
 * log a g_warning() -- without reporting an error. We don't want that,
 * so we need to hack error checking around it.
 *
 * Returns: whether the value was successfully set.
 */
gboolean
nm_g_object_set_property (GObject *object,
                          const char *property_name,
                          const GValue *value,
                          GError **error)
{
	GParamSpec *pspec;
	nm_auto_unset_gvalue GValue tmp_value = G_VALUE_INIT;
	GObjectClass *klass;

	g_return_val_if_fail (G_IS_OBJECT (object), FALSE);
	g_return_val_if_fail (property_name != NULL, FALSE);
	g_return_val_if_fail (G_IS_VALUE (value), FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	/* g_object_class_find_property() does g_param_spec_get_redirect_target(),
	 * where we differ from a plain g_object_set_property(). */
	pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (object), property_name);

	if (!pspec) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             _("object class '%s' has no property named '%s'"),
		             G_OBJECT_TYPE_NAME (object),
		             property_name);
		return FALSE;
	}
	if (!(pspec->flags & G_PARAM_WRITABLE)) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             _("property '%s' of object class '%s' is not writable"),
		             pspec->name,
		             G_OBJECT_TYPE_NAME (object));
		return FALSE;
	}
	if ((pspec->flags & G_PARAM_CONSTRUCT_ONLY)) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             _("construct property \"%s\" for object '%s' can't be set after construction"),
		             pspec->name, G_OBJECT_TYPE_NAME (object));
		return FALSE;
	}

	klass = g_type_class_peek (pspec->owner_type);
	if (klass == NULL) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             _("'%s::%s' is not a valid property name; '%s' is not a GObject subtype"),
		            g_type_name (pspec->owner_type), pspec->name, g_type_name (pspec->owner_type));
		return FALSE;
	}

	/* provide a copy to work from, convert (if necessary) and validate */
	g_value_init (&tmp_value, pspec->value_type);
	if (!g_value_transform (value, &tmp_value)) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             _("unable to set property '%s' of type '%s' from value of type '%s'"),
		             pspec->name,
		             g_type_name (pspec->value_type),
		             G_VALUE_TYPE_NAME (value));
		return FALSE;
	}
	if (   g_param_value_validate (pspec, &tmp_value)
	    && !(pspec->flags & G_PARAM_LAX_VALIDATION)) {
		gs_free char *contents = g_strdup_value_contents (value);

		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             _("value \"%s\" of type '%s' is invalid or out of range for property '%s' of type '%s'"),
		             contents,
		             G_VALUE_TYPE_NAME (value),
		             pspec->name,
		             g_type_name (pspec->value_type));
		return FALSE;
	}

	g_object_set_property (object, property_name, &tmp_value);
	return TRUE;
}

#define _set_property(object, property_name, gtype, gtype_set, value, error) \
	G_STMT_START { \
		nm_auto_unset_gvalue GValue gvalue = { 0 }; \
		\
		g_value_init (&gvalue, gtype); \
		gtype_set (&gvalue, (value)); \
		return nm_g_object_set_property ((object), (property_name), &gvalue, (error)); \
	} G_STMT_END

gboolean
nm_g_object_set_property_string (GObject *object,
                                 const char *property_name,
                                 const char *value,
                                 GError **error)
{
	_set_property (object, property_name, G_TYPE_STRING, g_value_set_string, value, error);
}

gboolean
nm_g_object_set_property_string_static (GObject *object,
                                        const char *property_name,
                                        const char *value,
                                        GError **error)
{
	_set_property (object, property_name, G_TYPE_STRING, g_value_set_static_string, value, error);
}

gboolean
nm_g_object_set_property_string_take (GObject *object,
                                      const char *property_name,
                                      char *value,
                                      GError **error)
{
	_set_property (object, property_name, G_TYPE_STRING, g_value_take_string, value, error);
}

gboolean
nm_g_object_set_property_boolean (GObject *object,
                                  const char *property_name,
                                  gboolean value,
                                  GError **error)
{
	_set_property (object, property_name, G_TYPE_BOOLEAN, g_value_set_boolean, !!value, error);
}

gboolean
nm_g_object_set_property_char (GObject *object,
                               const char *property_name,
                               gint8 value,
                               GError **error)
{
	/* glib says about G_TYPE_CHAR:
	 *
	 * The type designated by G_TYPE_CHAR is unconditionally an 8-bit signed integer.
	 *
	 * This is always a (signed!) char. */
	_set_property (object, property_name, G_TYPE_CHAR, g_value_set_schar, value, error);
}

gboolean
nm_g_object_set_property_uchar (GObject *object,
                                const char *property_name,
                                guint8 value,
                                GError **error)
{
	_set_property (object, property_name, G_TYPE_UCHAR, g_value_set_uchar, value, error);
}

gboolean
nm_g_object_set_property_int (GObject *object,
                              const char *property_name,
                              int value,
                              GError **error)
{
	_set_property (object, property_name, G_TYPE_INT, g_value_set_int, value, error);
}

gboolean
nm_g_object_set_property_int64 (GObject *object,
                                const char *property_name,
                                gint64 value,
                                GError **error)
{
	_set_property (object, property_name, G_TYPE_INT64, g_value_set_int64, value, error);
}

gboolean
nm_g_object_set_property_uint (GObject *object,
                               const char *property_name,
                               guint value,
                               GError **error)
{
	_set_property (object, property_name, G_TYPE_UINT, g_value_set_uint, value, error);
}

gboolean
nm_g_object_set_property_uint64 (GObject *object,
                                 const char *property_name,
                                 guint64 value,
                                 GError **error)
{
	_set_property (object, property_name, G_TYPE_UINT64, g_value_set_uint64, value, error);
}

gboolean
nm_g_object_set_property_flags (GObject *object,
                                const char *property_name,
                                GType gtype,
                                guint value,
                                GError **error)
{
	nm_assert (({
	                nm_auto_unref_gtypeclass GTypeClass *gtypeclass = g_type_class_ref (gtype);
	                G_IS_FLAGS_CLASS (gtypeclass);
	           }));
	_set_property (object, property_name, gtype, g_value_set_flags, value, error);
}

gboolean
nm_g_object_set_property_enum (GObject *object,
                               const char *property_name,
                               GType gtype,
                               int value,
                               GError **error)
{
	nm_assert (({
	                nm_auto_unref_gtypeclass GTypeClass *gtypeclass = g_type_class_ref (gtype);
	                G_IS_ENUM_CLASS (gtypeclass);
	           }));
	_set_property (object, property_name, gtype, g_value_set_enum, value, error);
}

GParamSpec *
nm_g_object_class_find_property_from_gtype (GType gtype,
                                            const char *property_name)
{
	nm_auto_unref_gtypeclass GObjectClass *gclass = NULL;

	gclass = g_type_class_ref (gtype);
	return g_object_class_find_property (gclass, property_name);
}

/*****************************************************************************/

/**
 * nm_g_type_find_implementing_class_for_property:
 * @gtype: the GObject type which has a property @pname
 * @pname: the name of the property to look up
 *
 * This is only a helper function for printf debugging. It's not
 * used in actual code. Hence, the function just asserts that
 * @pname and @gtype arguments are suitable. It cannot fail.
 *
 * Returns: the most ancestor type of @gtype, that
 *   implements the property @pname. It means, it
 *   searches the type hierarchy to find the type
 *   that added @pname.
 */
GType
nm_g_type_find_implementing_class_for_property (GType gtype,
                                                const char *pname)
{
	nm_auto_unref_gtypeclass GObjectClass *klass = NULL;
	GParamSpec *pspec;

	g_return_val_if_fail (pname, G_TYPE_INVALID);

	klass = g_type_class_ref (gtype);
	g_return_val_if_fail (G_IS_OBJECT_CLASS (klass), G_TYPE_INVALID);

	pspec = g_object_class_find_property (klass, pname);
	g_return_val_if_fail (pspec, G_TYPE_INVALID);

	gtype = G_TYPE_FROM_CLASS (klass);

	while (TRUE) {
		nm_auto_unref_gtypeclass GObjectClass *k = NULL;

		k = g_type_class_ref (g_type_parent (gtype));

		g_return_val_if_fail (G_IS_OBJECT_CLASS (k), G_TYPE_INVALID);

		if (g_object_class_find_property (k, pname) != pspec)
			return gtype;

		gtype = G_TYPE_FROM_CLASS (k);
	}
}

/*****************************************************************************/

static void
_str_buf_append_c_escape_octal (NMStrBuf *strbuf,
                                char ch)
{
	nm_str_buf_append_c4 (strbuf,
	                      '\\',
	                      '0' + ((char) ((((guchar) ch) >> 6) & 07)),
	                      '0' + ((char) ((((guchar) ch) >> 3) & 07)),
	                      '0' + ((char) ((((guchar) ch)     ) & 07)));
}

gconstpointer
nm_utils_buf_utf8safe_unescape (const char *str, gsize *out_len, gpointer *to_free)
{
	NMStrBuf strbuf;
	gsize len;
	const char *s;

	g_return_val_if_fail (to_free, NULL);
	g_return_val_if_fail (out_len, NULL);

	if (!str) {
		*out_len = 0;
		*to_free = NULL;
		return NULL;
	}

	len = strlen (str);

	s = memchr (str, '\\', len);
	if (!s) {
		*out_len = len;
		*to_free = NULL;
		return str;
	}

	nm_str_buf_init (&strbuf, len, FALSE);

	nm_str_buf_append_len (&strbuf, str, s - str);
	str = s;

	for (;;) {
		char ch;
		guint v;

		nm_assert (str[0] == '\\');

		ch = (++str)[0];

		if (ch == '\0') {
			// error. Trailing '\\'
			break;
		}

		if (ch >= '0' && ch <= '9') {
			v = ch - '0';
			ch = (++str)[0];
			if (ch >= '0' && ch <= '7') {
				v = v * 8 + (ch - '0');
				ch = (++str)[0];
				if (ch >= '0' && ch <= '7') {
					/* technically, escape sequences larger than \3FF are out of range
					 * and invalid. We don't check for that, and do the same as
					 * g_strcompress(): silently clip the value with & 0xFF. */
					v = v * 8 + (ch - '0');
					++str;
				}
			}
			ch = v;
		} else {
			switch (ch) {
			case 'b': ch = '\b'; break;
			case 'f': ch = '\f'; break;
			case 'n': ch = '\n'; break;
			case 'r': ch = '\r'; break;
			case 't': ch = '\t'; break;
			case 'v': ch = '\v'; break;
			default:
				/* Here we handle "\\\\", but all other unexpected escape sequences are really a bug.
				 * Take them literally, after removing the escape character */
				break;
			}
			str++;
		}

		nm_str_buf_append_c (&strbuf, ch);

		s = strchr (str, '\\');
		if (!s) {
			nm_str_buf_append (&strbuf, str);
			break;
		}

		nm_str_buf_append_len (&strbuf, str, s - str);
		str = s;
	}

	return (*to_free = nm_str_buf_finalize (&strbuf,
	                                        out_len));
}

/**
 * nm_utils_buf_utf8safe_escape:
 * @buf: byte array, possibly in utf-8 encoding, may have NUL characters.
 * @buflen: the length of @buf in bytes, or -1 if @buf is a NUL terminated
 *   string.
 * @flags: #NMUtilsStrUtf8SafeFlags flags
 * @to_free: (out): return the pointer location of the string
 *   if a copying was necessary.
 *
 * Based on the assumption, that @buf contains UTF-8 encoded bytes,
 * this will return valid UTF-8 sequence, and invalid sequences
 * will be escaped with backslash (C escaping, like g_strescape()).
 * This is sanitize non UTF-8 characters. The result is valid
 * UTF-8.
 *
 * The operation can be reverted with nm_utils_buf_utf8safe_unescape().
 * Note that if, and only if @buf contains no NUL bytes, the operation
 * can also be reverted with g_strcompress().
 *
 * Depending on @flags, valid UTF-8 characters are not escaped at all
 * (except the escape character '\\'). This is the difference to g_strescape(),
 * which escapes all non-ASCII characters. This allows to pass on
 * valid UTF-8 characters as-is and can be directly shown to the user
 * as UTF-8 -- with exception of the backslash escape character,
 * invalid UTF-8 sequences, and other (depending on @flags).
 *
 * Returns: the escaped input buffer, as valid UTF-8. If no escaping
 *   is necessary, it returns the input @buf. Otherwise, an allocated
 *   string @to_free is returned which must be freed by the caller
 *   with g_free. The escaping can be reverted by g_strcompress().
 **/
const char *
nm_utils_buf_utf8safe_escape (gconstpointer buf, gssize buflen, NMUtilsStrUtf8SafeFlags flags, char **to_free)
{
	const char *const str = buf;
	const char *p = NULL;
	const char *s;
	gboolean nul_terminated = FALSE;
	NMStrBuf strbuf;

	g_return_val_if_fail (to_free, NULL);

	*to_free = NULL;

	if (buflen == 0)
		return NULL;

	if (buflen < 0) {
		if (!str)
			return NULL;
		buflen = strlen (str);
		if (buflen == 0)
			return str;
		nul_terminated = TRUE;
	}

	if (   g_utf8_validate (str, buflen, &p)
	    && nul_terminated) {
		/* note that g_utf8_validate() does not allow NUL character inside @str. Good.
		 * We can treat @str like a NUL terminated string. */
		if (!NM_STRCHAR_ANY (str, ch,
		                        (   ch == '\\' \
		                         || (   NM_FLAGS_HAS (flags, NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL) \
		                             && ch < ' ') \
		                         || (   NM_FLAGS_HAS (flags, NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_NON_ASCII) \
		                             && ((guchar) ch) >= 127))))
			return str;
	}

	nm_str_buf_init (&strbuf,
	                 buflen + 5,
	                 NM_FLAGS_HAS (flags, NM_UTILS_STR_UTF8_SAFE_FLAG_SECRET));

	s = str;
	do {
		buflen -= p - s;
		nm_assert (buflen >= 0);

		for (; s < p; s++) {
			char ch = s[0];

			nm_assert (ch);
			if (ch == '\\')
				nm_str_buf_append_c2 (&strbuf, '\\', '\\');
			else if (   (   NM_FLAGS_HAS (flags, NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL) \
			             && ch < ' ') \
			         || (   NM_FLAGS_HAS (flags, NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_NON_ASCII) \
			             && ((guchar) ch) >= 127))
				_str_buf_append_c_escape_octal (&strbuf, ch);
			else
				nm_str_buf_append_c (&strbuf, ch);
		}

		if (buflen <= 0)
			break;

		_str_buf_append_c_escape_octal (&strbuf, p[0]);

		buflen--;
		if (buflen == 0)
			break;

		s = &p[1];
		(void) g_utf8_validate (s, buflen, &p);
	} while (TRUE);

	return (*to_free = nm_str_buf_finalize (&strbuf, NULL));
}

const char *
nm_utils_buf_utf8safe_escape_bytes (GBytes *bytes, NMUtilsStrUtf8SafeFlags flags, char **to_free)
{
	gconstpointer p;
	gsize l;

	if (bytes)
		p = g_bytes_get_data (bytes, &l);
	else {
		p = NULL;
		l = 0;
	}

	return nm_utils_buf_utf8safe_escape (p, l, flags, to_free);
}

/*****************************************************************************/

const char *
nm_utils_str_utf8safe_unescape (const char *str, char **to_free)
{
	gsize len;

	g_return_val_if_fail (to_free, NULL);

	return nm_utils_buf_utf8safe_unescape (str, &len, (gpointer *) to_free);
}

/**
 * nm_utils_str_utf8safe_escape:
 * @str: NUL terminated input string, possibly in utf-8 encoding
 * @flags: #NMUtilsStrUtf8SafeFlags flags
 * @to_free: (out): return the pointer location of the string
 *   if a copying was necessary.
 *
 * Returns the possible non-UTF-8 NUL terminated string @str
 * and uses backslash escaping (C escaping, like g_strescape())
 * to sanitize non UTF-8 characters. The result is valid
 * UTF-8.
 *
 * The operation can be reverted with g_strcompress() or
 * nm_utils_str_utf8safe_unescape().
 *
 * Depending on @flags, valid UTF-8 characters are not escaped at all
 * (except the escape character '\\'). This is the difference to g_strescape(),
 * which escapes all non-ASCII characters. This allows to pass on
 * valid UTF-8 characters as-is and can be directly shown to the user
 * as UTF-8 -- with exception of the backslash escape character,
 * invalid UTF-8 sequences, and other (depending on @flags).
 *
 * Returns: the escaped input string, as valid UTF-8. If no escaping
 *   is necessary, it returns the input @str. Otherwise, an allocated
 *   string @to_free is returned which must be freed by the caller
 *   with g_free. The escaping can be reverted by g_strcompress().
 **/
const char *
nm_utils_str_utf8safe_escape (const char *str, NMUtilsStrUtf8SafeFlags flags, char **to_free)
{
	return nm_utils_buf_utf8safe_escape (str, -1, flags, to_free);
}

/**
 * nm_utils_str_utf8safe_escape_cp:
 * @str: NUL terminated input string, possibly in utf-8 encoding
 * @flags: #NMUtilsStrUtf8SafeFlags flags
 *
 * Like nm_utils_str_utf8safe_escape(), except the returned value
 * is always a copy of the input and must be freed by the caller.
 *
 * Returns: the escaped input string in UTF-8 encoding. The returned
 *   value should be freed with g_free().
 *   The escaping can be reverted by g_strcompress().
 **/
char *
nm_utils_str_utf8safe_escape_cp (const char *str, NMUtilsStrUtf8SafeFlags flags)
{
	char *s;

	nm_utils_str_utf8safe_escape (str, flags, &s);
	return s ?: g_strdup (str);
}

char *
nm_utils_str_utf8safe_unescape_cp (const char *str)
{
	char *s;

	str = nm_utils_str_utf8safe_unescape (str, &s);
	return s ?: g_strdup (str);
}

char *
nm_utils_str_utf8safe_escape_take (char *str, NMUtilsStrUtf8SafeFlags flags)
{
	char *str_to_free;

	nm_utils_str_utf8safe_escape (str, flags, &str_to_free);
	if (str_to_free) {
		g_free (str);
		return str_to_free;
	}
	return str;
}

/*****************************************************************************/

/* taken from systemd's fd_wait_for_event(). Note that the timeout
 * is here in nano-seconds, not micro-seconds. */
int
nm_utils_fd_wait_for_event (int fd, int event, gint64 timeout_nsec)
{
	struct pollfd pollfd = {
		.fd = fd,
		.events = event,
	};
	struct timespec ts, *pts;
	int r;

	if (timeout_nsec < 0)
		pts = NULL;
	else {
		ts.tv_sec = (time_t) (timeout_nsec / NM_UTILS_NSEC_PER_SEC);
		ts.tv_nsec = (long int) (timeout_nsec % NM_UTILS_NSEC_PER_SEC);
		pts = &ts;
	}

	r = ppoll (&pollfd, 1, pts, NULL);
	if (r < 0)
		return -NM_ERRNO_NATIVE (errno);
	if (r == 0)
		return 0;
	return pollfd.revents;
}

/* taken from systemd's loop_read() */
ssize_t
nm_utils_fd_read_loop (int fd, void *buf, size_t nbytes, bool do_poll)
{
	uint8_t *p = buf;
	ssize_t n = 0;

	g_return_val_if_fail (fd >= 0, -EINVAL);
	g_return_val_if_fail (buf, -EINVAL);

	/* If called with nbytes == 0, let's call read() at least
	 * once, to validate the operation */

	if (nbytes > (size_t) SSIZE_MAX)
		return -EINVAL;

	do {
		ssize_t k;

		k = read (fd, p, nbytes);
		if (k < 0) {
			int errsv = errno;

			if (errsv == EINTR)
				continue;

			if (errsv == EAGAIN && do_poll) {

				/* We knowingly ignore any return value here,
				 * and expect that any error/EOF is reported
				 * via read() */

				(void) nm_utils_fd_wait_for_event (fd, POLLIN, -1);
				continue;
			}

			return n > 0 ? n : -NM_ERRNO_NATIVE (errsv);
		}

		if (k == 0)
			return n;

		g_assert ((size_t) k <= nbytes);

		p += k;
		nbytes -= k;
		n += k;
	} while (nbytes > 0);

	return n;
}

/* taken from systemd's loop_read_exact() */
int
nm_utils_fd_read_loop_exact (int fd, void *buf, size_t nbytes, bool do_poll)
{
	ssize_t n;

	n = nm_utils_fd_read_loop (fd, buf, nbytes, do_poll);
	if (n < 0)
		return (int) n;
	if ((size_t) n != nbytes)
		return -EIO;

	return 0;
}

/*****************************************************************************/

NMUtilsNamedValue *
nm_utils_named_values_from_str_dict_with_sort (GHashTable *hash,
                                               guint *out_len,
                                               GCompareDataFunc compare_func,
                                               gpointer user_data)
{
	GHashTableIter iter;
	NMUtilsNamedValue *values;
	guint i, len;

	if (   !hash
	    || !(len = g_hash_table_size (hash))) {
		NM_SET_OUT (out_len, 0);
		return NULL;
	}

	i = 0;
	values = g_new (NMUtilsNamedValue, len + 1);
	g_hash_table_iter_init (&iter, hash);
	while (g_hash_table_iter_next (&iter,
	                               (gpointer *) &values[i].name,
	                               (gpointer *) &values[i].value_ptr))
		i++;
	nm_assert (i == len);
	values[i].name = NULL;
	values[i].value_ptr = NULL;

	if (compare_func)
		nm_utils_named_value_list_sort (values, len, compare_func, user_data);

	NM_SET_OUT (out_len, len);
	return values;
}

gssize
nm_utils_named_value_list_find (const NMUtilsNamedValue *arr,
                                gsize len,
                                const char *name,
                                gboolean sorted)
{
	gsize i;

	nm_assert (name);

#if NM_MORE_ASSERTS > 5
	{
		for (i = 0; i < len; i++) {
			const NMUtilsNamedValue *v = &arr[i];

			nm_assert (v->name);
			if (   sorted
			    && i > 0)
				nm_assert (strcmp (arr[i - 1].name, v->name) < 0);
		}
	}

	nm_assert (   !sorted
	           || nm_utils_named_value_list_is_sorted (arr, len, FALSE, NULL, NULL));
#endif

	if (sorted) {
		return nm_utils_array_find_binary_search (arr,
		                                          sizeof (NMUtilsNamedValue),
		                                          len,
		                                          &name,
		                                          nm_strcmp_p_with_data,
		                                          NULL);
	}
	for (i = 0; i < len; i++) {
		if (nm_streq (arr[i].name, name))
			return i;
	}
	return ~((gssize) len);
}

gboolean
nm_utils_named_value_list_is_sorted (const NMUtilsNamedValue *arr,
                                     gsize len,
                                     gboolean accept_duplicates,
                                     GCompareDataFunc compare_func,
                                     gpointer user_data)
{
	gsize i;
	int c_limit;

	if (len == 0)
		return TRUE;

	g_return_val_if_fail (arr, FALSE);

	if (!compare_func)
		compare_func = nm_strcmp_p_with_data;

	c_limit = accept_duplicates ? 0 : -1;

	for (i = 1; i < len; i++) {
		int c;

		c = compare_func (&arr[i - 1], &arr[i], user_data);
		if (c > c_limit)
			return FALSE;
	}
	return TRUE;
}

void
nm_utils_named_value_list_sort (NMUtilsNamedValue *arr,
                                gsize len,
                                GCompareDataFunc compare_func,
                                gpointer user_data)
{
	if (len == 0)
		return;

	g_return_if_fail (arr);

	if (len == 1)
		return;

	g_qsort_with_data (arr,
	                   len,
	                   sizeof (NMUtilsNamedValue),
	                   compare_func ?: nm_strcmp_p_with_data,
	                   user_data);
}

/*****************************************************************************/

gpointer *
nm_utils_hash_keys_to_array (GHashTable *hash,
                             GCompareDataFunc compare_func,
                             gpointer user_data,
                             guint *out_len)
{
	guint len;
	gpointer *keys;

	/* by convention, we never return an empty array. In that
	 * case, always %NULL. */
	if (   !hash
	    || g_hash_table_size (hash) == 0) {
		NM_SET_OUT (out_len, 0);
		return NULL;
	}

	keys = g_hash_table_get_keys_as_array (hash, &len);
	if (   len > 1
	    && compare_func) {
		g_qsort_with_data (keys,
		                   len,
		                   sizeof (gpointer),
		                   compare_func,
		                   user_data);
	}
	NM_SET_OUT (out_len, len);
	return keys;
}

gpointer *
nm_utils_hash_values_to_array (GHashTable *hash,
                               GCompareDataFunc compare_func,
                               gpointer user_data,
                               guint *out_len)
{
	GHashTableIter iter;
	gpointer value;
	gpointer *arr;
	guint i, len;

	if (   !hash
	    || (len = g_hash_table_size (hash)) == 0u) {
		NM_SET_OUT (out_len, 0);
		return NULL;
	}

	arr = g_new (gpointer, ((gsize) len) + 1);
	i = 0;
	g_hash_table_iter_init (&iter, hash);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &value))
		arr[i++] = value;

	nm_assert (i == len);
	arr[len] = NULL;

	if (   len > 1
	    && compare_func) {
		g_qsort_with_data (arr,
		                   len,
		                   sizeof (gpointer),
		                   compare_func,
		                   user_data);
	}

	NM_SET_OUT (out_len, len);
	return arr;
}

gboolean
nm_utils_hashtable_same_keys (const GHashTable *a,
                              const GHashTable *b)
{
	GHashTableIter h;
	const char *k;

	if (a == b)
		return TRUE;
	if (!a || !b)
		return FALSE;
	if (g_hash_table_size ((GHashTable *) a) != g_hash_table_size ((GHashTable *) b))
		return FALSE;

	g_hash_table_iter_init (&h, (GHashTable *) a);
	while (g_hash_table_iter_next (&h, (gpointer) &k, NULL)) {
		if (!g_hash_table_contains ((GHashTable *) b, k))
			return FALSE;
	}

#if NM_MORE_ASSERTS > 5
	g_hash_table_iter_init (&h, (GHashTable *) b);
	while (g_hash_table_iter_next (&h, (gpointer) &k, NULL))
		nm_assert (g_hash_table_contains ((GHashTable *) a, k));
#endif

	return TRUE;
}

char **
nm_utils_strv_make_deep_copied (const char **strv)
{
	gsize i;

	/* it takes a strv list, and copies each
	 * strings. Note that this updates @strv *in-place*
	 * and returns it. */

	if (!strv)
		return NULL;
	for (i = 0; strv[i]; i++)
		strv[i] = g_strdup (strv[i]);

	return (char **) strv;
}

char **
nm_utils_strv_make_deep_copied_n (const char **strv, gsize len)
{
	gsize i;

	/* it takes a strv array with len elements, and copies each
	 * strings. Note that this updates @strv *in-place*
	 * and returns it. */

	if (!strv)
		return NULL;
	for (i = 0; i < len; i++)
		strv[i] = g_strdup (strv[i]);

	return (char **) strv;
}

/**
 * @strv: the strv array to copy. It may be %NULL if @len
 *   is negative or zero (in which case %NULL will be returned).
 * @len: the length of strings in @str. If negative, strv is assumed
 *   to be a NULL terminated array.
 * @deep_copied: if %TRUE, clones the individual strings. In that case,
 *   the returned array must be freed with g_strfreev(). Otherwise, the
 *   strings themself are not copied. You must take care of who owns the
 *   strings yourself.
 *
 * Like g_strdupv(), with two differences:
 *
 * - accepts a @len parameter for non-null terminated strv array.
 *
 * - this never returns an empty strv array, but always %NULL if
 *   there are no strings.
 *
 * Note that if @len is non-negative, then it still must not
 * contain any %NULL pointers within the first @len elements.
 * Otherwise you would leak elements if you try to free the
 * array with g_strfreev(). Allowing that would be error prone.
 *
 * Returns: (transfer full): a clone of the strv array. Always
 *   %NULL terminated. Depending on @deep_copied, the strings are
 *   cloned or not.
 */
char **
nm_utils_strv_dup (gpointer strv,
                   gssize len,
                   gboolean deep_copied)
{
	gsize i, l;
	char **v;
	const char *const *const src = strv;

	if (len < 0)
		l = NM_PTRARRAY_LEN (src);
	else
		l = len;
	if (l == 0) {
		/* this function never returns an empty strv array. If you
		 * need that, handle it yourself. */
		return NULL;
	}

	v = g_new (char *, l + 1);
	for (i = 0; i < l; i++) {

		if (G_UNLIKELY (!src[i])) {
			/* NULL strings are not allowed. Clear the remainder of the array
			 * and return it (with assertion failure). */
			l++;
			for (; i < l; i++)
				v[i] = NULL;
			g_return_val_if_reached (v);
		}

		if (deep_copied)
			v[i] = g_strdup (src[i]);
		else
			v[i] = (char *) src[i];
	}
	v[l] = NULL;
	return v;
}

/*****************************************************************************/

gssize
nm_utils_ptrarray_find_binary_search (gconstpointer *list,
                                      gsize len,
                                      gconstpointer needle,
                                      GCompareDataFunc cmpfcn,
                                      gpointer user_data,
                                      gssize *out_idx_first,
                                      gssize *out_idx_last)
{
	gssize imin, imax, imid, i2min, i2max, i2mid;
	int cmp;

	g_return_val_if_fail (list || !len, ~((gssize) 0));
	g_return_val_if_fail (cmpfcn, ~((gssize) 0));

	imin = 0;
	if (len > 0) {
		imax = len - 1;

		while (imin <= imax) {
			imid = imin + (imax - imin) / 2;

			cmp = cmpfcn (list[imid], needle, user_data);
			if (cmp == 0) {
				/* we found a matching entry at index imid.
				 *
				 * Does the caller request the first/last index as well (in case that
				 * there are multiple entries which compare equal). */

				if (out_idx_first) {
					i2min = imin;
					i2max = imid + 1;
					while (i2min <= i2max) {
						i2mid = i2min + (i2max - i2min) / 2;

						cmp = cmpfcn (list[i2mid], needle, user_data);
						if (cmp == 0)
							i2max = i2mid -1;
						else {
							nm_assert (cmp < 0);
							i2min = i2mid + 1;
						}
					}
					*out_idx_first = i2min;
				}
				if (out_idx_last) {
					i2min = imid + 1;
					i2max = imax;
					while (i2min <= i2max) {
						i2mid = i2min + (i2max - i2min) / 2;

						cmp = cmpfcn (list[i2mid], needle, user_data);
						if (cmp == 0)
							i2min = i2mid + 1;
						else {
							nm_assert (cmp > 0);
							i2max = i2mid - 1;
						}
					}
					*out_idx_last = i2min - 1;
				}
				return imid;
			}

			if (cmp < 0)
				imin = imid + 1;
			else
				imax = imid - 1;
		}
	}

	/* return the inverse of @imin. This is a negative number, but
	 * also is ~imin the position where the value should be inserted. */
	imin = ~imin;
	NM_SET_OUT (out_idx_first, imin);
	NM_SET_OUT (out_idx_last, imin);
	return imin;
}

/*****************************************************************************/

/**
 * nm_utils_array_find_binary_search:
 * @list: the list to search. It must be sorted according to @cmpfcn ordering.
 * @elem_size: the size in bytes of each element in the list
 * @len: the number of elements in @list
 * @needle: the value that is searched
 * @cmpfcn: the compare function. The elements @list are passed as first
 *   argument to @cmpfcn, while @needle is passed as second. Usually, the
 *   needle is the same data type as inside the list, however, that is
 *   not necessary, as long as @cmpfcn takes care to cast the two arguments
 *   accordingly.
 * @user_data: optional argument passed to @cmpfcn
 *
 * Performs binary search for @needle in @list. On success, returns the
 * (non-negative) index where the compare function found the searched element.
 * On success, it returns a negative value. Note that the return negative value
 * is the bitwise inverse of the position where the element should be inserted.
 *
 * If the list contains multiple matching elements, an arbitrary index is
 * returned.
 *
 * Returns: the index to the element in the list, or the (negative, bitwise inverted)
 *   position where it should be.
 */
gssize
nm_utils_array_find_binary_search (gconstpointer list,
                                   gsize elem_size,
                                   gsize len,
                                   gconstpointer needle,
                                   GCompareDataFunc cmpfcn,
                                   gpointer user_data)
{
	gssize imin, imax, imid;
	int cmp;

	g_return_val_if_fail (list || !len, ~((gssize) 0));
	g_return_val_if_fail (cmpfcn, ~((gssize) 0));
	g_return_val_if_fail (elem_size > 0, ~((gssize) 0));

	imin = 0;
	if (len == 0)
		return ~imin;

	imax = len - 1;

	while (imin <= imax) {
		imid = imin + (imax - imin) / 2;

		cmp = cmpfcn (&((const char *) list)[elem_size * imid], needle, user_data);
		if (cmp == 0)
			return imid;

		if (cmp < 0)
			imin = imid + 1;
		else
			imax = imid - 1;
	}

	/* return the inverse of @imin. This is a negative number, but
	 * also is ~imin the position where the value should be inserted. */
	return ~imin;
}

/*****************************************************************************/

/**
 * nm_utils_hash_table_equal:
 * @a: one #GHashTable
 * @b: other #GHashTable
 * @treat_null_as_empty: if %TRUE, when either @a or @b is %NULL, it is
 *   treated like an empty hash. It means, a %NULL hash will compare equal
 *   to an empty hash.
 * @equal_func: the equality function, for comparing the values.
 *   If %NULL, the values are not compared. In that case, the function
 *   only checks, if both dictionaries have the same keys -- according
 *   to @b's key equality function.
 *   Note that the values of @a will be passed as first argument
 *   to @equal_func.
 *
 * Compares two hash tables, whether they have equal content.
 * This only makes sense, if @a and @b have the same key types and
 * the same key compare-function.
 *
 * Returns: %TRUE, if both dictionaries have the same content.
 */
gboolean
nm_utils_hash_table_equal (const GHashTable *a,
                           const GHashTable *b,
                           gboolean treat_null_as_empty,
                           NMUtilsHashTableEqualFunc equal_func)
{
	guint n;
	GHashTableIter iter;
	gconstpointer key, v_a, v_b;

	if (a == b)
		return TRUE;
	if (!treat_null_as_empty) {
		if (!a || !b)
			return FALSE;
	}

	n = a ? g_hash_table_size ((GHashTable *) a) : 0;
	if (n != (b ? g_hash_table_size ((GHashTable *) b) : 0))
		return FALSE;

	if (n > 0) {
		g_hash_table_iter_init (&iter, (GHashTable *) a);
		while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &v_a)) {
			if (!g_hash_table_lookup_extended ((GHashTable *) b, key, NULL, (gpointer *) &v_b))
				return FALSE;
			if (   equal_func
			    && !equal_func (v_a, v_b))
				return FALSE;
		}
	}

	return TRUE;
}

/*****************************************************************************/

/**
 * nm_utils_get_start_time_for_pid:
 * @pid: the process identifier
 * @out_state: return the state character, like R, S, Z. See `man 5 proc`.
 * @out_ppid: parent process id
 *
 * Originally copied from polkit source (src/polkit/polkitunixprocess.c)
 * and adjusted.
 *
 * Returns: the timestamp when the process started (by parsing /proc/$PID/stat).
 * If an error occurs (e.g. the process does not exist), 0 is returned.
 *
 * The returned start time counts since boot, in the unit HZ (with HZ usually being (1/100) seconds)
 **/
guint64
nm_utils_get_start_time_for_pid (pid_t pid, char *out_state, pid_t *out_ppid)
{
	guint64 start_time;
	char filename[256];
	gs_free char *contents = NULL;
	size_t length;
	gs_free const char **tokens = NULL;
	char *p;
	char state = ' ';
	gint64 ppid = 0;

	start_time = 0;
	contents = NULL;

	g_return_val_if_fail (pid > 0, 0);

	G_STATIC_ASSERT_EXPR (sizeof (GPid) >= sizeof (pid_t));

	nm_sprintf_buf (filename, "/proc/%"G_PID_FORMAT"/stat", (GPid) pid);

	if (!g_file_get_contents (filename, &contents, &length, NULL))
		goto fail;

	/* start time is the token at index 19 after the '(process name)' entry - since only this
	 * field can contain the ')' character, search backwards for this to avoid malicious
	 * processes trying to fool us
	 */
	p = strrchr (contents, ')');
	if (!p)
		goto fail;
	p += 2; /* skip ') ' */
	if (p - contents >= (int) length)
		goto fail;

	state = p[0];

	tokens = nm_utils_strsplit_set (p, " ");

	if (NM_PTRARRAY_LEN (tokens) < 20)
		goto fail;

	if (out_ppid) {
		ppid = _nm_utils_ascii_str_to_int64 (tokens[1], 10, 1, G_MAXINT, 0);
		if (ppid == 0)
			goto fail;
	}

	start_time = _nm_utils_ascii_str_to_int64 (tokens[19], 10, 1, G_MAXINT64, 0);
	if (start_time == 0)
		goto fail;

	NM_SET_OUT (out_state, state);
	NM_SET_OUT (out_ppid, ppid);
	return start_time;

fail:
	NM_SET_OUT (out_state, ' ');
	NM_SET_OUT (out_ppid, 0);
	return 0;
}

/*****************************************************************************/

/**
 * _nm_utils_strv_sort:
 * @strv: pointer containing strings that will be sorted
 *   in-place, %NULL is allowed, unless @len indicates
 *   that there are more elements.
 * @len: the number of elements in strv. If negative,
 *   strv must be a NULL terminated array and the length
 *   will be calculated first. If @len is a positive
 *   number, @strv is allowed to contain %NULL strings
 *   too.
 *
 * Ascending sort of the array @strv inplace, using plain strcmp() string
 * comparison.
 */
void
_nm_utils_strv_sort (const char **strv, gssize len)
{
	GCompareDataFunc cmp;
	gsize l;

	if (len < 0) {
		l = NM_PTRARRAY_LEN (strv);
		cmp = nm_strcmp_p_with_data;
	} else {
		l = len;
		cmp = nm_strcmp0_p_with_data;
	}

	if (l <= 1)
		return;

	nm_assert (l <= (gsize) G_MAXINT);

	g_qsort_with_data (strv,
	                   l,
	                   sizeof (const char *),
	                   cmp,
	                   NULL);
}

/**
 * _nm_utils_strv_cmp_n:
 * @strv1: a string array
 * @len1: the length of @strv1, or -1 for NULL terminated array.
 * @strv2: a string array
 * @len2: the length of @strv2, or -1 for NULL terminated array.
 *
 * Note that
 *   - len == -1 && strv == NULL
 * is treated like a %NULL argument and compares differently from
 * other arrays.
 *
 * Note that an empty array can be represented as
 *   - len == -1 &&  strv && !strv[0]
 *   - len ==  0 && !strv
 *   - len ==  0 &&  strv
 * These 3 forms all compare equal.
 * It also means, if length is 0, then it is permissible for strv to be %NULL.
 *
 * The strv arrays may contain %NULL strings (if len is positive).
 *
 * Returns: 0 if the arrays are equal (using strcmp).
 **/
int
_nm_utils_strv_cmp_n (const char *const*strv1,
                      gssize len1,
                      const char *const*strv2,
                      gssize len2)
{
	gsize n, n2;

	if (len1 < 0) {
		if (!strv1)
			return (len2 < 0 && !strv2) ? 0 : -1;
		n = NM_PTRARRAY_LEN (strv1);
	} else
		n = len1;

	if (len2 < 0) {
		if (!strv2)
			return 1;
		n2 = NM_PTRARRAY_LEN (strv2);
	} else
		n2 = len2;

	NM_CMP_DIRECT (n, n2);
	for (; n > 0; n--, strv1++, strv2++)
		NM_CMP_DIRECT_STRCMP0 (*strv1, *strv2);
	return 0;
}

/*****************************************************************************/

/**
 * nm_utils_g_slist_find_str:
 * @list: the #GSList with NUL terminated strings to search
 * @needle: the needle string to look for.
 *
 * Search the list for @needle and return the first found match
 * (or %NULL if not found). Uses strcmp() for finding the first matching
 * element.
 *
 * Returns: the #GSList element with @needle as string value or
 *   %NULL if not found.
 */
GSList *
nm_utils_g_slist_find_str (const GSList *list,
                           const char *needle)
{
	nm_assert (needle);

	for (; list; list = list->next) {
		nm_assert (list->data);
		if (nm_streq (list->data, needle))
			return (GSList *) list;
	}
	return NULL;
}

/**
 * nm_utils_g_slist_strlist_cmp:
 * @a: the left #GSList of strings
 * @b: the right #GSList of strings to compare.
 *
 * Compares two string lists. The data elements are compared with
 * strcmp(), alloing %NULL elements.
 *
 * Returns: 0, 1, or -1, depending on how the lists compare.
 */
int
nm_utils_g_slist_strlist_cmp (const GSList *a, const GSList *b)
{
	while (TRUE) {
		if (!a)
			return !b ? 0 : -1;
		if (!b)
			return 1;
		NM_CMP_DIRECT_STRCMP0 (a->data, b->data);
		a = a->next;
		b = b->next;
	}
}

char *
nm_utils_g_slist_strlist_join (const GSList *a, const char *separator)
{
	GString *str = NULL;

	if (!a)
		return NULL;

	for (; a; a = a->next) {
		if (!str)
			str = g_string_new (NULL);
		else
			g_string_append (str, separator);
		g_string_append (str, a->data);
	}
	return g_string_free (str, FALSE);
}

/*****************************************************************************/

gpointer
_nm_utils_user_data_pack (int nargs, gconstpointer *args)
{
	int i;
	gpointer *data;

	nm_assert (nargs > 0);
	nm_assert (args);

	data = g_slice_alloc (((gsize) nargs) * sizeof (gconstpointer));
	for (i = 0; i < nargs; i++)
		data[i] = (gpointer) args[i];
	return data;
}

void
_nm_utils_user_data_unpack (gpointer user_data, int nargs, ...)
{
	gpointer *data = user_data;
	va_list ap;
	int i;

	nm_assert (data);
	nm_assert (nargs > 0);

	va_start (ap, nargs);
	for (i = 0; i < nargs; i++) {
		gpointer *dst;

		dst = va_arg (ap, gpointer *);
		nm_assert (dst);

		*dst = data[i];
	}
	va_end (ap);

	g_slice_free1 (((gsize) nargs) * sizeof (gconstpointer), data);
}

/*****************************************************************************/

typedef struct {
	gpointer callback_user_data;
	GCancellable *cancellable;
	NMUtilsInvokeOnIdleCallback callback;
	gulong cancelled_id;
	guint idle_id;
} InvokeOnIdleData;

static gboolean
_nm_utils_invoke_on_idle_cb_idle (gpointer user_data)
{
	InvokeOnIdleData *data = user_data;

	data->idle_id = 0;
	nm_clear_g_signal_handler (data->cancellable, &data->cancelled_id);

	data->callback (data->callback_user_data, data->cancellable);
	nm_g_object_unref (data->cancellable);
	g_slice_free (InvokeOnIdleData, data);
	return G_SOURCE_REMOVE;
}

static void
_nm_utils_invoke_on_idle_cb_cancelled (GCancellable *cancellable,
                                       InvokeOnIdleData *data)
{
	/* on cancellation, we invoke the callback synchronously. */
	nm_clear_g_signal_handler (data->cancellable, &data->cancelled_id);
	nm_clear_g_source (&data->idle_id);
	data->callback (data->callback_user_data, data->cancellable);
	nm_g_object_unref (data->cancellable);
	g_slice_free (InvokeOnIdleData, data);
}

void
nm_utils_invoke_on_idle (NMUtilsInvokeOnIdleCallback callback,
                         gpointer callback_user_data,
                         GCancellable *cancellable)
{
	InvokeOnIdleData *data;

	g_return_if_fail (callback);

	data = g_slice_new (InvokeOnIdleData);
	data->callback = callback;
	data->callback_user_data = callback_user_data;
	data->cancellable = nm_g_object_ref (cancellable);
	if (   cancellable
	    && !g_cancellable_is_cancelled (cancellable)) {
		/* if we are passed a non-cancelled cancellable, we register to the "cancelled"
		 * signal an invoke the callback synchronously (from the signal handler).
		 *
		 * We don't do that,
		 *  - if the cancellable is already cancelled (because we don't want to invoke
		 *    the callback synchronously from the caller).
		 *  - if we have no cancellable at hand. */
		data->cancelled_id = g_signal_connect (cancellable,
		                                       "cancelled",
		                                       G_CALLBACK (_nm_utils_invoke_on_idle_cb_cancelled),
		                                       data);
	} else
		data->cancelled_id = 0;
	data->idle_id = g_idle_add (_nm_utils_invoke_on_idle_cb_idle, data);
}

/*****************************************************************************/

int
nm_utils_getpagesize (void)
{
	static volatile int val = 0;
	long l;
	int v;

	v = g_atomic_int_get (&val);

	if (G_UNLIKELY (v == 0)) {
		l = sysconf (_SC_PAGESIZE);

		g_return_val_if_fail (l > 0 && l < G_MAXINT, 4*1024);

		v = (int) l;
		if (!g_atomic_int_compare_and_exchange (&val, 0, v)) {
			v = g_atomic_int_get (&val);
			g_return_val_if_fail (v > 0, 4*1024);
		}
	}

	nm_assert (v > 0);
#if NM_MORE_ASSERTS > 5
	nm_assert (v == getpagesize ());
	nm_assert (v == sysconf (_SC_PAGESIZE));
#endif

	return v;
}

gboolean
nm_utils_memeqzero (gconstpointer data, gsize length)
{
	const unsigned char *p = data;
	int len;

	/* Taken from https://github.com/rustyrussell/ccan/blob/9d2d2c49f053018724bcc6e37029da10b7c3d60d/ccan/mem/mem.c#L92,
	 * CC-0 licensed. */

	/* Check first 16 bytes manually */
	for (len = 0; len < 16; len++) {
		if (!length)
			return TRUE;
		if (*p)
			return FALSE;
		p++;
		length--;
	}

	/* Now we know that's zero, memcmp with self. */
	return memcmp (data, p, length) == 0;
}

/**
 * nm_utils_bin2hexstr_full:
 * @addr: pointer of @length bytes. If @length is zero, this may
 *   also be %NULL.
 * @length: number of bytes in @addr. May also be zero, in which
 *   case this will return an empty string.
 * @delimiter: either '\0', otherwise the output string will have the
 *   given delimiter character between each two hex numbers.
 * @upper_case: if TRUE, use upper case ASCII characters for hex.
 * @out: if %NULL, the function will allocate a new buffer of
 *   either (@length*2+1) or (@length*3) bytes, depending on whether
 *   a @delimiter is specified. In that case, the allocated buffer will
 *   be returned and must be freed by the caller.
 *   If not %NULL, the buffer must already be preallocated and contain
 *   at least (@length*2+1) or (@length*3) bytes, depending on the delimiter.
 *   If @length is zero, then of course at least one byte will be allocated
 *   or @out (if given) must contain at least room for the trailing NUL byte.
 *
 * Returns: the binary value converted to a hex string. If @out is given,
 *   this always returns @out. If @out is %NULL, a newly allocated string
 *   is returned. This never returns %NULL, for buffers of length zero
 *   an empty string is returend.
 */
char *
nm_utils_bin2hexstr_full (gconstpointer addr,
                          gsize length,
                          char delimiter,
                          gboolean upper_case,
                          char *out)
{
	const guint8 *in = addr;
	const char *LOOKUP = upper_case ? "0123456789ABCDEF" : "0123456789abcdef";
	char *out0;

	if (out)
		out0 = out;
	else {
		out0 = out = g_new (char, length == 0
		                          ? 1u
		                          : (  delimiter == '\0'
		                             ? length * 2u + 1u
		                             : length * 3u));
	}

	/* @out must contain at least @length*3 bytes if @delimiter is set,
	 * otherwise, @length*2+1. */

	if (length > 0) {
		nm_assert (in);
		for (;;) {
			const guint8 v = *in++;

			*out++ = LOOKUP[v >> 4];
			*out++ = LOOKUP[v & 0x0F];
			length--;
			if (!length)
				break;
			if (delimiter)
				*out++ = delimiter;
		}
	}

	*out = '\0';
	return out0;
}

guint8 *
nm_utils_hexstr2bin_full (const char *hexstr,
                          gboolean allow_0x_prefix,
                          gboolean delimiter_required,
                          const char *delimiter_candidates,
                          gsize required_len,
                          guint8 *buffer,
                          gsize buffer_len,
                          gsize *out_len)
{
	const char *in = hexstr;
	guint8 *out = buffer;
	gboolean delimiter_has = TRUE;
	guint8 delimiter = '\0';
	gsize len;

	nm_assert (hexstr);
	nm_assert (buffer);
	nm_assert (required_len > 0 || out_len);

	if (   allow_0x_prefix
	    && in[0] == '0'
	    && in[1] == 'x')
		in += 2;

	while (TRUE) {
		const guint8 d1 = in[0];
		guint8 d2;
		int i1, i2;

		i1 = nm_utils_hexchar_to_int (d1);
		if (i1 < 0)
			goto fail;

		/* If there's no leading zero (ie "aa:b:cc") then fake it */
		d2 = in[1];
		if (   d2
		    && (i2 = nm_utils_hexchar_to_int (d2)) >= 0) {
			*out++ = (i1 << 4) + i2;
			d2 = in[2];
			if (!d2)
				break;
			in += 2;
		} else {
			/* Fake leading zero */
			*out++ = i1;
			if (!d2) {
				if (!delimiter_has) {
					/* when using no delimiter, there must be pairs of hex chars */
					goto fail;
				}
				break;
			}
			in += 1;
		}

		if (--buffer_len == 0)
			goto fail;

		if (delimiter_has) {
			if (d2 != delimiter) {
				if (delimiter)
					goto fail;
				if (delimiter_candidates) {
					while (delimiter_candidates[0]) {
						if (delimiter_candidates++[0] == d2)
							delimiter = d2;
					}
				}
				if (!delimiter) {
					if (delimiter_required)
						goto fail;
					delimiter_has = FALSE;
					continue;
				}
			}
			in++;
		}
	}

	len = out - buffer;
	if (   required_len == 0
	    || len == required_len) {
		NM_SET_OUT (out_len, len);
		return buffer;
	}

fail:
	NM_SET_OUT (out_len, 0);
	return NULL;
}

guint8 *
nm_utils_hexstr2bin_alloc (const char *hexstr,
                           gboolean allow_0x_prefix,
                           gboolean delimiter_required,
                           const char *delimiter_candidates,
                           gsize required_len,
                           gsize *out_len)
{
	guint8 *buffer;
	gsize buffer_len, len;

	g_return_val_if_fail (hexstr, NULL);

	nm_assert (required_len > 0 || out_len);

	if (   allow_0x_prefix
	    && hexstr[0] == '0'
	    && hexstr[1] == 'x')
		hexstr += 2;

	if (!hexstr[0])
		goto fail;

	if (required_len > 0)
		buffer_len = required_len;
	else
		buffer_len = strlen (hexstr) / 2 + 3;

	buffer = g_malloc (buffer_len);

	if (nm_utils_hexstr2bin_full (hexstr,
	                              FALSE,
	                              delimiter_required,
	                              delimiter_candidates,
	                              required_len,
	                              buffer,
	                              buffer_len,
	                              &len)) {
		NM_SET_OUT (out_len, len);
		return buffer;
	}

	g_free (buffer);

fail:
	NM_SET_OUT (out_len, 0);
	return NULL;
}

/*****************************************************************************/

GVariant *
nm_utils_gvariant_vardict_filter (GVariant *src,
                                  gboolean (*filter_fcn) (const char *key,
                                                          GVariant *val,
                                                          char **out_key,
                                                          GVariant **out_val,
                                                          gpointer user_data),
                                  gpointer user_data)
{
	GVariantIter iter;
	GVariantBuilder builder;
	const char *key;
	GVariant *val;

	g_return_val_if_fail (src && g_variant_is_of_type (src, G_VARIANT_TYPE_VARDICT), NULL);
	g_return_val_if_fail (filter_fcn, NULL);

	g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);

	g_variant_iter_init (&iter, src);
	while (g_variant_iter_next (&iter, "{&sv}", &key, &val)) {
		_nm_unused gs_unref_variant GVariant *val_free = val;
		gs_free char *key2 = NULL;
		gs_unref_variant GVariant *val2 = NULL;

		if (filter_fcn (key,
		                val,
		                &key2,
		                &val2,
		                user_data)) {
			g_variant_builder_add (&builder,
			                       "{sv}",
			                       key2 ?: key,
			                       val2 ?: val);
		}
	}

	return g_variant_builder_end (&builder);
}

static gboolean
_gvariant_vardict_filter_drop_one (const char *key,
                                   GVariant *val,
                                   char **out_key,
                                   GVariant **out_val,
                                   gpointer user_data)
{
	return !nm_streq (key, user_data);
}

GVariant *
nm_utils_gvariant_vardict_filter_drop_one (GVariant *src,
                                           const char *key)
{
	return nm_utils_gvariant_vardict_filter (src,
	                                         _gvariant_vardict_filter_drop_one,
	                                         (gpointer) key);
}

/*****************************************************************************/

static gboolean
debug_key_matches (const char *key,
                   const char *token,
                   guint        length)
{
	/* may not call GLib functions: see note in g_parse_debug_string() */
	for (; length; length--, key++, token++) {
		char k = (*key   == '_') ? '-' : g_ascii_tolower (*key  );
		char t = (*token == '_') ? '-' : g_ascii_tolower (*token);

		if (k != t)
			return FALSE;
	}

	return *key == '\0';
}

/**
 * nm_utils_parse_debug_string:
 * @string: the string to parse
 * @keys: the debug keys
 * @nkeys: number of entries in @keys
 *
 * Similar to g_parse_debug_string(), but does not special
 * case "help" or "all".
 *
 * Returns: the flags
 */
guint
nm_utils_parse_debug_string (const char *string,
                             const GDebugKey *keys,
                             guint nkeys)
{
	guint i;
	guint result = 0;
	const char *q;

	if (string == NULL)
		return 0;

	while (*string) {
		q = strpbrk (string, ":;, \t");
		if (!q)
			q = string + strlen (string);

		for (i = 0; i < nkeys; i++) {
			if (debug_key_matches (keys[i].key, string, q - string))
				result |= keys[i].value;
		}

		string = q;
		if (*string)
			string++;
	}

	return result;
}

/*****************************************************************************/

GSource *
nm_g_idle_source_new (int priority,
                      GSourceFunc func,
                      gpointer user_data,
                      GDestroyNotify destroy_notify)
{
	GSource *source;

	source = g_idle_source_new ();
	if (priority != G_PRIORITY_DEFAULT)
		g_source_set_priority (source, priority);
	g_source_set_callback (source, func, user_data, destroy_notify);
	return source;
}

GSource *
nm_g_timeout_source_new (guint timeout_msec,
                         int priority,
                         GSourceFunc func,
                         gpointer user_data,
                         GDestroyNotify destroy_notify)
{
	GSource *source;

	source = g_timeout_source_new (timeout_msec);
	if (priority != G_PRIORITY_DEFAULT)
		g_source_set_priority (source, priority);
	g_source_set_callback (source, func, user_data, destroy_notify);
	return source;
}

GSource *
nm_g_unix_signal_source_new (int signum,
                             int priority,
                             GSourceFunc handler,
                             gpointer user_data,
                             GDestroyNotify notify)
{
	GSource *source;

	source = g_unix_signal_source_new (signum);

	if (priority != G_PRIORITY_DEFAULT)
		g_source_set_priority (source, priority);
	g_source_set_callback (source, handler, user_data, notify);
	return source;
}

GSource *
nm_g_unix_fd_source_new (int fd,
                         GIOCondition io_condition,
                         int priority,
                         gboolean (*source_func) (int fd,
                                                  GIOCondition condition,
                                                  gpointer user_data),
                         gpointer user_data,
                         GDestroyNotify destroy_notify)
{
	GSource *source;

	source = g_unix_fd_source_new (fd, io_condition);

	if (priority != G_PRIORITY_DEFAULT)
		g_source_set_priority (source, priority);
	g_source_set_callback (source, G_SOURCE_FUNC (source_func), user_data, destroy_notify);
	return source;
}

/*****************************************************************************/

#define _CTX_LOG(fmt, ...) \
	G_STMT_START { \
		if (FALSE) { \
			gint64 _ts = g_get_monotonic_time () / 100; \
			\
			g_printerr (">>>> [%"G_GINT64_FORMAT".%05"G_GINT64_FORMAT"] [src:%p]: " fmt "\n", \
			            _ts / 10000, \
			            _ts % 10000, \
			            (ctx_src), \
			            ##__VA_ARGS__); \
		} \
	} G_STMT_END

typedef struct {
	int fd;
	guint events;
	guint registered_events;
	union {
		int one;
		int *many;
	} idx;
	gpointer tag;
	bool stale:1;
	bool has_many_idx:1;
} PollData;

typedef struct {
	GSource source;
	GMainContext *context;
	GHashTable *fds;
	GPollFD *fds_arr;
	int fds_len;
	int max_priority;
	bool acquired:1;
} CtxIntegSource;

static void
_poll_data_free (gpointer user_data)
{
	PollData *poll_data = user_data;

	if (poll_data->has_many_idx)
		g_free (poll_data->idx.many);
	nm_g_slice_free (poll_data);
}

static void
_ctx_integ_source_reacquire (CtxIntegSource *ctx_src)
{
	if (G_LIKELY (   ctx_src->acquired
	              && g_main_context_is_owner (ctx_src->context)))
		return;

	/* the parent context now iterates on a different thread.
	 * We need to release and reacquire the inner context. */

	if (ctx_src->acquired)
		g_main_context_release (ctx_src->context);

	if (G_UNLIKELY (!g_main_context_acquire (ctx_src->context))) {
		/* Nobody is supposed to reacquire the context while we use it. This is a bug
		 * of the user. */
		ctx_src->acquired = FALSE;
		g_return_if_reached ();
	}
	ctx_src->acquired = TRUE;
}

static gboolean
_ctx_integ_source_prepare (GSource *source,
                           int *out_timeout)
{
	CtxIntegSource *ctx_src = ((CtxIntegSource *) source);
	int max_priority;
	int timeout = -1;
	gboolean any_ready;
	int fds_allocated;
	int fds_len_old;
	gs_free GPollFD *fds_arr_old = NULL;
	GHashTableIter h_iter;
	PollData *poll_data;
	gboolean fds_changed;
	int i;

	_CTX_LOG ("prepare...");

	_ctx_integ_source_reacquire (ctx_src);

	any_ready = g_main_context_prepare (ctx_src->context, &max_priority);

	fds_arr_old = g_steal_pointer (&ctx_src->fds_arr);
	fds_len_old = ctx_src->fds_len;

	fds_allocated = NM_MAX (1, fds_len_old); /* there is at least the wakeup's FD */
	ctx_src->fds_arr = g_new (GPollFD, fds_allocated);

	while ((ctx_src->fds_len = g_main_context_query (ctx_src->context,
	                                                 max_priority,
	                                                 &timeout,
	                                                 ctx_src->fds_arr,
	                                                 fds_allocated)) > fds_allocated) {
		fds_allocated = ctx_src->fds_len;
		g_free (ctx_src->fds_arr);
		ctx_src->fds_arr = g_new (GPollFD, fds_allocated);
	}

	fds_changed = FALSE;
	if (fds_len_old != ctx_src->fds_len)
		fds_changed = TRUE;
	else {
		for (i = 0; i < ctx_src->fds_len; i++) {
			if (   fds_arr_old[i].fd != ctx_src->fds_arr[i].fd
			    || fds_arr_old[i].events != ctx_src->fds_arr[i].events) {
				fds_changed = TRUE;
				break;
			}
		}
	}

	if (G_UNLIKELY (fds_changed)) {

		g_hash_table_iter_init (&h_iter, ctx_src->fds);
		while (g_hash_table_iter_next (&h_iter, (gpointer *) &poll_data, NULL))
			poll_data->stale = TRUE;

		for (i = 0; i < ctx_src->fds_len; i++) {
			const GPollFD *fd = &ctx_src->fds_arr[i];

			poll_data = g_hash_table_lookup (ctx_src->fds, &fd->fd);

			if (G_UNLIKELY (!poll_data)) {
				poll_data = g_slice_new (PollData);
				*poll_data = (PollData) {
					.fd                = fd->fd,
					.idx.one           = i,
					.has_many_idx      = FALSE,
					.events            = fd->events,
					.registered_events = 0,
					.tag               = NULL,
					.stale             = FALSE,
				};
				g_hash_table_add (ctx_src->fds, poll_data);
				nm_assert (poll_data == g_hash_table_lookup (ctx_src->fds, &fd->fd));
				continue;
			}

			if (G_LIKELY (poll_data->stale)) {
				if (poll_data->has_many_idx) {
					g_free (poll_data->idx.many);
					poll_data->has_many_idx = FALSE;
				}
				poll_data->events = fd->events;
				poll_data->idx.one = i;
				poll_data->stale = FALSE;
				continue;
			}

			/* How odd. We have duplicate FDs. In fact, currently g_main_context_query() always
			 * coalesces the FDs and this cannot happen. However, that is not documented behavior,
			 * so we should not rely on that. So we need to keep a list of indexes... */
			poll_data->events |= fd->events;
			if (!poll_data->has_many_idx) {
				int idx0;

				idx0 = poll_data->idx.one;
				poll_data->has_many_idx = TRUE;
				poll_data->idx.many = g_new (int, 4);
				poll_data->idx.many[0] = 2; /* number allocated */
				poll_data->idx.many[1] = 2; /* number used */
				poll_data->idx.many[2] = idx0;
				poll_data->idx.many[3] = i;
			} else {
				if (poll_data->idx.many[0] == poll_data->idx.many[1]) {
					poll_data->idx.many[0] *= 2;
					poll_data->idx.many = g_realloc (poll_data->idx.many, sizeof (int) * (2 + poll_data->idx.many[0]));
				}
				poll_data->idx.many[2 + poll_data->idx.many[1]] = i;
				poll_data->idx.many[1]++;
			}

		}

		g_hash_table_iter_init (&h_iter, ctx_src->fds);
		while (g_hash_table_iter_next (&h_iter, (gpointer *) &poll_data, NULL)) {
			if (poll_data->stale) {
				nm_assert (poll_data->tag);
				nm_assert (poll_data->events == poll_data->registered_events);
				_CTX_LOG ("prepare: remove poll fd=%d, events=0x%x", poll_data->fd, poll_data->events);
				g_source_remove_unix_fd (&ctx_src->source, poll_data->tag);
				g_hash_table_iter_remove (&h_iter);
				continue;
			}
			if (!poll_data->tag) {
				_CTX_LOG ("prepare: add poll fd=%d, events=0x%x", poll_data->fd, poll_data->events);
				poll_data->registered_events = poll_data->events;
				poll_data->tag = g_source_add_unix_fd (&ctx_src->source, poll_data->fd, poll_data->registered_events);
				continue;
			}
			if (poll_data->registered_events != poll_data->events) {
				_CTX_LOG ("prepare: update poll fd=%d, events=0x%x", poll_data->fd, poll_data->events);
				poll_data->registered_events = poll_data->events;
				g_source_modify_unix_fd (&ctx_src->source, poll_data->tag, poll_data->registered_events);
			}
		}
	}

	NM_SET_OUT (out_timeout, timeout);
	ctx_src->max_priority = max_priority;

	_CTX_LOG ("prepare: done, any-ready=%d, timeout=%d, max-priority=%d", any_ready, timeout, max_priority);

	/* we always need to poll, because we have some file descriptors. */
	return FALSE;
}

static gboolean
_ctx_integ_source_check (GSource *source)
{
	CtxIntegSource *ctx_src = ((CtxIntegSource *) source);
	GHashTableIter h_iter;
	gboolean some_ready;
	PollData *poll_data;

	nm_assert (ctx_src->context);

	_CTX_LOG ("check");

	_ctx_integ_source_reacquire (ctx_src);

	g_hash_table_iter_init (&h_iter, ctx_src->fds);
	while (g_hash_table_iter_next (&h_iter, (gpointer *) &poll_data, NULL)) {
		guint revents;

		revents = g_source_query_unix_fd (&ctx_src->source, poll_data->tag);
		if (G_UNLIKELY (poll_data->has_many_idx)) {
			int num = poll_data->idx.many[1];
			int *p_idx = &poll_data->idx.many[2];

			for (; num > 0; num--, p_idx++)
				ctx_src->fds_arr[*p_idx].revents = revents;
		} else
			ctx_src->fds_arr[poll_data->idx.one].revents = revents;
	}

	some_ready = g_main_context_check (ctx_src->context,
	                                   ctx_src->max_priority,
	                                   ctx_src->fds_arr,
	                                   ctx_src->fds_len);

	_CTX_LOG ("check (some-ready=%d)...", some_ready);

	return some_ready;
}

static gboolean
_ctx_integ_source_dispatch (GSource *source,
                            GSourceFunc callback,
                            gpointer user_data)
{
	CtxIntegSource *ctx_src = ((CtxIntegSource *) source);

	nm_assert (ctx_src->context);

	_ctx_integ_source_reacquire (ctx_src);

	_CTX_LOG ("dispatch");

	g_main_context_dispatch (ctx_src->context);

	return G_SOURCE_CONTINUE;
}

static void
_ctx_integ_source_finalize (GSource *source)
{
	CtxIntegSource *ctx_src = ((CtxIntegSource *) source);
	GHashTableIter h_iter;
	PollData *poll_data;

	g_return_if_fail (ctx_src->context);

	_CTX_LOG ("finalize...");

	g_hash_table_iter_init (&h_iter, ctx_src->fds);
	while (g_hash_table_iter_next (&h_iter, (gpointer *) &poll_data, NULL)) {
		nm_assert (poll_data->tag);
		_CTX_LOG ("prepare: remove poll fd=%d, events=0x%x", poll_data->fd, poll_data->events);
		g_source_remove_unix_fd (&ctx_src->source, poll_data->tag);
		g_hash_table_iter_remove (&h_iter);
	}

	nm_clear_pointer (&ctx_src->fds, g_hash_table_unref);
	nm_clear_g_free (&ctx_src->fds_arr);
	ctx_src->fds_len = 0;

	if (ctx_src->acquired) {
		ctx_src->acquired = FALSE;
		g_main_context_release (ctx_src->context);
	}

	nm_clear_pointer (&ctx_src->context, g_main_context_unref);
}

static GSourceFuncs ctx_integ_source_funcs = {
	.prepare  = _ctx_integ_source_prepare,
	.check    = _ctx_integ_source_check,
	.dispatch = _ctx_integ_source_dispatch,
	.finalize = _ctx_integ_source_finalize,
};

/**
 * nm_utils_g_main_context_create_integrate_source:
 * @inner_context: the inner context that will be integrated to an
 *   outer #GMainContext.
 *
 * By integrating the inner context with an outer context, when iterating the outer
 * context sources on the inner context will be dispatched. Note that while the
 * created source exists, the @inner_context will be acquired. The user gets restricted
 * what to do with the inner context. In particular while the inner context is integrated,
 * the user should not acquire the inner context again or explicitly iterate it. What
 * the user of course still can (and wants to) do is attaching new sources to the inner
 * context.
 *
 * Note that GSource has a priority. While each context dispatches events based on
 * their source's priorities, the outer context dispatches to the inner context
 * only with one priority (the priority of the created source). That is, the sources
 * from the two contexts are kept separate and are not sorted by their priorities.
 *
 * Returns: a newly created GSource that should be attached to the
 *   outer context.
 */
GSource *
nm_utils_g_main_context_create_integrate_source (GMainContext *inner_context)
{
	CtxIntegSource *ctx_src;

	g_return_val_if_fail (inner_context, NULL);

	if (!g_main_context_acquire (inner_context)) {
		/* We require to acquire the context while it's integrated. We need to keep it acquired
		 * for the entire duration.
		 *
		 * This is also necessary because g_source_attach() only wakes up the context, if
		 * the context is currently acquired. */
		g_return_val_if_reached (NULL);
	}

	ctx_src = (CtxIntegSource *) g_source_new (&ctx_integ_source_funcs, sizeof (CtxIntegSource));

	g_source_set_name (&ctx_src->source, "ContextIntegrateSource");

	ctx_src->context = g_main_context_ref (inner_context);
	ctx_src->fds = g_hash_table_new_full (nm_pint_hash, nm_pint_equals, _poll_data_free, NULL);
	ctx_src->fds_len = 0;
	ctx_src->fds_arr = NULL;
	ctx_src->acquired = TRUE;
	ctx_src->max_priority = G_MAXINT;

	_CTX_LOG ("create new integ-source for %p", inner_context);

	return &ctx_src->source;
}

gboolean
nm_utils_ifname_valid_kernel (const char *name, GError **error)
{
	int i;

	/* This function follows kernel's interface validation
	 * function dev_valid_name() in net/core/dev.c.
	 */

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

/*****************************************************************************/

static gboolean
_nm_utils_ifname_valid_kernel (const char *name, GError **error)
{
	if (!nm_utils_ifname_valid_kernel (name, error))
		return FALSE;

	if (strchr (name, '%')) {
		/* Kernel's dev_valid_name() accepts (almost) any binary up to 15 chars.
		 * However, '%' is treated special as a format specifier. Try
		 *
		 *   ip link add 'dummy%dx' type dummy
		 *
		 * Don't allow that for "connection.interface-name", which either
		 * matches an existing netdev name (thus, it cannot have a '%') or
		 * is used to configure a name (in which case we don't want kernel
		 * to replace the format specifier). */
		g_set_error_literal (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		                     _("'%%' is not allowed in interface names"));
		return FALSE;
	}

	if (NM_IN_STRSET (name, "all",
	                        "default",
	                        "bonding_masters")) {
		/* Certain names are not allowed. The "all" and "default" names are reserved
		 * due to their directories in "/proc/sys/net/ipv4/conf/" and "/proc/sys/net/ipv6/conf/".
		 *
		 * Also, there is "/sys/class/net/bonding_masters" file.
		 */
		nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN,
		                    _("'%s' is not allowed as interface name"), name);
		return FALSE;
	}

	return TRUE;
}

static gboolean
_nm_utils_ifname_valid_ovs (const char *name, GError **error)
{
	const char *ch;

	/* OVS actually accepts a wider range of chars (all printable UTF-8 chars),
	 NetworkManager restricts this to ASCII char as it's a safer option for
	 now since OVS is not well documented on this matter.
	 */
	for (ch = name; *ch; ++ch) {
		if (   *ch == '\\'
		    || *ch == '/'
		    || !g_ascii_isgraph (*ch)) {
			g_set_error_literal (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
			                     _("interface name must be alphanumerical with "
			                       "no forward or backward slashes"));
			return FALSE;
		}
	};
	return TRUE;
}

gboolean
nm_utils_ifname_valid (const char* name,
                       NMUtilsIfaceType type,
                       GError **error)
{
	g_return_val_if_fail (!error || !(*error), FALSE);

	if (!name || !(name[0])) {
		g_set_error_literal (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		                     _("interface name must not be empty"));
		return FALSE;
	}

	if (!g_utf8_validate (name, -1, NULL)) {
		g_set_error_literal (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		                     _("interface name must be UTF-8 encoded"));
		return FALSE;
	}

	switch (type) {
	case NMU_IFACE_KERNEL:
		return _nm_utils_ifname_valid_kernel (name, error);
	case NMU_IFACE_OVS:
		return _nm_utils_ifname_valid_ovs (name, error);
	case NMU_IFACE_OVS_AND_KERNEL:
		return    _nm_utils_ifname_valid_kernel (name, error)
		       && _nm_utils_ifname_valid_ovs (name, error);
	case NMU_IFACE_ANY: {
		gs_free_error GError *local = NULL;

		if (_nm_utils_ifname_valid_kernel (name, error ? &local : NULL))
			return TRUE;
		if (_nm_utils_ifname_valid_ovs (name, NULL))
			return TRUE;
		if (error)
			g_propagate_error (error, g_steal_pointer (&local));
		return FALSE;
	}
	}

	g_return_val_if_reached (FALSE);
}

/*****************************************************************************/

void
_nm_str_buf_ensure_size (NMStrBuf *strbuf,
                         gsize new_size,
                         gboolean reserve_exact)
{
	_nm_str_buf_assert (strbuf);

	/* Currently this only supports strictly growing the buffer. */
	nm_assert (new_size > strbuf->_priv_allocated);

	if (!reserve_exact) {
		new_size = nm_utils_get_next_realloc_size (!strbuf->_priv_do_bzero_mem,
		                                           new_size);
	}

	strbuf->_priv_str = nm_secret_mem_realloc (strbuf->_priv_str,
	                                           strbuf->_priv_do_bzero_mem,
	                                           strbuf->_priv_allocated,
	                                           new_size);
	strbuf->_priv_allocated = new_size;
}

void
nm_str_buf_append_printf (NMStrBuf *strbuf,
                          const char *format,
                          ...)
{
	va_list args;
	gsize available;
	int l;

	_nm_str_buf_assert (strbuf);

	available = strbuf->_priv_allocated - strbuf->_priv_len;

	va_start (args, format);
	l = g_vsnprintf (&strbuf->_priv_str[strbuf->_priv_len],
	                 available,
	                 format,
	                 args);
	va_end (args);

	nm_assert (l >= 0);
	nm_assert (l < G_MAXINT);

	if ((gsize) l > available) {
		gsize l2 = ((gsize) l) + 1u;

		nm_str_buf_maybe_expand (strbuf, l2, FALSE);

		va_start (args, format);
		l = g_vsnprintf (&strbuf->_priv_str[strbuf->_priv_len],
		                 l2,
		                 format,
		                 args);
		va_end (args);

		nm_assert (l >= 0);
		nm_assert (l == l2 - 1);
	}

	strbuf->_priv_len += (gsize) l;
}
