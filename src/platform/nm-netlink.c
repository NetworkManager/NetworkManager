/* nm-platform.c - Handle runtime kernel networking configuration
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-netlink.h"

#include <unistd.h>
#include <fcntl.h>

/*****************************************************************************/

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

/*****************************************************************************/

#define NL_SOCK_PASSCRED        (1<<1)
#define NL_MSG_PEEK             (1<<3)
#define NL_MSG_PEEK_EXPLICIT    (1<<4)
#define NL_NO_AUTO_ACK          (1<<5)

#ifndef NETLINK_EXT_ACK
#define NETLINK_EXT_ACK         11
#endif

struct nl_msg {
	int                     nm_protocol;
	struct sockaddr_nl      nm_src;
	struct sockaddr_nl      nm_dst;
	struct ucred            nm_creds;
	struct nlmsghdr *       nm_nlh;
	size_t                  nm_size;
	bool                    nm_creds_has:1;
};

struct nl_sock {
	struct sockaddr_nl      s_local;
	struct sockaddr_nl      s_peer;
	int                     s_fd;
	int                     s_proto;
	unsigned int            s_seq_next;
	unsigned int            s_seq_expect;
	int                     s_flags;
	size_t                  s_bufsize;
};

/*****************************************************************************/

NM_UTILS_ENUM2STR_DEFINE (nl_nlmsgtype2str, int,
	NM_UTILS_ENUM2STR (NLMSG_NOOP,    "NOOP"),
	NM_UTILS_ENUM2STR (NLMSG_ERROR,   "ERROR"),
	NM_UTILS_ENUM2STR (NLMSG_DONE,    "DONE"),
	NM_UTILS_ENUM2STR (NLMSG_OVERRUN, "OVERRUN"),
);

NM_UTILS_FLAGS2STR_DEFINE (nl_nlmsg_flags2str, int,
	NM_UTILS_FLAGS2STR (NLM_F_REQUEST, "REQUEST"),
	NM_UTILS_FLAGS2STR (NLM_F_MULTI,   "MULTI"),
	NM_UTILS_FLAGS2STR (NLM_F_ACK,     "ACK"),
	NM_UTILS_FLAGS2STR (NLM_F_ECHO,    "ECHO"),
	NM_UTILS_FLAGS2STR (NLM_F_ROOT,    "ROOT"),
	NM_UTILS_FLAGS2STR (NLM_F_MATCH,   "MATCH"),
	NM_UTILS_FLAGS2STR (NLM_F_ATOMIC,  "ATOMIC"),
	NM_UTILS_FLAGS2STR (NLM_F_REPLACE, "REPLACE"),
	NM_UTILS_FLAGS2STR (NLM_F_EXCL,    "EXCL"),
	NM_UTILS_FLAGS2STR (NLM_F_CREATE,  "CREATE"),
	NM_UTILS_FLAGS2STR (NLM_F_APPEND,  "APPEND"),
);

/*****************************************************************************/

const char *
nl_nlmsghdr_to_str (const struct nlmsghdr *hdr, char *buf, gsize len)
{
	const char *b;
	const char *s;
	guint flags, flags_before;
	const char *prefix;

	if (!nm_utils_to_string_buffer_init_null (hdr, &buf, &len))
		return buf;

	b = buf;

	switch (hdr->nlmsg_type) {
	case RTM_GETLINK:    s = "RTM_GETLINK";     break;
	case RTM_NEWLINK:    s = "RTM_NEWLINK";     break;
	case RTM_DELLINK:    s = "RTM_DELLINK";     break;
	case RTM_SETLINK:    s = "RTM_SETLINK";     break;
	case RTM_GETADDR:    s = "RTM_GETADDR";     break;
	case RTM_NEWADDR:    s = "RTM_NEWADDR";     break;
	case RTM_DELADDR:    s = "RTM_DELADDR";     break;
	case RTM_GETROUTE:   s = "RTM_GETROUTE";    break;
	case RTM_NEWROUTE:   s = "RTM_NEWROUTE";    break;
	case RTM_DELROUTE:   s = "RTM_DELROUTE";    break;
	case RTM_GETRULE:    s = "RTM_GETRULE";     break;
	case RTM_NEWRULE:    s = "RTM_NEWRULE";     break;
	case RTM_DELRULE:    s = "RTM_DELRULE";     break;
	case RTM_GETQDISC:   s = "RTM_GETQDISC";    break;
	case RTM_NEWQDISC:   s = "RTM_NEWQDISC";    break;
	case RTM_DELQDISC:   s = "RTM_DELQDISC";    break;
	case RTM_GETTFILTER: s = "RTM_GETTFILTER";  break;
	case RTM_NEWTFILTER: s = "RTM_NEWTFILTER";  break;
	case RTM_DELTFILTER: s = "RTM_DELTFILTER";  break;
	case NLMSG_NOOP:     s = "NLMSG_NOOP";      break;
	case NLMSG_ERROR:    s = "NLMSG_ERROR";     break;
	case NLMSG_DONE:     s = "NLMSG_DONE";      break;
	case NLMSG_OVERRUN:  s = "NLMSG_OVERRUN";   break;
	default:             s = NULL;              break;
	}

	if (s)
		nm_utils_strbuf_append_str (&buf, &len, s);
	else
		nm_utils_strbuf_append (&buf, &len, "(%u)", (unsigned) hdr->nlmsg_type);

	flags = hdr->nlmsg_flags;

	if (!flags) {
		nm_utils_strbuf_append_str (&buf, &len, ", flags 0");
		goto flags_done;
	}

#define _F(f, n) \
	G_STMT_START { \
		if (NM_FLAGS_ALL (flags, f)) { \
			flags &= ~(f); \
			nm_utils_strbuf_append (&buf, &len, "%s%s", prefix, n); \
			if (!flags) \
				goto flags_done; \
			prefix = ","; \
		} \
	} G_STMT_END

	prefix = ", flags ";
	flags_before = flags;
	_F (NLM_F_REQUEST, "request");
	_F (NLM_F_MULTI, "multi");
	_F (NLM_F_ACK, "ack");
	_F (NLM_F_ECHO, "echo");
	_F (NLM_F_DUMP_INTR, "dump_intr");
	_F (0x20 /*NLM_F_DUMP_FILTERED*/, "dump_filtered");

	if (flags_before != flags)
		prefix = ";";

	switch (hdr->nlmsg_type) {
	case RTM_NEWLINK:
	case RTM_NEWADDR:
	case RTM_NEWROUTE:
	case RTM_NEWQDISC:
	case RTM_NEWTFILTER:
		_F (NLM_F_REPLACE, "replace");
		_F (NLM_F_EXCL, "excl");
		_F (NLM_F_CREATE, "create");
		_F (NLM_F_APPEND, "append");
		break;
	case RTM_GETLINK:
	case RTM_GETADDR:
	case RTM_GETROUTE:
	case RTM_DELQDISC:
	case RTM_DELTFILTER:
		_F (NLM_F_DUMP, "dump");
		_F (NLM_F_ROOT, "root");
		_F (NLM_F_MATCH, "match");
		_F (NLM_F_ATOMIC, "atomic");
		break;
	}

#undef _F

	if (flags_before != flags)
		prefix = ";";
	nm_utils_strbuf_append (&buf, &len, "%s0x%04x", prefix, flags);

flags_done:

	nm_utils_strbuf_append (&buf, &len, ", seq %u", (unsigned) hdr->nlmsg_seq);

	return b;
}

/*****************************************************************************/

struct nlmsghdr *
nlmsg_hdr (struct nl_msg *n)
{
	return n->nm_nlh;
}

void *
nlmsg_reserve (struct nl_msg *n, size_t len, int pad)
{
	char *buf = (char *) n->nm_nlh;
	size_t nlmsg_len = n->nm_nlh->nlmsg_len;
	size_t tlen;

	nm_assert (pad >= 0);

	if (len > n->nm_size)
		return NULL;

	tlen = pad ? ((len + (pad - 1)) & ~(pad - 1)) : len;

	if ((tlen + nlmsg_len) > n->nm_size)
		return NULL;

	buf += nlmsg_len;
	n->nm_nlh->nlmsg_len += tlen;

	if (tlen > len)
		memset (buf + len, 0, tlen - len);

	return buf;
}

/*****************************************************************************/

struct nlattr *
nla_reserve (struct nl_msg *msg, int attrtype, int attrlen)
{
	struct nlattr *nla;
	int tlen;

	if (attrlen < 0)
		return NULL;

	tlen = NLMSG_ALIGN (msg->nm_nlh->nlmsg_len) + nla_total_size (attrlen);

	if (tlen > msg->nm_size)
		return NULL;

	nla = (struct nlattr *) nlmsg_tail (msg->nm_nlh);
	nla->nla_type = attrtype;
	nla->nla_len = nla_attr_size (attrlen);

	if (attrlen)
		memset ((unsigned char *) nla + nla->nla_len, 0, nla_padlen (attrlen));
	msg->nm_nlh->nlmsg_len = tlen;

	return nla;
}

/*****************************************************************************/

struct nl_msg *
nlmsg_alloc_size (size_t len)
{
	struct nl_msg *nm;

	if (len < sizeof (struct nlmsghdr))
		len = sizeof (struct nlmsghdr);

	nm = g_slice_new (struct nl_msg);
	*nm = (struct nl_msg) {
		.nm_protocol = -1,
		.nm_size = len,
		.nm_nlh = g_malloc0 (len),
	};
	nm->nm_nlh->nlmsg_len = nlmsg_total_size (0);
	return nm;
}

/**
 * Allocate a new netlink message with the default maximum payload size.
 *
 * Allocates a new netlink message without any further payload. The
 * maximum payload size defaults to PAGESIZE or as otherwise specified
 * with nlmsg_set_default_size().
 *
 * @return Newly allocated netlink message or NULL.
 */
struct nl_msg *
nlmsg_alloc (void)
{
	return nlmsg_alloc_size (nm_utils_getpagesize ());
}

struct nl_msg *
nlmsg_alloc_convert (struct nlmsghdr *hdr)
{
	struct nl_msg *nm;

	nm = nlmsg_alloc_size (NLMSG_ALIGN (hdr->nlmsg_len));
	memcpy (nm->nm_nlh, hdr, hdr->nlmsg_len);
	return nm;
}

struct nl_msg *
nlmsg_alloc_simple (int nlmsgtype, int flags)
{
	struct nl_msg *nm;
	struct nlmsghdr *new;

	nm = nlmsg_alloc ();
	new = nm->nm_nlh;
	new->nlmsg_type = nlmsgtype;
	new->nlmsg_flags = flags;
	return nm;
}

void nlmsg_free (struct nl_msg *msg)
{
	if (!msg)
		return;

	g_free (msg->nm_nlh);
	g_slice_free (struct nl_msg, msg);
}

/*****************************************************************************/

int
nlmsg_append (struct nl_msg *n,
              const void *data,
              size_t len,
              int pad)
{
	void *tmp;

	nm_assert (n);
	nm_assert (data);
	nm_assert (len > 0);
	nm_assert (pad >= 0);

	tmp = nlmsg_reserve (n, len, pad);
	if (tmp == NULL)
		return -ENOMEM;

	memcpy (tmp, data, len);
	return 0;
}

/*****************************************************************************/

int
nlmsg_parse (struct nlmsghdr *nlh, int hdrlen, struct nlattr *tb[],
             int maxtype, const struct nla_policy *policy)
{
	if (!nlmsg_valid_hdr (nlh, hdrlen))
		return -NME_NL_MSG_TOOSHORT;

	return nla_parse (tb, maxtype, nlmsg_attrdata (nlh, hdrlen),
	                  nlmsg_attrlen (nlh, hdrlen), policy);
}

struct nlmsghdr *
nlmsg_put (struct nl_msg *n, uint32_t pid, uint32_t seq,
           int type, int payload, int flags)
{
	struct nlmsghdr *nlh;

	if (n->nm_nlh->nlmsg_len < NLMSG_HDRLEN)
		g_return_val_if_reached (NULL);

	nlh = (struct nlmsghdr *) n->nm_nlh;
	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = flags;
	nlh->nlmsg_pid = pid;
	nlh->nlmsg_seq = seq;

	if (   payload > 0
	    && nlmsg_reserve (n, payload, NLMSG_ALIGNTO) == NULL)
		return NULL;

	return nlh;
}

size_t
nla_strlcpy (char *dst,
             const struct nlattr *nla,
             size_t dstsize)
{
	const char *src;
	size_t srclen;
	size_t len;

	/* - Always writes @dstsize bytes to @dst
	 * - Copies the first non-NUL characters to @dst.
	 *   Any characters after the first NUL bytes in @nla are ignored.
	 * - If the string @nla is longer than @dstsize, the string
	 *   gets truncated. @dst will always be NUL terminated. */

	if (G_UNLIKELY (dstsize <= 1)) {
		if (dstsize == 1)
			dst[0] = '\0';
		if (   nla
		    && (srclen = nla_len (nla)) > 0)
			return strnlen (nla_data (nla), srclen);
		return 0;
	}

	nm_assert (dst);

	if (nla) {
		srclen = nla_len (nla);
		if (srclen > 0) {
			src = nla_data (nla);
			srclen = strnlen (src, srclen);
			if (srclen > 0) {
				len = NM_MIN (dstsize - 1, srclen);
				memcpy (dst, src, len);
				memset (&dst[len], 0, dstsize - len);
				return srclen;
			}
		}
	}

	memset (dst, 0, dstsize);
	return 0;
}

size_t
nla_memcpy (void *dst, const struct nlattr *nla, size_t dstsize)
{
	size_t len;
	int srclen;

	if (!nla)
		return 0;

	srclen = nla_len (nla);

	if (srclen <= 0) {
		nm_assert (srclen == 0);
		return 0;
	}

	len = NM_MIN ((size_t) srclen, dstsize);
	if (len > 0) {
		/* there is a crucial difference between nla_strlcpy() and nla_memcpy().
		 * The former always write @dstsize bytes (akin to strncpy()), here, we only
		 * write the bytes that we actually have (leaving the remainder undefined). */
		memcpy (dst,
		        nla_data (nla),
		        len);
	}

	return srclen;
}

int
nla_put (struct nl_msg *msg, int attrtype, int datalen, const void *data)
{
	struct nlattr *nla;

	nla = nla_reserve (msg, attrtype, datalen);
	if (!nla) {
		if (datalen < 0)
			g_return_val_if_reached (-NME_BUG);

		return -ENOMEM;
	}

	if (datalen > 0)
		memcpy (nla_data (nla), data, datalen);

	return 0;
}

struct nlattr *
nla_find (const struct nlattr *head, int len, int attrtype)
{
	const struct nlattr *nla;
	int rem;

	nla_for_each_attr (nla, head, len, rem) {
		if (nla_type (nla) == attrtype)
			return (struct nlattr*)nla;
	}

	return NULL;
}

void
nla_nest_cancel (struct nl_msg *msg, const struct nlattr *attr)
{
	ssize_t len;

	len = (char *) nlmsg_tail (msg->nm_nlh) - (char *) attr;
	if (len < 0)
		g_return_if_reached ();
	else if (len > 0) {
		msg->nm_nlh->nlmsg_len -= len;
		memset (nlmsg_tail (msg->nm_nlh), 0, len);
	}
}

struct nlattr *
nla_nest_start (struct nl_msg *msg, int attrtype)
{
	struct nlattr *start = (struct nlattr *) nlmsg_tail (msg->nm_nlh);

	if (nla_put (msg, NLA_F_NESTED | attrtype, 0, NULL) < 0)
		return NULL;

	return start;
}

static int
_nest_end (struct nl_msg *msg, struct nlattr *start, int keep_empty)
{
	size_t pad, len;

	len = (char *) nlmsg_tail (msg->nm_nlh) - (char *) start;

	if (   len > USHRT_MAX
	    || (!keep_empty && len == NLA_HDRLEN)) {
		/*
		 * Max nlattr size exceeded or empty nested attribute, trim the
		 * attribute header again
		 */
		nla_nest_cancel (msg, start);

		/* Return error only if nlattr size was exceeded */
		return (len == NLA_HDRLEN) ? 0 : -NME_NL_ATTRSIZE;
	}

	start->nla_len = len;

	pad = NLMSG_ALIGN (msg->nm_nlh->nlmsg_len) - msg->nm_nlh->nlmsg_len;
	if (pad > 0) {
		/*
		 * Data inside attribute does not end at a alignment boundary.
		 * Pad accordingly and accoun for the additional space in
		 * the message. nlmsg_reserve() may never fail in this situation,
		 * the allocate message buffer must be a multiple of NLMSG_ALIGNTO.
		 */
		if (!nlmsg_reserve (msg, pad, 0))
			g_return_val_if_reached (-NME_BUG);
	}

	return 0;
}

int
nla_nest_end (struct nl_msg *msg, struct nlattr *start)
{
	return _nest_end (msg, start, 0);
}

static const uint16_t nla_attr_minlen[NLA_TYPE_MAX+1] = {
	[NLA_U8]        = sizeof (uint8_t),
	[NLA_U16]       = sizeof (uint16_t),
	[NLA_U32]       = sizeof (uint32_t),
	[NLA_U64]       = sizeof (uint64_t),
	[NLA_STRING]    = 1,
	[NLA_FLAG]      = 0,
};

static int
validate_nla (const struct nlattr *nla, int maxtype,
              const struct nla_policy *policy)
{
	const struct nla_policy *pt;
	unsigned int minlen = 0;
	int type = nla_type (nla);

	if (type < 0 || type > maxtype)
		return 0;

	pt = &policy[type];

	if (pt->type > NLA_TYPE_MAX)
		g_return_val_if_reached (-NME_BUG);

	if (pt->minlen)
		minlen = pt->minlen;
	else if (pt->type != NLA_UNSPEC)
		minlen = nla_attr_minlen[pt->type];

	if (nla_len (nla) < minlen)
		return -NME_UNSPEC;

	if (pt->maxlen && nla_len (nla) > pt->maxlen)
		return -NME_UNSPEC;

	if (pt->type == NLA_STRING) {
		const char *data;

		nm_assert (minlen > 0);

		data = nla_data (nla);
		if (data[nla_len (nla) - 1] != '\0')
			return -NME_UNSPEC;
	}

	return 0;
}

int
nla_parse (struct nlattr *tb[], int maxtype, struct nlattr *head, int len,
           const struct nla_policy *policy)
{
	struct nlattr *nla;
	int rem, nmerr;

	memset (tb, 0, sizeof (struct nlattr *) * (maxtype + 1));

	nla_for_each_attr (nla, head, len, rem) {
		int type = nla_type (nla);

		if (type > maxtype)
			continue;

		if (policy) {
			nmerr = validate_nla (nla, maxtype, policy);
			if (nmerr < 0)
				return nmerr;
		}

		tb[type] = nla;
	}

	return 0;
}

/*****************************************************************************/

int
nlmsg_get_proto (struct nl_msg *msg)
{
	return msg->nm_protocol;
}

void
nlmsg_set_proto (struct nl_msg *msg, int protocol)
{
	msg->nm_protocol = protocol;
}

void
nlmsg_set_src (struct nl_msg *msg, struct sockaddr_nl *addr)
{
	memcpy (&msg->nm_src, addr, sizeof (*addr));
}

struct ucred *
nlmsg_get_creds (struct nl_msg *msg)
{
	if (msg->nm_creds_has)
		return &msg->nm_creds;
	return NULL;
}

void
nlmsg_set_creds (struct nl_msg *msg, struct ucred *creds)
{
	if (creds) {
		memcpy (&msg->nm_creds, creds, sizeof (*creds));
		msg->nm_creds_has = TRUE;
	} else
		msg->nm_creds_has = FALSE;
}

/*****************************************************************************/

void *
genlmsg_put (struct nl_msg *msg, uint32_t port, uint32_t seq, int family,
             int hdrlen, int flags, uint8_t cmd, uint8_t version)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr hdr = {
		.cmd = cmd,
		.version = version,
	};

	nlh = nlmsg_put (msg, port, seq, family, GENL_HDRLEN + hdrlen, flags);
	if (nlh == NULL)
		return NULL;

	memcpy (nlmsg_data (nlh), &hdr, sizeof (hdr));

	return (char *) nlmsg_data (nlh) + GENL_HDRLEN;
}

void *
genlmsg_data (const struct genlmsghdr *gnlh)
{
	return ((unsigned char *) gnlh + GENL_HDRLEN);
}

void *
genlmsg_user_hdr (const struct genlmsghdr *gnlh)
{
	return genlmsg_data (gnlh);
}

struct genlmsghdr *
genlmsg_hdr (struct nlmsghdr *nlh)
{
	return nlmsg_data (nlh);
}

void *
genlmsg_user_data (const struct genlmsghdr *gnlh, const int hdrlen)
{
	return (char *) genlmsg_user_hdr (gnlh) + NLMSG_ALIGN (hdrlen);
}

struct nlattr *
genlmsg_attrdata (const struct genlmsghdr *gnlh, int hdrlen)
{
	return genlmsg_user_data (gnlh, hdrlen);
}

int
genlmsg_len (const struct genlmsghdr *gnlh)
{
	const struct nlmsghdr *nlh;

	nlh = (const struct nlmsghdr *) ((const unsigned char *) gnlh - NLMSG_HDRLEN);
	return (nlh->nlmsg_len - GENL_HDRLEN - NLMSG_HDRLEN);
}

int
genlmsg_attrlen (const struct genlmsghdr *gnlh, int hdrlen)
{
	return genlmsg_len (gnlh) - NLMSG_ALIGN (hdrlen);
}

int
genlmsg_valid_hdr (struct nlmsghdr *nlh, int hdrlen)
{
	struct genlmsghdr *ghdr;

	if (!nlmsg_valid_hdr (nlh, GENL_HDRLEN))
		return 0;

	ghdr = nlmsg_data (nlh);
	if (genlmsg_len (ghdr) < NLMSG_ALIGN (hdrlen))
		return 0;

	return 1;
}

int
genlmsg_parse (struct nlmsghdr *nlh, int hdrlen, struct nlattr *tb[],
               int maxtype, const struct nla_policy *policy)
{
	struct genlmsghdr *ghdr;

	if (!genlmsg_valid_hdr (nlh, hdrlen))
		return -NME_NL_MSG_TOOSHORT;

	ghdr = nlmsg_data (nlh);
	return nla_parse (tb, maxtype, genlmsg_attrdata (ghdr, hdrlen),
	                  genlmsg_attrlen (ghdr, hdrlen), policy);
}

static int
_genl_parse_getfamily (struct nl_msg *msg, void *arg)
{
	static const struct nla_policy ctrl_policy[] = {
		[CTRL_ATTR_FAMILY_ID]    = { .type = NLA_U16 },
		[CTRL_ATTR_FAMILY_NAME]  = { .type = NLA_STRING,
		                             .maxlen = GENL_NAMSIZ },
		[CTRL_ATTR_VERSION]      = { .type = NLA_U32 },
		[CTRL_ATTR_HDRSIZE]      = { .type = NLA_U32 },
		[CTRL_ATTR_MAXATTR]      = { .type = NLA_U32 },
		[CTRL_ATTR_OPS]          = { .type = NLA_NESTED },
		[CTRL_ATTR_MCAST_GROUPS] = { .type = NLA_NESTED },
	};
	struct nlattr *tb[G_N_ELEMENTS (ctrl_policy)];
	struct nlmsghdr *nlh = nlmsg_hdr (msg);
	gint32 *response_data = arg;

	if (genlmsg_parse_arr (nlh, 0, tb, ctrl_policy) < 0)
		return NL_SKIP;

	if (tb[CTRL_ATTR_FAMILY_ID])
		*response_data = nla_get_u16 (tb[CTRL_ATTR_FAMILY_ID]);

	return NL_STOP;
}

int
genl_ctrl_resolve (struct nl_sock *sk, const char *name)
{
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	int nmerr;
	gint32 response_data = -1;
	const struct nl_cb cb = {
		.valid_cb = _genl_parse_getfamily,
		.valid_arg = &response_data,
	};

	msg = nlmsg_alloc ();

	if (!genlmsg_put (msg, NL_AUTO_PORT, NL_AUTO_SEQ, GENL_ID_CTRL,
	                  0, 0, CTRL_CMD_GETFAMILY, 1))
		return -ENOMEM;

	nmerr = nla_put_string (msg, CTRL_ATTR_FAMILY_NAME, name);
	if (nmerr < 0)
		return nmerr;

	nmerr = nl_send_auto (sk, msg);
	if (nmerr < 0)
		return nmerr;

	nmerr = nl_recvmsgs (sk, &cb);
	if (nmerr < 0)
		return nmerr;

	/* If search was successful, request may be ACKed after data */
	nmerr = nl_wait_for_ack (sk, NULL);
	if (nmerr < 0)
		return nmerr;

	if (response_data < 0)
		return -NME_UNSPEC;

	return response_data;
}

/*****************************************************************************/

struct nl_sock *
nl_socket_alloc (void)
{
	struct nl_sock *sk;

	sk = g_slice_new0 (struct nl_sock);

	sk->s_fd = -1;
	sk->s_local.nl_family = AF_NETLINK;
	sk->s_peer.nl_family = AF_NETLINK;
	sk->s_seq_expect = sk->s_seq_next = time (NULL);

	return sk;
}

void
nl_socket_free (struct nl_sock *sk)
{
	if (!sk)
		return;

	if (sk->s_fd >= 0)
		nm_close (sk->s_fd);
	g_slice_free (struct nl_sock, sk);
}

int
nl_socket_get_fd (const struct nl_sock *sk)
{
	return sk->s_fd;
}

uint32_t
nl_socket_get_local_port (const struct nl_sock *sk)
{
	return sk->s_local.nl_pid;
}

size_t
nl_socket_get_msg_buf_size (struct nl_sock *sk)
{
	return sk->s_bufsize;
}

int
nl_socket_set_passcred (struct nl_sock *sk, int state)
{
	int err;

	if (sk->s_fd == -1)
		return -NME_NL_BAD_SOCK;

	err = setsockopt (sk->s_fd, SOL_SOCKET, SO_PASSCRED,
	                  &state, sizeof (state));
	if (err < 0)
		return -nm_errno_from_native (errno);

	if (state)
		sk->s_flags |= NL_SOCK_PASSCRED;
	else
		sk->s_flags &= ~NL_SOCK_PASSCRED;

	return 0;
}

int
nl_socket_set_msg_buf_size (struct nl_sock *sk, size_t bufsize)
{
	sk->s_bufsize = bufsize;

	return 0;
}

struct sockaddr_nl *
nlmsg_get_dst (struct nl_msg *msg)
{
	return &msg->nm_dst;
}

int
nl_socket_set_nonblocking (const struct nl_sock *sk)
{
	if (sk->s_fd == -1)
		return -NME_NL_BAD_SOCK;

	if (fcntl (sk->s_fd, F_SETFL, O_NONBLOCK) < 0)
		return -nm_errno_from_native (errno);

	return 0;
}

int
nl_socket_set_buffer_size (struct nl_sock *sk, int rxbuf, int txbuf)
{
	int err;

	if (rxbuf <= 0)
		rxbuf = 32768;

	if (txbuf <= 0)
		txbuf = 32768;

	if (sk->s_fd == -1)
		return -NME_NL_BAD_SOCK;

	err = setsockopt (sk->s_fd, SOL_SOCKET, SO_SNDBUF,
	                  &txbuf, sizeof (txbuf));
	if (err < 0) {
		return -nm_errno_from_native (errno);
	}

	err = setsockopt (sk->s_fd, SOL_SOCKET, SO_RCVBUF,
	                  &rxbuf, sizeof (rxbuf));
	if (err < 0) {
		return -nm_errno_from_native (errno);
	}

	return 0;
}

int
nl_socket_add_memberships (struct nl_sock *sk, int group, ...)
{
	int err;
	va_list ap;

	if (sk->s_fd == -1)
		return -NME_NL_BAD_SOCK;

	va_start (ap, group);

	while (group != 0) {
		if (group < 0) {
			va_end (ap);
			g_return_val_if_reached (-NME_BUG);
		}

		err = setsockopt (sk->s_fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
		                  &group, sizeof (group));
		if (err < 0) {
			int errsv = errno;

			va_end (ap);
			return -nm_errno_from_native (errsv);
		}

		group = va_arg (ap, int);
	}

	va_end (ap);

	return 0;
}

int
nl_socket_set_ext_ack (struct nl_sock *sk, gboolean enable)
{
	int err, val;

	if (sk->s_fd == -1)
		return -NME_NL_BAD_SOCK;

	val = !!enable;
	err = setsockopt (sk->s_fd, SOL_NETLINK, NETLINK_EXT_ACK, &val, sizeof (val));
	if (err < 0)
		return -nm_errno_from_native (errno);

	return 0;
}

void nl_socket_disable_msg_peek (struct nl_sock *sk)
{
	sk->s_flags |= NL_MSG_PEEK_EXPLICIT;
	sk->s_flags &= ~NL_MSG_PEEK;
}

int
nl_connect (struct nl_sock *sk, int protocol)
{
	int err, nmerr;
	socklen_t addrlen;
	struct sockaddr_nl local = { 0 };

	if (sk->s_fd != -1)
		return -NME_NL_BAD_SOCK;

	sk->s_fd = socket (AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, protocol);
	if (sk->s_fd < 0) {
		nmerr = -nm_errno_from_native (errno);
		goto errout;
	}

	nmerr = nl_socket_set_buffer_size (sk, 0, 0);
	if (nmerr < 0)
		goto errout;

	nm_assert (sk->s_local.nl_pid == 0);

	err = bind (sk->s_fd, (struct sockaddr*) &sk->s_local,
	            sizeof (sk->s_local));
	if (err != 0) {
		nmerr = -nm_errno_from_native (errno);
		goto errout;
	}

	addrlen = sizeof (local);
	err = getsockname (sk->s_fd, (struct sockaddr *) &local,
	                   &addrlen);
	if (err < 0) {
		nmerr = -nm_errno_from_native (errno);
		goto errout;
	}

	if (addrlen != sizeof (local)) {
		nmerr = -NME_UNSPEC;
		goto errout;
	}

	if (local.nl_family != AF_NETLINK) {
		nmerr = -NME_UNSPEC;
		goto errout;
	}

	sk->s_local = local;
	sk->s_proto = protocol;

	return 0;

errout:
	if (sk->s_fd != -1) {
		close (sk->s_fd);
		sk->s_fd = -1;
	}
	return nmerr;
}

/*****************************************************************************/

static void
_cb_init (struct nl_cb *dst, const struct nl_cb *src)
{
	nm_assert (dst);

	if (src)
		*dst = *src;
	else
		memset (dst, 0, sizeof (*dst));
}

static int ack_wait_handler (struct nl_msg *msg, void *arg)
{
	return NL_STOP;
}

int
nl_wait_for_ack (struct nl_sock *sk,
                 const struct nl_cb *cb)
{
	struct nl_cb cb2;

	_cb_init (&cb2, cb);
	cb2.ack_cb = ack_wait_handler;
	return nl_recvmsgs (sk, &cb2);
}

#define NL_CB_CALL(cb, type, msg) \
do { \
	const struct nl_cb *_cb = (cb); \
	\
	if (_cb && _cb->type##_cb) { \
		/* the returned value here must be either a negative
		 * netlink error number, or one of NL_SKIP, NL_STOP, NL_OK. */ \
		nmerr = _cb->type##_cb ((msg), _cb->type##_arg); \
		switch (nmerr) { \
		case NL_OK: \
			nm_assert (nmerr == 0); \
			break; \
		case NL_SKIP: \
			goto skip; \
		case NL_STOP: \
			goto stop; \
		default: \
			if (nmerr >= 0) { \
				nm_assert_not_reached (); \
				nmerr = -NME_BUG; \
			} \
			goto out; \
		} \
	} \
} while (0)

int
nl_recvmsgs (struct nl_sock *sk, const struct nl_cb *cb)
{
	int n, nmerr = 0, multipart = 0, interrupted = 0, nrecv = 0;
	gs_free unsigned char *buf = NULL;
	struct nlmsghdr *hdr;
	struct sockaddr_nl nla = { 0 };
	struct ucred creds;
	gboolean creds_has;

continue_reading:
	n = nl_recv (sk, &nla, &buf, &creds, &creds_has);
	if (n <= 0)
		return n;

	hdr = (struct nlmsghdr *) buf;
	while (nlmsg_ok (hdr, n)) {
		nm_auto_nlmsg struct nl_msg *msg = NULL;

		msg = nlmsg_alloc_convert (hdr);

		nlmsg_set_proto (msg, sk->s_proto);
		nlmsg_set_src (msg, &nla);
		nlmsg_set_creds (msg, creds_has ? &creds : NULL);

		nrecv++;

		/* Only do sequence checking if auto-ack mode is enabled */
		if (! (sk->s_flags & NL_NO_AUTO_ACK)) {
			if (hdr->nlmsg_seq != sk->s_seq_expect) {
				nmerr = -NME_NL_SEQ_MISMATCH;
				goto out;
			}
		}

		if (hdr->nlmsg_type == NLMSG_DONE ||
		    hdr->nlmsg_type == NLMSG_ERROR ||
		    hdr->nlmsg_type == NLMSG_NOOP ||
		    hdr->nlmsg_type == NLMSG_OVERRUN) {
			/* We can't check for !NLM_F_MULTI since some netlink
			 * users in the kernel are broken. */
			sk->s_seq_expect++;
		}

		if (hdr->nlmsg_flags & NLM_F_MULTI)
			multipart = 1;

		if (hdr->nlmsg_flags & NLM_F_DUMP_INTR) {
			/*
			 * We have to continue reading to clear
			 * all messages until a NLMSG_DONE is
			 * received and report the inconsistency.
			 */
			interrupted = 1;
		}

		/* messages terminates a multipart message, this is
		 * usually the end of a message and therefore we slip
		 * out of the loop by default. the user may overrule
		 * this action by skipping this packet. */
		if (hdr->nlmsg_type == NLMSG_DONE) {
			multipart = 0;
			NL_CB_CALL (cb, finish, msg);
		}

		/* Message to be ignored, the default action is to
		 * skip this message if no callback is specified. The
		 * user may overrule this action by returning
		 * NL_PROCEED. */
		else if (hdr->nlmsg_type == NLMSG_NOOP)
			goto skip;

		/* Data got lost, report back to user. The default action is to
		 * quit parsing. The user may overrule this action by retuning
		 * NL_SKIP or NL_PROCEED (dangerous) */
		else if (hdr->nlmsg_type == NLMSG_OVERRUN) {
			nmerr = -NME_NL_MSG_OVERFLOW;
			goto out;
		}

		/* Message carries a nlmsgerr */
		else if (hdr->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *e = nlmsg_data (hdr);

			if (hdr->nlmsg_len < nlmsg_size (sizeof (*e))) {
				/* Truncated error message, the default action
				 * is to stop parsing. The user may overrule
				 * this action by returning NL_SKIP or
				 * NL_PROCEED (dangerous) */
				nmerr = -NME_NL_MSG_TRUNC;
				goto out;
			}
			if (e->error) {
				/* Error message reported back from kernel. */
				if (cb && cb->err_cb) {
					/* the returned value here must be either a negative
					 * netlink error number, or one of NL_SKIP, NL_STOP, NL_OK. */
					nmerr = cb->err_cb (&nla, e,
					                    cb->err_arg);
					if (nmerr < 0)
						goto out;
					else if (nmerr == NL_SKIP)
						goto skip;
					else if (nmerr == NL_STOP) {
						nmerr = -nm_errno_from_native (e->error);
						goto out;
					}
					nm_assert (nmerr == NL_OK);
				} else {
					nmerr = -nm_errno_from_native (e->error);
					goto out;
				}
			} else
				NL_CB_CALL (cb, ack, msg);
		} else {
			/* Valid message (not checking for MULTIPART bit to
			 * get along with broken kernels. NL_SKIP has no
			 * effect on this.  */
			NL_CB_CALL (cb, valid, msg);
		}
skip:
		nmerr = 0;
		hdr = nlmsg_next (hdr, &n);
	}

	if (multipart) {
		/* Multipart message not yet complete, continue reading */
		nm_clear_g_free (&buf);

		nmerr = 0;
		goto continue_reading;
	}

stop:
	nmerr = 0;

out:
	if (interrupted)
		nmerr = -NME_NL_DUMP_INTR;

	nm_assert (nmerr <= 0);
	return nmerr ?: nrecv;
}

int
nl_sendmsg (struct nl_sock *sk, struct nl_msg *msg, struct msghdr *hdr)
{
	int ret;

	if (sk->s_fd < 0)
		return -NME_NL_BAD_SOCK;

	nlmsg_set_src (msg, &sk->s_local);

	ret = sendmsg (sk->s_fd, hdr, 0);
	if (ret < 0)
		return -nm_errno_from_native (errno);

	return ret;
}

int
nl_send_iovec (struct nl_sock *sk, struct nl_msg *msg, struct iovec *iov, unsigned iovlen)
{
	struct sockaddr_nl *dst;
	struct ucred *creds;
	struct msghdr hdr = {
		.msg_name = (void *) &sk->s_peer,
		.msg_namelen = sizeof (struct sockaddr_nl),
		.msg_iov = iov,
		.msg_iovlen = iovlen,
	};
	char buf[CMSG_SPACE (sizeof (struct ucred))];

	/* Overwrite destination if specified in the message itself, defaults
	 * to the peer address of the socket.
	 */
	dst = nlmsg_get_dst (msg);
	if (dst->nl_family == AF_NETLINK)
		hdr.msg_name = dst;

	/* Add credentials if present. */
	creds = nlmsg_get_creds (msg);
	if (creds != NULL) {
		struct cmsghdr *cmsg;

		hdr.msg_control = buf;
		hdr.msg_controllen = sizeof (buf);

		cmsg = CMSG_FIRSTHDR (&hdr);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_CREDENTIALS;
		cmsg->cmsg_len = CMSG_LEN (sizeof (struct ucred));
		memcpy (CMSG_DATA (cmsg), creds, sizeof (struct ucred));
	}

	return nl_sendmsg (sk, msg, &hdr);
}

void
nl_complete_msg (struct nl_sock *sk, struct nl_msg *msg)
{
	struct nlmsghdr *nlh;

	nlh = nlmsg_hdr (msg);
	if (nlh->nlmsg_pid == NL_AUTO_PORT)
		nlh->nlmsg_pid = nl_socket_get_local_port (sk);

	if (nlh->nlmsg_seq == NL_AUTO_SEQ)
		nlh->nlmsg_seq = sk->s_seq_next++;

	if (msg->nm_protocol == -1)
		msg->nm_protocol = sk->s_proto;

	nlh->nlmsg_flags |= NLM_F_REQUEST;

	if (!(sk->s_flags & NL_NO_AUTO_ACK))
		nlh->nlmsg_flags |= NLM_F_ACK;
}

int
nl_send (struct nl_sock *sk, struct nl_msg *msg)
{
	struct iovec iov = {
		.iov_base = (void *) nlmsg_hdr (msg),
		.iov_len = nlmsg_hdr (msg)->nlmsg_len,
	};

	return nl_send_iovec (sk, msg, &iov, 1);
}

int nl_send_auto (struct nl_sock *sk, struct nl_msg *msg)
{
	nl_complete_msg (sk, msg);

	return nl_send (sk, msg);
}

int
nl_recv (struct nl_sock *sk,
         struct sockaddr_nl *nla,
         unsigned char **buf,
         struct ucred *out_creds,
         gboolean *out_creds_has)
{
	ssize_t n;
	int flags = 0;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = (void *) nla,
		.msg_namelen = sizeof (struct sockaddr_nl),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	struct ucred tmpcreds;
	gboolean tmpcreds_has = FALSE;
	int retval;
	int errsv;

	nm_assert (nla);
	nm_assert (buf && !*buf);
	nm_assert (!out_creds_has == !out_creds);

	if (   (sk->s_flags & NL_MSG_PEEK)
	    || (   !(sk->s_flags & NL_MSG_PEEK_EXPLICIT)
	        && sk->s_bufsize == 0))
		flags |= MSG_PEEK | MSG_TRUNC;

	iov.iov_len =    sk->s_bufsize
	              ?: (((size_t) nm_utils_getpagesize ()) * 4u);
	iov.iov_base = g_malloc (iov.iov_len);

	if (   out_creds
	    && (sk->s_flags & NL_SOCK_PASSCRED)) {
		msg.msg_controllen = CMSG_SPACE (sizeof (struct ucred));
		msg.msg_control = g_malloc (msg.msg_controllen);
	}

retry:
	n = recvmsg (sk->s_fd, &msg, flags);
	if (!n) {
		retval = 0;
		goto abort;
	}

	if (n < 0) {
		errsv = errno;
		if (errsv == EINTR)
			goto retry;
		retval = -nm_errno_from_native (errsv);
		goto abort;
	}

	if (msg.msg_flags & MSG_CTRUNC) {
		if (msg.msg_controllen == 0) {
			retval = -NME_NL_MSG_TRUNC;
			goto abort;
		}

		msg.msg_controllen *= 2;
		msg.msg_control = g_realloc (msg.msg_control, msg.msg_controllen);
		goto retry;
	}

	if (   iov.iov_len < n
	    || (msg.msg_flags & MSG_TRUNC)) {
		/* respond with error to an incomplete message */
		if (flags == 0) {
			retval = -NME_NL_MSG_TRUNC;
			goto abort;
		}

		/* Provided buffer is not long enough, enlarge it
		 * to size of n (which should be total length of the message)
		 * and try again. */
		iov.iov_base = g_realloc (iov.iov_base, n);
		iov.iov_len = n;
		flags = 0;
		goto retry;
	}

	if (flags != 0) {
		/* Buffer is big enough, do the actual reading */
		flags = 0;
		goto retry;
	}

	if (msg.msg_namelen != sizeof (struct sockaddr_nl)) {
		retval =  -NME_UNSPEC;
		goto abort;
	}

	if (out_creds && (sk->s_flags & NL_SOCK_PASSCRED)) {
		struct cmsghdr *cmsg;

		for (cmsg = CMSG_FIRSTHDR (&msg); cmsg; cmsg = CMSG_NXTHDR (&msg, cmsg)) {
			if (cmsg->cmsg_level != SOL_SOCKET)
				continue;
			if (cmsg->cmsg_type != SCM_CREDENTIALS)
				continue;
			memcpy (&tmpcreds, CMSG_DATA (cmsg), sizeof (tmpcreds));
			tmpcreds_has = TRUE;
			break;
		}
	}

	retval = n;

abort:
	g_free (msg.msg_control);

	if (retval <= 0) {
		g_free (iov.iov_base);
		return retval;
	}

	*buf = iov.iov_base;
	if (out_creds && tmpcreds_has)
		*out_creds = tmpcreds;
	NM_SET_OUT (out_creds_has, tmpcreds_has);
	return retval;
}
