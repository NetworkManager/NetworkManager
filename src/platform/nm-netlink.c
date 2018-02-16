/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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

#define NL_MSG_CRED_PRESENT 1

struct nl_msg {
	int                     nm_protocol;
	int                     nm_flags;
	struct sockaddr_nl      nm_src;
	struct sockaddr_nl      nm_dst;
	struct ucred            nm_creds;
	struct nlmsghdr *       nm_nlh;
	size_t                  nm_size;
	int                     nm_refcnt;
};

struct nl_sock {
	struct sockaddr_nl      s_local;
	struct sockaddr_nl      s_peer;
	int                     s_fd;
	int                     s_proto;
	unsigned int            s_seq_next;
	unsigned int            s_seq_expect;
	int                     s_flags;
	struct nl_cb *          s_cb;
	size_t                  s_bufsize;
};

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (_geterror, int,
	NM_UTILS_LOOKUP_DEFAULT (NULL),
	NM_UTILS_LOOKUP_ITEM (NLE_UNSPEC,          "NLE_UNSPEC"),
	NM_UTILS_LOOKUP_ITEM (NLE_BUG,             "NLE_BUG"),
	NM_UTILS_LOOKUP_ITEM (NLE_NATIVE_ERRNO,    "NLE_NATIVE_ERRNO"),

	NM_UTILS_LOOKUP_ITEM (NLE_ATTRSIZE,        "NLE_ATTRSIZE"),
	NM_UTILS_LOOKUP_ITEM (NLE_BAD_SOCK,        "NLE_BAD_SOCK"),
	NM_UTILS_LOOKUP_ITEM (NLE_DUMP_INTR,       "NLE_DUMP_INTR"),
	NM_UTILS_LOOKUP_ITEM (NLE_MSG_OVERFLOW,    "NLE_MSG_OVERFLOW"),
	NM_UTILS_LOOKUP_ITEM (NLE_MSG_TOOSHORT,    "NLE_MSG_TOOSHORT"),
	NM_UTILS_LOOKUP_ITEM (NLE_MSG_TRUNC,       "NLE_MSG_TRUNC"),
	NM_UTILS_LOOKUP_ITEM (NLE_SEQ_MISMATCH,    "NLE_SEQ_MISMATCH"),
	NM_UTILS_LOOKUP_ITEM (NLE_USER_NOBUFS,     "NLE_USER_NOBUFS"),
	NM_UTILS_LOOKUP_ITEM (NLE_USER_MSG_TRUNC,  "NLE_USER_MSG_TRUNC"),
)

const char *
nl_geterror (int err)
{
	const char *s;

	err = nl_errno (err);

	if (err >= _NLE_BASE) {
		s = _geterror (err);
		if (s)
			return s;
	}
	return g_strerror (err);
}

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
	case RTM_NEWLINK:    s = "RTM_NEWLINK";  break;
	case RTM_DELLINK:    s = "RTM_DELLINK";  break;
	case RTM_NEWADDR:    s = "RTM_NEWADDR";  break;
	case RTM_DELADDR:    s = "RTM_DELADDR";  break;
	case RTM_NEWROUTE:   s = "RTM_NEWROUTE"; break;
	case RTM_DELROUTE:   s = "RTM_DELROUTE"; break;
	case RTM_NEWQDISC:   s = "RTM_NEWQDISC"; break;
	case RTM_DELQDISC:   s = "RTM_DELQDISC"; break;
	case RTM_NEWTFILTER: s = "RTM_NEWTFILTER"; break;
	case RTM_DELTFILTER: s = "RTM_DELTFILTER"; break;
	case NLMSG_NOOP:     s = "NLMSG_NOOP"; break;
	case NLMSG_ERROR:    s = "NLMSG_ERROR"; break;
	case NLMSG_DONE:     s = "NLMSG_DONE"; break;
	case NLMSG_OVERRUN:  s = "NLMSG_OVERRUN"; break;
	default:             s = NULL;       break;
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

	if (len > n->nm_size)
		return NULL;

	tlen = pad ? ((len + (pad - 1)) & ~(pad - 1)) : len;

	if ((tlen + nlmsg_len) > n->nm_size)
		return NULL;

	buf += nlmsg_len;
	n->nm_nlh->nlmsg_len += tlen;

	if (tlen > len)
		memset(buf + len, 0, tlen - len);

	return buf;
}

/*****************************************************************************/

static int
 get_default_page_size (void)
{
	static int val = 0;
	int v;

	if (G_UNLIKELY (val == 0)) {
		v = getpagesize ();
		g_assert (v > 0);
		val = v;
	}
	return val;
}

struct nlattr *
nla_reserve (struct nl_msg *msg, int attrtype, int attrlen)
{
	struct nlattr *nla;
	int tlen;

	if (attrlen < 0)
		return NULL;

	tlen = NLMSG_ALIGN(msg->nm_nlh->nlmsg_len) + nla_total_size(attrlen);

	if (tlen > msg->nm_size)
		return NULL;

	nla = (struct nlattr *) nlmsg_tail(msg->nm_nlh);
	nla->nla_type = attrtype;
	nla->nla_len = nla_attr_size(attrlen);

	if (attrlen)
		memset((unsigned char *) nla + nla->nla_len, 0, nla_padlen(attrlen));
	msg->nm_nlh->nlmsg_len = tlen;

	return nla;
}

static struct nl_msg *
_nlmsg_alloc(size_t len)
{
	struct nl_msg *nm;

	if (len < sizeof(struct nlmsghdr))
		len = sizeof(struct nlmsghdr);

	nm = calloc(1, sizeof(*nm));
	if (!nm)
		goto errout;

	nm->nm_refcnt = 1;

	nm->nm_nlh = calloc(1, len);
	if (!nm->nm_nlh)
		goto errout;

	nm->nm_protocol = -1;
	nm->nm_size = len;
	nm->nm_nlh->nlmsg_len = nlmsg_total_size(0);

	return nm;
errout:
	free(nm);
	return NULL;
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
	return _nlmsg_alloc (get_default_page_size ());
}

/**
 * Allocate a new netlink message with maximum payload size specified.
 */
struct nl_msg *
nlmsg_alloc_size (size_t max)
{
	return _nlmsg_alloc (max);
}

struct nl_msg *
nlmsg_inherit (struct nlmsghdr *hdr)
{
	struct nl_msg *nm;

	nm = nlmsg_alloc();
	if (nm && hdr) {
		struct nlmsghdr *new = nm->nm_nlh;

		new->nlmsg_type = hdr->nlmsg_type;
		new->nlmsg_flags = hdr->nlmsg_flags;
		new->nlmsg_seq = hdr->nlmsg_seq;
		new->nlmsg_pid = hdr->nlmsg_pid;
	}

	return nm;
}

struct nl_msg *
nlmsg_convert (struct nlmsghdr *hdr)
{
	struct nl_msg *nm;

	nm = _nlmsg_alloc(NLMSG_ALIGN(hdr->nlmsg_len));
	if (!nm)
		return NULL;

	memcpy(nm->nm_nlh, hdr, hdr->nlmsg_len);

	return nm;
}

struct nl_msg *
nlmsg_alloc_simple (int nlmsgtype, int flags)
{
	struct nlmsghdr nlh = {
		.nlmsg_type = nlmsgtype,
		.nlmsg_flags = flags,
	};

	return nlmsg_inherit (&nlh);
}

int
nlmsg_append (struct nl_msg *n, void *data, size_t len, int pad)
{
	void *tmp;

	tmp = nlmsg_reserve(n, len, pad);
	if (tmp == NULL)
		return -ENOMEM;

	memcpy(tmp, data, len);
	return 0;
}

int
nlmsg_parse (struct nlmsghdr *nlh, int hdrlen, struct nlattr *tb[],
             int maxtype, const struct nla_policy *policy)
{
	if (!nlmsg_valid_hdr(nlh, hdrlen))
		return -NLE_MSG_TOOSHORT;

	return nla_parse (tb, maxtype, nlmsg_attrdata(nlh, hdrlen),
	                  nlmsg_attrlen(nlh, hdrlen), policy);
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

	if (payload > 0 &&
	    nlmsg_reserve(n, payload, NLMSG_ALIGNTO) == NULL)
		return NULL;

	return nlh;
}

uint64_t
nla_get_u64 (const struct nlattr *nla)
{
	uint64_t tmp = 0;

	if (nla && nla_len(nla) >= sizeof(tmp))
		memcpy(&tmp, nla_data(nla), sizeof(tmp));

	return tmp;
}

size_t
nla_strlcpy (char *dst, const struct nlattr *nla, size_t dstsize)
{
	size_t srclen = nla_len(nla);
	const char *src = nla_data(nla);

	if (srclen > 0 && src[srclen - 1] == '\0')
		srclen--;

	if (dstsize > 0) {
		size_t len = (srclen >= dstsize) ? dstsize - 1 : srclen;

		memset(dst, 0, dstsize);
		memcpy(dst, src, len);
	}

	return srclen;
}

int
nla_memcpy (void *dest, const struct nlattr *src, int count)
{
	int minlen;

	if (!src)
		return 0;

	minlen = NM_MIN (count, (int) nla_len (src));
	memcpy(dest, nla_data(src), minlen);

	return minlen;
}

int
nla_put (struct nl_msg *msg, int attrtype, int datalen, const void *data)
{
	struct nlattr *nla;

	nla = nla_reserve(msg, attrtype, datalen);
	if (!nla) {
		if (datalen < 0)
			g_return_val_if_reached (-NLE_BUG);

		return -ENOMEM;
	}

	if (datalen > 0)
		memcpy (nla_data(nla), data, datalen);

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

	len = (char *) nlmsg_tail(msg->nm_nlh) - (char *) attr;
	if (len < 0)
		g_return_if_reached ();
	else if (len > 0) {
		msg->nm_nlh->nlmsg_len -= len;
		memset(nlmsg_tail(msg->nm_nlh), 0, len);
	}
}

struct nlattr *
nla_nest_start (struct nl_msg *msg, int attrtype)
{
	struct nlattr *start = (struct nlattr *) nlmsg_tail(msg->nm_nlh);

	if (nla_put(msg, attrtype, 0, NULL) < 0)
		return NULL;

	return start;
}

static int
_nest_end (struct nl_msg *msg, struct nlattr *start, int keep_empty)
{
	size_t pad, len;

	len = (char *) nlmsg_tail(msg->nm_nlh) - (char *) start;

	if (   len > USHRT_MAX
	    || (!keep_empty && len == NLA_HDRLEN)) {
		/*
		 * Max nlattr size exceeded or empty nested attribute, trim the
		 * attribute header again
		 */
		nla_nest_cancel(msg, start);

		/* Return error only if nlattr size was exceeded */
		return (len == NLA_HDRLEN) ? 0 : -NLE_ATTRSIZE;
	}

	start->nla_len = len;

	pad = NLMSG_ALIGN(msg->nm_nlh->nlmsg_len) - msg->nm_nlh->nlmsg_len;
	if (pad > 0) {
		/*
		 * Data inside attribute does not end at a alignment boundry.
		 * Pad accordingly and accoun for the additional space in
		 * the message. nlmsg_reserve() may never fail in this situation,
		 * the allocate message buffer must be a multiple of NLMSG_ALIGNTO.
		 */
		if (!nlmsg_reserve(msg, pad, 0))
			g_return_val_if_reached (-NLE_BUG);
	}

	return 0;
}

int
nla_nest_end (struct nl_msg *msg, struct nlattr *start)
{
	return _nest_end (msg, start, 0);
}

static const uint16_t nla_attr_minlen[NLA_TYPE_MAX+1] = {
	[NLA_U8]        = sizeof(uint8_t),
	[NLA_U16]       = sizeof(uint16_t),
	[NLA_U32]       = sizeof(uint32_t),
	[NLA_U64]       = sizeof(uint64_t),
	[NLA_STRING]    = 1,
	[NLA_FLAG]      = 0,
};

static int
validate_nla (const struct nlattr *nla, int maxtype,
              const struct nla_policy *policy)
{
	const struct nla_policy *pt;
	unsigned int minlen = 0;
	int type = nla_type(nla);

	if (type < 0 || type > maxtype)
		return 0;

	pt = &policy[type];

	if (pt->type > NLA_TYPE_MAX)
		g_return_val_if_reached (-NLE_BUG);

	if (pt->minlen)
		minlen = pt->minlen;
	else if (pt->type != NLA_UNSPEC)
		minlen = nla_attr_minlen[pt->type];

	if (nla_len(nla) < minlen)
		return -NLE_UNSPEC;

	if (pt->maxlen && nla_len(nla) > pt->maxlen)
		return -NLE_UNSPEC;

	if (pt->type == NLA_STRING) {
		const char *data = nla_data(nla);
		if (data[nla_len(nla) - 1] != '\0')
			return -NLE_UNSPEC;
	}

	return 0;
}

int
nla_parse (struct nlattr *tb[], int maxtype, struct nlattr *head, int len,
           const struct nla_policy *policy)
{
	struct nlattr *nla;
	int rem, err;

	memset(tb, 0, sizeof(struct nlattr *) * (maxtype + 1));

	nla_for_each_attr(nla, head, len, rem) {
		int type = nla_type(nla);

		if (type > maxtype)
			continue;

		if (policy) {
			err = validate_nla(nla, maxtype, policy);
			if (err < 0)
				goto errout;
		}

		tb[type] = nla;
	}

	err = 0;
errout:
	return err;
}

/*****************************************************************************/

void nlmsg_free (struct nl_msg *msg)
{
	if (!msg)
		return;

	if (msg->nm_refcnt < 1)
		g_return_if_reached ();

	msg->nm_refcnt--;

	if (msg->nm_refcnt <= 0) {
		free(msg->nm_nlh);
		free(msg);
	}
}

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
	memcpy (&msg->nm_src, addr, sizeof(*addr));
}

struct ucred *
nlmsg_get_creds (struct nl_msg *msg)
{
	if (msg->nm_flags & NL_MSG_CRED_PRESENT)
		return &msg->nm_creds;
	return NULL;
}

void
nlmsg_set_creds (struct nl_msg *msg, struct ucred *creds)
{
	memcpy (&msg->nm_creds, creds, sizeof(*creds));
	msg->nm_flags |= NL_MSG_CRED_PRESENT;
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
		return -NLE_MSG_TOOSHORT;

	ghdr = nlmsg_data (nlh);
	return nla_parse (tb, maxtype, genlmsg_attrdata (ghdr, hdrlen),
	                  genlmsg_attrlen (ghdr, hdrlen), policy);
}

/*****************************************************************************/

struct nl_cb {
	nl_recvmsg_msg_cb_t     cb_set[NL_CB_TYPE_MAX+1];
	void *                  cb_args[NL_CB_TYPE_MAX+1];

	nl_recvmsg_err_cb_t     cb_err;
	void *                  cb_err_arg;

	/* May be used to replace nl_recvmsgs with your own implementation
	 * in all internal calls to nl_recvmsgs. */
	int                     (*cb_recvmsgs_ow)(struct nl_sock *,
	                                          struct nl_cb *);

	/* Overwrite internal calls to nl_recv, must return the number of
	 * octets read and allocate a buffer for the received data. */
	int                     (*cb_recv_ow)(struct nl_sock *,
	                                      struct sockaddr_nl *,
	                                      unsigned char **,
	                                      struct ucred **);

	/* Overwrites internal calls to nl_send, must send the netlink
	 * message. */
	int                     (*cb_send_ow)(struct nl_sock *,
	                                      struct nl_msg *);

	int                     cb_refcnt;
	/* indicates the callback that is currently active */
	enum nl_cb_type         cb_active;
};

/*****************************************************************************/

static int
nl_cb_call (struct nl_cb *cb, enum nl_cb_type type, struct nl_msg *msg)
{
	int ret;

	cb->cb_active = type;
	ret = cb->cb_set[type](msg, cb->cb_args[type]);
	cb->cb_active = __NL_CB_TYPE_MAX;
	return ret;
}

struct nl_cb *
nl_cb_alloc (enum nl_cb_kind kind)
{
	int i;
	struct nl_cb *cb;

	if ((unsigned int) kind > NL_CB_KIND_MAX)
		return NULL;

	cb = calloc(1, sizeof(*cb));
	if (!cb)
		return NULL;

	cb->cb_refcnt = 1;
	cb->cb_active = NL_CB_TYPE_MAX + 1;

	for (i = 0; i <= NL_CB_TYPE_MAX; i++)
		nl_cb_set(cb, i, kind, NULL, NULL);

	nl_cb_err(cb, kind, NULL, NULL);

	return cb;
}

struct nl_cb *nl_cb_clone(struct nl_cb *orig)
{
	struct nl_cb *cb;

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb)
		return NULL;

	memcpy(cb, orig, sizeof(*orig));
	cb->cb_refcnt = 1;

	return cb;
}

struct nl_cb *nl_cb_get(struct nl_cb *cb)
{
	cb->cb_refcnt++;

	return cb;
}

void nl_cb_put(struct nl_cb *cb)
{
	if (!cb)
		return;

	if (cb->cb_refcnt <= 0)
		g_return_if_reached ();

	cb->cb_refcnt--;

	if (cb->cb_refcnt <= 0)
		free(cb);
}

int
nl_cb_err (struct nl_cb *cb, enum nl_cb_kind kind,
           nl_recvmsg_err_cb_t func, void *arg)
{
	if ((unsigned int) kind > NL_CB_KIND_MAX)
		g_return_val_if_reached (-NLE_BUG);

	if (kind == NL_CB_CUSTOM) {
		cb->cb_err = func;
		cb->cb_err_arg = arg;
	} else {
		cb->cb_err = NULL;
		cb->cb_err_arg = arg;
	}

	return 0;
}

int
nl_cb_set (struct nl_cb *cb, enum nl_cb_type type, enum nl_cb_kind kind,
           nl_recvmsg_msg_cb_t func, void *arg)
{
	if ((unsigned int) type > NL_CB_TYPE_MAX)
		g_return_val_if_reached (-NLE_BUG);

	if ((unsigned int) kind > NL_CB_KIND_MAX)
		g_return_val_if_reached (-NLE_BUG);

	if (kind == NL_CB_CUSTOM) {
		cb->cb_set[type] = func;
		cb->cb_args[type] = arg;
	} else {
		cb->cb_set[type] = NULL;
		cb->cb_args[type] = arg;
	}

	return 0;
}

/*****************************************************************************/

static struct nl_sock *
_alloc_socket (struct nl_cb *cb)
{
	struct nl_sock *sk;

	sk = calloc(1, sizeof(*sk));
	if (!sk)
		return NULL;

	sk->s_fd = -1;
	sk->s_cb = nl_cb_get(cb);
	sk->s_local.nl_family = AF_NETLINK;
	sk->s_peer.nl_family = AF_NETLINK;
	sk->s_seq_expect = sk->s_seq_next = time(NULL);

	return sk;
}

struct nl_sock *
nl_socket_alloc (void)
{
	struct nl_cb *cb;
	struct nl_sock *sk;

	cb = nl_cb_alloc (NL_CB_DEFAULT);
	if (!cb)
		return NULL;

	/* will increment cb reference count on success */
	sk = _alloc_socket(cb);

	nl_cb_put(cb);

	return sk;
}

void
nl_socket_free (struct nl_sock *sk)
{
	if (!sk)
		return;

	if (sk->s_fd >= 0)
		close(sk->s_fd);

	nl_cb_put(sk->s_cb);
	free(sk);
}

struct nl_cb *
nl_socket_get_cb (const struct nl_sock *sk)
{
	return nl_cb_get(sk->s_cb);
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
		return -NLE_BAD_SOCK;

	err = setsockopt (sk->s_fd, SOL_SOCKET, SO_PASSCRED,
	                  &state, sizeof(state));
	if (err < 0)
		return -nl_syserr2nlerr (errno);

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
		return -NLE_BAD_SOCK;

	if (fcntl(sk->s_fd, F_SETFL, O_NONBLOCK) < 0)
		return -nl_syserr2nlerr (errno);

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
		return -NLE_BAD_SOCK;

	err = setsockopt (sk->s_fd, SOL_SOCKET, SO_SNDBUF,
	                  &txbuf, sizeof(txbuf));
	if (err < 0) {
		return -nl_syserr2nlerr (errno);
	}

	err = setsockopt (sk->s_fd, SOL_SOCKET, SO_RCVBUF,
	                  &rxbuf, sizeof(rxbuf));
	if (err < 0) {
		return -nl_syserr2nlerr (errno);
	}

	return 0;
}

int
nl_socket_add_memberships (struct nl_sock *sk, int group, ...)
{
	int err;
	va_list ap;

	if (sk->s_fd == -1)
		return -NLE_BAD_SOCK;

	va_start(ap, group);

	while (group != 0) {
		if (group < 0) {
			va_end(ap);
			g_return_val_if_reached (-NLE_BUG);
		}

		err = setsockopt (sk->s_fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
		                  &group, sizeof(group));
		if (err < 0) {
			va_end(ap);
			return -nl_syserr2nlerr (errno);
		}

		group = va_arg(ap, int);
	}

	va_end(ap);

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
	int err;
	socklen_t addrlen;
	struct sockaddr_nl local = { 0 };

	if (sk->s_fd != -1)
		return -NLE_BAD_SOCK;

	sk->s_fd = socket (AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, protocol);
	if (sk->s_fd < 0) {
		err = -nl_syserr2nlerr (errno);
		goto errout;
	}

	err = nl_socket_set_buffer_size(sk, 0, 0);
	if (err < 0)
		goto errout;

	nm_assert (sk->s_local.nl_pid == 0);

	err = bind (sk->s_fd, (struct sockaddr*) &sk->s_local,
	            sizeof(sk->s_local));
	if (err != 0) {
		err = -nl_syserr2nlerr (errno);
		goto errout;
	}

	addrlen = sizeof(local);
	err = getsockname (sk->s_fd, (struct sockaddr *) &local,
	                   &addrlen);
	if (err < 0) {
		err = -nl_syserr2nlerr (errno);
		goto errout;
	}

	if (addrlen != sizeof(local)) {
		err = -NLE_UNSPEC;
		goto errout;
	}

	if (local.nl_family != AF_NETLINK) {
		err = -NLE_UNSPEC;
		goto errout;
	}

	sk->s_local = local;
	sk->s_proto = protocol;

	return 0;

errout:
	if (sk->s_fd != -1) {
		close(sk->s_fd);
		sk->s_fd = -1;
	}
	return err;
}

/*****************************************************************************/

static int ack_wait_handler(struct nl_msg *msg, void *arg)
{
	return NL_STOP;
}

int
nl_wait_for_ack(struct nl_sock *sk)
{
	int err;
	struct nl_cb *cb;

	cb = nl_cb_clone(sk->s_cb);
	if (cb == NULL)
		return -ENOMEM;

	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_wait_handler, NULL);
	err = nl_recvmsgs(sk, cb);
	nl_cb_put(cb);

	return err;
}

#define NL_CB_CALL(cb, type, msg) \
do { \
	err = nl_cb_call(cb, type, msg); \
	switch (err) { \
	case NL_OK: \
		err = 0; \
		break; \
	case NL_SKIP: \
		goto skip; \
	case NL_STOP: \
		goto stop; \
	default: \
		goto out; \
	} \
} while (0)

static int
recvmsgs (struct nl_sock *sk, struct nl_cb *cb)
{
	int n, err = 0, multipart = 0, interrupted = 0, nrecv = 0;
	unsigned char *buf = NULL;
	struct nlmsghdr *hdr;

	/*
	nla is passed on to not only to nl_recv() but may also be passed
	to a function pointer provided by the caller which may or may not
	initialize the variable. Thomas Graf.
	*/
	struct sockaddr_nl nla = {0};
	struct nl_msg *msg = NULL;
	struct ucred *creds = NULL;

continue_reading:
	if (cb->cb_recv_ow)
		n = cb->cb_recv_ow(sk, &nla, &buf, &creds);
	else
		n = nl_recv(sk, &nla, &buf, &creds);

	if (n <= 0)
		return n;

	hdr = (struct nlmsghdr *) buf;
	while (nlmsg_ok(hdr, n)) {
		nlmsg_free(msg);
		msg = nlmsg_convert(hdr);
		if (!msg) {
			err = -ENOMEM;
			goto out;
		}

		nlmsg_set_proto(msg, sk->s_proto);
		nlmsg_set_src(msg, &nla);
		if (creds)
			nlmsg_set_creds(msg, creds);

		nrecv++;

		/* Raw callback is the first, it gives the most control
		 * to the user and he can do his very own parsing. */
		if (cb->cb_set[NL_CB_MSG_IN])
			NL_CB_CALL(cb, NL_CB_MSG_IN, msg);

		/* Sequence number checking. The check may be done by
		 * the user, otherwise a very simple check is applied
		 * enforcing strict ordering */
		if (cb->cb_set[NL_CB_SEQ_CHECK]) {
			NL_CB_CALL(cb, NL_CB_SEQ_CHECK, msg);

		/* Only do sequence checking if auto-ack mode is enabled */
		} else if (!(sk->s_flags & NL_NO_AUTO_ACK)) {
			if (hdr->nlmsg_seq != sk->s_seq_expect) {
				if (cb->cb_set[NL_CB_INVALID])
					NL_CB_CALL(cb, NL_CB_INVALID, msg);
				else {
					err = -NLE_SEQ_MISMATCH;
					goto out;
				}
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
			if (cb->cb_set[NL_CB_DUMP_INTR])
				NL_CB_CALL(cb, NL_CB_DUMP_INTR, msg);
			else {
				/*
				 * We have to continue reading to clear
				 * all messages until a NLMSG_DONE is
				 * received and report the inconsistency.
				 */
				interrupted = 1;
			}
		}

		/* Other side wishes to see an ack for this message */
		if (hdr->nlmsg_flags & NLM_F_ACK) {
			if (cb->cb_set[NL_CB_SEND_ACK])
				NL_CB_CALL(cb, NL_CB_SEND_ACK, msg);
			else {
				/* FIXME: implement */
			}
		}

		/* messages terminates a multipart message, this is
		 * usually the end of a message and therefore we slip
		 * out of the loop by default. the user may overrule
		 * this action by skipping this packet. */
		if (hdr->nlmsg_type == NLMSG_DONE) {
			multipart = 0;
			if (cb->cb_set[NL_CB_FINISH])
				NL_CB_CALL(cb, NL_CB_FINISH, msg);
		}

		/* Message to be ignored, the default action is to
		 * skip this message if no callback is specified. The
		 * user may overrule this action by returning
		 * NL_PROCEED. */
		else if (hdr->nlmsg_type == NLMSG_NOOP) {
			if (cb->cb_set[NL_CB_SKIPPED])
				NL_CB_CALL(cb, NL_CB_SKIPPED, msg);
			else
				goto skip;
		}

		/* Data got lost, report back to user. The default action is to
		 * quit parsing. The user may overrule this action by retuning
		 * NL_SKIP or NL_PROCEED (dangerous) */
		else if (hdr->nlmsg_type == NLMSG_OVERRUN) {
			if (cb->cb_set[NL_CB_OVERRUN])
				NL_CB_CALL(cb, NL_CB_OVERRUN, msg);
			else {
				err = -NLE_MSG_OVERFLOW;
				goto out;
			}
		}

		/* Message carries a nlmsgerr */
		else if (hdr->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *e = nlmsg_data(hdr);

			if (hdr->nlmsg_len < nlmsg_size(sizeof(*e))) {
				/* Truncated error message, the default action
				 * is to stop parsing. The user may overrule
				 * this action by returning NL_SKIP or
				 * NL_PROCEED (dangerous) */
				if (cb->cb_set[NL_CB_INVALID])
					NL_CB_CALL(cb, NL_CB_INVALID, msg);
				else {
					err = -NLE_MSG_TRUNC;
					goto out;
				}
			} else if (e->error) {
				/* Error message reported back from kernel. */
				if (cb->cb_err) {
					err = cb->cb_err(&nla, e,
							 cb->cb_err_arg);
					if (err < 0)
						goto out;
					else if (err == NL_SKIP)
						goto skip;
					else if (err == NL_STOP) {
						err = -e->error;
						goto out;
					}
				} else {
					err = -e->error;
					goto out;
				}
			} else if (cb->cb_set[NL_CB_ACK])
				NL_CB_CALL(cb, NL_CB_ACK, msg);
		} else {
			/* Valid message (not checking for MULTIPART bit to
			 * get along with broken kernels. NL_SKIP has no
			 * effect on this.  */
			if (cb->cb_set[NL_CB_VALID])
				NL_CB_CALL(cb, NL_CB_VALID, msg);
		}
skip:
		err = 0;
		hdr = nlmsg_next(hdr, &n);
	}

	nlmsg_free(msg);
	free(buf);
	free(creds);
	buf = NULL;
	msg = NULL;
	creds = NULL;

	if (multipart) {
		/* Multipart message not yet complete, continue reading */
		goto continue_reading;
	}
stop:
	err = 0;
out:
	nlmsg_free(msg);
	free(buf);
	free(creds);

	if (interrupted)
		err = -NLE_DUMP_INTR;

	if (!err)
		err = nrecv;

	return err;
}

int
nl_recvmsgs_report (struct nl_sock *sk, struct nl_cb *cb)
{
	if (cb->cb_recvmsgs_ow)
		return cb->cb_recvmsgs_ow(sk, cb);
	else
		return recvmsgs(sk, cb);
}

int
nl_recvmsgs (struct nl_sock *sk, struct nl_cb *cb)
{
	int err;

	if ((err = nl_recvmsgs_report(sk, cb)) > 0)
		err = 0;

	return err;
}

int
nl_sendmsg (struct nl_sock *sk, struct nl_msg *msg, struct msghdr *hdr)
{
	struct nl_cb *cb;
	int ret;

	if (sk->s_fd < 0)
		return -NLE_BAD_SOCK;

	nlmsg_set_src (msg, &sk->s_local);

	cb = sk->s_cb;
	if (cb->cb_set[NL_CB_MSG_OUT])
		if ((ret = nl_cb_call(cb, NL_CB_MSG_OUT, msg)) != NL_OK)
			return ret;

	ret = sendmsg(sk->s_fd, hdr, 0);
	if (ret < 0)
		return -nl_syserr2nlerr (errno);

	return ret;
}

int
nl_send_iovec (struct nl_sock *sk, struct nl_msg *msg, struct iovec *iov, unsigned iovlen)
{
	struct sockaddr_nl *dst;
	struct ucred *creds;
	struct msghdr hdr = {
		.msg_name = (void *) &sk->s_peer,
		.msg_namelen = sizeof(struct sockaddr_nl),
		.msg_iov = iov,
		.msg_iovlen = iovlen,
	};
	char buf[CMSG_SPACE(sizeof(struct ucred))];

	/* Overwrite destination if specified in the message itself, defaults
	 * to the peer address of the socket.
	 */
	dst = nlmsg_get_dst(msg);
	if (dst->nl_family == AF_NETLINK)
		hdr.msg_name = dst;

	/* Add credentials if present. */
	creds = nlmsg_get_creds(msg);
	if (creds != NULL) {
		struct cmsghdr *cmsg;

		hdr.msg_control = buf;
		hdr.msg_controllen = sizeof(buf);

		cmsg = CMSG_FIRSTHDR(&hdr);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_CREDENTIALS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
		memcpy(CMSG_DATA(cmsg), creds, sizeof(struct ucred));
	}

	return nl_sendmsg(sk, msg, &hdr);
}

void
nl_complete_msg (struct nl_sock *sk, struct nl_msg *msg)
{
	struct nlmsghdr *nlh;

	nlh = nlmsg_hdr(msg);
	if (nlh->nlmsg_pid == NL_AUTO_PORT)
		nlh->nlmsg_pid = nl_socket_get_local_port(sk);

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
	struct nl_cb *cb = sk->s_cb;

	if (cb->cb_send_ow)
		return cb->cb_send_ow(sk, msg);
	else {
		struct iovec iov = {
			.iov_base = (void *) nlmsg_hdr(msg),
			.iov_len = nlmsg_hdr(msg)->nlmsg_len,
		};

		return nl_send_iovec(sk, msg, &iov, 1);
	}
}

int nl_send_auto(struct nl_sock *sk, struct nl_msg *msg)
{
	nl_complete_msg(sk, msg);

	return nl_send(sk, msg);
}

int
nl_recv (struct nl_sock *sk, struct sockaddr_nl *nla,
         unsigned char **buf, struct ucred **creds)
{
	ssize_t n;
	int flags = 0;
	static int page_size = 0;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = (void *) nla,
		.msg_namelen = sizeof(struct sockaddr_nl),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	struct ucred* tmpcreds = NULL;
	int retval = 0;

	if (!buf || !nla)
		g_return_val_if_reached (-NLE_BUG);

	if (   (sk->s_flags & NL_MSG_PEEK)
	    || (!(sk->s_flags & NL_MSG_PEEK_EXPLICIT) && sk->s_bufsize == 0))
		flags |= MSG_PEEK | MSG_TRUNC;

	if (page_size == 0)
		page_size = getpagesize() * 4;

	iov.iov_len = sk->s_bufsize ? : page_size;
	iov.iov_base = malloc(iov.iov_len);

	if (!iov.iov_base) {
		retval = -ENOMEM;
		goto abort;
	}

	if (creds && (sk->s_flags & NL_SOCK_PASSCRED)) {
		msg.msg_controllen = CMSG_SPACE(sizeof(struct ucred));
		msg.msg_control = malloc(msg.msg_controllen);
		if (!msg.msg_control) {
			retval = -ENOMEM;
			goto abort;
		}
	}
retry:

	n = recvmsg(sk->s_fd, &msg, flags);
	if (!n) {
		retval = 0;
		goto abort;
	}
	if (n < 0) {
		if (errno == EINTR)
			goto retry;

		retval = -nl_syserr2nlerr (errno);
		goto abort;
	}

	if (msg.msg_flags & MSG_CTRUNC) {
		void *tmp;

		if (msg.msg_controllen == 0) {
			retval = -NLE_MSG_TRUNC;
			goto abort;
		}

		msg.msg_controllen *= 2;
		tmp = realloc(msg.msg_control, msg.msg_controllen);
		if (!tmp) {
			retval = -ENOMEM;
			goto abort;
		}
		msg.msg_control = tmp;
		goto retry;
	}

	if (iov.iov_len < n || (msg.msg_flags & MSG_TRUNC)) {
		void *tmp;

		/* respond with error to an incomplete message */
		if (flags == 0) {
			retval = -NLE_MSG_TRUNC;
			goto abort;
		}

		/* Provided buffer is not long enough, enlarge it
		 * to size of n (which should be total length of the message)
		 * and try again. */
		iov.iov_len = n;
		tmp = realloc(iov.iov_base, iov.iov_len);
		if (!tmp) {
			retval = -ENOMEM;
			goto abort;
		}
		iov.iov_base = tmp;
		flags = 0;
		goto retry;
	}

	if (flags != 0) {
		/* Buffer is big enough, do the actual reading */
		flags = 0;
		goto retry;
	}

	if (msg.msg_namelen != sizeof(struct sockaddr_nl)) {
		retval =  -NLE_UNSPEC;
		goto abort;
	}

	if (creds && (sk->s_flags & NL_SOCK_PASSCRED)) {
		struct cmsghdr *cmsg;

		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_level != SOL_SOCKET)
				continue;
			if (cmsg->cmsg_type != SCM_CREDENTIALS)
				continue;
			tmpcreds = malloc(sizeof(*tmpcreds));
			if (!tmpcreds) {
				retval = -ENOMEM;
				goto abort;
			}
			memcpy(tmpcreds, CMSG_DATA(cmsg), sizeof(*tmpcreds));
			break;
		}
	}

	retval = n;
abort:
	free(msg.msg_control);

	if (retval <= 0) {
		free(iov.iov_base);
		iov.iov_base = NULL;
		free(tmpcreds);
		tmpcreds = NULL;
	} else
		*buf = iov.iov_base;

	if (creds)
		*creds = tmpcreds;

	return retval;
}
