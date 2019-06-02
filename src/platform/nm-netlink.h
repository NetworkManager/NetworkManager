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

#ifndef __NM_NETLINK_H__
#define __NM_NETLINK_H__

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>

#include "nm-std-aux/unaligned.h"

/*****************************************************************************/

#define NLMSGERR_ATTR_UNUSED            0
#define NLMSGERR_ATTR_MSG               1
#define NLMSGERR_ATTR_OFFS              2
#define NLMSGERR_ATTR_COOKIE            3
#define NLMSGERR_ATTR_MAX               3

#ifndef NLM_F_ACK_TLVS
#define NLM_F_ACK_TLVS                  0x200
#endif

/*****************************************************************************/

/* Basic attribute data types */
enum {
	NLA_UNSPEC,     /* Unspecified type, binary data chunk */
	NLA_U8,         /* 8 bit integer */
	NLA_U16,        /* 16 bit integer */
	NLA_U32,        /* 32 bit integer */
	NLA_U64,        /* 64 bit integer */
	NLA_STRING,     /* NUL terminated character string */
	NLA_FLAG,       /* Flag */
	NLA_MSECS,      /* Micro seconds (64bit) */
	NLA_NESTED,     /* Nested attributes */
	NLA_NESTED_COMPAT,
	NLA_NUL_STRING,
	NLA_BINARY,
	NLA_S8,
	NLA_S16,
	NLA_S32,
	NLA_S64,
	__NLA_TYPE_MAX,
};

#define NLA_TYPE_MAX (__NLA_TYPE_MAX - 1)

struct nl_msg;

/*****************************************************************************/

const char *nl_nlmsgtype2str (int type, char *buf, size_t size);

const char *nl_nlmsg_flags2str (int flags, char *buf, size_t len);

const char *nl_nlmsghdr_to_str (const struct nlmsghdr *hdr, char *buf, gsize len);

/*****************************************************************************/

struct nla_policy {
	/* Type of attribute or NLA_UNSPEC */
	uint16_t type;

	/* Minimal length of payload required */
	uint16_t minlen;

	/* Maximal length of payload allowed */
	uint16_t maxlen;
};

/*****************************************************************************/

/* static asserts that @tb and @policy are suitable arguments to nla_parse(). */
#define _nl_static_assert_tb(tb, policy) \
	G_STMT_START { \
		\
		G_STATIC_ASSERT_EXPR (G_N_ELEMENTS (tb) > 0); \
		\
		/* we allow @policy to be either NULL or a C array. */ \
		G_STATIC_ASSERT_EXPR (   sizeof (policy) == sizeof (NULL) \
		                      || G_N_ELEMENTS (tb) == (sizeof (policy) / sizeof (struct nla_policy))); \
		\
		/* For above check to work, we don't support policy being an array with same size as
		 * sizeof(NULL), otherwise, the compile time check breaks down. */ \
		G_STATIC_ASSERT_EXPR (sizeof (NULL) != G_N_ELEMENTS (tb) * sizeof (struct nla_policy)); \
		\
	} G_STMT_END

/*****************************************************************************/

static inline int
nla_attr_size (int payload)
{
	nm_assert (payload >= 0);

	return NLA_HDRLEN + payload;
}

static inline int
nla_total_size (int payload)
{
	return NLA_ALIGN (nla_attr_size (payload));
}

static inline int
nla_padlen (int payload)
{
	return nla_total_size (payload) - nla_attr_size (payload);
}

struct nlattr *nla_reserve (struct nl_msg *msg, int attrtype, int attrlen);

static inline int
nla_len (const struct nlattr *nla)
{
	nm_assert (nla);
	nm_assert (nla->nla_len >= NLA_HDRLEN);

	return ((int) nla->nla_len) - NLA_HDRLEN;
}

static inline int
nla_type (const struct nlattr *nla)
{
	nm_assert (nla_len (nla) >= 0);

	return nla->nla_type & NLA_TYPE_MASK;
}

static inline void *
nla_data (const struct nlattr *nla)
{
	nm_assert (nla_len (nla) >= 0);

	return &(((char *) nla)[NLA_HDRLEN]);
}

#define nla_data_as(type, nla) \
	({ \
		const struct nlattr *_nla = (nla); \
		\
		nm_assert (nla_len (_nla) >= sizeof (type)); \
		\
		/* note that casting the pointer is undefined behavior in C, if
		 * the data has wrong alignment. Netlink data is aligned to 4 bytes,
		 * that means, if the alignment is larger than 4, this is invalid. */ \
		G_STATIC_ASSERT_EXPR (_nm_alignof (type) <= NLA_ALIGNTO); \
		\
		(type *) nla_data (_nla); \
	})

static inline uint8_t
nla_get_u8 (const struct nlattr *nla)
{
	nm_assert (nla_len (nla) >= sizeof (uint8_t));

	return *((const uint8_t *) nla_data (nla));
}

static inline int8_t
nla_get_s8 (const struct nlattr *nla)
{
	nm_assert (nla_len (nla) >= sizeof (int8_t));

	return *((const int8_t *) nla_data (nla));
}

static inline uint8_t
nla_get_u8_cond (/*const*/ struct nlattr *const*tb, int attr, uint8_t default_val)
{
	nm_assert (tb);
	nm_assert (attr >= 0);

	return tb[attr] ? nla_get_u8 (tb[attr]) : default_val;
}

static inline uint16_t
nla_get_u16 (const struct nlattr *nla)
{
	nm_assert (nla_len (nla) >= sizeof (uint16_t));

	return *((const uint16_t *) nla_data (nla));
}

static inline uint32_t
nla_get_u32 (const struct nlattr *nla)
{
	nm_assert (nla_len (nla) >= sizeof (uint32_t));

	return *((const uint32_t *) nla_data (nla));
}

static inline int32_t
nla_get_s32 (const struct nlattr *nla)
{
	nm_assert (nla_len (nla) >= sizeof (int32_t));

	return *((const int32_t *) nla_data (nla));
}

static inline uint64_t
nla_get_u64 (const struct nlattr *nla)
{
	nm_assert (nla_len (nla) >= sizeof (uint64_t));

	return unaligned_read_ne64 (nla_data (nla));
}

static inline uint64_t
nla_get_be64 (const struct nlattr *nla)
{
	nm_assert (nla_len (nla) >= sizeof (uint64_t));

	return unaligned_read_be64 (nla_data (nla));
}

static inline char *
nla_get_string (const struct nlattr *nla)
{
	nm_assert (nla_len (nla) >= 0);

	return (char *) nla_data (nla);
}

size_t nla_strlcpy (char *dst, const struct nlattr *nla, size_t dstsize);

size_t nla_memcpy (void *dst, const struct nlattr *nla, size_t dstsize);

#define nla_memcpy_checked_size(dst, nla, dstsize) \
	G_STMT_START { \
		void *const _dst = (dst); \
		const struct nlattr *const _nla = (nla); \
		const size_t _dstsize = (dstsize); \
		size_t _srcsize; \
		\
		/* assert that, if @nla is given, that it has the exact expected
		 * size. This implies that the caller previously verified the length
		 * of the attribute (via minlen/maxlen at nla_parse()). */ \
		\
		if (_nla) { \
			_srcsize = nla_memcpy (_dst, _nla, _dstsize); \
			nm_assert (_srcsize == _dstsize); \
		} \
	} G_STMT_END

int nla_put (struct nl_msg *msg, int attrtype, int datalen, const void *data);

static inline int
nla_put_string (struct nl_msg *msg, int attrtype, const char *str)
{
	nm_assert (str);

	return nla_put (msg, attrtype, strlen (str) + 1, str);
}

static inline int
nla_put_uint8 (struct nl_msg *msg, int attrtype, uint8_t val)
{
	return nla_put (msg, attrtype, sizeof (val), &val);
}

static inline int
nla_put_uint16 (struct nl_msg *msg, int attrtype, uint16_t val)
{
	return nla_put (msg, attrtype, sizeof (val), &val);
}

static inline int
nla_put_uint32 (struct nl_msg *msg, int attrtype, uint32_t val)
{
	return nla_put (msg, attrtype, sizeof (val), &val);
}

#define NLA_PUT(msg, attrtype, attrlen, data) \
	G_STMT_START { \
		if (nla_put (msg, attrtype, attrlen, data) < 0) \
			goto nla_put_failure; \
	} G_STMT_END

#define NLA_PUT_TYPE(msg, type, attrtype, value) \
	G_STMT_START { \
		type __nla_tmp = value; \
		NLA_PUT (msg, attrtype, sizeof (type), &__nla_tmp); \
	} G_STMT_END

#define NLA_PUT_U8(msg, attrtype, value) \
	NLA_PUT_TYPE (msg, uint8_t, attrtype, value)

#define NLA_PUT_S8(msg, attrtype, value) \
	NLA_PUT_TYPE (msg, int8_t, attrtype, value)

#define NLA_PUT_U16(msg, attrtype, value) \
	NLA_PUT_TYPE (msg, uint16_t, attrtype, value)

#define NLA_PUT_U32(msg, attrtype, value) \
	NLA_PUT_TYPE (msg, uint32_t, attrtype, value)

#define NLA_PUT_S32(msg, attrtype, value) \
	NLA_PUT_TYPE (msg, int32_t, attrtype, value)

#define NLA_PUT_U64(msg, attrtype, value) \
	NLA_PUT_TYPE (msg, uint64_t, attrtype, value)

#define NLA_PUT_STRING(msg, attrtype, value) \
	NLA_PUT (msg, attrtype, (int) strlen (value) + 1, value)

#define NLA_PUT_FLAG(msg, attrtype) \
	NLA_PUT (msg, attrtype, 0, NULL)

struct nlattr *nla_find (const struct nlattr *head, int len, int attrtype);

static inline int
nla_ok (const struct nlattr *nla, int remaining)
{
	return remaining >= (int) sizeof (*nla) &&
	       nla->nla_len >= sizeof (*nla) &&
	       nla->nla_len <= remaining;
}

static inline struct nlattr *
nla_next (const struct nlattr *nla, int *remaining)
{
	int totlen = NLA_ALIGN (nla->nla_len);

	*remaining -= totlen;
	return (struct nlattr *) ((char *) nla + totlen);
}

#define nla_for_each_attr(pos, head, len, rem) \
	for (pos = head, rem = len; \
	     nla_ok (pos, rem); \
	     pos = nla_next (pos, &(rem)))

#define nla_for_each_nested(pos, nla, rem) \
	for (pos = (struct nlattr *) nla_data (nla), rem = nla_len (nla); \
	     nla_ok (pos, rem); \
	     pos = nla_next (pos, &(rem)))

void nla_nest_cancel (struct nl_msg *msg, const struct nlattr *attr);
struct nlattr *nla_nest_start (struct nl_msg *msg, int attrtype);
int nla_nest_end (struct nl_msg *msg, struct nlattr *start);

int nla_parse (struct nlattr *tb[],
               int maxtype,
               struct nlattr *head,
               int len,
               const struct nla_policy *policy);

#define nla_parse_arr(tb, head, len, policy) \
	({ \
		_nl_static_assert_tb ((tb), (policy)); \
		\
		nla_parse ((tb), G_N_ELEMENTS (tb) - 1, (head), (len), (policy)); \
	})

static inline int
nla_parse_nested (struct nlattr *tb[],
                  int maxtype,
                  struct nlattr *nla,
                  const struct nla_policy *policy)
{
	return nla_parse (tb, maxtype, nla_data (nla), nla_len (nla), policy);
}

#define nla_parse_nested_arr(tb, nla, policy) \
	({ \
		_nl_static_assert_tb ((tb), (policy)); \
		\
		nla_parse_nested ((tb), G_N_ELEMENTS (tb) - 1, (nla), (policy)); \
	})

/*****************************************************************************/

struct nl_msg *nlmsg_alloc (void);

struct nl_msg *nlmsg_alloc_size (size_t max);

struct nl_msg *nlmsg_alloc_convert (struct nlmsghdr *hdr);

struct nl_msg *nlmsg_alloc_simple (int nlmsgtype, int flags);

void *nlmsg_reserve (struct nl_msg *n, size_t len, int pad);

int nlmsg_append (struct nl_msg *n,
                  const void *data,
                  size_t len,
                  int pad);

#define nlmsg_append_struct(n, data) \
	nlmsg_append (n, (data), sizeof (*(data)), NLMSG_ALIGNTO)

void nlmsg_free (struct nl_msg *msg);

static inline int
nlmsg_size (int payload)
{
	nm_assert (payload >= 0 && payload < G_MAXINT - NLMSG_HDRLEN - 4);
	return NLMSG_HDRLEN + payload;
}

static inline int
nlmsg_total_size (int payload)
{
	return NLMSG_ALIGN (nlmsg_size (payload));
}

static inline int
nlmsg_ok (const struct nlmsghdr *nlh, int remaining)
{
	return (remaining >= (int) sizeof (struct nlmsghdr) &&
	       nlh->nlmsg_len >= sizeof (struct nlmsghdr) &&
	       nlh->nlmsg_len <= remaining);
}

static inline struct nlmsghdr *
nlmsg_next (struct nlmsghdr *nlh, int *remaining)
{
	int totlen = NLMSG_ALIGN (nlh->nlmsg_len);

	*remaining -= totlen;

	return (struct nlmsghdr *) ((unsigned char *) nlh + totlen);
}

int nlmsg_get_proto (struct nl_msg *msg);
void nlmsg_set_proto (struct nl_msg *msg, int protocol);

void nlmsg_set_src (struct nl_msg *msg, struct sockaddr_nl *addr);

struct ucred *nlmsg_get_creds (struct nl_msg *msg);
void nlmsg_set_creds (struct nl_msg *msg, struct ucred *creds);

static inline void
_nm_auto_nl_msg_cleanup (struct nl_msg **ptr)
{
	nlmsg_free (*ptr);
}
#define nm_auto_nlmsg nm_auto (_nm_auto_nl_msg_cleanup)

static inline void *
nlmsg_data (const struct nlmsghdr *nlh)
{
	return (unsigned char *) nlh + NLMSG_HDRLEN;
}

static inline void *
nlmsg_tail (const struct nlmsghdr *nlh)
{
	return (unsigned char *) nlh + NLMSG_ALIGN (nlh->nlmsg_len);
}

struct nlmsghdr *nlmsg_hdr (struct nl_msg *n);

static inline int
nlmsg_valid_hdr (const struct nlmsghdr *nlh, int hdrlen)
{
	if (nlh->nlmsg_len < nlmsg_size (hdrlen))
		return 0;

	return 1;
}

static inline int
nlmsg_datalen (const struct nlmsghdr *nlh)
{
	return nlh->nlmsg_len - NLMSG_HDRLEN;
}

static inline int
nlmsg_attrlen (const struct nlmsghdr *nlh, int hdrlen)
{
	return NM_MAX ((int) (nlmsg_datalen (nlh) - NLMSG_ALIGN (hdrlen)), 0);
}

static inline struct nlattr *
nlmsg_attrdata (const struct nlmsghdr *nlh, int hdrlen)
{
	unsigned char *data = nlmsg_data (nlh);
	return (struct nlattr *) (data + NLMSG_ALIGN (hdrlen));
}

static inline struct nlattr *
nlmsg_find_attr (struct nlmsghdr *nlh, int hdrlen, int attrtype)
{
	return nla_find (nlmsg_attrdata (nlh, hdrlen),
	                 nlmsg_attrlen (nlh, hdrlen),
	                 attrtype);
}

int nlmsg_parse (struct nlmsghdr *nlh,
                 int hdrlen,
                 struct nlattr *tb[],
                 int maxtype,
                 const struct nla_policy *policy);

#define nlmsg_parse_arr(nlh, hdrlen, tb, policy) \
	({ \
		_nl_static_assert_tb ((tb), (policy)); \
		G_STATIC_ASSERT_EXPR ((hdrlen) >= 0); \
		\
		nlmsg_parse ((nlh), (hdrlen), (tb), G_N_ELEMENTS (tb) - 1, (policy)); \
	})

struct nlmsghdr *nlmsg_put (struct nl_msg *n, uint32_t pid, uint32_t seq,
                            int type, int payload, int flags);

/*****************************************************************************/

#define NL_AUTO_PORT 0
#define NL_AUTO_SEQ  0

struct nl_sock;

struct nl_sock *nl_socket_alloc (void);

void nl_socket_free (struct nl_sock *sk);

int nl_socket_get_fd (const struct nl_sock *sk);

struct sockaddr_nl *nlmsg_get_dst (struct nl_msg *msg);

size_t nl_socket_get_msg_buf_size (struct nl_sock *sk);
int nl_socket_set_msg_buf_size (struct nl_sock *sk, size_t bufsize);

int nl_socket_set_buffer_size (struct nl_sock *sk, int rxbuf, int txbuf);

int nl_socket_set_passcred (struct nl_sock *sk, int state);

int nl_socket_set_nonblocking (const struct nl_sock *sk);

void nl_socket_disable_msg_peek (struct nl_sock *sk);

uint32_t nl_socket_get_local_port (const struct nl_sock *sk);

int nl_socket_add_memberships (struct nl_sock *sk, int group, ...);

int nl_connect (struct nl_sock *sk, int protocol);

int nl_recv (struct nl_sock *sk,
             struct sockaddr_nl *nla,
             unsigned char **buf,
             struct ucred *out_creds,
             gboolean *out_creds_has);

int nl_send (struct nl_sock *sk, struct nl_msg *msg);

int nl_send_auto (struct nl_sock *sk, struct nl_msg *msg);

/*****************************************************************************/

enum nl_cb_action {
	/* Proceed with wathever would come next */
	NL_OK,
	/* Skip this message */
	NL_SKIP,
	/* Stop parsing altogether and discard remaining messages */
	NL_STOP,
};

typedef int (*nl_recvmsg_msg_cb_t) (struct nl_msg *msg, void *arg);

typedef int (*nl_recvmsg_err_cb_t) (struct sockaddr_nl *nla,
                                    struct nlmsgerr *nlerr, void *arg);

struct nl_cb {
	nl_recvmsg_msg_cb_t     valid_cb;
	void *                  valid_arg;

	nl_recvmsg_msg_cb_t     finish_cb;
	void *                  finish_arg;

	nl_recvmsg_msg_cb_t     ack_cb;
	void *                  ack_arg;

	nl_recvmsg_err_cb_t     err_cb;
	void *                  err_arg;
};

int nl_sendmsg (struct nl_sock *sk, struct nl_msg *msg, struct msghdr *hdr);

int nl_send_iovec (struct nl_sock *sk, struct nl_msg *msg, struct iovec *iov, unsigned iovlen);

void nl_complete_msg (struct nl_sock *sk, struct nl_msg *msg);

int nl_recvmsgs (struct nl_sock *sk, const struct nl_cb *cb);

int nl_wait_for_ack (struct nl_sock *sk,
                     const struct nl_cb *cb);

int nl_socket_set_ext_ack (struct nl_sock *sk, gboolean enable);

/*****************************************************************************/

void *genlmsg_put (struct nl_msg *msg, uint32_t port, uint32_t seq, int family,
                   int hdrlen, int flags, uint8_t cmd, uint8_t version);
void *genlmsg_data (const struct genlmsghdr *gnlh);
void *genlmsg_user_hdr (const struct genlmsghdr *gnlh);
struct genlmsghdr *genlmsg_hdr (struct nlmsghdr *nlh);
void *genlmsg_user_data (const struct genlmsghdr *gnlh, const int hdrlen);
struct nlattr *genlmsg_attrdata (const struct genlmsghdr *gnlh, int hdrlen);
int genlmsg_len (const struct genlmsghdr *gnlh);
int genlmsg_attrlen (const struct genlmsghdr *gnlh, int hdrlen);
int genlmsg_valid_hdr (struct nlmsghdr *nlh, int hdrlen);

int genlmsg_parse (struct nlmsghdr *nlh,
                   int hdrlen,
                   struct nlattr *tb[],
                   int maxtype,
                   const struct nla_policy *policy);

#define genlmsg_parse_arr(nlh, hdrlen, tb, policy) \
	({ \
		_nl_static_assert_tb ((tb), (policy)); \
		G_STATIC_ASSERT_EXPR ((hdrlen) >= 0); \
		\
		genlmsg_parse ((nlh), (hdrlen), (tb), G_N_ELEMENTS (tb) - 1, (policy)); \
	})

int genl_ctrl_resolve (struct nl_sock *sk, const char *name);

/*****************************************************************************/

#endif /* __NM_NETLINK_H__ */
