/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#ifndef __NM_NETLINK_H__
#define __NM_NETLINK_H__

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>

#include "libnm-std-aux/unaligned.h"

/*****************************************************************************/

#define NLMSGERR_ATTR_UNUSED 0
#define NLMSGERR_ATTR_MSG    1
#define NLMSGERR_ATTR_OFFS   2
#define NLMSGERR_ATTR_COOKIE 3
#define NLMSGERR_ATTR_MAX    3

#ifndef NLM_F_ACK_TLVS
#define NLM_F_ACK_TLVS 0x200
#endif

/*****************************************************************************/

/* Basic attribute data types */
enum {
    NLA_UNSPEC, /* Unspecified type, binary data chunk */
    NLA_U8,     /* 8 bit integer */
    NLA_U16,    /* 16 bit integer */
    NLA_S32,    /* 32 bit integer */
    NLA_U32,    /* 32 bit integer */
    NLA_U64,    /* 64 bit integer */
    NLA_STRING, /* NUL terminated character string */
    NLA_FLAG,   /* Flag */
    NLA_NESTED, /* Nested attributes */
    __NLA_TYPE_MAX,
};

#define NLA_TYPE_MAX (__NLA_TYPE_MAX - 1)

struct nl_msg;

/* This is similar to "struct nl_msg", in that it contains a
 * netlink message including additional information like the
 * src, creds, protocol.
 *
 * The difference is that "struct nl_msg" is an opaque type and
 * contains a copy of the message (requiring two heap allocations).
 * "struct nl_msg_lite" can be on the stack and it can directly
 * point to the receive buffer, without need to copy the message.
 * That can be useful, if you don't need to clone the message and
 * just need to pass it "down the stack" for somebody to parse
 * the message. */
struct nl_msg_lite {
    int                       nm_protocol;
    const struct sockaddr_nl *nm_src;
    const struct sockaddr_nl *nm_dst;
    const struct ucred       *nm_creds;
    const struct nlmsghdr    *nm_nlh;
    uint32_t                  nm_size;
};

/*****************************************************************************/

const char *nl_nlmsgtype2str(int type, char *buf, size_t size);

const char *nl_nlmsg_flags2str(int flags, char *buf, size_t len);

const char *nl_nlmsghdr_to_str(int                    netlink_protocol,
                               guint32                pktinfo_group,
                               const struct nlmsghdr *hdr,
                               char                  *buf,
                               gsize                  len);

/*****************************************************************************/

struct nla_policy {
    /* Type of attribute or NLA_UNSPEC */
    uint8_t type;

    /* Minimal length of payload required */
    uint8_t minlen;

    /* Maximal length of payload allowed */
    uint16_t maxlen;
};

/*****************************************************************************/

/* static asserts that @tb and @policy are suitable arguments to nla_parse(). */
#if _NM_CC_SUPPORT_GENERIC
#define _nl_static_assert_tb(tb, policy)                                                 \
    G_STMT_START                                                                         \
    {                                                                                    \
        G_STATIC_ASSERT_EXPR(G_N_ELEMENTS(tb) > 0);                                      \
                                                                                         \
        /* We allow @policy to be either a C array or NULL. The sizeof()
         * must either match the expected array size or we check that
         * "policy" has typeof(NULL). This isn't a perfect compile time check,
         * but good enough. */                 \
        G_STATIC_ASSERT_EXPR(_Generic((policy),                                          \
            typeof(NULL): 1,                                                             \
            default: (sizeof(policy) == G_N_ELEMENTS(tb) * sizeof(struct nla_policy)))); \
    }                                                                                    \
    G_STMT_END
#else
#define _nl_static_assert_tb(tb, policy) G_STATIC_ASSERT_EXPR(G_N_ELEMENTS(tb) > 0)
#endif

/*****************************************************************************/

static inline int
nla_attr_size(int payload)
{
    nm_assert(payload >= 0);

    return NLA_HDRLEN + payload;
}

static inline int
nla_total_size(int payload)
{
    return NLA_ALIGN(nla_attr_size(payload));
}

static inline int
nla_padlen(int payload)
{
    return nla_total_size(payload) - nla_attr_size(payload);
}

struct nlattr *nla_reserve(struct nl_msg *msg, int attrtype, int attrlen);

static inline uint16_t
nla_len(const struct nlattr *nla)
{
    nm_assert(nla);
    nm_assert(nla->nla_len >= NLA_HDRLEN);

    return nla->nla_len - ((uint16_t) NLA_HDRLEN);
}

static inline int
nla_type(const struct nlattr *nla)
{
    return nla->nla_type & NLA_TYPE_MASK;
}

static inline void *
nla_data(const struct nlattr *nla)
{
    return &(((char *) nla)[NLA_HDRLEN]);
}

#define nla_data_as(type, nla)                                          \
    ({                                                                  \
        const struct nlattr *_nla = (nla);                              \
                                                                        \
        nm_assert(nla_len(_nla) >= sizeof(type));                       \
                                                                        \
        /* note that casting the pointer is undefined behavior in C, if
         * the data has wrong alignment. Netlink data is aligned to 4 bytes,
         * that means, if the alignment is larger than 4, this is invalid. */ \
        G_STATIC_ASSERT_EXPR(_nm_alignof(type) <= NLA_ALIGNTO);         \
                                                                        \
        (type *) nla_data(_nla);                                        \
    })

static inline uint8_t
nla_get_u8(const struct nlattr *nla)
{
    nm_assert(nla_len(nla) >= sizeof(uint8_t));

    return *((const uint8_t *) nla_data(nla));
}

static inline int8_t
nla_get_s8(const struct nlattr *nla)
{
    nm_assert(nla_len(nla) >= sizeof(int8_t));

    return *((const int8_t *) nla_data(nla));
}

static inline uint8_t
nla_get_u8_cond(/*const*/ struct nlattr *const *tb, int attr, uint8_t default_val)
{
    nm_assert(tb);
    nm_assert(attr >= 0);

    return tb[attr] ? nla_get_u8(tb[attr]) : default_val;
}

static inline uint16_t
nla_get_u16(const struct nlattr *nla)
{
    nm_assert(nla_len(nla) >= sizeof(uint16_t));

    return *((const uint16_t *) nla_data(nla));
}

static inline uint32_t
nla_get_u32(const struct nlattr *nla)
{
    nm_assert(nla_len(nla) >= sizeof(uint32_t));

    return *((const uint32_t *) nla_data(nla));
}

static inline int32_t
nla_get_s32(const struct nlattr *nla)
{
    nm_assert(nla_len(nla) >= sizeof(int32_t));

    return *((const int32_t *) nla_data(nla));
}

static inline uint64_t
nla_get_u64(const struct nlattr *nla)
{
    nm_assert(nla_len(nla) >= sizeof(uint64_t));

    return unaligned_read_ne64(nla_data(nla));
}

static inline uint64_t
nla_get_be64(const struct nlattr *nla)
{
    nm_assert(nla_len(nla) >= sizeof(uint64_t));

    return unaligned_read_be64(nla_data(nla));
}

static inline char *
nla_get_string(const struct nlattr *nla)
{
    char *s;

    /* nla_get_string() requires that nla contains a NUL terminated string.
     * It cannot return NULL. Only use it with attributes that validate as NLA_STRING. */

    nm_assert(nla_len(nla) > 0);

    s = nla_data(nla);

    nm_assert(memchr(s, 0, nla_len(nla)));

    return s;
}

size_t
_nla_strlcpy_full(char *dst, const struct nlattr *nla, size_t dstsize, gboolean wipe_remainder);

static inline size_t
nla_strlcpy(char *dst, const struct nlattr *nla, size_t dstsize)
{
    return _nla_strlcpy_full(dst, nla, dstsize, FALSE);
}

static inline size_t
nla_strlcpy_wipe(char *dst, const struct nlattr *nla, size_t dstsize)
{
    /* Behaves exactly like nla_strlcpy(), but (similar to strncpy()) it fills the
     * remaining @dstsize bytes with NUL. */
    return _nla_strlcpy_full(dst, nla, dstsize, TRUE);
}

size_t nla_memcpy(void *dst, const struct nlattr *nla, size_t dstsize);

#define nla_memcpy_checked_size(dst, nla, dstsize)                       \
    G_STMT_START                                                         \
    {                                                                    \
        void *const                _dst     = (dst);                     \
        const struct nlattr *const _nla     = (nla);                     \
        const size_t               _dstsize = (dstsize);                 \
        size_t                     _srcsize;                             \
                                                                         \
        /* assert that, if @nla is given, that it has the exact expected
         * size. This implies that the caller previously verified the length
         * of the attribute (via minlen/maxlen at nla_parse()). */ \
                                                                         \
        if (_nla) {                                                      \
            _srcsize = nla_memcpy(_dst, _nla, _dstsize);                 \
            nm_assert(_srcsize == _dstsize);                             \
        }                                                                \
    }                                                                    \
    G_STMT_END

static inline struct in6_addr
nla_get_in6_addr(const struct nlattr *nla)
{
    struct in6_addr in6;

    nm_assert(nla_len(nla) >= sizeof(struct in6_addr));

    nla_memcpy(&in6, nla, sizeof(in6));
    return in6;
}

int nla_put(struct nl_msg *msg, int attrtype, int datalen, const void *data);

static inline int
nla_put_string(struct nl_msg *msg, int attrtype, const char *str)
{
    nm_assert(str);

    return nla_put(msg, attrtype, strlen(str) + 1, str);
}

static inline int
nla_put_uint8(struct nl_msg *msg, int attrtype, uint8_t val)
{
    return nla_put(msg, attrtype, sizeof(val), &val);
}

static inline int
nla_put_uint16(struct nl_msg *msg, int attrtype, uint16_t val)
{
    return nla_put(msg, attrtype, sizeof(val), &val);
}

static inline int
nla_put_uint32(struct nl_msg *msg, int attrtype, uint32_t val)
{
    return nla_put(msg, attrtype, sizeof(val), &val);
}

#define NLA_PUT(msg, attrtype, attrlen, data)                  \
    G_STMT_START                                               \
    {                                                          \
        if (nla_put((msg), (attrtype), (attrlen), (data)) < 0) \
            goto nla_put_failure;                              \
    }                                                          \
    G_STMT_END

#define NLA_PUT_TYPE(msg, type, attrtype, value)                 \
    G_STMT_START                                                 \
    {                                                            \
        type const _nla_tmp = value;                             \
                                                                 \
        NLA_PUT((msg), (attrtype), sizeof(_nla_tmp), &_nla_tmp); \
    }                                                            \
    G_STMT_END

#define NLA_PUT_U8(msg, attrtype, value) NLA_PUT_TYPE(msg, uint8_t, attrtype, value)

#define NLA_PUT_S8(msg, attrtype, value) NLA_PUT_TYPE(msg, int8_t, attrtype, value)

#define NLA_PUT_U16(msg, attrtype, value) NLA_PUT_TYPE(msg, uint16_t, attrtype, value)

#define NLA_PUT_U32(msg, attrtype, value) NLA_PUT_TYPE(msg, uint32_t, attrtype, value)

#define NLA_PUT_S32(msg, attrtype, value) NLA_PUT_TYPE(msg, int32_t, attrtype, value)

#define NLA_PUT_U64(msg, attrtype, value) NLA_PUT_TYPE(msg, uint64_t, attrtype, value)

#define NLA_PUT_STRING(msg, attrtype, value) NLA_PUT(msg, attrtype, (int) strlen(value) + 1, value)

#define NLA_PUT_FLAG(msg, attrtype) NLA_PUT(msg, attrtype, 0, NULL)

struct nlattr *nla_find(const struct nlattr *head, int len, int attrtype);

static inline int
nla_ok(const struct nlattr *nla, int remaining)
{
    return remaining >= (int) sizeof(*nla) && nla->nla_len >= sizeof(*nla)
           && nla->nla_len <= remaining;
}

static inline struct nlattr *
nla_next(const struct nlattr *nla, int *remaining)
{
    int totlen = NLA_ALIGN(nla->nla_len);

    *remaining -= totlen;
    return NM_CAST_ALIGN(struct nlattr, (((char *) nla) + totlen));
}

#define nla_for_each_attr(pos, head, len, rem) \
    for (pos = head, rem = len; nla_ok(pos, rem); pos = nla_next(pos, &(rem)))

#define nla_for_each_nested(pos, nla, rem)                                            \
    for (pos = (struct nlattr *) nla_data(nla), rem = nla_len(nla); nla_ok(pos, rem); \
         pos = nla_next(pos, &(rem)))

void           nla_nest_cancel(struct nl_msg *msg, const struct nlattr *attr);
struct nlattr *nla_nest_start(struct nl_msg *msg, int attrtype);
int            nla_nest_end(struct nl_msg *msg, struct nlattr *start);

#define NLA_NEST_END(msg, nest_start)              \
    G_STMT_START                                   \
    {                                              \
        if (nla_nest_end((msg), (nest_start)) < 0) \
            goto nla_put_failure;                  \
    }                                              \
    G_STMT_END

int nla_parse(struct nlattr           *tb[],
              int                      maxtype,
              struct nlattr           *head,
              int                      len,
              const struct nla_policy *policy);

#define nla_parse_arr(tb, head, len, policy)                            \
    ({                                                                  \
        _nl_static_assert_tb((tb), (policy));                           \
                                                                        \
        nla_parse((tb), G_N_ELEMENTS(tb) - 1, (head), (len), (policy)); \
    })

static inline int
nla_parse_nested(struct nlattr           *tb[],
                 int                      maxtype,
                 struct nlattr           *nla,
                 const struct nla_policy *policy)
{
    return nla_parse(tb, maxtype, nla_data(nla), nla_len(nla), policy);
}

#define nla_parse_nested_arr(tb, nla, policy)                          \
    ({                                                                 \
        _nl_static_assert_tb((tb), (policy));                          \
                                                                       \
        nla_parse_nested((tb), G_N_ELEMENTS(tb) - 1, (nla), (policy)); \
    })

/*****************************************************************************/

struct nl_msg *nlmsg_alloc(size_t len);

struct nl_msg *nlmsg_alloc_convert(struct nlmsghdr *hdr);

struct nl_msg *nlmsg_alloc_new(size_t size, uint16_t nlmsgtype, uint16_t flags);

void *nlmsg_reserve(struct nl_msg *n, uint32_t len, uint32_t pad);

int nlmsg_append(struct nl_msg *n, const void *data, uint32_t len, uint32_t pad);

#define nlmsg_append_struct(n, data) (nlmsg_append((n), (data), sizeof(*(data)), NLMSG_ALIGNTO))

void nlmsg_free(struct nl_msg *msg);

static inline int
nlmsg_size(int payload)
{
    nm_assert(payload >= 0 && payload < G_MAXINT - NLMSG_HDRLEN - 4);
    return NLMSG_HDRLEN + payload;
}

static inline int
nlmsg_total_size(int payload)
{
    return NLMSG_ALIGN(nlmsg_size(payload));
}

static inline int
nlmsg_ok(const struct nlmsghdr *nlh, int remaining)
{
    return (remaining >= (int) sizeof(struct nlmsghdr) && nlh->nlmsg_len >= sizeof(struct nlmsghdr)
            && nlh->nlmsg_len <= remaining);
}

static inline struct nlmsghdr *
nlmsg_next(struct nlmsghdr *nlh, int *remaining)
{
    int totlen = NLMSG_ALIGN(nlh->nlmsg_len);

    *remaining -= totlen;

    return NM_CAST_ALIGN(struct nlmsghdr, (((char *) nlh) + totlen));
}

int  nlmsg_get_proto(struct nl_msg *msg);
void nlmsg_set_proto(struct nl_msg *msg, int protocol);

void nlmsg_set_src(struct nl_msg *msg, struct sockaddr_nl *addr);

struct ucred *nlmsg_get_creds(struct nl_msg *msg);
void          nlmsg_set_creds(struct nl_msg *msg, struct ucred *creds);

NM_AUTO_DEFINE_FCN0(struct nl_msg *, _nm_auto_nl_msg_cleanup, nlmsg_free);
#define nm_auto_nlmsg nm_auto(_nm_auto_nl_msg_cleanup)

static inline const struct nlmsghdr *
nlmsg_undata(const void *data)
{
    /* from the data, get back the header. It's the inverse of nlmsg_data(). */
    return (void *) (((unsigned char *) data) - NLMSG_HDRLEN);
}

static inline void *
nlmsg_data(const struct nlmsghdr *nlh)
{
    return ((unsigned char *) nlh) + NLMSG_HDRLEN;
}

static inline void *
nlmsg_tail(const struct nlmsghdr *nlh)
{
    return ((unsigned char *) nlh) + NLMSG_ALIGN(nlh->nlmsg_len);
}

struct nlmsghdr *nlmsg_hdr(const struct nl_msg *n);

static inline int
nlmsg_valid_hdr(const struct nlmsghdr *nlh, int hdrlen)
{
    if (nlh->nlmsg_len < nlmsg_size(hdrlen))
        return 0;

    return 1;
}

static inline int
nlmsg_datalen(const struct nlmsghdr *nlh)
{
    return nlh->nlmsg_len - NLMSG_HDRLEN;
}

static inline int
nlmsg_attrlen(const struct nlmsghdr *nlh, int hdrlen)
{
    return NM_MAX((int) (nlmsg_datalen(nlh) - NLMSG_ALIGN(hdrlen)), 0);
}

static inline struct nlattr *
nlmsg_attrdata(const struct nlmsghdr *nlh, int hdrlen)
{
    char *data = nlmsg_data(nlh);

    return NM_CAST_ALIGN(struct nlattr, (data + NLMSG_ALIGN(hdrlen)));
}

static inline struct nlattr *
nlmsg_find_attr(struct nlmsghdr *nlh, int hdrlen, int attrtype)
{
    return nla_find(nlmsg_attrdata(nlh, hdrlen), nlmsg_attrlen(nlh, hdrlen), attrtype);
}

int nlmsg_parse_error(const struct nlmsghdr *nlh, const char **out_extack_msg);

int nlmsg_parse(const struct nlmsghdr   *nlh,
                int                      hdrlen,
                struct nlattr           *tb[],
                int                      maxtype,
                const struct nla_policy *policy);

#define nlmsg_parse_arr(nlh, hdrlen, tb, policy)                            \
    ({                                                                      \
        _nl_static_assert_tb((tb), (policy));                               \
        G_STATIC_ASSERT_EXPR((hdrlen) >= 0);                                \
                                                                            \
        nlmsg_parse((nlh), (hdrlen), (tb), G_N_ELEMENTS(tb) - 1, (policy)); \
    })

struct nlmsghdr *nlmsg_put(struct nl_msg *n,
                           uint32_t       pid,
                           uint32_t       seq,
                           uint16_t       type,
                           uint32_t       payload,
                           uint16_t       flags);

/*****************************************************************************/

typedef enum {
    NL_SOCKET_FLAGS_NONE             = 0,
    NL_SOCKET_FLAGS_NONBLOCK         = 0x1,
    NL_SOCKET_FLAGS_PASSCRED         = 0x2,
    NL_SOCKET_FLAGS_PKTINFO          = 0x4,
    NL_SOCKET_FLAGS_DISABLE_MSG_PEEK = 0x8,

    _NL_SOCKET_FLAGS_ALL = (NL_SOCKET_FLAGS_DISABLE_MSG_PEEK << 1) - 1,
} NLSocketFlags;

#define NL_AUTO_PORT 0
#define NL_AUTO_SEQ  0

struct nl_sock;

int nl_socket_new(struct nl_sock **out_sk,
                  int              protocol,
                  NLSocketFlags    flags,
                  int              bufsize_rx,
                  int              bufsize_tx);

void nl_socket_free(struct nl_sock *sk);

NM_AUTO_DEFINE_FCN0(struct nl_sock *, _nm_auto_nlsock, nl_socket_free);
#define nm_auto_nlsock nm_auto(_nm_auto_nlsock)

int nl_socket_get_fd(const struct nl_sock *sk);

struct sockaddr_nl *nlmsg_get_dst(struct nl_msg *msg);

size_t nl_socket_get_msg_buf_size(struct nl_sock *sk);
int    nl_socket_set_msg_buf_size(struct nl_sock *sk, size_t bufsize);

int nl_socket_set_buffer_size(struct nl_sock *sk, int rxbuf, int txbuf);

int nl_socket_set_passcred(struct nl_sock *sk, int state);

int nl_socket_set_pktinfo(struct nl_sock *sk, int state);

uint32_t nl_socket_get_local_port(const struct nl_sock *sk);

int nl_socket_add_memberships(struct nl_sock *sk, int group, ...);

int nl_connect(struct nl_sock *sk, int protocol);

int nl_recv(struct nl_sock     *sk,
            unsigned char      *buf0,
            size_t              buf0_len,
            struct sockaddr_nl *nla,
            unsigned char     **buf,
            struct ucred       *out_creds,
            gboolean           *out_creds_has,
            uint32_t           *out_pktinfo_group,
            gboolean           *out_pktinfo_has);

int nl_send(struct nl_sock *sk, struct nl_msg *msg);

int nl_send_auto(struct nl_sock *sk, struct nl_msg *msg);

/*****************************************************************************/

enum nl_cb_action {
    /* Proceed with wathever would come next */
    NL_OK,
    /* Skip this message */
    NL_SKIP,
    /* Stop parsing altogether and discard remaining messages */
    NL_STOP,
};

typedef int (*nl_recvmsg_msg_cb_t)(const struct nl_msg *msg, void *arg);

typedef int (*nl_recvmsg_err_cb_t)(const struct sockaddr_nl *nla,
                                   const struct nlmsgerr    *nlerr,
                                   void                     *arg);

struct nl_cb {
    nl_recvmsg_msg_cb_t valid_cb;
    void               *valid_arg;

    nl_recvmsg_msg_cb_t finish_cb;
    void               *finish_arg;

    nl_recvmsg_msg_cb_t ack_cb;
    void               *ack_arg;

    nl_recvmsg_err_cb_t err_cb;
    void               *err_arg;
};

int nl_sendmsg(struct nl_sock *sk, struct nl_msg *msg, struct msghdr *hdr);

int nl_send_iovec(struct nl_sock *sk, struct nl_msg *msg, struct iovec *iov, unsigned iovlen);

void nl_complete_msg(struct nl_sock *sk, struct nl_msg *msg);

int nl_recvmsgs(struct nl_sock *sk, const struct nl_cb *cb);

int nl_wait_for_ack(struct nl_sock *sk, const struct nl_cb *cb);

/*****************************************************************************/

extern const struct nla_policy genl_ctrl_policy[8];

void                    *genlmsg_put(struct nl_msg *msg,
                                     uint32_t       port,
                                     uint32_t       seq,
                                     uint16_t       family,
                                     uint32_t       hdrlen,
                                     uint16_t       flags,
                                     uint8_t        cmd,
                                     uint8_t        version);
void                    *genlmsg_data(const struct genlmsghdr *gnlh);
void                    *genlmsg_user_hdr(const struct genlmsghdr *gnlh);
const struct genlmsghdr *genlmsg_hdr(const struct nlmsghdr *nlh);
void                    *genlmsg_user_data(const struct genlmsghdr *gnlh, const int hdrlen);
struct nlattr           *genlmsg_attrdata(const struct genlmsghdr *gnlh, int hdrlen);
int                      genlmsg_len(const struct genlmsghdr *gnlh);
int                      genlmsg_attrlen(const struct genlmsghdr *gnlh, int hdrlen);
int                      genlmsg_valid_hdr(const struct nlmsghdr *nlh, int hdrlen);

int genlmsg_parse(const struct nlmsghdr   *nlh,
                  int                      hdrlen,
                  struct nlattr           *tb[],
                  int                      maxtype,
                  const struct nla_policy *policy);

#define genlmsg_parse_arr(nlh, hdrlen, tb, policy)                            \
    ({                                                                        \
        _nl_static_assert_tb((tb), (policy));                                 \
        G_STATIC_ASSERT_EXPR((hdrlen) >= 0);                                  \
                                                                              \
        genlmsg_parse((nlh), (hdrlen), (tb), G_N_ELEMENTS(tb) - 1, (policy)); \
    })

int genl_ctrl_resolve(struct nl_sock *sk, const char *name);

/*****************************************************************************/

#endif /* __NM_NETLINK_H__ */
