/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-netlink.h"

#include <unistd.h>
#include <fcntl.h>

/*****************************************************************************/

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

/*****************************************************************************/

#define nm_assert_sk(sk)                  \
    G_STMT_START                          \
    {                                     \
        const struct nl_sock *_sk = (sk); \
                                          \
        nm_assert(_sk);                   \
        nm_assert(_sk->s_fd >= 0);        \
    }                                     \
    G_STMT_END

#ifndef NETLINK_EXT_ACK
#define NETLINK_EXT_ACK 11
#endif

struct nl_msg {
    int                nm_protocol;
    struct sockaddr_nl nm_src;
    struct sockaddr_nl nm_dst;
    struct ucred       nm_creds;
    struct nlmsghdr   *nm_nlh;
    uint32_t           nm_size;
    bool               nm_creds_has : 1;
};

struct nl_sock {
    struct sockaddr_nl s_local;
    struct sockaddr_nl s_peer;
    size_t             s_bufsize;
    int                s_fd;
    int                s_proto;
    unsigned int       s_seq_next;
    unsigned int       s_seq_expect;
    bool               s_msg_peek : 1;
    bool               s_auto_ack : 1;
};

/*****************************************************************************/

NM_UTILS_ENUM2STR_DEFINE(nl_nlmsgtype2str,
                         int,
                         NM_UTILS_ENUM2STR(NLMSG_NOOP, "NOOP"),
                         NM_UTILS_ENUM2STR(NLMSG_ERROR, "ERROR"),
                         NM_UTILS_ENUM2STR(NLMSG_DONE, "DONE"),
                         NM_UTILS_ENUM2STR(NLMSG_OVERRUN, "OVERRUN"), );

NM_UTILS_FLAGS2STR_DEFINE(nl_nlmsg_flags2str,
                          int,
                          NM_UTILS_FLAGS2STR(NLM_F_REQUEST, "REQUEST"),
                          NM_UTILS_FLAGS2STR(NLM_F_MULTI, "MULTI"),
                          NM_UTILS_FLAGS2STR(NLM_F_ACK, "ACK"),
                          NM_UTILS_FLAGS2STR(NLM_F_ECHO, "ECHO"),
                          NM_UTILS_FLAGS2STR(NLM_F_ROOT, "ROOT"),
                          NM_UTILS_FLAGS2STR(NLM_F_MATCH, "MATCH"),
                          NM_UTILS_FLAGS2STR(NLM_F_ATOMIC, "ATOMIC"),
                          NM_UTILS_FLAGS2STR(NLM_F_REPLACE, "REPLACE"),
                          NM_UTILS_FLAGS2STR(NLM_F_EXCL, "EXCL"),
                          NM_UTILS_FLAGS2STR(NLM_F_CREATE, "CREATE"),
                          NM_UTILS_FLAGS2STR(NLM_F_APPEND, "APPEND"), );

static NM_UTILS_LOOKUP_STR_DEFINE(_rtnl_type_to_str,
                                  guint16,
                                  NM_UTILS_LOOKUP_DEFAULT(NULL),
                                  NM_UTILS_LOOKUP_STR_ITEM(RTM_GETLINK, "RTM_GETLINK"),
                                  NM_UTILS_LOOKUP_STR_ITEM(RTM_NEWLINK, "RTM_NEWLINK"),
                                  NM_UTILS_LOOKUP_STR_ITEM(RTM_DELLINK, "RTM_DELLINK"),
                                  NM_UTILS_LOOKUP_STR_ITEM(RTM_SETLINK, "RTM_SETLINK"),
                                  NM_UTILS_LOOKUP_STR_ITEM(RTM_GETADDR, "RTM_GETADDR"),
                                  NM_UTILS_LOOKUP_STR_ITEM(RTM_NEWADDR, "RTM_NEWADDR"),
                                  NM_UTILS_LOOKUP_STR_ITEM(RTM_DELADDR, "RTM_DELADDR"),
                                  NM_UTILS_LOOKUP_STR_ITEM(RTM_GETROUTE, "RTM_GETROUTE"),
                                  NM_UTILS_LOOKUP_STR_ITEM(RTM_NEWROUTE, "RTM_NEWROUTE"),
                                  NM_UTILS_LOOKUP_STR_ITEM(RTM_DELROUTE, "RTM_DELROUTE"),
                                  NM_UTILS_LOOKUP_STR_ITEM(RTM_GETRULE, "RTM_GETRULE"),
                                  NM_UTILS_LOOKUP_STR_ITEM(RTM_NEWRULE, "RTM_NEWRULE"),
                                  NM_UTILS_LOOKUP_STR_ITEM(RTM_DELRULE, "RTM_DELRULE"),
                                  NM_UTILS_LOOKUP_STR_ITEM(RTM_GETQDISC, "RTM_GETQDISC"),
                                  NM_UTILS_LOOKUP_STR_ITEM(RTM_NEWQDISC, "RTM_NEWQDISC"),
                                  NM_UTILS_LOOKUP_STR_ITEM(RTM_DELQDISC, "RTM_DELQDISC"),
                                  NM_UTILS_LOOKUP_STR_ITEM(RTM_GETTFILTER, "RTM_GETTFILTER"),
                                  NM_UTILS_LOOKUP_STR_ITEM(RTM_NEWTFILTER, "RTM_NEWTFILTER"),
                                  NM_UTILS_LOOKUP_STR_ITEM(RTM_DELTFILTER, "RTM_DELTFILTER"),
                                  NM_UTILS_LOOKUP_STR_ITEM(NLMSG_NOOP, "NLMSG_NOOP"),
                                  NM_UTILS_LOOKUP_STR_ITEM(NLMSG_ERROR, "NLMSG_ERROR"),
                                  NM_UTILS_LOOKUP_STR_ITEM(NLMSG_DONE, "NLMSG_DONE"),
                                  NM_UTILS_LOOKUP_STR_ITEM(NLMSG_OVERRUN, "NLMSG_OVERRUN"), );

static NM_UTILS_LOOKUP_STR_DEFINE(
    _genl_ctrl_cmd_to_str,
    guint8,
    NM_UTILS_LOOKUP_DEFAULT(NULL),
    NM_UTILS_LOOKUP_STR_ITEM(CTRL_CMD_UNSPEC, "CTRL_CMD_UNSPEC"),
    NM_UTILS_LOOKUP_STR_ITEM(CTRL_CMD_NEWFAMILY, "CTRL_CMD_NEWFAMILY"),
    NM_UTILS_LOOKUP_STR_ITEM(CTRL_CMD_DELFAMILY, "CTRL_CMD_DELFAMILY"),
    NM_UTILS_LOOKUP_STR_ITEM(CTRL_CMD_GETFAMILY, "CTRL_CMD_GETFAMILY"),
    NM_UTILS_LOOKUP_STR_ITEM(CTRL_CMD_NEWOPS, "CTRL_CMD_NEWOPS"),
    NM_UTILS_LOOKUP_STR_ITEM(CTRL_CMD_DELOPS, "CTRL_CMD_DELOPS"),
    NM_UTILS_LOOKUP_STR_ITEM(CTRL_CMD_GETOPS, "CTRL_CMD_GETOPS"),
    NM_UTILS_LOOKUP_STR_ITEM(CTRL_CMD_NEWMCAST_GRP, "CTRL_CMD_NEWMCAST_GRP"),
    NM_UTILS_LOOKUP_STR_ITEM(CTRL_CMD_DELMCAST_GRP, "CTRL_CMD_DELMCAST_GRP"),
    NM_UTILS_LOOKUP_STR_ITEM(CTRL_CMD_GETMCAST_GRP, "CTRL_CMD_GETMCAST_GRP"),
    /* CTRL_CMD_GETPOLICY was added in Linux 5.7 (released on 31 May, 2020),
     * commit d07dcf9aadd6 ('netlink: add infrastructure to expose policies to userspace') */
    NM_UTILS_LOOKUP_STR_ITEM(10 /* CTRL_CMD_GETPOLICY */, "CTRL_CMD_GETPOLICY"), );

/*****************************************************************************/

const char *
nl_nlmsghdr_to_str(int                    netlink_protocol,
                   guint32                pktinfo_group,
                   const struct nlmsghdr *hdr,
                   char                  *buf,
                   gsize                  len)
{
    const char *b;
    const char *s = NULL;
    guint       flags, flags_before;
    const char *prefix;

    if (!nm_utils_to_string_buffer_init_null(hdr, &buf, &len))
        return buf;

    b = buf;

    switch (netlink_protocol) {
    case NETLINK_ROUTE:
        s = _rtnl_type_to_str(hdr->nlmsg_type);
        if (s)
            nm_strbuf_append_str(&buf, &len, s);
        else
            nm_strbuf_append(&buf, &len, "(%u)", (unsigned) hdr->nlmsg_type);
        break;
    default:
        nm_assert_not_reached();
        /* fall-through */
    case NETLINK_GENERIC:
        if (pktinfo_group == 0)
            nm_strbuf_append(&buf, &len, "group:unicast");
        else
            nm_strbuf_append(&buf, &len, "group:multicast(%u)", (unsigned) pktinfo_group);

        s = NULL;
        if (hdr->nlmsg_type == GENL_ID_CTRL)
            s = "GENL_ID_CTRL";
        if (s)
            nm_strbuf_append(&buf, &len, ", msg-type:%s", s);
        else
            nm_strbuf_append(&buf, &len, ", msg-type:(%u)", (unsigned) hdr->nlmsg_type);

        if (genlmsg_valid_hdr(hdr, 0)) {
            const struct genlmsghdr *ghdr;

            ghdr = nlmsg_data(hdr);
            s    = NULL;
            if (hdr->nlmsg_type == GENL_ID_CTRL)
                s = _genl_ctrl_cmd_to_str(ghdr->cmd);
            if (s)
                nm_strbuf_append(&buf, &len, ", cmd:%s", s);
            else
                nm_strbuf_append(&buf, &len, ", cmd:(%u)", (unsigned) ghdr->cmd);
        }
        break;
    }

    flags = hdr->nlmsg_flags;

    if (!flags) {
        nm_strbuf_append_str(&buf, &len, ", flags 0");
        goto flags_done;
    }

#define _F(f, n)                                             \
    G_STMT_START                                             \
    {                                                        \
        if (NM_FLAGS_ALL(flags, f)) {                        \
            flags &= ~(f);                                   \
            nm_strbuf_append(&buf, &len, "%s%s", prefix, n); \
            if (!flags)                                      \
                goto flags_done;                             \
            prefix = ",";                                    \
        }                                                    \
    }                                                        \
    G_STMT_END

    prefix       = ", flags ";
    flags_before = flags;
    _F(NLM_F_REQUEST, "request");
    _F(NLM_F_MULTI, "multi");
    _F(NLM_F_ACK, "ack");
    _F(NLM_F_ECHO, "echo");
    _F(NLM_F_DUMP_INTR, "dump_intr");
    _F(0x20 /*NLM_F_DUMP_FILTERED*/, "dump_filtered");

    if (flags_before != flags)
        prefix = ";";

    switch (netlink_protocol) {
    case NETLINK_ROUTE:
        switch (hdr->nlmsg_type) {
        case RTM_NEWLINK:
        case RTM_NEWADDR:
        case RTM_NEWROUTE:
        case RTM_NEWQDISC:
        case RTM_NEWTFILTER:
            _F(NLM_F_REPLACE, "replace");
            _F(NLM_F_EXCL, "excl");
            _F(NLM_F_CREATE, "create");
            _F(NLM_F_APPEND, "append");
            break;
        case RTM_GETLINK:
        case RTM_GETADDR:
        case RTM_GETROUTE:
        case RTM_DELQDISC:
        case RTM_DELTFILTER:
            _F(NLM_F_DUMP, "dump");
            _F(NLM_F_ROOT, "root");
            _F(NLM_F_MATCH, "match");
            _F(NLM_F_ATOMIC, "atomic");
            break;
        }
    }

#undef _F

    if (flags_before != flags)
        prefix = ";";
    nm_strbuf_append(&buf, &len, "%s0x%04x", prefix, flags);

flags_done:

    nm_strbuf_append(&buf, &len, ", seq %u", (unsigned) hdr->nlmsg_seq);

    return b;
}

/*****************************************************************************/

struct nlmsghdr *
nlmsg_hdr(const struct nl_msg *n)
{
    return n->nm_nlh;
}

void *
nlmsg_reserve(struct nl_msg *n, uint32_t len, uint32_t pad)
{
    char    *buf = (char *) n->nm_nlh;
    uint32_t tlen;

    nm_assert(n);
    nm_assert(pad == 0 || nm_utils_is_power_of_two(pad));
    nm_assert(n->nm_nlh->nlmsg_len <= n->nm_size);

    if (pad != 0) {
        tlen = (len + (pad - 1u)) & ~(pad - 1u);
        if (tlen < len)
            return NULL;
    } else
        tlen = len;

    if (tlen > n->nm_size - n->nm_nlh->nlmsg_len)
        return NULL;

    buf += n->nm_nlh->nlmsg_len;
    n->nm_nlh->nlmsg_len += tlen;

    if (tlen > len)
        memset(buf + len, 0, tlen - len);

    return buf;
}

/*****************************************************************************/

int
nlmsg_parse_error(const struct nlmsghdr *nlh, const char **out_extack_msg)
{
    const struct nlmsgerr *e;

    nm_assert(nlh);

    NM_SET_OUT(out_extack_msg, NULL);

    if (nlh->nlmsg_type != NLMSG_ERROR)
        return -NME_NL_MSG_INVAL;

    if (nlh->nlmsg_len < nlmsg_size(sizeof(struct nlmsgerr))) {
        /* Truncated error message, the default action
         * is to stop parsing. The user may overrule
         * this action by returning NL_SKIP or
         * NL_PROCEED (dangerous) */
        return -NME_NL_MSG_TRUNC;
    }

    e = nlmsg_data(nlh);

    if (!e->error)
        return 0;

    if (NM_FLAGS_HAS(nlh->nlmsg_flags, NLM_F_ACK_TLVS) && out_extack_msg
        && nlh->nlmsg_len >= sizeof(*e) + e->msg.nlmsg_len) {
        static const struct nla_policy policy[] = {
            [NLMSGERR_ATTR_MSG]  = {.type = NLA_STRING},
            [NLMSGERR_ATTR_OFFS] = {.type = NLA_U32},
        };
        struct nlattr *tb[G_N_ELEMENTS(policy)];
        struct nlattr *tlvs;

        tlvs = NM_CAST_ALIGN(struct nlattr,
                             (((char *) e) + sizeof(*e) + e->msg.nlmsg_len - NLMSG_HDRLEN));
        if (nla_parse_arr(tb, tlvs, nlh->nlmsg_len - sizeof(*e) - e->msg.nlmsg_len, policy) >= 0) {
            if (tb[NLMSGERR_ATTR_MSG])
                *out_extack_msg = nla_get_string(tb[NLMSGERR_ATTR_MSG]);
        }
    }

    return -nm_errno_from_native(e->error);
}

/*****************************************************************************/

struct nlattr *
nla_reserve(struct nl_msg *msg, int attrtype, int attrlen)
{
    struct nlattr *nla;
    int            tlen;

    if (attrlen < 0)
        return NULL;

    tlen = NLMSG_ALIGN(msg->nm_nlh->nlmsg_len) + nla_total_size(attrlen);

    if (tlen > msg->nm_size)
        return NULL;

    nla           = (struct nlattr *) nlmsg_tail(msg->nm_nlh);
    nla->nla_type = attrtype;
    nla->nla_len  = nla_attr_size(attrlen);

    if (attrlen)
        memset((unsigned char *) nla + nla->nla_len, 0, nla_padlen(attrlen));
    msg->nm_nlh->nlmsg_len = tlen;

    return nla;
}

/*****************************************************************************/

/**
 * Allocate a new netlink message.
 *
 * Allocates a new netlink message without any further payload. If @len is zero,
 * the maximum payload size is set to the size of one memory page.
 *
 * @return Newly allocated netlink message or NULL.
 */
struct nl_msg *
nlmsg_alloc(size_t len)
{
    struct nl_msg *nm;

    if (len == 0)
        len = nm_utils_getpagesize();

    if (len < sizeof(struct nlmsghdr))
        len = sizeof(struct nlmsghdr);
    else if (len > UINT32_MAX)
        g_return_val_if_reached(NULL);

    nm  = g_slice_new(struct nl_msg);
    *nm = (struct nl_msg){
        .nm_protocol = -1,
        .nm_size     = len,
        .nm_nlh      = g_malloc0(len),
    };
    nm->nm_nlh->nlmsg_len = nlmsg_total_size(0);
    return nm;
}

struct nl_msg *
nlmsg_alloc_convert(struct nlmsghdr *hdr)
{
    struct nl_msg *nm;

    nm = nlmsg_alloc(NLMSG_ALIGN(hdr->nlmsg_len));
    memcpy(nm->nm_nlh, hdr, hdr->nlmsg_len);
    return nm;
}

struct nl_msg *
nlmsg_alloc_new(size_t size, uint16_t nlmsgtype, uint16_t flags)
{
    struct nl_msg *nm;
    struct nlmsghdr *new;

    nm               = nlmsg_alloc(size);
    new              = nm->nm_nlh;
    new->nlmsg_type  = nlmsgtype;
    new->nlmsg_flags = flags;
    return nm;
}

void
nlmsg_free(struct nl_msg *msg)
{
    if (!msg)
        return;

    g_free(msg->nm_nlh);
    g_slice_free(struct nl_msg, msg);
}

/*****************************************************************************/

int
nlmsg_append(struct nl_msg *n, const void *data, uint32_t len, uint32_t pad)
{
    void *tmp;

    nm_assert(n);
    nm_assert(len == 0 || data);

    tmp = nlmsg_reserve(n, len, pad);
    if (!tmp)
        return -ENOMEM;

    if (len > 0)
        memcpy(tmp, data, len);

    return 0;
}

/*****************************************************************************/

int
nlmsg_parse(const struct nlmsghdr   *nlh,
            int                      hdrlen,
            struct nlattr           *tb[],
            int                      maxtype,
            const struct nla_policy *policy)
{
    if (!nlmsg_valid_hdr(nlh, hdrlen))
        return -NME_NL_MSG_TOOSHORT;

    return nla_parse(tb, maxtype, nlmsg_attrdata(nlh, hdrlen), nlmsg_attrlen(nlh, hdrlen), policy);
}

struct nlmsghdr *
nlmsg_put(struct nl_msg *n,
          uint32_t       pid,
          uint32_t       seq,
          uint16_t       type,
          uint32_t       payload,
          uint16_t       flags)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *) n->nm_nlh;

    nm_assert(nlh->nlmsg_len >= NLMSG_HDRLEN);

    nlh->nlmsg_type  = type;
    nlh->nlmsg_flags = flags;
    nlh->nlmsg_pid   = pid;
    nlh->nlmsg_seq   = seq;

    if (payload > 0 && nlmsg_reserve(n, payload, NLMSG_ALIGNTO) == NULL)
        return NULL;

    return nlh;
}

size_t
nla_strlcpy(char *dst, const struct nlattr *nla, size_t dstsize)
{
    const char *src;
    size_t      srclen;
    size_t      len;

    /* - Always writes @dstsize bytes to @dst
     * - Copies the first non-NUL characters to @dst.
     *   Any characters after the first NUL bytes in @nla are ignored.
     * - If the string @nla is longer than @dstsize, the string
     *   gets truncated. @dst will always be NUL terminated. */

    if (G_UNLIKELY(dstsize <= 1)) {
        if (dstsize == 1)
            dst[0] = '\0';
        if (nla && (srclen = nla_len(nla)) > 0)
            return strnlen(nla_data(nla), srclen);
        return 0;
    }

    nm_assert(dst);

    if (nla) {
        srclen = nla_len(nla);
        if (srclen > 0) {
            src    = nla_data(nla);
            srclen = strnlen(src, srclen);
            if (srclen > 0) {
                len = NM_MIN(dstsize - 1, srclen);
                memcpy(dst, src, len);
                memset(&dst[len], 0, dstsize - len);
                return srclen;
            }
        }
    }

    memset(dst, 0, dstsize);
    return 0;
}

size_t
nla_memcpy(void *dst, const struct nlattr *nla, size_t dstsize)
{
    size_t len;
    int    srclen;

    if (!nla)
        return 0;

    srclen = nla_len(nla);

    if (srclen <= 0) {
        nm_assert(srclen == 0);
        return 0;
    }

    len = NM_MIN((size_t) srclen, dstsize);
    if (len > 0) {
        /* there is a crucial difference between nla_strlcpy() and nla_memcpy().
         * The former always write @dstsize bytes (akin to strncpy()), here, we only
         * write the bytes that we actually have (leaving the remainder undefined). */
        memcpy(dst, nla_data(nla), len);
    }

    return srclen;
}

int
nla_put(struct nl_msg *msg, int attrtype, int datalen, const void *data)
{
    struct nlattr *nla;

    nla = nla_reserve(msg, attrtype, datalen);
    if (!nla) {
        if (datalen < 0)
            g_return_val_if_reached(-NME_BUG);

        return -ENOMEM;
    }

    if (datalen > 0)
        memcpy(nla_data(nla), data, datalen);

    return 0;
}

struct nlattr *
nla_find(const struct nlattr *head, int len, int attrtype)
{
    const struct nlattr *nla;
    int                  rem;

    nla_for_each_attr (nla, head, len, rem) {
        if (nla_type(nla) == attrtype)
            return (struct nlattr *) nla;
    }

    return NULL;
}

void
nla_nest_cancel(struct nl_msg *msg, const struct nlattr *attr)
{
    ssize_t len;

    len = (char *) nlmsg_tail(msg->nm_nlh) - (char *) attr;
    if (len < 0)
        g_return_if_reached();
    else if (len > 0) {
        msg->nm_nlh->nlmsg_len -= len;
        memset(nlmsg_tail(msg->nm_nlh), 0, len);
    }
}

struct nlattr *
nla_nest_start(struct nl_msg *msg, int attrtype)
{
    struct nlattr *start = (struct nlattr *) nlmsg_tail(msg->nm_nlh);

    if (nla_put(msg, NLA_F_NESTED | attrtype, 0, NULL) < 0)
        return NULL;

    return start;
}

static int
_nest_end(struct nl_msg *msg, struct nlattr *start, int keep_empty)
{
    size_t   len;
    uint32_t pad;

    len = (char *) nlmsg_tail(msg->nm_nlh) - (char *) start;

    if (len > USHRT_MAX || (!keep_empty && len == NLA_HDRLEN)) {
        /*
         * Max nlattr size exceeded or empty nested attribute, trim the
         * attribute header again
         */
        nla_nest_cancel(msg, start);

        /* Return error only if nlattr size was exceeded */
        return (len == NLA_HDRLEN) ? 0 : -NME_NL_ATTRSIZE;
    }

    start->nla_len = len;

    pad = NLMSG_ALIGN(msg->nm_nlh->nlmsg_len) - msg->nm_nlh->nlmsg_len;
    if (pad > 0) {
        void *p;

        /*
         * Data inside attribute does not end at a alignment boundary.
         * Pad accordingly and account for the additional space in
         * the message. nlmsg_reserve() may never fail in this situation,
         * the allocate message buffer must be a multiple of NLMSG_ALIGNTO.
         */
        p = nlmsg_reserve(msg, pad, 0);
        if (!p)
            g_return_val_if_reached(-NME_BUG);
        memset(p, 0, pad);
    }

    return 0;
}

int
nla_nest_end(struct nl_msg *msg, struct nlattr *start)
{
    return _nest_end(msg, start, 0);
}

static const uint8_t nla_attr_minlen[NLA_TYPE_MAX + 1] = {
    [NLA_U8]     = sizeof(uint8_t),
    [NLA_U16]    = sizeof(uint16_t),
    [NLA_S32]    = sizeof(int32_t),
    [NLA_U32]    = sizeof(uint32_t),
    [NLA_U64]    = sizeof(uint64_t),
    [NLA_STRING] = 1,
};

static int
validate_nla(const struct nlattr *nla, int maxtype, const struct nla_policy *policy)
{
    const struct nla_policy *pt;
    uint8_t                  minlen;
    uint16_t                 len;
    int                      type = nla_type(nla);

    if (type < 0 || type > maxtype)
        return 0;

    pt = &policy[type];

    if (pt->type > NLA_TYPE_MAX)
        g_return_val_if_reached(-NME_BUG);

    if (pt->minlen > 0)
        minlen = pt->minlen;
    else
        minlen = nla_attr_minlen[pt->type];

    len = nla_len(nla);

    if (len < minlen)
        return -NME_UNSPEC;

    if (pt->maxlen > 0 && len > pt->maxlen)
        return -NME_UNSPEC;

    switch (pt->type) {
    case NLA_STRING:
    {
        const char *data = nla_data(nla);

        nm_assert(minlen > 0);

        if (data[len - 1u] != '\0')
            return -NME_UNSPEC;
        break;
    }
    }

    return 0;
}

int
nla_parse(struct nlattr           *tb[],
          int                      maxtype,
          struct nlattr           *head,
          int                      len,
          const struct nla_policy *policy)
{
    struct nlattr *nla;
    int            rem, nmerr;

    memset(tb, 0, sizeof(struct nlattr *) * (maxtype + 1));

    nla_for_each_attr (nla, head, len, rem) {
        int type = nla_type(nla);

        if (type > maxtype)
            continue;

        if (policy) {
            nmerr = validate_nla(nla, maxtype, policy);
            if (nmerr < 0)
                return nmerr;
        }

        tb[type] = nla;
    }

    return 0;
}

/*****************************************************************************/

int
nlmsg_get_proto(struct nl_msg *msg)
{
    return msg->nm_protocol;
}

void
nlmsg_set_proto(struct nl_msg *msg, int protocol)
{
    msg->nm_protocol = protocol;
}

void
nlmsg_set_src(struct nl_msg *msg, struct sockaddr_nl *addr)
{
    memcpy(&msg->nm_src, addr, sizeof(*addr));
}

struct ucred *
nlmsg_get_creds(struct nl_msg *msg)
{
    if (msg->nm_creds_has)
        return &msg->nm_creds;
    return NULL;
}

void
nlmsg_set_creds(struct nl_msg *msg, struct ucred *creds)
{
    if (creds) {
        memcpy(&msg->nm_creds, creds, sizeof(*creds));
        msg->nm_creds_has = TRUE;
    } else
        msg->nm_creds_has = FALSE;
}

/*****************************************************************************/

void *
genlmsg_put(struct nl_msg *msg,
            uint32_t       port,
            uint32_t       seq,
            uint16_t       family,
            uint32_t       hdrlen,
            uint16_t       flags,
            uint8_t        cmd,
            uint8_t        version)
{
    struct nlmsghdr  *nlh;
    struct genlmsghdr hdr = {
        .cmd     = cmd,
        .version = version,
    };

    nlh = nlmsg_put(msg, port, seq, family, GENL_HDRLEN + hdrlen, flags);
    if (nlh == NULL)
        return NULL;

    memcpy(nlmsg_data(nlh), &hdr, sizeof(hdr));

    return (char *) nlmsg_data(nlh) + GENL_HDRLEN;
}

void *
genlmsg_data(const struct genlmsghdr *gnlh)
{
    return ((unsigned char *) gnlh + GENL_HDRLEN);
}

void *
genlmsg_user_hdr(const struct genlmsghdr *gnlh)
{
    return genlmsg_data(gnlh);
}

const struct genlmsghdr *
genlmsg_hdr(const struct nlmsghdr *nlh)
{
    return nlmsg_data(nlh);
}

void *
genlmsg_user_data(const struct genlmsghdr *gnlh, const int hdrlen)
{
    return (char *) genlmsg_user_hdr(gnlh) + NLMSG_ALIGN(hdrlen);
}

struct nlattr *
genlmsg_attrdata(const struct genlmsghdr *gnlh, int hdrlen)
{
    return genlmsg_user_data(gnlh, hdrlen);
}

int
genlmsg_len(const struct genlmsghdr *gnlh)
{
    const struct nlmsghdr *nlh;

    nlh = NM_CAST_ALIGN(const struct nlmsghdr, (((char *) gnlh) - NLMSG_HDRLEN));
    return (nlh->nlmsg_len - GENL_HDRLEN - NLMSG_HDRLEN);
}

int
genlmsg_attrlen(const struct genlmsghdr *gnlh, int hdrlen)
{
    return genlmsg_len(gnlh) - NLMSG_ALIGN(hdrlen);
}

int
genlmsg_valid_hdr(const struct nlmsghdr *nlh, int hdrlen)
{
    struct genlmsghdr *ghdr;

    if (!nlmsg_valid_hdr(nlh, GENL_HDRLEN))
        return 0;

    ghdr = nlmsg_data(nlh);
    if (genlmsg_len(ghdr) < NLMSG_ALIGN(hdrlen))
        return 0;

    return 1;
}

int
genlmsg_parse(const struct nlmsghdr   *nlh,
              int                      hdrlen,
              struct nlattr           *tb[],
              int                      maxtype,
              const struct nla_policy *policy)
{
    const struct genlmsghdr *ghdr;

    if (!genlmsg_valid_hdr(nlh, hdrlen))
        return -NME_NL_MSG_TOOSHORT;

    ghdr = nlmsg_data(nlh);
    return nla_parse(tb,
                     maxtype,
                     genlmsg_attrdata(ghdr, hdrlen),
                     genlmsg_attrlen(ghdr, hdrlen),
                     policy);
}

const struct nla_policy genl_ctrl_policy[CTRL_ATTR_MCAST_GROUPS + 1] = {
    [CTRL_ATTR_FAMILY_ID]    = {.type = NLA_U16},
    [CTRL_ATTR_FAMILY_NAME]  = {.type = NLA_STRING, .maxlen = GENL_NAMSIZ},
    [CTRL_ATTR_VERSION]      = {.type = NLA_U32},
    [CTRL_ATTR_HDRSIZE]      = {.type = NLA_U32},
    [CTRL_ATTR_MAXATTR]      = {.type = NLA_U32},
    [CTRL_ATTR_OPS]          = {.type = NLA_NESTED},
    [CTRL_ATTR_MCAST_GROUPS] = {.type = NLA_NESTED},
};

static int
_genl_parse_getfamily(const struct nl_msg *msg, void *arg)
{
    struct nlattr   *tb[G_N_ELEMENTS(genl_ctrl_policy)];
    struct nlmsghdr *nlh           = nlmsg_hdr(msg);
    gint32          *response_data = arg;

    if (genlmsg_parse_arr(nlh, 0, tb, genl_ctrl_policy) < 0)
        return NL_SKIP;

    if (tb[CTRL_ATTR_FAMILY_ID])
        *response_data = nla_get_u16(tb[CTRL_ATTR_FAMILY_ID]);

    return NL_STOP;
}

int
genl_ctrl_resolve(struct nl_sock *sk, const char *name)
{
    nm_auto_nlmsg struct nl_msg *msg = NULL;
    int                          nmerr;
    gint32                       response_data = -1;
    const struct nl_cb           cb            = {
                             .valid_cb  = _genl_parse_getfamily,
                             .valid_arg = &response_data,
    };

    msg = nlmsg_alloc(0);

    if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, GENL_ID_CTRL, 0, 0, CTRL_CMD_GETFAMILY, 1))
        return -ENOMEM;

    nmerr = nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, name);
    if (nmerr < 0)
        return nmerr;

    nmerr = nl_send_auto(sk, msg);
    if (nmerr < 0)
        return nmerr;

    nmerr = nl_recvmsgs(sk, &cb);
    if (nmerr < 0)
        return nmerr;

    /* If search was successful, request may be ACKed after data */
    nmerr = nl_wait_for_ack(sk, NULL);
    if (nmerr < 0)
        return nmerr;

    if (response_data < 0)
        return -NME_UNSPEC;

    return response_data;
}

/*****************************************************************************/

void
nl_socket_free(struct nl_sock *sk)
{
    if (!sk)
        return;

    nm_close(sk->s_fd);
    nm_g_slice_free(sk);
}

int
nl_socket_get_fd(const struct nl_sock *sk)
{
    return sk->s_fd;
}

uint32_t
nl_socket_get_local_port(const struct nl_sock *sk)
{
    return sk->s_local.nl_pid;
}

size_t
nl_socket_get_msg_buf_size(struct nl_sock *sk)
{
    return sk->s_bufsize;
}

int
nl_socket_set_passcred(struct nl_sock *sk, int state)
{
    int err;

    nm_assert_sk(sk);

    err = setsockopt(sk->s_fd, SOL_SOCKET, SO_PASSCRED, &state, sizeof(state));
    if (err < 0)
        return -nm_errno_from_native(errno);
    return 0;
}

int
nl_socket_set_pktinfo(struct nl_sock *sk, int state)
{
    int err;

    nm_assert_sk(sk);

    err = setsockopt(sk->s_fd, SOL_NETLINK, NETLINK_PKTINFO, &state, sizeof(state));
    if (err < 0)
        return -nm_errno_from_native(errno);
    return 0;
}

int
nl_socket_set_msg_buf_size(struct nl_sock *sk, size_t bufsize)
{
    sk->s_bufsize = bufsize;

    return 0;
}

struct sockaddr_nl *
nlmsg_get_dst(struct nl_msg *msg)
{
    return &msg->nm_dst;
}

int
nl_socket_set_nonblocking(const struct nl_sock *sk)
{
    nm_assert_sk(sk);

    if (fcntl(sk->s_fd, F_SETFL, O_NONBLOCK) < 0)
        return -nm_errno_from_native(errno);

    return 0;
}

int
nl_socket_set_buffer_size(struct nl_sock *sk, int rxbuf, int txbuf)
{
    int err;

    nm_assert_sk(sk);

    if (rxbuf <= 0)
        rxbuf = 32768;

    if (txbuf <= 0)
        txbuf = 32768;

    err = setsockopt(sk->s_fd, SOL_SOCKET, SO_SNDBUF, &txbuf, sizeof(txbuf));
    if (err < 0) {
        return -nm_errno_from_native(errno);
    }

    err = setsockopt(sk->s_fd, SOL_SOCKET, SO_RCVBUF, &rxbuf, sizeof(rxbuf));
    if (err < 0) {
        return -nm_errno_from_native(errno);
    }

    return 0;
}

int
nl_socket_add_memberships(struct nl_sock *sk, int group, ...)
{
    int     err;
    va_list ap;

    nm_assert_sk(sk);

    va_start(ap, group);

    while (group != 0) {
        if (group < 0) {
            va_end(ap);
            g_return_val_if_reached(-NME_BUG);
        }

        err = setsockopt(sk->s_fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group));
        if (err < 0) {
            int errsv = errno;

            va_end(ap);
            return -nm_errno_from_native(errsv);
        }

        group = va_arg(ap, int);
    }

    va_end(ap);

    return 0;
}

/*****************************************************************************/

int
nl_socket_new(struct nl_sock **out_sk,
              int              protocol,
              NLSocketFlags    flags,
              int              bufsize_rx,
              int              bufsize_tx)
{
    nm_auto_nlsock struct nl_sock *sk = NULL;
    nm_auto_close int              fd = -1;
    time_t                         t;
    int                            err;
    int                            nmerr;
    socklen_t                      addrlen;
    struct sockaddr_nl             local = {0};
    int                            i_val;

    nm_assert(out_sk && !*out_sk);

    fd = socket(AF_NETLINK,
                SOCK_RAW | SOCK_CLOEXEC
                    | (NM_FLAGS_HAS(flags, NL_SOCKET_FLAGS_NONBLOCK) ? SOCK_NONBLOCK : 0),
                protocol);
    if (fd < 0)
        return -nm_errno_from_native(errno);

    t = time(NULL);

    sk  = g_slice_new(struct nl_sock);
    *sk = (struct nl_sock){
        .s_fd = nm_steal_fd(&fd),
        .s_local =
            {
                .nl_pid    = 0,
                .nl_family = AF_NETLINK,
                .nl_groups = 0,
            },
        .s_peer =
            {
                .nl_pid    = 0,
                .nl_family = AF_NETLINK,
                .nl_groups = 0,
            },
        .s_seq_expect = t,
        .s_seq_next   = t,
        .s_bufsize    = 0,
        .s_msg_peek   = !NM_FLAGS_HAS(flags, NL_SOCKET_FLAGS_DISABLE_MSG_PEEK),
        .s_auto_ack   = TRUE,
    };

    nmerr = nl_socket_set_buffer_size(sk, bufsize_rx, bufsize_tx);
    if (nmerr < 0)
        return nmerr;

    i_val = 1;
    (void) setsockopt(sk->s_fd, SOL_NETLINK, NETLINK_EXT_ACK, &i_val, sizeof(i_val));

    if (NM_FLAGS_HAS(flags, NL_SOCKET_FLAGS_PASSCRED)) {
        err = nl_socket_set_passcred(sk, 1);
        if (err < 0)
            return err;
    }

    if (NM_FLAGS_HAS(flags, NL_SOCKET_FLAGS_PKTINFO)) {
        err = nl_socket_set_pktinfo(sk, 1);
        if (err < 0)
            return err;
    }

    err = bind(sk->s_fd, (struct sockaddr *) &sk->s_local, sizeof(sk->s_local));
    if (err != 0)
        return -nm_errno_from_native(errno);

    addrlen = sizeof(local);
    err     = getsockname(sk->s_fd, (struct sockaddr *) &local, &addrlen);
    if (err < 0)
        return -nm_errno_from_native(errno);

    if (addrlen != sizeof(local))
        return -NME_UNSPEC;

    if (local.nl_family != AF_NETLINK)
        return -NME_UNSPEC;

    sk->s_local = local;
    sk->s_proto = protocol;

    *out_sk = g_steal_pointer(&sk);
    return 0;
}

/*****************************************************************************/

static void
_cb_init(struct nl_cb *dst, const struct nl_cb *src)
{
    nm_assert(dst);

    if (src)
        *dst = *src;
    else
        memset(dst, 0, sizeof(*dst));
}

static int
ack_wait_handler(const struct nl_msg *msg, void *arg)
{
    return NL_STOP;
}

int
nl_wait_for_ack(struct nl_sock *sk, const struct nl_cb *cb)
{
    struct nl_cb cb2;

    _cb_init(&cb2, cb);
    cb2.ack_cb = ack_wait_handler;
    return nl_recvmsgs(sk, &cb2);
}

#define NL_CB_CALL(cb, type, msg)                                \
    do {                                                         \
        const struct nl_cb *_cb = (cb);                          \
                                                                 \
        if (_cb && _cb->type##_cb) {                             \
            /* the returned value here must be either a negative
         * netlink error number, or one of NL_SKIP, NL_STOP, NL_OK. */ \
            nmerr = _cb->type##_cb((msg), _cb->type##_arg);      \
            switch (nmerr) {                                     \
            case NL_OK:                                          \
                nm_assert(nmerr == 0);                           \
                break;                                           \
            case NL_SKIP:                                        \
                goto skip;                                       \
            case NL_STOP:                                        \
                goto stop;                                       \
            default:                                             \
                if (nmerr >= 0) {                                \
                    nm_assert_not_reached();                     \
                    nmerr = -NME_BUG;                            \
                }                                                \
                goto out;                                        \
            }                                                    \
        }                                                        \
    } while (0)

int
nl_recvmsgs(struct nl_sock *sk, const struct nl_cb *cb)
{
    int                    n, nmerr = 0, multipart = 0, interrupted = 0, nrecv = 0;
    gs_free unsigned char *buf = NULL;
    struct nlmsghdr       *hdr;
    struct sockaddr_nl     nla;
    struct ucred           creds;
    gboolean               creds_has;

continue_reading:
    n = nl_recv(sk, NULL, 0, &nla, &buf, &creds, &creds_has, NULL, NULL);
    if (n <= 0)
        return n;

    hdr = NM_CAST_ALIGN(struct nlmsghdr, buf);
    while (nlmsg_ok(hdr, n)) {
        nm_auto_nlmsg struct nl_msg *msg = NULL;

        msg = nlmsg_alloc_convert(hdr);

        nlmsg_set_proto(msg, sk->s_proto);
        nlmsg_set_src(msg, &nla);
        nlmsg_set_creds(msg, creds_has ? &creds : NULL);

        nrecv++;

        /* Only do sequence checking if auto-ack mode is enabled */
        if (sk->s_auto_ack) {
            if (hdr->nlmsg_seq != sk->s_seq_expect) {
                nmerr = -NME_NL_SEQ_MISMATCH;
                goto out;
            }
        }

        if (hdr->nlmsg_type == NLMSG_DONE || hdr->nlmsg_type == NLMSG_ERROR
            || hdr->nlmsg_type == NLMSG_NOOP || hdr->nlmsg_type == NLMSG_OVERRUN) {
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
            NL_CB_CALL(cb, finish, msg);
        }

        /* Message to be ignored, the default action is to
         * skip this message if no callback is specified. The
         * user may overrule this action by returning
         * NL_PROCEED. */
        else if (hdr->nlmsg_type == NLMSG_NOOP)
            goto skip;

        /* Data got lost, report back to user. The default action is to
         * quit parsing. The user may overrule this action by returning
         * NL_SKIP or NL_PROCEED (dangerous) */
        else if (hdr->nlmsg_type == NLMSG_OVERRUN) {
            nmerr = -NME_NL_MSG_OVERFLOW;
            goto out;
        }

        /* Message carries a nlmsgerr */
        else if (hdr->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *e = nlmsg_data(hdr);

            if (hdr->nlmsg_len < nlmsg_size(sizeof(*e))) {
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
                    nmerr = cb->err_cb(&nla, e, cb->err_arg);
                    if (nmerr < 0)
                        goto out;
                    else if (nmerr == NL_SKIP)
                        goto skip;
                    else if (nmerr == NL_STOP) {
                        nmerr = -nm_errno_from_native(e->error);
                        goto out;
                    }
                    nm_assert(nmerr == NL_OK);
                } else {
                    nmerr = -nm_errno_from_native(e->error);
                    goto out;
                }
            } else
                NL_CB_CALL(cb, ack, msg);
        } else {
            /* Valid message (not checking for MULTIPART bit to
             * get along with broken kernels. NL_SKIP has no
             * effect on this.  */
            NL_CB_CALL(cb, valid, msg);
        }
skip:
        nmerr = 0;
        hdr   = nlmsg_next(hdr, &n);
    }

    if (multipart) {
        /* Multipart message not yet complete, continue reading */
        nm_clear_g_free(&buf);

        nmerr = 0;
        goto continue_reading;
    }

stop:
    nmerr = 0;

out:
    if (interrupted)
        nmerr = -NME_NL_DUMP_INTR;

    nm_assert(nmerr <= 0);
    return nmerr ?: nrecv;
}

int
nl_sendmsg(struct nl_sock *sk, struct nl_msg *msg, struct msghdr *hdr)
{
    int ret;

    if (sk->s_fd < 0)
        return -NME_NL_BAD_SOCK;

    nlmsg_set_src(msg, &sk->s_local);

    ret = sendmsg(sk->s_fd, hdr, 0);
    if (ret < 0)
        return -nm_errno_from_native(errno);

    return ret;
}

int
nl_send_iovec(struct nl_sock *sk, struct nl_msg *msg, struct iovec *iov, unsigned iovlen)
{
    struct sockaddr_nl *dst;
    struct ucred       *creds;
    struct msghdr       hdr = {
              .msg_name    = (void *) &sk->s_peer,
              .msg_namelen = sizeof(struct sockaddr_nl),
              .msg_iov     = iov,
              .msg_iovlen  = iovlen,
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

        hdr.msg_control    = buf;
        hdr.msg_controllen = sizeof(buf);

        cmsg             = CMSG_FIRSTHDR(&hdr);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type  = SCM_CREDENTIALS;
        cmsg->cmsg_len   = CMSG_LEN(sizeof(struct ucred));
        memcpy(CMSG_DATA(cmsg), creds, sizeof(struct ucred));
    }

    return nl_sendmsg(sk, msg, &hdr);
}

void
nl_complete_msg(struct nl_sock *sk, struct nl_msg *msg)
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

    if (sk->s_auto_ack)
        nlh->nlmsg_flags |= NLM_F_ACK;
}

int
nl_send(struct nl_sock *sk, struct nl_msg *msg)
{
    struct iovec iov = {
        .iov_base = (void *) nlmsg_hdr(msg),
        .iov_len  = nlmsg_hdr(msg)->nlmsg_len,
    };

    return nl_send_iovec(sk, msg, &iov, 1);
}

int
nl_send_auto(struct nl_sock *sk, struct nl_msg *msg)
{
    nl_complete_msg(sk, msg);

    return nl_send(sk, msg);
}

/**
 * nl_recv():
 * @sk: the netlink socket
 * @buf0: NULL or a receive buffer of length @buf0_len
 * @buf0_len: the length of the optional receive buffer.
 * @nla: (out): the source address on success.
 * @buf: (out): pointer to the result buffer on success. This is
 *   either @buf0 or an allocated buffer that gets returned.
 * @out_creds: (out) (allow-none): optional out buffer for the credentials
 *   on success.
 * @out_creds_has: (out) (allow-none): result indicating whether
 *   @out_creds was filled.
* @out_pktinfo_group: (out) (allow-none): optional out buffer for NETLINK_PKTINFO
*    group on success.
 * @out_pktinfo_has: (out) (allow-none): result indicating whether
 *   @out_pktinfo_group was filled.
 *
 * If @buf0_len is zero, the function will g_malloc() a new receive buffer of size
 * nl_socket_get_msg_buf_size(). If @buf0_len is larger than zero, then @buf0
 * is used as receive buffer. That is also the buffer returned by @buf.
 *
 * If NL_MSG_PEEK is not enabled and the receive buffer is too small, then
 * the message was lost and -NME_NL_MSG_TRUNC gets returned.
 * If NL_MSG_PEEK is enabled, then we first peek. If the buffer is too small,
 * we g_malloc() a new buffer. In any case, we proceed to receive the buffer.
 * NL_MSG_PEEK is great because it means no messages are lost. But it's bad,
 * because we always need two syscalls on every receive.
 *
 * Returns: a negative error code or the length of the received message in
 *   @buf.
 */
int
nl_recv(struct nl_sock     *sk,
        unsigned char      *buf0,
        size_t              buf0_len,
        struct sockaddr_nl *nla,
        unsigned char     **buf,
        struct ucred       *out_creds,
        gboolean           *out_creds_has,
        uint32_t           *out_pktinfo_group,
        gboolean           *out_pktinfo_has)
{
    union {
        struct cmsghdr _dummy_for_alignment;
        struct {
            char buf[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(struct nl_pktinfo))];

            /* We really expect that "buf" is large enough end even assert against
             * that. We don't expect and don't want to handle MSG_CTRUNC error.
             * Still, add some extra safety. This is on the stack and essentially for free. */
            char _extra[512];
        };
    } msg_contol_buf;
    ssize_t       n;
    int           flags = 0;
    struct iovec  iov;
    struct msghdr msg = {
        .msg_name       = (void *) nla,
        .msg_namelen    = sizeof(struct sockaddr_nl),
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
        .msg_controllen = 0,
        .msg_control    = NULL,
    };
    struct cmsghdr *cmsg;
    int             retval;
    int             errsv;

    nm_assert(nla);
    nm_assert(buf && !*buf);
    nm_assert(!out_creds_has || out_creds);
    nm_assert(!out_pktinfo_has || out_pktinfo_group);

    if (sk->s_msg_peek)
        flags |= MSG_PEEK | MSG_TRUNC;

    if (buf0_len > 0) {
        iov.iov_len  = buf0_len;
        iov.iov_base = buf0;
    } else {
        iov.iov_len  = sk->s_bufsize ?: (((size_t) nm_utils_getpagesize()) * 4u);
        iov.iov_base = g_malloc(iov.iov_len);
    }

    if (out_creds_has || out_pktinfo_has) {
        msg.msg_controllen = sizeof(msg_contol_buf);
        msg.msg_control    = msg_contol_buf.buf;
    }

retry:
    n = recvmsg(sk->s_fd, &msg, flags);
    if (!n) {
        retval = 0;
        goto abort;
    }

    if (n < 0) {
        errsv = errno;
        if (errsv == EINTR)
            goto retry;
        retval = -nm_errno_from_native(errsv);
        goto abort;
    }

    nm_assert((gsize) n <= G_MAXINT);

    /* We really don't expect truncation of ancillary data. We provided a large
    * enough buffer, so this is likely a bug. In the worst case, we might lack
    * the requested credentials and the caller likely will reject the message
    * later. */
    nm_assert(!(msg.msg_flags & MSG_CTRUNC));
    nm_assert(msg.msg_controllen <= G_STRUCT_OFFSET(typeof(msg_contol_buf), _extra));

    if (iov.iov_len < n || (msg.msg_flags & MSG_TRUNC)) {
        /* respond with error to an incomplete message */
        if (flags == 0) {
            retval = -NME_NL_MSG_TRUNC;
            goto abort;
        }

        /* Provided buffer is not long enough, enlarge it
         * to size of n (which should be total length of the message)
         * and try again. */
        iov.iov_base = g_realloc(iov.iov_base != buf0 ? iov.iov_base : NULL, n);
        iov.iov_len  = n;
        flags        = 0;
        goto retry;
    }

    if (flags != 0) {
        /* Buffer is big enough, do the actual reading */
        flags = 0;
        goto retry;
    }

    if (msg.msg_namelen != sizeof(struct sockaddr_nl)) {
        retval = -NME_UNSPEC;
        goto abort;
    }

    if (out_creds_has || out_pktinfo_has) {
        NM_SET_OUT(out_creds_has, FALSE);
        NM_SET_OUT(out_pktinfo_has, FALSE);
        for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            switch (cmsg->cmsg_level) {
            case SOL_SOCKET:
                if (cmsg->cmsg_type == SCM_CREDENTIALS && out_creds_has) {
                    memcpy(out_creds, CMSG_DATA(cmsg), sizeof(*out_creds));
                    *out_creds_has = TRUE;
                }
                break;
            case SOL_NETLINK:
                if (cmsg->cmsg_type == NETLINK_PKTINFO && out_pktinfo_has) {
                    struct nl_pktinfo p;

                    memcpy(&p, CMSG_DATA(cmsg), sizeof(p));
                    *out_pktinfo_group = p.group;
                    *out_pktinfo_has   = TRUE;
                }
                break;
            }
        }
    }

    *buf = iov.iov_base;
    return (int) n;

abort:
    if (iov.iov_base != buf0)
        g_free(iov.iov_base);
    return retval;
}
