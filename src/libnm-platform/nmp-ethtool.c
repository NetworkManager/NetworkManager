/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nmp-ethtool.h"

#include "libnm-std-aux/nm-linux-compat.h"

#include "libnm-platform/nm-platform.h"
#include "libnm-platform/nm-platform-utils.h"
#include "libnm-log-core/nm-logging.h"

enum {
    ETHTOOL_A_HEADER_UNSPEC,
    ETHTOOL_A_HEADER_DEV_INDEX, /* u32 */
    ETHTOOL_A_HEADER_DEV_NAME,  /* string */
    ETHTOOL_A_HEADER_FLAGS,     /* u32 - ETHTOOL_FLAG_* */
    ETHTOOL_A_HEADER_PHY_INDEX, /* u32 */

    /* add new constants above here */
    __ETHTOOL_A_HEADER_CNT,
    ETHTOOL_A_HEADER_MAX = __ETHTOOL_A_HEADER_CNT - 1
};

enum {
    ETHTOOL_MSG_USER_NONE  = 0,
    ETHTOOL_MSG_STRSET_GET = 1,
    ETHTOOL_MSG_LINKINFO_GET,
    ETHTOOL_MSG_LINKINFO_SET,
    ETHTOOL_MSG_LINKMODES_GET,
    ETHTOOL_MSG_LINKMODES_SET,
    ETHTOOL_MSG_LINKSTATE_GET,
    ETHTOOL_MSG_DEBUG_GET,
    ETHTOOL_MSG_DEBUG_SET,
    ETHTOOL_MSG_WOL_GET,
    ETHTOOL_MSG_WOL_SET,
    ETHTOOL_MSG_FEATURES_GET,
    ETHTOOL_MSG_FEATURES_SET,
    ETHTOOL_MSG_PRIVFLAGS_GET,
    ETHTOOL_MSG_PRIVFLAGS_SET,
    ETHTOOL_MSG_RINGS_GET,
    ETHTOOL_MSG_RINGS_SET,
    ETHTOOL_MSG_CHANNELS_GET,
    ETHTOOL_MSG_CHANNELS_SET,
    ETHTOOL_MSG_COALESCE_GET,
    ETHTOOL_MSG_COALESCE_SET,
    ETHTOOL_MSG_PAUSE_GET,
    ETHTOOL_MSG_PAUSE_SET,
    ETHTOOL_MSG_EEE_GET,
    ETHTOOL_MSG_EEE_SET,
    ETHTOOL_MSG_TSINFO_GET,
    ETHTOOL_MSG_CABLE_TEST_ACT,
    ETHTOOL_MSG_CABLE_TEST_TDR_ACT,
    ETHTOOL_MSG_TUNNEL_INFO_GET,
    ETHTOOL_MSG_FEC_GET,
    ETHTOOL_MSG_FEC_SET,

    /* add new constants above here */
    __ETHTOOL_MSG_USER_CNT,
    ETHTOOL_MSG_USER_MAX = __ETHTOOL_MSG_USER_CNT - 1
};

#define ETHTOOL_GENL_VERSION 1

/* LINKMODES_SET needs attribute overhead in addition to the mode bitset. */
#define _ETHTOOL_MSG_PAYLOAD_SIZE (128 + sizeof(NMPEthtoolLinkModesMask))

#define _NMLOG_DOMAIN      LOGD_PLATFORM
#define _NMLOG_PREFIX_NAME "ethtool"
#define _NMLOG(_level, ...)                                   \
    G_STMT_START                                              \
    {                                                         \
        int _ifindex = ifindex;                               \
                                                              \
        nm_log((_level),                                      \
               (_NMLOG_DOMAIN),                               \
               NULL,                                          \
               NULL,                                          \
               "%s[%d]: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
               _NMLOG_PREFIX_NAME,                            \
               _ifindex _NM_UTILS_MACRO_REST(__VA_ARGS__));   \
    }                                                         \
    G_STMT_END

#define CB_RESULT_PENDING 0
#define CB_RESULT_OK      1

static int
ack_cb_handler(const struct nl_msg *msg, void *data)
{
    int *result = data;
    *result     = CB_RESULT_OK;
    return NL_STOP;
}

static int
finish_cb_handler(const struct nl_msg *msg, void *data)
{
    int *result = data;
    *result     = CB_RESULT_OK;
    return NL_SKIP;
}

static int
err_cb_handler(const struct sockaddr_nl *nla, const struct nlmsgerr *err, void *data)
{
    void      **args       = data;
    int        *result     = args[0];
    char      **err_msg    = args[1];
    const char *extack_msg = NULL;

    *result = err->error;
    nlmsg_parse_error(nlmsg_undata(err), &extack_msg);

    if (err_msg)
        *err_msg = g_strdup(extack_msg ?: nm_strerror(err->error));

    return NL_SKIP;
}

static int
ethtool_send_and_recv(struct nl_sock *sock,
                      int             ifindex,
                      struct nl_msg  *msg,
                      int (*valid_handler)(const struct nl_msg *, void *),
                      void       *valid_data,
                      char      **err_msg,
                      const char *log_prefix)
{
    int                nle;
    int                cb_result = CB_RESULT_PENDING;
    void              *err_arg[] = {&cb_result, err_msg};
    const struct nl_cb cb        = {
        .err_cb     = err_cb_handler,
        .err_arg    = err_arg,
        .finish_cb  = finish_cb_handler,
        .finish_arg = &cb_result,
        .ack_cb     = ack_cb_handler,
        .ack_arg    = &cb_result,
        .valid_cb   = valid_handler,
        .valid_arg  = valid_data,
    };

    g_return_val_if_fail(msg, -ENOMEM);

    if (err_msg)
        *err_msg = NULL;

    nle = nl_send_auto(sock, msg);
    if (nle < 0)
        goto out;

    while (cb_result == CB_RESULT_PENDING) {
        nle = nl_recvmsgs(sock, &cb);
        if (nle < 0 && nle != -EAGAIN) {
            break;
        }
    }

out:
    if (nle < 0 && err_msg && *err_msg == NULL)
        *err_msg = g_strdup(nm_strerror(nle));

    if (nle >= 0 && cb_result < 0)
        nle = cb_result;

    if (nle < 0) {
        _LOGT("%s: netlink error: %d (%s)", log_prefix, nle, err_msg && *err_msg ? *err_msg : "");
    }

    return nle;
}

static struct nl_msg *
ethtool_create_msg(guint16     family_id,
                   int         ifindex,
                   guint8      cmd,
                   int         header_attr,
                   guint32     header_flags,
                   const char *log_prefix)
{
    nm_auto_nlmsg struct nl_msg *msg = NULL;
    struct nlattr               *nest_header;

    if (family_id == 0) {
        _LOGT("%s: ethtool genl family not found", log_prefix);
        return NULL;
    }

    msg = nlmsg_alloc(nlmsg_total_size(GENL_HDRLEN) + _ETHTOOL_MSG_PAYLOAD_SIZE);

    if (!genlmsg_put(msg,
                     NL_AUTO_PORT,
                     NL_AUTO_SEQ,
                     family_id,
                     0,
                     NLM_F_REQUEST,
                     cmd,
                     ETHTOOL_GENL_VERSION))
        goto nla_put_failure;

    nest_header = nla_nest_start(msg, header_attr);
    NLA_PUT_U32(msg, ETHTOOL_A_HEADER_DEV_INDEX, (guint32) ifindex);
    if (header_flags != 0)
        NLA_PUT_U32(msg, ETHTOOL_A_HEADER_FLAGS, header_flags);
    NLA_NEST_END(msg, nest_header);
    return g_steal_pointer(&msg);

nla_put_failure:
    g_return_val_if_reached(NULL);
}

/*****************************************************************************/
/* PAUSE                                                                     */
/*****************************************************************************/

enum {
    ETHTOOL_A_PAUSE_UNSPEC,
    ETHTOOL_A_PAUSE_HEADER,
    ETHTOOL_A_PAUSE_AUTONEG,
    ETHTOOL_A_PAUSE_RX,
    ETHTOOL_A_PAUSE_TX,

    __ETHTOOL_A_PAUSE_CNT,
    ETHTOOL_A_PAUSE_MAX = (__ETHTOOL_A_PAUSE_CNT - 1)
};

static int
ethtool_parse_pause(const struct nl_msg *msg, void *data)
{
    NMEthtoolPauseState           *pause    = data;
    static const struct nla_policy policy[] = {
        [ETHTOOL_A_PAUSE_AUTONEG] = {.type = NLA_U8},
        [ETHTOOL_A_PAUSE_RX]      = {.type = NLA_U8},
        [ETHTOOL_A_PAUSE_TX]      = {.type = NLA_U8},
    };
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr     *tb[G_N_ELEMENTS(policy)];

    *pause = (NMEthtoolPauseState) {};

    if (nla_parse_arr(tb, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), policy) < 0)
        return NL_SKIP;

    if (tb[ETHTOOL_A_PAUSE_AUTONEG])
        pause->autoneg = !!nla_get_u8(tb[ETHTOOL_A_PAUSE_AUTONEG]);
    if (tb[ETHTOOL_A_PAUSE_RX])
        pause->rx = !!nla_get_u8(tb[ETHTOOL_A_PAUSE_RX]);
    if (tb[ETHTOOL_A_PAUSE_TX])
        pause->tx = !!nla_get_u8(tb[ETHTOOL_A_PAUSE_TX]);

    return NL_OK;
}

gboolean
nmp_ethtool_get_pause(struct nl_sock      *genl_sock,
                      guint16              family_id,
                      int                  ifindex,
                      NMEthtoolPauseState *pause)
{
    nm_auto_nlmsg struct nl_msg *msg     = NULL;
    gs_free char                *err_msg = NULL;
    int                          r;

    g_return_val_if_fail(pause, FALSE);

    _LOGT("get-pause: start");
    *pause = (NMEthtoolPauseState) {};

    msg = ethtool_create_msg(family_id,
                             ifindex,
                             ETHTOOL_MSG_PAUSE_GET,
                             ETHTOOL_A_PAUSE_HEADER,
                             0,
                             "get-pause");
    if (!msg)
        return FALSE;

    r = ethtool_send_and_recv(genl_sock,
                              ifindex,
                              msg,
                              ethtool_parse_pause,
                              pause,
                              &err_msg,
                              "get-pause");
    if (r < 0)
        return FALSE;

    _LOGT("get-pause: autoneg %d rx %d tx %d", pause->autoneg, pause->rx, pause->tx);

    return TRUE;
}

gboolean
nmp_ethtool_set_pause(struct nl_sock            *genl_sock,
                      guint16                    family_id,
                      int                        ifindex,
                      const NMEthtoolPauseState *pause)
{
    nm_auto_nlmsg struct nl_msg *msg     = NULL;
    gs_free char                *err_msg = NULL;
    int                          r;

    g_return_val_if_fail(pause, FALSE);

    _LOGT("set-pause: autoneg %d rx %d tx %d", pause->autoneg, pause->rx, pause->tx);

    msg = ethtool_create_msg(family_id,
                             ifindex,
                             ETHTOOL_MSG_PAUSE_SET,
                             ETHTOOL_A_PAUSE_HEADER,
                             0,
                             "set-pause");
    if (!msg)
        return FALSE;

    NLA_PUT_U8(msg, ETHTOOL_A_PAUSE_AUTONEG, pause->autoneg);
    NLA_PUT_U8(msg, ETHTOOL_A_PAUSE_RX, pause->rx);
    NLA_PUT_U8(msg, ETHTOOL_A_PAUSE_TX, pause->tx);

    r = ethtool_send_and_recv(genl_sock, ifindex, msg, NULL, NULL, &err_msg, "set-pause");
    if (r < 0)
        return FALSE;

    _LOGT("set-pause: succeeded");

    return TRUE;
nla_put_failure:
    g_return_val_if_reached(FALSE);
}

/*****************************************************************************/
/* EEE                                                                       */
/*****************************************************************************/

enum {
    ETHTOOL_A_EEE_UNSPEC,
    ETHTOOL_A_EEE_HEADER,     /* nest - _A_HEADER_* */
    ETHTOOL_A_EEE_MODES_OURS, /* bitset */
    ETHTOOL_A_EEE_MODES_PEER, /* bitset */
    ETHTOOL_A_EEE_ACTIVE,     /* u8 */
    ETHTOOL_A_EEE_ENABLED,    /* u8 */

    /* add new constants above here */
    __ETHTOOL_A_EEE_CNT,
    ETHTOOL_A_EEE_MAX = (__ETHTOOL_A_EEE_CNT - 1)
};

static int
ethtool_parse_eee(const struct nl_msg *msg, void *data)
{
    NMEthtoolEEEState             *eee      = data;
    static const struct nla_policy policy[] = {
        [ETHTOOL_A_EEE_ENABLED] = {.type = NLA_U8},
    };
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr     *tb[G_N_ELEMENTS(policy)];

    *eee = (NMEthtoolEEEState) {};

    if (nla_parse_arr(tb, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), policy) < 0)
        return NL_SKIP;

    if (tb[ETHTOOL_A_EEE_ENABLED])
        eee->enabled = !!nla_get_u8(tb[ETHTOOL_A_EEE_ENABLED]);

    return NL_OK;
}

gboolean
nmp_ethtool_get_eee(struct nl_sock    *genl_sock,
                    guint16            family_id,
                    int                ifindex,
                    NMEthtoolEEEState *eee)
{
    nm_auto_nlmsg struct nl_msg *msg     = NULL;
    gs_free char                *err_msg = NULL;
    int                          r;

    g_return_val_if_fail(eee, FALSE);

    _LOGT("get-eee: start");
    *eee = (NMEthtoolEEEState) {};

    msg = ethtool_create_msg(family_id,
                             ifindex,
                             ETHTOOL_MSG_EEE_GET,
                             ETHTOOL_A_EEE_HEADER,
                             0,
                             "get-eee");
    if (!msg)
        return FALSE;

    r = ethtool_send_and_recv(genl_sock, ifindex, msg, ethtool_parse_eee, eee, &err_msg, "get-eee");
    if (r < 0)
        return FALSE;

    _LOGT("get-eee: enabled %d", eee->enabled);

    return TRUE;
}

gboolean
nmp_ethtool_set_eee(struct nl_sock          *genl_sock,
                    guint16                  family_id,
                    int                      ifindex,
                    const NMEthtoolEEEState *eee)
{
    nm_auto_nlmsg struct nl_msg *msg     = NULL;
    gs_free char                *err_msg = NULL;
    int                          r;

    g_return_val_if_fail(eee, FALSE);

    _LOGT("set-eee: enabled %d", eee->enabled);

    msg = ethtool_create_msg(family_id,
                             ifindex,
                             ETHTOOL_MSG_EEE_SET,
                             ETHTOOL_A_EEE_HEADER,
                             0,
                             "set-eee");
    if (!msg)
        return FALSE;

    NLA_PUT_U8(msg, ETHTOOL_A_EEE_ENABLED, eee->enabled);

    r = ethtool_send_and_recv(genl_sock, ifindex, msg, NULL, NULL, &err_msg, "set-eee");
    if (r < 0)
        return FALSE;

    _LOGT("set-eee: succeeded");

    return TRUE;
nla_put_failure:
    g_return_val_if_reached(FALSE);
}

/*****************************************************************************/
/* RINGS                                                                     */
/*****************************************************************************/

enum {
    ETHTOOL_A_RINGS_UNSPEC,
    ETHTOOL_A_RINGS_HEADER,       /* nest - _A_HEADER_* */
    ETHTOOL_A_RINGS_RX_MAX,       /* u32 */
    ETHTOOL_A_RINGS_RX_MINI_MAX,  /* u32 */
    ETHTOOL_A_RINGS_RX_JUMBO_MAX, /* u32 */
    ETHTOOL_A_RINGS_TX_MAX,       /* u32 */
    ETHTOOL_A_RINGS_RX,           /* u32 */
    ETHTOOL_A_RINGS_RX_MINI,      /* u32 */
    ETHTOOL_A_RINGS_RX_JUMBO,     /* u32 */
    ETHTOOL_A_RINGS_TX,           /* u32 */

    /* add new constants above here */
    __ETHTOOL_A_RINGS_CNT,
    ETHTOOL_A_RINGS_MAX = (__ETHTOOL_A_RINGS_CNT - 1)
};

static int
ethtool_parse_ring(const struct nl_msg *msg, void *data)
{
    NMEthtoolRingState            *ring     = data;
    static const struct nla_policy policy[] = {
        [ETHTOOL_A_RINGS_RX]       = {.type = NLA_U32},
        [ETHTOOL_A_RINGS_RX_MINI]  = {.type = NLA_U32},
        [ETHTOOL_A_RINGS_RX_JUMBO] = {.type = NLA_U32},
        [ETHTOOL_A_RINGS_TX]       = {.type = NLA_U32},
    };
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr     *tb[G_N_ELEMENTS(policy)];

    *ring = (NMEthtoolRingState) {};

    if (nla_parse_arr(tb, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), policy) < 0)
        return NL_SKIP;

    if (tb[ETHTOOL_A_RINGS_RX])
        ring->rx_pending = nla_get_u32(tb[ETHTOOL_A_RINGS_RX]);
    if (tb[ETHTOOL_A_RINGS_RX_MINI])
        ring->rx_mini_pending = nla_get_u32(tb[ETHTOOL_A_RINGS_RX_MINI]);
    if (tb[ETHTOOL_A_RINGS_RX_JUMBO])
        ring->rx_jumbo_pending = nla_get_u32(tb[ETHTOOL_A_RINGS_RX_JUMBO]);
    if (tb[ETHTOOL_A_RINGS_TX])
        ring->tx_pending = nla_get_u32(tb[ETHTOOL_A_RINGS_TX]);

    return NL_OK;
}

gboolean
nmp_ethtool_get_ring(struct nl_sock     *genl_sock,
                     guint16             family_id,
                     int                 ifindex,
                     NMEthtoolRingState *ring)
{
    nm_auto_nlmsg struct nl_msg *msg     = NULL;
    gs_free char                *err_msg = NULL;
    int                          r;

    g_return_val_if_fail(ring, FALSE);

    _LOGT("get-ring: start");
    *ring = (NMEthtoolRingState) {};

    msg = ethtool_create_msg(family_id,
                             ifindex,
                             ETHTOOL_MSG_RINGS_GET,
                             ETHTOOL_A_RINGS_HEADER,
                             0,
                             "get-ring");
    if (!msg)
        return FALSE;

    r = ethtool_send_and_recv(genl_sock,
                              ifindex,
                              msg,
                              ethtool_parse_ring,
                              ring,
                              &err_msg,
                              "get-ring");
    if (r < 0)
        return FALSE;

    _LOGT("get-ring: rx %u rx-mini %u rx-jumbo %u tx %u",
          ring->rx_pending,
          ring->rx_mini_pending,
          ring->rx_jumbo_pending,
          ring->tx_pending);

    return TRUE;
}

gboolean
nmp_ethtool_set_ring(struct nl_sock           *genl_sock,
                     guint16                   family_id,
                     int                       ifindex,
                     const NMEthtoolRingState *ring)
{
    nm_auto_nlmsg struct nl_msg *msg     = NULL;
    gs_free char                *err_msg = NULL;
    int                          r;

    g_return_val_if_fail(ring, FALSE);

    _LOGT("set-ring: rx %u rx-mini %u rx-jumbo %u tx %u",
          ring->rx_pending,
          ring->rx_mini_pending,
          ring->rx_jumbo_pending,
          ring->tx_pending);

    msg = ethtool_create_msg(family_id,
                             ifindex,
                             ETHTOOL_MSG_RINGS_SET,
                             ETHTOOL_A_RINGS_HEADER,
                             0,
                             "set-ring");
    if (!msg)
        return FALSE;

    NLA_PUT_U32(msg, ETHTOOL_A_RINGS_RX, ring->rx_pending);
    NLA_PUT_U32(msg, ETHTOOL_A_RINGS_RX_MINI, ring->rx_mini_pending);
    NLA_PUT_U32(msg, ETHTOOL_A_RINGS_RX_JUMBO, ring->rx_jumbo_pending);
    NLA_PUT_U32(msg, ETHTOOL_A_RINGS_TX, ring->tx_pending);

    r = ethtool_send_and_recv(genl_sock, ifindex, msg, NULL, NULL, &err_msg, "set-ring");
    if (r < 0)
        return FALSE;

    _LOGT("set-ring: succeeded");

    return TRUE;
nla_put_failure:
    g_return_val_if_reached(FALSE);
}

enum {
    ETHTOOL_A_LINKMODES_UNSPEC,
    ETHTOOL_A_LINKMODES_HEADER,             /* nest - _A_HEADER_* */
    ETHTOOL_A_LINKMODES_AUTONEG,            /* u8 */
    ETHTOOL_A_LINKMODES_OURS,               /* bitset */
    ETHTOOL_A_LINKMODES_PEER,               /* bitset */
    ETHTOOL_A_LINKMODES_SPEED,              /* u32 */
    ETHTOOL_A_LINKMODES_DUPLEX,             /* u8 */
    ETHTOOL_A_LINKMODES_MASTER_SLAVE_CFG,   /* u8 */
    ETHTOOL_A_LINKMODES_MASTER_SLAVE_STATE, /* u8 */
    ETHTOOL_A_LINKMODES_LANES,              /* u32 */
    ETHTOOL_A_LINKMODES_RATE_MATCHING,      /* u8 */

    __ETHTOOL_A_LINKMODES_CNT,
    ETHTOOL_A_LINKMODES_MAX = (__ETHTOOL_A_LINKMODES_CNT - 1)
};

enum {
    ETHTOOL_A_BITSET_UNSPEC,
    ETHTOOL_A_BITSET_NOMASK, /* flag */
    ETHTOOL_A_BITSET_SIZE,   /* u32 */
    ETHTOOL_A_BITSET_BITS,   /* nest */
    ETHTOOL_A_BITSET_VALUE,  /* binary */
    ETHTOOL_A_BITSET_MASK,   /* binary */

    __ETHTOOL_A_BITSET_CNT,
    ETHTOOL_A_BITSET_MAX = (__ETHTOOL_A_BITSET_CNT - 1)
};

#define ETHTOOL_FLAG_COMPACT_BITSETS ((guint32) (1u << 0))

typedef struct {
    guint32 speed;
    guint8  duplex;
} EthtoolLinkModeParam;

#define _DUPLEX_Half DUPLEX_HALF
#define _DUPLEX_Full DUPLEX_FULL

#define LM(_speed, _type, _duplex)                                  \
    [ETHTOOL_LINK_MODE_##_speed##base##_type##_##_duplex##_BIT] = { \
        .speed  = (_speed),                                         \
        .duplex = _DUPLEX_##_duplex,                                \
    }

/* From link_mode_params[] in the kernel's net/ethtool/common.c.
 * Zero-speed entries are capability bits. */
static const EthtoolLinkModeParam _link_mode_params[] = {
    LM(10, T, Half),
    LM(10, T, Full),
    LM(100, T, Half),
    LM(100, T, Full),
    LM(1000, T, Half),
    LM(1000, T, Full),
    LM(10000, T, Full),
    LM(2500, X, Full),
    LM(1000, KX, Full),
    LM(10000, KX4, Full),
    LM(10000, KR, Full),
    [ETHTOOL_LINK_MODE_10000baseR_FEC_BIT] = {.speed = 10000, .duplex = DUPLEX_FULL},
    LM(20000, MLD2, Full),
    LM(20000, KR2, Full),
    LM(40000, KR4, Full),
    LM(40000, CR4, Full),
    LM(40000, SR4, Full),
    LM(40000, LR4, Full),
    LM(56000, KR4, Full),
    LM(56000, CR4, Full),
    LM(56000, SR4, Full),
    LM(56000, LR4, Full),
    LM(25000, CR, Full),
    LM(25000, KR, Full),
    LM(25000, SR, Full),
    LM(50000, CR2, Full),
    LM(50000, KR2, Full),
    LM(100000, KR4, Full),
    LM(100000, SR4, Full),
    LM(100000, CR4, Full),
    LM(100000, LR4_ER4, Full),
    LM(50000, SR2, Full),
    LM(1000, X, Full),
    LM(10000, CR, Full),
    LM(10000, SR, Full),
    LM(10000, LR, Full),
    LM(10000, LRM, Full),
    LM(10000, ER, Full),
    LM(2500, T, Full),
    LM(5000, T, Full),
    LM(50000, KR, Full),
    LM(50000, SR, Full),
    LM(50000, CR, Full),
    LM(50000, LR_ER_FR, Full),
    LM(50000, DR, Full),
    LM(100000, KR2, Full),
    LM(100000, SR2, Full),
    LM(100000, CR2, Full),
    LM(100000, LR2_ER2_FR2, Full),
    LM(100000, DR2, Full),
    LM(200000, KR4, Full),
    LM(200000, SR4, Full),
    LM(200000, LR4_ER4_FR4, Full),
    LM(200000, DR4, Full),
    LM(200000, CR4, Full),
    LM(100, T1, Full),
    LM(1000, T1, Full),
    LM(400000, KR8, Full),
    LM(400000, SR8, Full),
    LM(400000, LR8_ER8_FR8, Full),
    LM(400000, DR8, Full),
    LM(400000, CR8, Full),
    LM(100000, KR, Full),
    LM(100000, SR, Full),
    LM(100000, LR_ER_FR, Full),
    LM(100000, CR, Full),
    LM(100000, DR, Full),
    LM(200000, KR2, Full),
    LM(200000, SR2, Full),
    LM(200000, LR2_ER2_FR2, Full),
    LM(200000, DR2, Full),
    LM(200000, CR2, Full),
    LM(400000, KR4, Full),
    LM(400000, SR4, Full),
    LM(400000, LR4_ER4_FR4, Full),
    LM(400000, DR4, Full),
    LM(400000, CR4, Full),
    LM(100, FX, Half),
    LM(100, FX, Full),
};

#undef LM
#undef _DUPLEX_Half
#undef _DUPLEX_Full

gboolean
_nmp_ethtool_link_mode_has_speed(guint bit)
{
    return bit < G_N_ELEMENTS(_link_mode_params) && _link_mode_params[bit].speed != 0;
}

/**
 * _nmp_ethtool_link_modes_mask_restrict:
 * @mask: the supported link modes, modified in place
 * @speed: the speed in Mbit/s
 * @duplex: %DUPLEX_HALF or %DUPLEX_FULL
 *
 * Clear the link modes that don't match @speed and @duplex, and those unknown
 * to our table. Capability bits (autoneg, port, pause, FEC) are kept. If no
 * known mode matches, @mask is emptied.
 *
 * Returns: %NM_OPTION_BOOL_TRUE if a known mode matches,
 *   %NM_OPTION_BOOL_DEFAULT if only modes unknown to our table might match,
 *   and %NM_OPTION_BOOL_FALSE if no mode matches.
 */
NMOptionBool
_nmp_ethtool_link_modes_mask_restrict(NMPEthtoolLinkModesMask *mask, guint32 speed, guint8 duplex)
{
    NMOptionBool match = NM_OPTION_BOOL_FALSE;
    guint        n_bits;
    guint        i;

    G_STATIC_ASSERT(G_N_ELEMENTS(_link_mode_params) == __ETHTOOL_LINK_MODE_MASK_NBITS);

    nm_assert(mask->len % sizeof(guint32) == 0);
    nm_assert(mask->len <= sizeof(mask->modes));

    n_bits = (mask->len / sizeof(guint32)) * 32u;

    for (i = 0; i < n_bits; i++) {
        guint32 bit = ((guint32) 1u) << (i % 32u);

        if (!(mask->modes[i / 32u] & bit))
            continue;
        if (i >= G_N_ELEMENTS(_link_mode_params)) {
            if (match == NM_OPTION_BOOL_FALSE)
                match = NM_OPTION_BOOL_DEFAULT;
        } else if (_link_mode_params[i].speed == 0)
            continue;
        else if (_link_mode_params[i].speed == speed && _link_mode_params[i].duplex == duplex) {
            match = NM_OPTION_BOOL_TRUE;
            continue;
        }
        mask->modes[i / 32u] &= ~bit;
    }

    if (match != NM_OPTION_BOOL_TRUE)
        mask->len = 0;

    return match;
}

static int
ethtool_parse_link_settings(const struct nl_msg *msg, void *data)
{
    NMEthtoolLinkSettingsState    *settings = data;
    static const struct nla_policy policy[] = {
        [ETHTOOL_A_LINKMODES_AUTONEG] = {.type = NLA_U8},
        [ETHTOOL_A_LINKMODES_SPEED]   = {.type = NLA_U32},
        [ETHTOOL_A_LINKMODES_DUPLEX]  = {.type = NLA_U8},
    };
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr     *tb[G_N_ELEMENTS(policy)];
    int                r;

    *settings = (NMEthtoolLinkSettingsState) {
        .duplex = NM_PLATFORM_LINK_DUPLEX_UNKNOWN,
    };

    r = nla_parse_arr(tb, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), policy);
    if (r < 0)
        return r;

    if (tb[ETHTOOL_A_LINKMODES_AUTONEG])
        settings->autoneg = (nla_get_u8(tb[ETHTOOL_A_LINKMODES_AUTONEG]) == AUTONEG_ENABLE);
    if (tb[ETHTOOL_A_LINKMODES_SPEED]) {
        guint32 speed = nla_get_u32(tb[ETHTOOL_A_LINKMODES_SPEED]);

        if (speed != (guint32) SPEED_UNKNOWN)
            settings->speed = speed;
    }
    if (tb[ETHTOOL_A_LINKMODES_DUPLEX]) {
        switch (nla_get_u8(tb[ETHTOOL_A_LINKMODES_DUPLEX])) {
        case DUPLEX_HALF:
            settings->duplex = NM_PLATFORM_LINK_DUPLEX_HALF;
            break;
        case DUPLEX_FULL:
            settings->duplex = NM_PLATFORM_LINK_DUPLEX_FULL;
            break;
        }
    }

    return NL_OK;
}

static int
ethtool_parse_link_modes_mask(const struct nl_msg *msg, void *data)
{
    NMPEthtoolLinkModesMask       *mask     = data;
    static const struct nla_policy policy[] = {
        [ETHTOOL_A_LINKMODES_OURS] = {.type = NLA_NESTED},
    };
    static const struct nla_policy policy_bitset[] = {
        [ETHTOOL_A_BITSET_SIZE] = {.type = NLA_U32},
        [ETHTOOL_A_BITSET_MASK] = {.type = NLA_UNSPEC},
    };
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr     *tb[G_N_ELEMENTS(policy)];
    struct nlattr     *tb_bitset[G_N_ELEMENTS(policy_bitset)];
    struct nlattr     *attr;
    int                r;

    *mask = (NMPEthtoolLinkModesMask) {};

    r = nla_parse_arr(tb, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), policy);
    if (r < 0)
        return r;

    if (!tb[ETHTOOL_A_LINKMODES_OURS])
        return NL_SKIP;

    r = nla_parse_nested_arr(tb_bitset, tb[ETHTOOL_A_LINKMODES_OURS], policy_bitset);
    if (r < 0)
        return r;

    /* with ETHTOOL_FLAG_COMPACT_BITSETS, "ours" is {SIZE, VALUE = advertising,
     * MASK = supported}, each mask an array of native-endian u32 words. */
    attr = tb_bitset[ETHTOOL_A_BITSET_MASK];
    if (!tb_bitset[ETHTOOL_A_BITSET_SIZE] || !attr)
        return NL_SKIP;

    mask->bits = nla_get_u32(tb_bitset[ETHTOOL_A_BITSET_SIZE]);
    if (mask->bits == 0 || mask->bits > sizeof(mask->modes) * 8u
        || nla_len(attr) != NM_DIV_ROUND_UP(mask->bits, 32u) * sizeof(guint32))
        return NL_SKIP;

    mask->len = nla_len(attr);
    nla_memcpy(mask->modes, attr, sizeof(mask->modes));

    return NL_OK;
}

gboolean
nmp_ethtool_get_link_settings(struct nl_sock             *genl_sock,
                              guint16                     family_id,
                              int                         ifindex,
                              NMEthtoolLinkSettingsState *settings)
{
    nm_auto_nlmsg struct nl_msg *msg     = NULL;
    gs_free char                *err_msg = NULL;
    int                          r;

    g_return_val_if_fail(settings, FALSE);

    _LOGT("get-link-settings: start");
    *settings = (NMEthtoolLinkSettingsState) {
        .duplex = NM_PLATFORM_LINK_DUPLEX_UNKNOWN,
    };

    msg = ethtool_create_msg(family_id,
                             ifindex,
                             ETHTOOL_MSG_LINKMODES_GET,
                             ETHTOOL_A_LINKMODES_HEADER,
                             ETHTOOL_FLAG_COMPACT_BITSETS,
                             "get-link-settings");
    if (!msg)
        return FALSE;

    r = ethtool_send_and_recv(genl_sock,
                              ifindex,
                              msg,
                              ethtool_parse_link_settings,
                              settings,
                              &err_msg,
                              "get-link-settings");
    if (r < 0)
        return FALSE;

    _LOGT("get-link-settings: autoneg %d speed %u duplex %s",
          settings->autoneg,
          settings->speed,
          nm_platform_link_duplex_type_to_string(settings->duplex));

    return TRUE;
}

static gboolean
ethtool_get_link_modes_mask(struct nl_sock          *genl_sock,
                            guint16                  family_id,
                            int                      ifindex,
                            NMPEthtoolLinkModesMask *mask)
{
    nm_auto_nlmsg struct nl_msg *msg     = NULL;
    gs_free char                *err_msg = NULL;
    int                          r;

    *mask = (NMPEthtoolLinkModesMask) {};

    msg = ethtool_create_msg(family_id,
                             ifindex,
                             ETHTOOL_MSG_LINKMODES_GET,
                             ETHTOOL_A_LINKMODES_HEADER,
                             ETHTOOL_FLAG_COMPACT_BITSETS,
                             "get-link-modes-mask");
    if (!msg)
        return FALSE;

    r = ethtool_send_and_recv(genl_sock,
                              ifindex,
                              msg,
                              ethtool_parse_link_modes_mask,
                              mask,
                              &err_msg,
                              "get-link-modes-mask");
    if (r < 0)
        return FALSE;

    return mask->len > 0;
}

gboolean
nmp_ethtool_set_link_settings(struct nl_sock                   *genl_sock,
                              guint16                           family_id,
                              int                               ifindex,
                              const NMEthtoolLinkSettingsState *settings)
{
    nm_auto_nlmsg struct nl_msg *msg     = NULL;
    gs_free char                *err_msg = NULL;
    NMPEthtoolLinkModesMask      mask    = {};
    guint8                       duplex  = DUPLEX_UNKNOWN;
    int                          r;

    g_return_val_if_fail(settings, FALSE);
    g_return_val_if_fail(
        (settings->speed != 0
         && NM_IN_SET(settings->duplex, NM_PLATFORM_LINK_DUPLEX_HALF, NM_PLATFORM_LINK_DUPLEX_FULL))
            || (settings->speed == 0 && settings->duplex == NM_PLATFORM_LINK_DUPLEX_UNKNOWN),
        FALSE);

    if (settings->speed != 0)
        duplex = settings->duplex == NM_PLATFORM_LINK_DUPLEX_FULL ? DUPLEX_FULL : DUPLEX_HALF;

    _LOGT("set-link-settings: autoneg %d speed %u duplex %s",
          settings->autoneg,
          settings->speed,
          nm_platform_link_duplex_type_to_string(settings->duplex));

    if (settings->autoneg && settings->speed == 0) {
        /* Restore all supported modes after a speed/duplex restriction. */
        if (!ethtool_get_link_modes_mask(genl_sock, family_id, ifindex, &mask))
            _LOGT("set-link-settings: supported link modes unknown, not resetting advertised "
                  "modes");
    } else if (settings->speed != 0) {
        /* Drivers such as ixgbe select forced speeds from advertising, which
         * the kernel only adjusts when autonegotiation is enabled. */
        if (ethtool_get_link_modes_mask(genl_sock, family_id, ifindex, &mask)) {
            NMOptionBool match;

            match = _nmp_ethtool_link_modes_mask_restrict(&mask, settings->speed, duplex);
            if (settings->autoneg) {
                /* Some PHY drivers accept advertising with no speed bits. */
                if (match == NM_OPTION_BOOL_FALSE) {
                    _LOGT("set-link-settings: no supported link mode matches");
                    return FALSE;
                }
                /* Omit OURS so the kernel selects matching modes, including ones
                 * newer than our headers. */
                mask.len = 0;
            } else if (mask.len == 0)
                _LOGT("set-link-settings: no supported link mode matches, not restricting "
                      "advertised modes");
        }
    }

    msg = ethtool_create_msg(family_id,
                             ifindex,
                             ETHTOOL_MSG_LINKMODES_SET,
                             ETHTOOL_A_LINKMODES_HEADER,
                             0,
                             "set-link-settings");
    if (!msg)
        return FALSE;

    NLA_PUT_U8(msg,
               ETHTOOL_A_LINKMODES_AUTONEG,
               settings->autoneg ? AUTONEG_ENABLE : AUTONEG_DISABLE);

    if (settings->speed != 0) {
        NLA_PUT_U32(msg, ETHTOOL_A_LINKMODES_SPEED, settings->speed);
        NLA_PUT_U8(msg, ETHTOOL_A_LINKMODES_DUPLEX, duplex);
    }

    if (mask.len > 0) {
        struct nlattr *nest;

        nest = nla_nest_start(msg, ETHTOOL_A_LINKMODES_OURS);
        NLA_PUT_FLAG(msg, ETHTOOL_A_BITSET_NOMASK);
        NLA_PUT_U32(msg, ETHTOOL_A_BITSET_SIZE, mask.bits);
        NLA_PUT(msg, ETHTOOL_A_BITSET_VALUE, mask.len, mask.modes);
        NLA_NEST_END(msg, nest);
    }

    r = ethtool_send_and_recv(genl_sock, ifindex, msg, NULL, NULL, &err_msg, "set-link-settings");
    if (r < 0)
        return FALSE;

    _LOGT("set-link-settings: succeeded");

    return TRUE;
nla_put_failure:
    g_return_val_if_reached(FALSE);
}
