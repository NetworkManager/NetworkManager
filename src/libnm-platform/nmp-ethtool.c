/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nmp-ethtool.h"

#include "libnm-platform/nm-platform.h"
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
                   const char *log_prefix)
{
    nm_auto_nlmsg struct nl_msg *msg = NULL;
    struct nlattr               *nest_header;

    if (family_id == 0) {
        _LOGT("%s: ethtool genl family not found", log_prefix);
        return NULL;
    }

    msg = nlmsg_alloc(nlmsg_total_size(GENL_HDRLEN) + 200);

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
