/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nmp-ethtool-ioctl.h"

#include "libnm-platform/nm-platform.h"
#include "libnm-platform/nm-platform-utils.h"
#include "libnm-log-core/nm-logging.h"
#include "libnm-base/nm-ethtool-base.h"

#include <linux/ethtool.h>
#include <linux/if.h>
#include <linux/mii.h>
#include <linux/sockios.h>
#include <linux/version.h>
#include <sys/ioctl.h>

#define ONOFF(bool_val) ((bool_val) ? "on" : "off")

/*****************************************************************************/

typedef struct {
    int       fd;
    const int ifindex;
    char      ifname[IFNAMSIZ];
} SocketHandle;

#define SOCKET_HANDLE_INIT(_ifindex) \
    {                                \
        .fd      = -1,               \
        .ifindex = (_ifindex),       \
    }

static void
_nm_auto_socket_handle(SocketHandle *shandle)
{
    if (shandle->fd >= 0)
        nm_close(shandle->fd);
}

#define nm_auto_socket_handle nm_auto(_nm_auto_socket_handle)

/*****************************************************************************/

typedef enum {
    IOCTL_CALL_DATA_TYPE_NONE,
    IOCTL_CALL_DATA_TYPE_IFRDATA,
    IOCTL_CALL_DATA_TYPE_IFRU,
} IoctlCallDataType;

static int
_ioctl_call(const char       *log_ioctl_type,
            const char       *log_subtype,
            unsigned long int ioctl_request,
            int               ifindex,
            int              *inout_fd,
            char             *inout_ifname,
            IoctlCallDataType edata_type,
            gpointer          edata,
            gsize             edata_size,
            struct ifreq     *out_ifreq)
{
    nm_auto_close int fd_close = -1;
    int               fd;
    int               r;
    gpointer          edata_backup      = NULL;
    gs_free gpointer  edata_backup_free = NULL;
    guint             try_count;
    char              known_ifnames[2][IFNAMSIZ];
    const char       *failure_reason = NULL;
    struct ifreq      ifr;

    nm_assert(ifindex > 0);
    nm_assert(NM_IN_SET(edata_type,
                        IOCTL_CALL_DATA_TYPE_NONE,
                        IOCTL_CALL_DATA_TYPE_IFRDATA,
                        IOCTL_CALL_DATA_TYPE_IFRU));
    nm_assert(edata_type != IOCTL_CALL_DATA_TYPE_NONE || edata_size == 0);
    nm_assert(edata_type != IOCTL_CALL_DATA_TYPE_IFRDATA || edata_size > 0);
    nm_assert(edata_type != IOCTL_CALL_DATA_TYPE_IFRU
              || (edata_size > 0 && edata_size <= sizeof(ifr.ifr_ifru)));
    nm_assert(edata_size == 0 || edata);

    /* open a file descriptor (or use the one provided). */
    if (inout_fd && *inout_fd >= 0)
        fd = *inout_fd;
    else {
        fd = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            r              = -NM_ERRNO_NATIVE(errno);
            failure_reason = "failed creating socket or ioctl";
            goto out;
        }
        if (inout_fd)
            *inout_fd = fd;
        else
            fd_close = fd;
    }

    /* resolve the ifindex to name (or use the one provided). */
    if (inout_ifname && inout_ifname[0])
        nm_utils_ifname_cpy(known_ifnames[0], inout_ifname);
    else {
        if (!nmp_utils_if_indextoname(ifindex, known_ifnames[0])) {
            failure_reason = "cannot resolve ifindex";
            r              = -ENODEV;
            goto out;
        }
        if (inout_ifname)
            nm_utils_ifname_cpy(inout_ifname, known_ifnames[0]);
    }

    /* we might need to retry the request. Backup edata so that we can
     * restore it on retry. */
    if (edata_size > 0)
        edata_backup = nm_memdup_maybe_a(500, edata, edata_size, &edata_backup_free);

    try_count = 0;

again:
{
    const char *ifname = known_ifnames[try_count % 2];

    nm_assert(ifindex > 0);
    nm_assert(ifname && nm_utils_ifname_valid_kernel(ifname, NULL));
    nm_assert(fd >= 0);

    memset(&ifr, 0, sizeof(ifr));
    nm_utils_ifname_cpy(ifr.ifr_name, ifname);
    if (edata_type == IOCTL_CALL_DATA_TYPE_IFRDATA)
        ifr.ifr_data = edata;
    else if (edata_type == IOCTL_CALL_DATA_TYPE_IFRU)
        memcpy(&ifr.ifr_ifru, edata, NM_MIN(edata_size, sizeof(ifr.ifr_ifru)));

    if (ioctl(fd, ioctl_request, &ifr) < 0) {
        r = -NM_ERRNO_NATIVE(errno);
        nm_log_trace(LOGD_PLATFORM,
                     "%s[%d]: %s, %s: failed: %s",
                     log_ioctl_type,
                     ifindex,
                     log_subtype,
                     ifname,
                     nm_strerror_native(-r));
    } else {
        r = 0;
        nm_log_trace(LOGD_PLATFORM,
                     "%s[%d]: %s, %s: success",
                     log_ioctl_type,
                     ifindex,
                     log_subtype,
                     ifname);
    }
}

    try_count++;

    /* resolve the name again to see whether the ifindex still has the same name. */
    if (!nmp_utils_if_indextoname(ifindex, known_ifnames[try_count % 2])) {
        /* we could not find the ifindex again. Probably the device just got
         * removed.
         *
         * In both cases we return the error code we got from ioctl above.
         * Either it failed because the device was gone already or it still
         * managed to complete the call. In both cases, the error code is good. */
        failure_reason =
            "cannot resolve ifindex after ioctl call. Probably the device was just removed";
        goto out;
    }

    /* check whether the ifname changed in the meantime. If yes, would render the result
     * invalid. Note that this cannot detect every race regarding renames, for example:
     *
     *  - if_indextoname(#10) gives eth0
     *  - rename(#10) => eth0_tmp
     *  - rename(#11) => eth0
     *  - ioctl(eth0) (wrongly fetching #11, formerly eth1)
     *  - rename(#11) => eth_something
     *  - rename(#10) => eth0
     *  - if_indextoname(#10) gives eth0
     */
    if (!nm_streq(known_ifnames[0], known_ifnames[1])) {
        gboolean retry;

        /* we detected a possible(!) rename.
         *
         * For getters it's straight forward to just retry the call.
         *
         * For setters we also always retry. If our previous call operated on the right device,
         * calling it again should have no bad effect (just setting the same thing more than once).
         *
         * The only potential bad thing is if there was a race involving swapping names, and we just
         * set the ioctl option on the wrong device. But then the bad thing already happenned and
         * we cannot detect it (nor do anything about it). At least, we can retry and set the
         * option on the right interface. */
        retry = (try_count < 5);

        nm_log_trace(LOGD_PLATFORM,
                     "%s[%d]: %s: rename detected from \"%s\" to \"%s\". %s",
                     log_ioctl_type,
                     ifindex,
                     log_subtype,
                     known_ifnames[(try_count - 1) % 2],
                     known_ifnames[try_count % 2],
                     retry ? "Retry" : "No retry");
        if (inout_ifname)
            nm_utils_ifname_cpy(inout_ifname, known_ifnames[try_count % 2]);
        if (retry) {
            if (edata_size > 0)
                memcpy(edata, edata_backup, edata_size);
            goto again;
        }
    }

out:
    if (failure_reason) {
        nm_log_trace(LOGD_PLATFORM,
                     "%s[%d]: %s: %s: %s",
                     log_ioctl_type,
                     ifindex,
                     log_subtype,
                     failure_reason,
                     r < 0 ? nm_strerror_native(-r) : "assume success");
    }
    if (r >= 0)
        NM_SET_OUT(out_ifreq, ifr);
    return r;
}

/******************************************************************************
 * ethtool
 *****************************************************************************/

static NM_UTILS_ENUM2STR_DEFINE(_ethtool_cmd_to_string,
                                guint32,
                                NM_UTILS_ENUM2STR(ETHTOOL_GCOALESCE, "ETHTOOL_GCOALESCE"),
                                NM_UTILS_ENUM2STR(ETHTOOL_GDRVINFO, "ETHTOOL_GDRVINFO"),
                                NM_UTILS_ENUM2STR(ETHTOOL_GFEATURES, "ETHTOOL_GFEATURES"),
                                NM_UTILS_ENUM2STR(ETHTOOL_GLINK, "ETHTOOL_GLINK"),
                                NM_UTILS_ENUM2STR(ETHTOOL_GLINKSETTINGS, "ETHTOOL_GLINKSETTINGS"),
                                NM_UTILS_ENUM2STR(ETHTOOL_GPERMADDR, "ETHTOOL_GPERMADDR"),
                                NM_UTILS_ENUM2STR(ETHTOOL_GRINGPARAM, "ETHTOOL_GRINGPARAM"),
                                NM_UTILS_ENUM2STR(ETHTOOL_GPAUSEPARAM, "ETHTOOL_GPAUSEPARAM"),
                                NM_UTILS_ENUM2STR(ETHTOOL_GSET, "ETHTOOL_GSET"),
                                NM_UTILS_ENUM2STR(ETHTOOL_GSSET_INFO, "ETHTOOL_GSSET_INFO"),
                                NM_UTILS_ENUM2STR(ETHTOOL_GSTATS, "ETHTOOL_GSTATS"),
                                NM_UTILS_ENUM2STR(ETHTOOL_GSTRINGS, "ETHTOOL_GSTRINGS"),
                                NM_UTILS_ENUM2STR(ETHTOOL_GWOL, "ETHTOOL_GWOL"),
                                NM_UTILS_ENUM2STR(ETHTOOL_SCOALESCE, "ETHTOOL_SCOALESCE"),
                                NM_UTILS_ENUM2STR(ETHTOOL_SFEATURES, "ETHTOOL_SFEATURES"),
                                NM_UTILS_ENUM2STR(ETHTOOL_SLINKSETTINGS, "ETHTOOL_SLINKSETTINGS"),
                                NM_UTILS_ENUM2STR(ETHTOOL_SRINGPARAM, "ETHTOOL_SRINGPARAM"),
                                NM_UTILS_ENUM2STR(ETHTOOL_SPAUSEPARAM, "ETHTOOL_SPAUSEPARAM"),
                                NM_UTILS_ENUM2STR(ETHTOOL_SSET, "ETHTOOL_SSET"),
                                NM_UTILS_ENUM2STR(ETHTOOL_SWOL, "ETHTOOL_SWOL"), );

static const char *
_ethtool_edata_to_string(gpointer edata, gsize edata_size, char *sbuf, gsize sbuf_len)
{
    nm_assert(edata);
    nm_assert(edata_size >= sizeof(guint32));
    nm_assert((((intptr_t) edata) % _nm_alignof(guint32)) == 0);

    return _ethtool_cmd_to_string(*((guint32 *) edata), sbuf, sbuf_len);
}

/*****************************************************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
#define ethtool_cmd_speed(pedata) ((pedata)->speed)

#define ethtool_cmd_speed_set(pedata, speed) \
    G_STMT_START                             \
    {                                        \
        (pedata)->speed = (guint16) (speed); \
    }                                        \
    G_STMT_END
#endif

static int
_ethtool_call_handle(SocketHandle *shandle, gpointer edata, gsize edata_size)
{
    char sbuf[50];

    return _ioctl_call("ethtool",
                       _ethtool_edata_to_string(edata, edata_size, sbuf, sizeof(sbuf)),
                       SIOCETHTOOL,
                       shandle->ifindex,
                       &shandle->fd,
                       shandle->ifname,
                       IOCTL_CALL_DATA_TYPE_IFRDATA,
                       edata,
                       edata_size,
                       NULL);
}

static int
_ethtool_call_once(int ifindex, gpointer edata, gsize edata_size)
{
    char sbuf[50];

    return _ioctl_call("ethtool",
                       _ethtool_edata_to_string(edata, edata_size, sbuf, sizeof(sbuf)),
                       SIOCETHTOOL,
                       ifindex,
                       NULL,
                       NULL,
                       IOCTL_CALL_DATA_TYPE_IFRDATA,
                       edata,
                       edata_size,
                       NULL);
}

/*****************************************************************************/

static struct ethtool_gstrings *
ethtool_get_stringset(SocketHandle *shandle, int stringset_id)
{
    struct {
        struct ethtool_sset_info info;
        guint32                  sentinel;
    } sset_info = {
        .info.cmd       = ETHTOOL_GSSET_INFO,
        .info.reserved  = 0,
        .info.sset_mask = (1ULL << stringset_id),
    };
    const guint32                   *pdata;
    gs_free struct ethtool_gstrings *gstrings = NULL;
    gsize                            gstrings_len;
    guint32                          i, len;

    if (_ethtool_call_handle(shandle, &sset_info, sizeof(sset_info)) < 0)
        return NULL;
    if (!sset_info.info.sset_mask)
        return NULL;

    pdata = (guint32 *) sset_info.info.data;

    len = *pdata;

    gstrings_len         = sizeof(*gstrings) + (len * ETH_GSTRING_LEN);
    gstrings             = g_malloc0(gstrings_len);
    gstrings->cmd        = ETHTOOL_GSTRINGS;
    gstrings->string_set = stringset_id;
    gstrings->len        = len;
    if (gstrings->len > 0) {
        if (_ethtool_call_handle(shandle, gstrings, gstrings_len) < 0)
            return NULL;
        for (i = 0; i < gstrings->len; i++) {
            /* ensure NUL terminated */
            gstrings->data[i * ETH_GSTRING_LEN + (ETH_GSTRING_LEN - 1)] = '\0';
        }
    }

    return g_steal_pointer(&gstrings);
}

static int
ethtool_gstrings_find(const struct ethtool_gstrings *gstrings, const char *needle)
{
    guint32 i;

    /* ethtool_get_stringset() always ensures NUL terminated strings at ETH_GSTRING_LEN.
     * that means, we cannot possibly request longer names. */
    nm_assert(needle && strlen(needle) < ETH_GSTRING_LEN);

    for (i = 0; i < gstrings->len; i++) {
        if (nm_streq((char *) &gstrings->data[i * ETH_GSTRING_LEN], needle))
            return i;
    }
    return -1;
}

static int
ethtool_get_stringset_index(SocketHandle *shandle, int stringset_id, const char *needle)
{
    gs_free struct ethtool_gstrings *gstrings = NULL;

    /* ethtool_get_stringset() always ensures NUL terminated strings at ETH_GSTRING_LEN.
     * that means, we cannot possibly request longer names. */
    nm_assert(needle && strlen(needle) < ETH_GSTRING_LEN);

    gstrings = ethtool_get_stringset(shandle, stringset_id);
    if (gstrings)
        return ethtool_gstrings_find(gstrings, needle);
    return -1;
}

/*****************************************************************************/

static const NMEthtoolFeatureInfo _ethtool_feature_infos[_NM_ETHTOOL_ID_FEATURE_NUM] = {
#define ETHT_FEAT(eid, ...)                                      \
    {                                                            \
        .ethtool_id     = eid,                                   \
        .n_kernel_names = NM_NARG(__VA_ARGS__),                  \
        .kernel_names   = ((const char *const[]) {__VA_ARGS__}), \
    }

    /* the order does only matter for one thing: if it happens that more than one NMEthtoolID
     * reference the same kernel-name, then the one that is mentioned *later* will win in
     * case these NMEthtoolIDs are set. That mostly only makes sense for ethtool-ids which
     * refer to multiple features ("feature-tso"), while also having more specific ids
     * ("feature-tx-tcp-segmentation"). */

    /* names from ethtool utility, which are aliases for multiple features. */
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_SG, "tx-scatter-gather", "tx-scatter-gather-fraglist"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TSO,
              "tx-tcp-segmentation",
              "tx-tcp-ecn-segmentation",
              "tx-tcp-mangleid-segmentation",
              "tx-tcp6-segmentation"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX,
              "tx-checksum-ipv4",
              "tx-checksum-ip-generic",
              "tx-checksum-ipv6",
              "tx-checksum-fcoe-crc",
              "tx-checksum-sctp"),

    /* names from ethtool utility, which are aliases for one feature. */
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_GRO, "rx-gro"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_GSO, "tx-generic-segmentation"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_LRO, "rx-lro"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_NTUPLE, "rx-ntuple-filter"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_RX, "rx-checksum"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_RXHASH, "rx-hashing"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_RXVLAN, "rx-vlan-hw-parse"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TXVLAN, "tx-vlan-hw-insert"),

    /* names of features, as known by kernel. */
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_ESP_HW_OFFLOAD, "esp-hw-offload"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_ESP_TX_CSUM_HW_OFFLOAD, "esp-tx-csum-hw-offload"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_FCOE_MTU, "fcoe-mtu"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_HIGHDMA, "highdma"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_HW_TC_OFFLOAD, "hw-tc-offload"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_L2_FWD_OFFLOAD, "l2-fwd-offload"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_LOOPBACK, "loopback"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_MACSEC_HW_OFFLOAD, "macsec-hw-offload"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_RX_ALL, "rx-all"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_RX_FCS, "rx-fcs"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_RX_GRO_HW, "rx-gro-hw"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_RX_GRO_LIST, "rx-gro-list"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_RX_UDP_GRO_FORWARDING, "rx-udp-gro-forwarding"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_RX_UDP_TUNNEL_PORT_OFFLOAD, "rx-udp_tunnel-port-offload"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_RX_VLAN_FILTER, "rx-vlan-filter"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_RX_VLAN_STAG_FILTER, "rx-vlan-stag-filter"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_RX_VLAN_STAG_HW_PARSE, "rx-vlan-stag-hw-parse"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TLS_HW_RECORD, "tls-hw-record"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TLS_HW_RX_OFFLOAD, "tls-hw-rx-offload"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TLS_HW_TX_OFFLOAD, "tls-hw-tx-offload"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_CHECKSUM_FCOE_CRC, "tx-checksum-fcoe-crc"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_CHECKSUM_IPV4, "tx-checksum-ipv4"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_CHECKSUM_IPV6, "tx-checksum-ipv6"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_CHECKSUM_IP_GENERIC, "tx-checksum-ip-generic"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_CHECKSUM_SCTP, "tx-checksum-sctp"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_ESP_SEGMENTATION, "tx-esp-segmentation"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_FCOE_SEGMENTATION, "tx-fcoe-segmentation"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_GRE_CSUM_SEGMENTATION, "tx-gre-csum-segmentation"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_GRE_SEGMENTATION, "tx-gre-segmentation"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_GSO_LIST, "tx-gso-list"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_GSO_PARTIAL, "tx-gso-partial"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_GSO_ROBUST, "tx-gso-robust"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_IPXIP4_SEGMENTATION, "tx-ipxip4-segmentation"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_IPXIP6_SEGMENTATION, "tx-ipxip6-segmentation"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_NOCACHE_COPY, "tx-nocache-copy"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_SCATTER_GATHER, "tx-scatter-gather"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_SCATTER_GATHER_FRAGLIST, "tx-scatter-gather-fraglist"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_SCTP_SEGMENTATION, "tx-sctp-segmentation"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_TCP6_SEGMENTATION, "tx-tcp6-segmentation"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_TCP_ECN_SEGMENTATION, "tx-tcp-ecn-segmentation"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_TCP_MANGLEID_SEGMENTATION, "tx-tcp-mangleid-segmentation"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_TCP_SEGMENTATION, "tx-tcp-segmentation"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_TUNNEL_REMCSUM_SEGMENTATION,
              "tx-tunnel-remcsum-segmentation"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_UDP_SEGMENTATION, "tx-udp-segmentation"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_UDP_TNL_CSUM_SEGMENTATION, "tx-udp_tnl-csum-segmentation"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_UDP_TNL_SEGMENTATION, "tx-udp_tnl-segmentation"),
    ETHT_FEAT(NM_ETHTOOL_ID_FEATURE_TX_VLAN_STAG_HW_INSERT, "tx-vlan-stag-hw-insert"),
};

/* the number of kernel features that we handle. It essentially is the sum of all
 * kernel_names. So, all ethtool-ids that reference exactly one kernel-name
 * (_NM_ETHTOOL_ID_FEATURE_NUM) + some extra, for ethtool-ids that are aliases
 * for multiple kernel-names. */
#define N_ETHTOOL_KERNEL_FEATURES (((guint) _NM_ETHTOOL_ID_FEATURE_NUM) + 8u)

static void
_ASSERT_ethtool_feature_infos(void)
{
#if NM_MORE_ASSERTS > 10
    guint i, k, n;
    bool  found[_NM_ETHTOOL_ID_FEATURE_NUM] = {};

    G_STATIC_ASSERT_EXPR(G_N_ELEMENTS(_ethtool_feature_infos) == _NM_ETHTOOL_ID_FEATURE_NUM);

    n = 0;
    for (i = 0; i < G_N_ELEMENTS(_ethtool_feature_infos); i++) {
        NMEthtoolFeatureState       kstate;
        const NMEthtoolFeatureInfo *inf = &_ethtool_feature_infos[i];

        g_assert(inf->ethtool_id >= _NM_ETHTOOL_ID_FEATURE_FIRST);
        g_assert(inf->ethtool_id <= _NM_ETHTOOL_ID_FEATURE_LAST);
        g_assert(inf->n_kernel_names > 0);

        for (k = 0; k < i; k++)
            g_assert(inf->ethtool_id != _ethtool_feature_infos[k].ethtool_id);

        g_assert(!found[_NM_ETHTOOL_ID_FEATURE_AS_IDX(inf->ethtool_id)]);
        found[_NM_ETHTOOL_ID_FEATURE_AS_IDX(inf->ethtool_id)] = TRUE;

        kstate.idx_kernel_name = inf->n_kernel_names - 1;
        g_assert((guint) kstate.idx_kernel_name == (guint) (inf->n_kernel_names - 1));

        n += inf->n_kernel_names;
        for (k = 0; k < inf->n_kernel_names; k++) {
            const char *name = inf->kernel_names[k];

            g_assert(!nm_strv_contains(inf->kernel_names, k, name));

            /* these offload features are only informational and cannot be set from user-space
             * (NETIF_F_NEVER_CHANGE). We should not track them in _ethtool_feature_infos. */
            g_assert(!nm_streq(name, "netns-local"));
            g_assert(!nm_streq(name, "tx-lockless"));
            g_assert(!nm_streq(name, "vlan-challenged"));
        }
    }

    for (i = 0; i < _NM_ETHTOOL_ID_FEATURE_NUM; i++)
        g_assert(found[i]);

    g_assert(n == N_ETHTOOL_KERNEL_FEATURES);
#endif
}

static NMEthtoolFeatureStates *
ethtool_get_features(SocketHandle *shandle)
{
    gs_free NMEthtoolFeatureStates  *states      = NULL;
    gs_free struct ethtool_gstrings *ss_features = NULL;

    _ASSERT_ethtool_feature_infos();

    ss_features = ethtool_get_stringset(shandle, ETH_SS_FEATURES);
    if (!ss_features)
        return NULL;

    if (ss_features->len > 0) {
        gs_free struct ethtool_gfeatures   *gfeatures_free = NULL;
        struct ethtool_gfeatures           *gfeatures;
        gsize                               gfeatures_len;
        guint                               idx;
        const NMEthtoolFeatureState        *states_list0   = NULL;
        const NMEthtoolFeatureState *const *states_plist0  = NULL;
        guint                               states_plist_n = 0;

        gfeatures_len = sizeof(struct ethtool_gfeatures)
                        + (NM_DIV_ROUND_UP(ss_features->len, 32u) * sizeof(gfeatures->features[0]));
        gfeatures       = nm_malloc0_maybe_a(300, gfeatures_len, &gfeatures_free);
        gfeatures->cmd  = ETHTOOL_GFEATURES;
        gfeatures->size = NM_DIV_ROUND_UP(ss_features->len, 32u);
        if (_ethtool_call_handle(shandle, gfeatures, gfeatures_len) < 0)
            return NULL;

        for (idx = 0; idx < G_N_ELEMENTS(_ethtool_feature_infos); idx++) {
            const NMEthtoolFeatureInfo *info = &_ethtool_feature_infos[idx];
            guint                       idx_kernel_name;

            for (idx_kernel_name = 0; idx_kernel_name < info->n_kernel_names; idx_kernel_name++) {
                NMEthtoolFeatureState *kstate;
                const char            *kernel_name = info->kernel_names[idx_kernel_name];
                int                    i_feature;
                guint                  i_block;
                guint32                i_flag;

                i_feature = ethtool_gstrings_find(ss_features, kernel_name);
                if (i_feature < 0)
                    continue;

                i_block = ((guint) i_feature) / 32u;
                i_flag  = (guint32) (1u << (((guint) i_feature) % 32u));

                if (!states) {
                    states = g_malloc0(
                        sizeof(NMEthtoolFeatureStates)
                        + (N_ETHTOOL_KERNEL_FEATURES * sizeof(NMEthtoolFeatureState))
                        + ((N_ETHTOOL_KERNEL_FEATURES + G_N_ELEMENTS(_ethtool_feature_infos))
                           * sizeof(NMEthtoolFeatureState *)));
                    states_list0          = &states->states_list[0];
                    states_plist0         = (gpointer) &states_list0[N_ETHTOOL_KERNEL_FEATURES];
                    states->n_ss_features = ss_features->len;
                }

                nm_assert(states->n_states < N_ETHTOOL_KERNEL_FEATURES);
                kstate = (NMEthtoolFeatureState *) &states_list0[states->n_states];
                states->n_states++;

                kstate->info            = info;
                kstate->idx_ss_features = i_feature;
                kstate->idx_kernel_name = idx_kernel_name;
                kstate->available       = !!(gfeatures->features[i_block].available & i_flag);
                kstate->requested       = !!(gfeatures->features[i_block].requested & i_flag);
                kstate->active          = !!(gfeatures->features[i_block].active & i_flag);
                kstate->never_changed   = !!(gfeatures->features[i_block].never_changed & i_flag);

                nm_assert(states_plist_n
                          < N_ETHTOOL_KERNEL_FEATURES + G_N_ELEMENTS(_ethtool_feature_infos));

                if (!states->states_indexed[_NM_ETHTOOL_ID_FEATURE_AS_IDX(info->ethtool_id)])
                    states->states_indexed[_NM_ETHTOOL_ID_FEATURE_AS_IDX(info->ethtool_id)] =
                        &states_plist0[states_plist_n];
                ((const NMEthtoolFeatureState **) states_plist0)[states_plist_n] = kstate;
                states_plist_n++;
            }

            if (states && states->states_indexed[_NM_ETHTOOL_ID_FEATURE_AS_IDX(info->ethtool_id)]) {
                nm_assert(states_plist_n
                          < N_ETHTOOL_KERNEL_FEATURES + G_N_ELEMENTS(_ethtool_feature_infos));
                nm_assert(!states_plist0[states_plist_n]);
                states_plist_n++;
            }
        }
    }

    return g_steal_pointer(&states);
}

NMEthtoolFeatureStates *
nmp_ethtool_ioctl_get_features(int ifindex)
{
    nm_auto_socket_handle SocketHandle shandle = SOCKET_HANDLE_INIT(ifindex);
    NMEthtoolFeatureStates            *features;

    g_return_val_if_fail(ifindex > 0, 0);

    features = ethtool_get_features(&shandle);

    if (!features) {
        nm_log_trace(LOGD_PLATFORM,
                     "ethtool[%d]: %s: failure getting features",
                     ifindex,
                     "get-features");
        return NULL;
    }

    nm_log_trace(LOGD_PLATFORM,
                 "ethtool[%d]: %s: retrieved kernel features",
                 ifindex,
                 "get-features");
    return features;
}

static const char *
_ethtool_feature_state_to_string(char                        *buf,
                                 gsize                        buf_size,
                                 const NMEthtoolFeatureState *s,
                                 const char                  *prefix)
{
    int l;

    l = g_snprintf(buf,
                   buf_size,
                   "%s %s%s",
                   prefix ?: "",
                   ONOFF(s->active),
                   (!s->available || s->never_changed)
                       ? ", [fixed]"
                       : ((s->requested != s->active)
                              ? (s->requested ? ", [requested on]" : ", [requested off]")
                              : ""));
    nm_assert(l < buf_size);
    return buf;
}

gboolean
nmp_ethtool_ioctl_set_features(
    int                           ifindex,
    const NMEthtoolFeatureStates *features,
    const NMOptionBool *requested /* indexed by NMEthtoolID - _NM_ETHTOOL_ID_FEATURE_FIRST */,
    gboolean            do_set /* or reset */)
{
    nm_auto_socket_handle SocketHandle shandle        = SOCKET_HANDLE_INIT(ifindex);
    gs_free struct ethtool_sfeatures  *sfeatures_free = NULL;
    struct ethtool_sfeatures          *sfeatures;
    gsize                              sfeatures_len;
    int                                r;
    guint                              i, j;
    struct {
        const NMEthtoolFeatureState *f_state;
        NMOptionBool                 requested;
    } set_states[N_ETHTOOL_KERNEL_FEATURES];
    guint    set_states_n = 0;
    gboolean success      = TRUE;

    g_return_val_if_fail(ifindex > 0, 0);
    g_return_val_if_fail(features, 0);
    g_return_val_if_fail(requested, 0);

    nm_assert(features->n_states <= N_ETHTOOL_KERNEL_FEATURES);

    for (i = 0; i < _NM_ETHTOOL_ID_FEATURE_NUM; i++) {
        const NMEthtoolFeatureState *const *states_indexed;

        if (requested[i] == NM_OPTION_BOOL_DEFAULT)
            continue;

        if (!(states_indexed = features->states_indexed[i])) {
            if (do_set) {
                nm_log_trace(LOGD_PLATFORM,
                             "ethtool[%d]: %s: set feature %s: skip (not found)",
                             ifindex,
                             "set-features",
                             nm_ethtool_data[i + _NM_ETHTOOL_ID_FEATURE_FIRST]->optname);
                success = FALSE;
            }
            continue;
        }

        for (j = 0; states_indexed[j]; j++) {
            const NMEthtoolFeatureState *s = states_indexed[j];
            char                         sbuf[255];

            if (set_states_n >= G_N_ELEMENTS(set_states))
                g_return_val_if_reached(FALSE);

            if (s->never_changed) {
                nm_log_trace(LOGD_PLATFORM,
                             "ethtool[%d]: %s: %s feature %s (%s): %s, %s (skip feature marked as "
                             "never changed)",
                             ifindex,
                             "set-features",
                             do_set ? "set" : "reset",
                             nm_ethtool_data[i + _NM_ETHTOOL_ID_FEATURE_FIRST]->optname,
                             s->info->kernel_names[s->idx_kernel_name],
                             ONOFF(do_set ? requested[i] == NM_OPTION_BOOL_TRUE : s->active),
                             _ethtool_feature_state_to_string(sbuf,
                                                              sizeof(sbuf),
                                                              s,
                                                              do_set ? " currently:" : " before:"));
                continue;
            }

            nm_log_trace(LOGD_PLATFORM,
                         "ethtool[%d]: %s: %s feature %s (%s): %s, %s",
                         ifindex,
                         "set-features",
                         do_set ? "set" : "reset",
                         nm_ethtool_data[i + _NM_ETHTOOL_ID_FEATURE_FIRST]->optname,
                         s->info->kernel_names[s->idx_kernel_name],
                         ONOFF(do_set ? requested[i] == NM_OPTION_BOOL_TRUE : s->active),
                         _ethtool_feature_state_to_string(sbuf,
                                                          sizeof(sbuf),
                                                          s,
                                                          do_set ? " currently:" : " before:"));

            if (do_set && (!s->available || s->never_changed)
                && (s->active != (requested[i] == NM_OPTION_BOOL_TRUE))) {
                /* we request to change a flag which kernel reported as fixed.
                 * While the ethtool operation will silently succeed, mark the request
                 * as failure. */
                success = FALSE;
            }

            set_states[set_states_n].f_state   = s;
            set_states[set_states_n].requested = requested[i];
            set_states_n++;
        }
    }

    if (set_states_n == 0) {
        nm_log_trace(LOGD_PLATFORM,
                     "ethtool[%d]: %s: no feature requested",
                     ifindex,
                     "set-features");
        return TRUE;
    }

    sfeatures_len =
        sizeof(struct ethtool_sfeatures)
        + (NM_DIV_ROUND_UP(features->n_ss_features, 32U) * sizeof(sfeatures->features[0]));
    sfeatures       = nm_malloc0_maybe_a(300, sfeatures_len, &sfeatures_free);
    sfeatures->cmd  = ETHTOOL_SFEATURES;
    sfeatures->size = NM_DIV_ROUND_UP(features->n_ss_features, 32U);

    for (i = 0; i < set_states_n; i++) {
        const NMEthtoolFeatureState *s = set_states[i].f_state;
        guint                        i_block;
        guint32                      i_flag;
        gboolean                     is_requested;

        i_block = s->idx_ss_features / 32u;
        i_flag  = (guint32) (1u << (s->idx_ss_features % 32u));

        sfeatures->features[i_block].valid |= i_flag;

        if (do_set)
            is_requested = (set_states[i].requested == NM_OPTION_BOOL_TRUE);
        else
            is_requested = s->active;

        if (is_requested)
            sfeatures->features[i_block].requested |= i_flag;
        else
            sfeatures->features[i_block].requested &= ~i_flag;
    }

    r = _ethtool_call_handle(&shandle, sfeatures, sfeatures_len);
    if (r < 0) {
        success = FALSE;
        nm_log_trace(LOGD_PLATFORM,
                     "ethtool[%d]: %s: failure setting features (%s)",
                     ifindex,
                     "set-features",
                     nm_strerror_native(-r));
        return FALSE;
    }

    nm_log_trace(LOGD_PLATFORM,
                 "ethtool[%d]: %s: %s",
                 ifindex,
                 "set-features",
                 success ? "successfully setting features"
                         : "at least some of the features were not successfully set");
    return success;
}

gboolean
nmp_ethtool_ioctl_get_coalesce(int ifindex, NMEthtoolCoalesceState *coalesce)
{
    struct ethtool_coalesce eth_data;

    g_return_val_if_fail(ifindex > 0, FALSE);
    g_return_val_if_fail(coalesce, FALSE);

    eth_data.cmd = ETHTOOL_GCOALESCE;

    if (_ethtool_call_once(ifindex, &eth_data, sizeof(eth_data)) < 0) {
        nm_log_trace(LOGD_PLATFORM,
                     "ethtool[%d]: %s: failure getting coalesce settings",
                     ifindex,
                     "get-coalesce");
        return FALSE;
    }

    *coalesce = (NMEthtoolCoalesceState) {
        .s = {
            [_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_RX_USECS)] =
                eth_data.rx_coalesce_usecs,
            [_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_RX_FRAMES)] =
                eth_data.rx_max_coalesced_frames,
            [_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_RX_USECS_IRQ)] =
                eth_data.rx_coalesce_usecs_irq,
            [_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_RX_FRAMES_IRQ)] =
                eth_data.rx_max_coalesced_frames_irq,
            [_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_TX_USECS)] =
                eth_data.tx_coalesce_usecs,
            [_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_TX_FRAMES)] =
                eth_data.tx_max_coalesced_frames,
            [_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_TX_USECS_IRQ)] =
                eth_data.tx_coalesce_usecs_irq,
            [_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_TX_FRAMES_IRQ)] =
                eth_data.tx_max_coalesced_frames_irq,
            [_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_STATS_BLOCK_USECS)] =
                eth_data.stats_block_coalesce_usecs,
            [_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_ADAPTIVE_RX)] =
                eth_data.use_adaptive_rx_coalesce,
            [_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_ADAPTIVE_TX)] =
                eth_data.use_adaptive_tx_coalesce,
            [_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_PKT_RATE_LOW)] =
                eth_data.pkt_rate_low,
            [_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_RX_USECS_LOW)] =
                eth_data.rx_coalesce_usecs_low,
            [_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_RX_FRAMES_LOW)] =
                eth_data.rx_max_coalesced_frames_low,
            [_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_TX_USECS_LOW)] =
                eth_data.tx_coalesce_usecs_low,
            [_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_TX_FRAMES_LOW)] =
                eth_data.tx_max_coalesced_frames_low,
            [_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_PKT_RATE_HIGH)] =
                eth_data.pkt_rate_high,
            [_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_RX_USECS_HIGH)] =
                eth_data.rx_coalesce_usecs_high,
            [_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_RX_FRAMES_HIGH)] =
                eth_data.rx_max_coalesced_frames_high,
            [_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_TX_USECS_HIGH)] =
                eth_data.tx_coalesce_usecs_high,
            [_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_TX_FRAMES_HIGH)] =
                eth_data.tx_max_coalesced_frames_high,
            [_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_SAMPLE_INTERVAL)] =
                eth_data.rate_sample_interval,
        }};
    return TRUE;

    nm_log_trace(LOGD_PLATFORM,
                 "ethtool[%d]: %s: retrieved kernel coalesce settings",
                 ifindex,
                 "get-coalesce");
    return TRUE;
}

gboolean
nmp_ethtool_ioctl_set_coalesce(int ifindex, const NMEthtoolCoalesceState *coalesce)
{
    struct ethtool_coalesce eth_data;

    g_return_val_if_fail(ifindex > 0, FALSE);
    g_return_val_if_fail(coalesce, FALSE);

    eth_data = (struct ethtool_coalesce) {
        .cmd = ETHTOOL_SCOALESCE,
        .rx_coalesce_usecs =
            coalesce->s[_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_RX_USECS)],
        .rx_max_coalesced_frames =
            coalesce->s[_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_RX_FRAMES)],
        .rx_coalesce_usecs_irq =
            coalesce->s[_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_RX_USECS_IRQ)],
        .rx_max_coalesced_frames_irq =
            coalesce->s[_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_RX_FRAMES_IRQ)],
        .tx_coalesce_usecs =
            coalesce->s[_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_TX_USECS)],
        .tx_max_coalesced_frames =
            coalesce->s[_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_TX_FRAMES)],
        .tx_coalesce_usecs_irq =
            coalesce->s[_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_TX_USECS_IRQ)],
        .tx_max_coalesced_frames_irq =
            coalesce->s[_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_TX_FRAMES_IRQ)],
        .stats_block_coalesce_usecs =
            coalesce->s[_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_STATS_BLOCK_USECS)],
        .use_adaptive_rx_coalesce =
            coalesce->s[_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_ADAPTIVE_RX)],
        .use_adaptive_tx_coalesce =
            coalesce->s[_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_ADAPTIVE_TX)],
        .pkt_rate_low =
            coalesce->s[_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_PKT_RATE_LOW)],
        .rx_coalesce_usecs_low =
            coalesce->s[_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_RX_USECS_LOW)],
        .rx_max_coalesced_frames_low =
            coalesce->s[_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_RX_FRAMES_LOW)],
        .tx_coalesce_usecs_low =
            coalesce->s[_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_TX_USECS_LOW)],
        .tx_max_coalesced_frames_low =
            coalesce->s[_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_TX_FRAMES_LOW)],
        .pkt_rate_high =
            coalesce->s[_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_PKT_RATE_HIGH)],
        .rx_coalesce_usecs_high =
            coalesce->s[_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_RX_USECS_HIGH)],
        .rx_max_coalesced_frames_high =
            coalesce->s[_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_RX_FRAMES_HIGH)],
        .tx_coalesce_usecs_high =
            coalesce->s[_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_TX_USECS_HIGH)],
        .tx_max_coalesced_frames_high =
            coalesce->s[_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_TX_FRAMES_HIGH)],
        .rate_sample_interval =
            coalesce->s[_NM_ETHTOOL_ID_COALESCE_AS_IDX(NM_ETHTOOL_ID_COALESCE_SAMPLE_INTERVAL)],
    };

    if (_ethtool_call_once(ifindex, &eth_data, sizeof(eth_data)) < 0) {
        nm_log_trace(LOGD_PLATFORM,
                     "ethtool[%d]: %s: failure setting coalesce settings",
                     ifindex,
                     "set-coalesce");
        return FALSE;
    }

    nm_log_trace(LOGD_PLATFORM,
                 "ethtool[%d]: %s: set kernel coalesce settings",
                 ifindex,
                 "set-coalesce");
    return TRUE;
}

gboolean
nmp_ethtool_ioctl_get_channels(int ifindex, NMEthtoolChannelsState *channels)
{
    struct ethtool_channels eth_data;

    g_return_val_if_fail(ifindex > 0, FALSE);
    g_return_val_if_fail(channels, FALSE);

    eth_data.cmd = ETHTOOL_GCHANNELS;

    if (_ethtool_call_once(ifindex, &eth_data, sizeof(eth_data)) < 0) {
        nm_log_trace(LOGD_PLATFORM,
                     "ethtool[%d]: %s: failure getting channels settings",
                     ifindex,
                     "get-channels");
        return FALSE;
    }

    *channels = (NMEthtoolChannelsState) {
        .rx       = eth_data.rx_count,
        .tx       = eth_data.tx_count,
        .other    = eth_data.other_count,
        .combined = eth_data.combined_count,
    };

    nm_log_trace(LOGD_PLATFORM,
                 "ethtool[%d]: %s: retrieved kernel channels settings",
                 ifindex,
                 "get-channels");
    return TRUE;
}

gboolean
nmp_ethtool_ioctl_set_channels(int ifindex, const NMEthtoolChannelsState *channels)
{
    struct ethtool_channels eth_data;

    g_return_val_if_fail(ifindex > 0, FALSE);
    g_return_val_if_fail(channels, FALSE);

    eth_data = (struct ethtool_channels) {
        .cmd            = ETHTOOL_SCHANNELS,
        .rx_count       = channels->rx,
        .tx_count       = channels->tx,
        .other_count    = channels->other,
        .combined_count = channels->combined,
    };

    if (_ethtool_call_once(ifindex, &eth_data, sizeof(eth_data)) < 0) {
        nm_log_trace(LOGD_PLATFORM,
                     "ethtool[%d]: %s: failure setting channels settings",
                     ifindex,
                     "set-channels");
        return FALSE;
    }

    nm_log_trace(LOGD_PLATFORM,
                 "ethtool[%d]: %s: set kernel channels settings",
                 ifindex,
                 "set-channels");
    return TRUE;
}

gboolean
nmp_ethtool_ioctl_get_fec_mode(int ifindex, uint32_t *fec_mode)
{
    int                     r;
    struct ethtool_fecparam fec_param = {
        .cmd = ETHTOOL_GFECPARAM,
        .fec = 0,
    };

    g_return_val_if_fail(ifindex > 0, FALSE);

    if (_ethtool_call_once(ifindex, &fec_param, sizeof(fec_param)) >= 0) {
        nm_log_dbg(LOGD_PLATFORM, "ethtool[%d]: get FEC options 0x%x", ifindex, fec_param.fec);
        *fec_mode = fec_param.fec;
        return TRUE;
    } else {
        r = -NM_ERRNO_NATIVE(errno);
        nm_log_dbg(LOGD_PLATFORM,
                   "ethtool[%d]: ETHTOOL_GFECPARAM failure get fec mode: (%s)",
                   ifindex,
                   nm_strerror_native(-r));
        return FALSE;
    }
}

gboolean
nmp_ethtool_ioctl_set_fec_mode(int ifindex, uint32_t fec_mode)
{
    struct ethtool_fecparam fec_param = {
        .cmd = ETHTOOL_SFECPARAM,
        .fec = fec_mode,
    };

    g_return_val_if_fail(ifindex > 0, FALSE);

    nm_log_dbg(LOGD_PLATFORM, "ethtool[%d]: setting FEC options 0x%x", ifindex, fec_mode);

    return _ethtool_call_once(ifindex, &fec_param, sizeof(fec_param)) >= 0;
}

/*****************************************************************************/

gboolean
nmp_ethtool_ioctl_get_driver_info(int ifindex, NMPUtilsEthtoolDriverInfo *data)
{
    struct ethtool_drvinfo *drvinfo;

    G_STATIC_ASSERT_EXPR(sizeof(*data) == sizeof(*drvinfo));
    G_STATIC_ASSERT_EXPR(offsetof(NMPUtilsEthtoolDriverInfo, driver)
                         == offsetof(struct ethtool_drvinfo, driver));
    G_STATIC_ASSERT_EXPR(offsetof(NMPUtilsEthtoolDriverInfo, version)
                         == offsetof(struct ethtool_drvinfo, version));
    G_STATIC_ASSERT_EXPR(offsetof(NMPUtilsEthtoolDriverInfo, fw_version)
                         == offsetof(struct ethtool_drvinfo, fw_version));
    G_STATIC_ASSERT_EXPR(sizeof(data->driver) == sizeof(drvinfo->driver));
    G_STATIC_ASSERT_EXPR(sizeof(data->version) == sizeof(drvinfo->version));
    G_STATIC_ASSERT_EXPR(sizeof(data->fw_version) == sizeof(drvinfo->fw_version));

    g_return_val_if_fail(ifindex > 0, FALSE);
    g_return_val_if_fail(data, FALSE);

    drvinfo  = (struct ethtool_drvinfo *) data;
    *drvinfo = (struct ethtool_drvinfo) {
        .cmd = ETHTOOL_GDRVINFO,
    };
    return _ethtool_call_once(ifindex, drvinfo, sizeof(*drvinfo)) >= 0;
}

gboolean
nmp_ethtool_ioctl_get_permanent_address(int ifindex, guint8 *buf, size_t *length)
{
    struct {
        struct ethtool_perm_addr e;
        guint8                   _extra_data[_NM_UTILS_HWADDR_LEN_MAX + 1];
    } edata = {
        .e.cmd  = ETHTOOL_GPERMADDR,
        .e.size = _NM_UTILS_HWADDR_LEN_MAX,
    };
    const guint8 *pdata;

    guint i;

    g_return_val_if_fail(ifindex > 0, FALSE);

    if (_ethtool_call_once(ifindex, &edata, sizeof(edata)) < 0)
        return FALSE;

    if (edata.e.size > _NM_UTILS_HWADDR_LEN_MAX)
        return FALSE;
    if (edata.e.size < 1)
        return FALSE;

    pdata = (const guint8 *) edata.e.data;

    if (NM_IN_SET(pdata[0], 0, 0xFF)) {
        /* Some drivers might return a permanent address of all zeros.
         * Reject that (rh#1264024)
         *
         * Some drivers return a permanent address of all ones. Reject that too */
        for (i = 1; i < edata.e.size; i++) {
            if (pdata[0] != pdata[i])
                goto not_all_0or1;
        }
        return FALSE;
    }

not_all_0or1:
    memcpy(buf, pdata, edata.e.size);
    *length = edata.e.size;
    return TRUE;
}

gboolean
nmp_ethtool_ioctl_supports_carrier_detect(int ifindex)
{
    struct ethtool_cmd edata = {.cmd = ETHTOOL_GLINK};

    g_return_val_if_fail(ifindex > 0, FALSE);

    /* We ignore the result. If the ETHTOOL_GLINK call succeeded, then we
     * assume the device supports carrier-detect, otherwise we assume it
     * doesn't.
     */
    return _ethtool_call_once(ifindex, &edata, sizeof(edata)) >= 0;
}

gboolean
nmp_ethtool_ioctl_supports_vlans(int ifindex)
{
    nm_auto_socket_handle SocketHandle shandle       = SOCKET_HANDLE_INIT(ifindex);
    gs_free struct ethtool_gfeatures  *features_free = NULL;
    struct ethtool_gfeatures          *features;
    gsize                              features_len;
    int                                idx, block, bit, size;

    g_return_val_if_fail(ifindex > 0, FALSE);

    idx = ethtool_get_stringset_index(&shandle, ETH_SS_FEATURES, "vlan-challenged");
    if (idx < 0) {
        nm_log_dbg(LOGD_PLATFORM,
                   "ethtool[%d]: vlan-challenged ethtool feature does not exist?",
                   ifindex);
        return FALSE;
    }

    block = idx / 32;
    bit   = idx % 32;
    size  = block + 1;

    features_len   = sizeof(*features) + (size * sizeof(struct ethtool_get_features_block));
    features       = nm_malloc0_maybe_a(300, features_len, &features_free);
    features->cmd  = ETHTOOL_GFEATURES;
    features->size = size;

    if (_ethtool_call_handle(&shandle, features, features_len) < 0)
        return FALSE;

    return !(features->features[block].active & (1 << bit));
}

gboolean
nmp_ethtool_ioctl_get_wake_on_lan(int ifindex)
{
    struct ethtool_wolinfo wol = {
        .cmd = ETHTOOL_GWOL,
    };

    g_return_val_if_fail(ifindex > 0, FALSE);

    if (_ethtool_call_once(ifindex, &wol, sizeof(wol)) < 0)
        return FALSE;

    return wol.wolopts != 0;
}

gboolean
nmp_ethtool_ioctl_set_wake_on_lan(int                      ifindex,
                                  _NMSettingWiredWakeOnLan wol,
                                  const char              *wol_password)
{
    struct ethtool_wolinfo wol_info = {
        .cmd     = ETHTOOL_SWOL,
        .wolopts = 0,
    };

    g_return_val_if_fail(ifindex > 0, FALSE);

    if (wol == _NM_SETTING_WIRED_WAKE_ON_LAN_IGNORE)
        return TRUE;

    nm_log_dbg(LOGD_PLATFORM,
               "ethtool[%d]: setting Wake-on-LAN options 0x%x, password '%s'",
               ifindex,
               (unsigned) wol,
               wol_password);

    if (NM_FLAGS_HAS(wol, _NM_SETTING_WIRED_WAKE_ON_LAN_PHY))
        wol_info.wolopts |= WAKE_PHY;
    if (NM_FLAGS_HAS(wol, _NM_SETTING_WIRED_WAKE_ON_LAN_UNICAST))
        wol_info.wolopts |= WAKE_UCAST;
    if (NM_FLAGS_HAS(wol, _NM_SETTING_WIRED_WAKE_ON_LAN_MULTICAST))
        wol_info.wolopts |= WAKE_MCAST;
    if (NM_FLAGS_HAS(wol, _NM_SETTING_WIRED_WAKE_ON_LAN_BROADCAST))
        wol_info.wolopts |= WAKE_BCAST;
    if (NM_FLAGS_HAS(wol, _NM_SETTING_WIRED_WAKE_ON_LAN_ARP))
        wol_info.wolopts |= WAKE_ARP;
    if (NM_FLAGS_HAS(wol, _NM_SETTING_WIRED_WAKE_ON_LAN_MAGIC))
        wol_info.wolopts |= WAKE_MAGIC;

    if (wol_password) {
        if (!_nm_utils_hwaddr_aton_exact(wol_password, wol_info.sopass, ETH_ALEN)) {
            nm_log_dbg(LOGD_PLATFORM,
                       "ethtool[%d]: couldn't parse Wake-on-LAN password '%s'",
                       ifindex,
                       wol_password);
            return FALSE;
        }
        wol_info.wolopts |= WAKE_MAGICSECURE;
    }

    return _ethtool_call_once(ifindex, &wol_info, sizeof(wol_info)) >= 0;
}

/*****************************************************************************/

gboolean
nmp_ethtool_ioctl_get_link_settings(int                       ifindex,
                                    gboolean                 *out_autoneg,
                                    guint32                  *out_speed,
                                    NMPlatformLinkDuplexType *out_duplex)
{
    struct ethtool_cmd edata = {
        .cmd = ETHTOOL_GSET,
    };

    g_return_val_if_fail(ifindex > 0, FALSE);

    if (_ethtool_call_once(ifindex, &edata, sizeof(edata)) < 0)
        return FALSE;

    NM_SET_OUT(out_autoneg, (edata.autoneg == AUTONEG_ENABLE));

    if (out_speed) {
        guint32 speed;

        speed = ethtool_cmd_speed(&edata);
        if (speed == G_MAXUINT16 || speed == G_MAXUINT32)
            speed = 0;

        *out_speed = speed;
    }

    if (out_duplex) {
        switch (edata.duplex) {
        case DUPLEX_HALF:
            *out_duplex = NM_PLATFORM_LINK_DUPLEX_HALF;
            break;
        case DUPLEX_FULL:
            *out_duplex = NM_PLATFORM_LINK_DUPLEX_FULL;
            break;
        default: /* DUPLEX_UNKNOWN */
            *out_duplex = NM_PLATFORM_LINK_DUPLEX_UNKNOWN;
            break;
        }
    }

    return TRUE;
}

#define ADVERTISED_INVALID 0

static guint32
get_baset_mode(guint32 speed, NMPlatformLinkDuplexType duplex)
{
    if (duplex == NM_PLATFORM_LINK_DUPLEX_UNKNOWN)
        return ADVERTISED_INVALID;

    if (duplex == NM_PLATFORM_LINK_DUPLEX_HALF) {
        switch (speed) {
        case 10:
            return ADVERTISED_10baseT_Half;
        case 100:
            return ADVERTISED_100baseT_Half;
        case 1000:
            return ADVERTISED_1000baseT_Half;
        default:
            return ADVERTISED_INVALID;
        }
    } else {
        switch (speed) {
        case 10:
            return ADVERTISED_10baseT_Full;
        case 100:
            return ADVERTISED_100baseT_Full;
        case 1000:
            return ADVERTISED_1000baseT_Full;
        case 10000:
            return ADVERTISED_10000baseT_Full;
        default:
            return ADVERTISED_INVALID;
        }
    }
}

static gboolean
platform_link_duplex_type_to_native(NMPlatformLinkDuplexType duplex_type, guint8 *out_native)
{
    switch (duplex_type) {
    case NM_PLATFORM_LINK_DUPLEX_HALF:
        *out_native = DUPLEX_HALF;
        return TRUE;
    case NM_PLATFORM_LINK_DUPLEX_FULL:
        *out_native = DUPLEX_FULL;
        return TRUE;
    case NM_PLATFORM_LINK_DUPLEX_UNKNOWN:
        return FALSE;
    default:
        g_return_val_if_reached(FALSE);
    }
}

static NMOptionBool
set_link_settings_new(SocketHandle            *shandle,
                      gboolean                 autoneg,
                      guint32                  speed,
                      NMPlatformLinkDuplexType duplex)
{
    struct ethtool_link_settings          edata0;
    gs_free struct ethtool_link_settings *edata = NULL;
    gsize                                 edata_size;
    guint                                 nwords;
    guint                                 i;

    edata0 = (struct ethtool_link_settings) {
        .cmd                    = ETHTOOL_GLINKSETTINGS,
        .link_mode_masks_nwords = 0,
    };

    /* perform the handshake to find the size of masks */
    if (_ethtool_call_handle(shandle, &edata0, sizeof(edata0)) < 0
        || edata0.link_mode_masks_nwords >= 0) {
        /* new API not supported */
        return NM_OPTION_BOOL_DEFAULT;
    }

    nwords                        = -edata0.link_mode_masks_nwords;
    edata_size                    = sizeof(*edata) + sizeof(guint32) * nwords * 3;
    edata                         = g_malloc0(edata_size);
    edata->cmd                    = ETHTOOL_GLINKSETTINGS;
    edata->link_mode_masks_nwords = nwords;

    /* retrieve first current settings */
    if (_ethtool_call_handle(shandle, edata, edata_size) < 0)
        return FALSE;

    /* then change the needed ones */
    edata->cmd = ETHTOOL_SLINKSETTINGS;

    {
        const guint32 *v_map_supported      = &edata->link_mode_masks[0];
        guint32       *v_map_advertising    = &edata->link_mode_masks[nwords];
        guint32       *v_map_lp_advertising = &edata->link_mode_masks[2 * nwords];

        memcpy(v_map_advertising, v_map_supported, sizeof(guint32) * nwords);
        (void) v_map_lp_advertising;

        if (speed != 0) {
            guint32 mode;

            mode = get_baset_mode(speed, duplex);

            if (mode == ADVERTISED_INVALID) {
                if (!autoneg)
                    goto set_autoneg;
                nm_log_trace(LOGD_PLATFORM,
                             "ethtool[%d]: %uBASE-T %s duplex mode cannot be advertised",
                             shandle->ifindex,
                             speed,
                             nm_platform_link_duplex_type_to_string(duplex));
                return FALSE;
            }

            if (!(v_map_supported[0] & mode)) {
                if (!autoneg)
                    goto set_autoneg;
                nm_log_trace(LOGD_PLATFORM,
                             "ethtool[%d]: device does not support %uBASE-T %s duplex mode",
                             shandle->ifindex,
                             speed,
                             nm_platform_link_duplex_type_to_string(duplex));
                return FALSE;
            }

            for (i = 0; i < (guint) G_N_ELEMENTS(_nmp_link_mode_all_advertised_modes); i++)
                v_map_advertising[i] &= ~_nmp_link_mode_all_advertised_modes[i];
            v_map_advertising[0] |= mode;
        }
    }

set_autoneg:
    if (autoneg)
        edata->autoneg = AUTONEG_ENABLE;
    else {
        edata->autoneg = AUTONEG_DISABLE;

        if (speed)
            edata->speed = speed;

        platform_link_duplex_type_to_native(duplex, &edata->duplex);
    }

    return _ethtool_call_handle(shandle, edata, edata_size) >= 0;
}

gboolean
nmp_ethtool_ioctl_set_link_settings(int                      ifindex,
                                    gboolean                 autoneg,
                                    guint32                  speed,
                                    NMPlatformLinkDuplexType duplex)
{
    nm_auto_socket_handle SocketHandle shandle = SOCKET_HANDLE_INIT(ifindex);
    struct ethtool_cmd                 edata   = {
                          .cmd = ETHTOOL_GSET,
    };
    NMOptionBool ret;

    g_return_val_if_fail(ifindex > 0, FALSE);
    g_return_val_if_fail((speed && duplex != NM_PLATFORM_LINK_DUPLEX_UNKNOWN)
                             || (!speed && duplex == NM_PLATFORM_LINK_DUPLEX_UNKNOWN),
                         FALSE);

    nm_log_trace(LOGD_PLATFORM,
                 "ethtool[%d]: set link: autoneg=%d, speed=%d, duplex=%s",
                 ifindex,
                 autoneg,
                 speed,
                 nm_platform_link_duplex_type_to_string(duplex));

    ret = set_link_settings_new(&shandle, autoneg, speed, duplex);
    if (ret != NM_OPTION_BOOL_DEFAULT)
        return ret;

    /* new ETHTOOL_GLINKSETTINGS API not supported, fall back to GSET */

    /* retrieve first current settings */
    if (_ethtool_call_handle(&shandle, &edata, sizeof(edata)) < 0)
        return FALSE;

    /* then change the needed ones */
    edata.cmd = ETHTOOL_SSET;

    edata.advertising = edata.supported;
    if (speed != 0) {
        guint32 mode;

        mode = get_baset_mode(speed, duplex);

        if (mode == ADVERTISED_INVALID) {
            if (!autoneg)
                goto set_autoneg;
            nm_log_trace(LOGD_PLATFORM,
                         "ethtool[%d]: %uBASE-T %s duplex mode cannot be advertised",
                         ifindex,
                         speed,
                         nm_platform_link_duplex_type_to_string(duplex));
            return FALSE;
        }
        if (!(edata.supported & mode)) {
            if (!autoneg)
                goto set_autoneg;
            nm_log_trace(LOGD_PLATFORM,
                         "ethtool[%d]: device does not support %uBASE-T %s duplex mode",
                         ifindex,
                         speed,
                         nm_platform_link_duplex_type_to_string(duplex));
            return FALSE;
        }
        edata.advertising &= ~_nmp_link_mode_all_advertised_modes[0];
        edata.advertising |= mode;
    }

set_autoneg:
    if (autoneg)
        edata.autoneg = AUTONEG_ENABLE;
    else {
        edata.autoneg = AUTONEG_DISABLE;

        if (speed)
            ethtool_cmd_speed_set(&edata, speed);

        platform_link_duplex_type_to_native(duplex, &edata.duplex);
    }

    return _ethtool_call_handle(&shandle, &edata, sizeof(edata)) >= 0;
}

gboolean
nmp_mii_ioctl_supports_carrier_detect(int ifindex)
{
    nm_auto_socket_handle SocketHandle shandle = SOCKET_HANDLE_INIT(ifindex);
    int                                r;
    struct ifreq                       ifr;
    struct mii_ioctl_data             *mii;

    g_return_val_if_fail(ifindex > 0, FALSE);

    r = _ioctl_call("mii",
                    "SIOCGMIIPHY",
                    SIOCGMIIPHY,
                    shandle.ifindex,
                    &shandle.fd,
                    shandle.ifname,
                    IOCTL_CALL_DATA_TYPE_NONE,
                    NULL,
                    0,
                    &ifr);
    if (r < 0)
        return FALSE;

    /* If we can read the BMSR register, we assume that the card supports MII link detection */
    mii          = (struct mii_ioctl_data *) &ifr.ifr_ifru;
    mii->reg_num = MII_BMSR;

    r = _ioctl_call("mii",
                    "SIOCGMIIREG",
                    SIOCGMIIREG,
                    shandle.ifindex,
                    &shandle.fd,
                    shandle.ifname,
                    IOCTL_CALL_DATA_TYPE_IFRU,
                    mii,
                    sizeof(*mii),
                    &ifr);
    if (r < 0)
        return FALSE;

    mii = (struct mii_ioctl_data *) &ifr.ifr_ifru;
    nm_log_trace(LOGD_PLATFORM,
                 "mii[%d,%s]: carrier-detect yes: SIOCGMIIREG result 0x%X",
                 ifindex,
                 shandle.ifname,
                 mii->val_out);
    return TRUE;
}
