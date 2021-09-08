/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-platform-utils.h"

#include "libnm-std-aux/nm-linux-compat.h"

#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <linux/mii.h>
#include <linux/if.h>
#include <linux/version.h>
#include <linux/rtnetlink.h>
#include <fcntl.h>
#include <libudev.h>

#include "libnm-base/nm-ethtool-base.h"
#include "libnm-log-core/nm-logging.h"
#include "libnm-glib-aux/nm-time-utils.h"

/*****************************************************************************/

#define ONOFF(bool_val) ((bool_val) ? "on" : "off")

/******************************************************************************
 * utils
 *****************************************************************************/

extern char *if_indextoname(unsigned __ifindex, char *__ifname);
unsigned     if_nametoindex(const char *__ifname);

const char *
nmp_utils_if_indextoname(int ifindex, char *out_ifname /*IFNAMSIZ*/)
{
    g_return_val_if_fail(ifindex > 0, NULL);
    g_return_val_if_fail(out_ifname, NULL);

    return if_indextoname(ifindex, out_ifname);
}

int
nmp_utils_if_nametoindex(const char *ifname)
{
    g_return_val_if_fail(ifname, 0);

    return if_nametoindex(ifname);
}

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE(nm_platform_link_duplex_type_to_string,
                           NMPlatformLinkDuplexType,
                           NM_UTILS_LOOKUP_DEFAULT_WARN(NULL),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_PLATFORM_LINK_DUPLEX_UNKNOWN, "unknown"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_PLATFORM_LINK_DUPLEX_FULL, "full"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_PLATFORM_LINK_DUPLEX_HALF, "half"), );

/*****************************************************************************/

typedef struct {
    int       fd;
    const int ifindex;
    char      ifname[IFNAMSIZ];
} SocketHandle;

#define SOCKET_HANDLE_INIT(_ifindex)     \
    {                                    \
        .fd = -1, .ifindex = (_ifindex), \
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
_ioctl_call(const char *      log_ioctl_type,
            const char *      log_subtype,
            unsigned long int ioctl_request,
            int               ifindex,
            int *             inout_fd,
            char *            inout_ifname,
            IoctlCallDataType edata_type,
            gpointer          edata,
            gsize             edata_size,
            struct ifreq *    out_ifreq)
{
    nm_auto_close int fd_close = -1;
    int               fd;
    int               r;
    gpointer          edata_backup      = NULL;
    gs_free gpointer  edata_backup_free = NULL;
    guint             try_count;
    char              known_ifnames[2][IFNAMSIZ];
    const char *      failure_reason = NULL;
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
    const guint32 *                  pdata;
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
#define ETHT_FEAT(eid, ...)                                        \
    {                                                              \
        .ethtool_id = eid, .n_kernel_names = NM_NARG(__VA_ARGS__), \
        .kernel_names = ((const char *const[]){__VA_ARGS__}),      \
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

            g_assert(nm_utils_strv_find_first((char **) inf->kernel_names, k, name) < 0);

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
    gs_free NMEthtoolFeatureStates * states      = NULL;
    gs_free struct ethtool_gstrings *ss_features = NULL;

    _ASSERT_ethtool_feature_infos();

    ss_features = ethtool_get_stringset(shandle, ETH_SS_FEATURES);
    if (!ss_features)
        return NULL;

    if (ss_features->len > 0) {
        gs_free struct ethtool_gfeatures *  gfeatures_free = NULL;
        struct ethtool_gfeatures *          gfeatures;
        gsize                               gfeatures_len;
        guint                               idx;
        const NMEthtoolFeatureState *       states_list0   = NULL;
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
                const char *           kernel_name = info->kernel_names[idx_kernel_name];
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
nmp_utils_ethtool_get_features(int ifindex)
{
    nm_auto_socket_handle SocketHandle shandle = SOCKET_HANDLE_INIT(ifindex);
    NMEthtoolFeatureStates *           features;

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
_ethtool_feature_state_to_string(char *                       buf,
                                 gsize                        buf_size,
                                 const NMEthtoolFeatureState *s,
                                 const char *                 prefix)
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
nmp_utils_ethtool_set_features(
    int                           ifindex,
    const NMEthtoolFeatureStates *features,
    const NMOptionBool *requested /* indexed by NMEthtoolID - _NM_ETHTOOL_ID_FEATURE_FIRST */,
    gboolean            do_set /* or reset */)
{
    nm_auto_socket_handle SocketHandle shandle        = SOCKET_HANDLE_INIT(ifindex);
    gs_free struct ethtool_sfeatures * sfeatures_free = NULL;
    struct ethtool_sfeatures *         sfeatures;
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
nmp_utils_ethtool_get_coalesce(int ifindex, NMEthtoolCoalesceState *coalesce)
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

    *coalesce = (NMEthtoolCoalesceState){
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
nmp_utils_ethtool_set_coalesce(int ifindex, const NMEthtoolCoalesceState *coalesce)
{
    struct ethtool_coalesce eth_data;

    g_return_val_if_fail(ifindex > 0, FALSE);
    g_return_val_if_fail(coalesce, FALSE);

    eth_data = (struct ethtool_coalesce){
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
nmp_utils_ethtool_get_ring(int ifindex, NMEthtoolRingState *ring)
{
    struct ethtool_ringparam eth_data;

    g_return_val_if_fail(ifindex > 0, FALSE);
    g_return_val_if_fail(ring, FALSE);

    eth_data.cmd = ETHTOOL_GRINGPARAM;

    if (_ethtool_call_once(ifindex, &eth_data, sizeof(eth_data)) < 0) {
        nm_log_trace(LOGD_PLATFORM,
                     "ethtool[%d]: %s: failure getting ring settings",
                     ifindex,
                     "get-ring");
        return FALSE;
    }

    *ring = (NMEthtoolRingState){
        .rx_pending       = eth_data.rx_pending,
        .rx_jumbo_pending = eth_data.rx_jumbo_pending,
        .rx_mini_pending  = eth_data.rx_mini_pending,
        .tx_pending       = eth_data.tx_pending,
    };

    nm_log_trace(LOGD_PLATFORM,
                 "ethtool[%d]: %s: retrieved kernel ring settings",
                 ifindex,
                 "get-ring");
    return TRUE;
}

gboolean
nmp_utils_ethtool_set_ring(int ifindex, const NMEthtoolRingState *ring)
{
    struct ethtool_ringparam eth_data;

    g_return_val_if_fail(ifindex > 0, FALSE);
    g_return_val_if_fail(ring, FALSE);

    eth_data = (struct ethtool_ringparam){
        .cmd              = ETHTOOL_SRINGPARAM,
        .rx_pending       = ring->rx_pending,
        .rx_jumbo_pending = ring->rx_jumbo_pending,
        .rx_mini_pending  = ring->rx_mini_pending,
        .tx_pending       = ring->tx_pending,
    };

    if (_ethtool_call_once(ifindex, &eth_data, sizeof(eth_data)) < 0) {
        nm_log_trace(LOGD_PLATFORM,
                     "ethtool[%d]: %s: failure setting ring settings",
                     ifindex,
                     "set-ring");
        return FALSE;
    }

    nm_log_trace(LOGD_PLATFORM, "ethtool[%d]: %s: set kernel ring settings", ifindex, "set-ring");
    return TRUE;
}

gboolean
nmp_utils_ethtool_get_pause(int ifindex, NMEthtoolPauseState *pause)
{
    struct ethtool_pauseparam          eth_data;
    nm_auto_socket_handle SocketHandle shandle = SOCKET_HANDLE_INIT(ifindex);

    g_return_val_if_fail(ifindex > 0, FALSE);
    g_return_val_if_fail(pause, FALSE);

    eth_data.cmd = ETHTOOL_GPAUSEPARAM;
    if (_ethtool_call_handle(&shandle, &eth_data, sizeof(struct ethtool_pauseparam)) != 0) {
        nm_log_trace(LOGD_PLATFORM,
                     "ethtool[%d]: %s: failure getting pause settings",
                     ifindex,
                     "get-pause");
        return FALSE;
    }

    *pause = (NMEthtoolPauseState){
        .autoneg = eth_data.autoneg == 1,
        .rx      = eth_data.rx_pause == 1,
        .tx      = eth_data.tx_pause == 1,
    };

    nm_log_trace(LOGD_PLATFORM,
                 "ethtool[%d]: %s: retrieved kernel pause settings",
                 ifindex,
                 "get-pause");
    return TRUE;
}

gboolean
nmp_utils_ethtool_set_pause(int ifindex, const NMEthtoolPauseState *pause)
{
    struct ethtool_pauseparam          eth_data;
    nm_auto_socket_handle SocketHandle shandle = SOCKET_HANDLE_INIT(ifindex);

    g_return_val_if_fail(ifindex > 0, FALSE);
    g_return_val_if_fail(pause, FALSE);

    eth_data = (struct ethtool_pauseparam){
        .cmd      = ETHTOOL_SPAUSEPARAM,
        .autoneg  = pause->autoneg ? 1 : 0,
        .rx_pause = pause->rx ? 1 : 0,
        .tx_pause = pause->tx ? 1 : 0,
    };

    if (_ethtool_call_handle(&shandle, &eth_data, sizeof(struct ethtool_pauseparam)) != 0) {
        nm_log_trace(LOGD_PLATFORM,
                     "ethtool[%d]: %s: failure setting pause settings",
                     ifindex,
                     "set-pause");
        return FALSE;
    }
    nm_log_trace(LOGD_PLATFORM, "ethtool[%d]: %s: set kernel puase settings", ifindex, "set-pause");
    return TRUE;
}

/*****************************************************************************/

gboolean
nmp_utils_ethtool_get_driver_info(int ifindex, NMPUtilsEthtoolDriverInfo *data)
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
    *drvinfo = (struct ethtool_drvinfo){
        .cmd = ETHTOOL_GDRVINFO,
    };
    return _ethtool_call_once(ifindex, drvinfo, sizeof(*drvinfo)) >= 0;
}

gboolean
nmp_utils_ethtool_get_permanent_address(int ifindex, guint8 *buf, size_t *length)
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
nmp_utils_ethtool_supports_carrier_detect(int ifindex)
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
nmp_utils_ethtool_supports_vlans(int ifindex)
{
    nm_auto_socket_handle SocketHandle shandle       = SOCKET_HANDLE_INIT(ifindex);
    gs_free struct ethtool_gfeatures * features_free = NULL;
    struct ethtool_gfeatures *         features;
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

int
nmp_utils_ethtool_get_peer_ifindex(int ifindex)
{
    nm_auto_socket_handle SocketHandle shandle = SOCKET_HANDLE_INIT(ifindex);
    gsize                              stats_len;
    gs_free struct ethtool_stats *     stats_free = NULL;
    struct ethtool_stats *             stats;
    int                                peer_ifindex_stat;

    g_return_val_if_fail(ifindex > 0, 0);

    peer_ifindex_stat = ethtool_get_stringset_index(&shandle, ETH_SS_STATS, "peer_ifindex");
    if (peer_ifindex_stat < 0) {
        nm_log_dbg(LOGD_PLATFORM, "ethtool[%d]: peer_ifindex stat does not exist?", ifindex);
        return FALSE;
    }

    stats_len      = sizeof(*stats) + (peer_ifindex_stat + 1) * sizeof(guint64);
    stats          = nm_malloc0_maybe_a(300, stats_len, &stats_free);
    stats->cmd     = ETHTOOL_GSTATS;
    stats->n_stats = peer_ifindex_stat + 1;
    if (_ethtool_call_handle(&shandle, stats, stats_len) < 0)
        return 0;

    return stats->data[peer_ifindex_stat];
}

gboolean
nmp_utils_ethtool_get_wake_on_lan(int ifindex)
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
nmp_utils_ethtool_get_link_settings(int                       ifindex,
                                    gboolean *                out_autoneg,
                                    guint32 *                 out_speed,
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

const guint8 _nmp_link_mode_all_advertised_modes_bits[] = {
    ETHTOOL_LINK_MODE_10baseT_Half_BIT,
    ETHTOOL_LINK_MODE_10baseT_Full_BIT,
    ETHTOOL_LINK_MODE_100baseT_Half_BIT,
    ETHTOOL_LINK_MODE_100baseT_Full_BIT,
    ETHTOOL_LINK_MODE_1000baseT_Half_BIT,
    ETHTOOL_LINK_MODE_1000baseT_Full_BIT,
    ETHTOOL_LINK_MODE_10000baseT_Full_BIT,
    ETHTOOL_LINK_MODE_2500baseX_Full_BIT,
    ETHTOOL_LINK_MODE_1000baseKX_Full_BIT,
    ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT,
    ETHTOOL_LINK_MODE_10000baseKR_Full_BIT,
    ETHTOOL_LINK_MODE_10000baseR_FEC_BIT,
    ETHTOOL_LINK_MODE_20000baseMLD2_Full_BIT,
    ETHTOOL_LINK_MODE_20000baseKR2_Full_BIT,
    ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT,
    ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT,
    ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT,
    ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT,
    ETHTOOL_LINK_MODE_56000baseKR4_Full_BIT,
    ETHTOOL_LINK_MODE_56000baseCR4_Full_BIT,
    ETHTOOL_LINK_MODE_56000baseSR4_Full_BIT,
    ETHTOOL_LINK_MODE_56000baseLR4_Full_BIT,
    ETHTOOL_LINK_MODE_25000baseCR_Full_BIT,
    /* 32 bit flags start here. */
    ETHTOOL_LINK_MODE_25000baseKR_Full_BIT,
    ETHTOOL_LINK_MODE_25000baseSR_Full_BIT,
    ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT,
    ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT,
    ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT,
    ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT,
    ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT,
    ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT,
    ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT,
    ETHTOOL_LINK_MODE_1000baseX_Full_BIT,
    ETHTOOL_LINK_MODE_10000baseCR_Full_BIT,
    ETHTOOL_LINK_MODE_10000baseSR_Full_BIT,
    ETHTOOL_LINK_MODE_10000baseLR_Full_BIT,
    ETHTOOL_LINK_MODE_10000baseLRM_Full_BIT,
    ETHTOOL_LINK_MODE_10000baseER_Full_BIT,
    ETHTOOL_LINK_MODE_2500baseT_Full_BIT,
    ETHTOOL_LINK_MODE_5000baseT_Full_BIT,
    ETHTOOL_LINK_MODE_50000baseKR_Full_BIT,
    ETHTOOL_LINK_MODE_50000baseSR_Full_BIT,
    ETHTOOL_LINK_MODE_50000baseCR_Full_BIT,
    ETHTOOL_LINK_MODE_50000baseLR_ER_FR_Full_BIT,
    ETHTOOL_LINK_MODE_50000baseDR_Full_BIT,
    ETHTOOL_LINK_MODE_100000baseKR2_Full_BIT,
    ETHTOOL_LINK_MODE_100000baseSR2_Full_BIT,
    ETHTOOL_LINK_MODE_100000baseCR2_Full_BIT,
    ETHTOOL_LINK_MODE_100000baseLR2_ER2_FR2_Full_BIT,
    ETHTOOL_LINK_MODE_100000baseDR2_Full_BIT,
    ETHTOOL_LINK_MODE_200000baseKR4_Full_BIT,
    ETHTOOL_LINK_MODE_200000baseSR4_Full_BIT,
    ETHTOOL_LINK_MODE_200000baseLR4_ER4_FR4_Full_BIT,
    ETHTOOL_LINK_MODE_200000baseDR4_Full_BIT,
    ETHTOOL_LINK_MODE_200000baseCR4_Full_BIT,
    ETHTOOL_LINK_MODE_100baseT1_Full_BIT,
    ETHTOOL_LINK_MODE_1000baseT1_Full_BIT,
    ETHTOOL_LINK_MODE_400000baseKR8_Full_BIT,
    ETHTOOL_LINK_MODE_400000baseSR8_Full_BIT,
    ETHTOOL_LINK_MODE_400000baseLR8_ER8_FR8_Full_BIT,
    ETHTOOL_LINK_MODE_400000baseDR8_Full_BIT,
    ETHTOOL_LINK_MODE_400000baseCR8_Full_BIT,
    ETHTOOL_LINK_MODE_100000baseKR_Full_BIT,
    ETHTOOL_LINK_MODE_100000baseSR_Full_BIT,
    ETHTOOL_LINK_MODE_100000baseLR_ER_FR_Full_BIT,
    ETHTOOL_LINK_MODE_100000baseCR_Full_BIT,
    ETHTOOL_LINK_MODE_100000baseDR_Full_BIT,
    ETHTOOL_LINK_MODE_200000baseKR2_Full_BIT,
    ETHTOOL_LINK_MODE_200000baseSR2_Full_BIT,
    ETHTOOL_LINK_MODE_200000baseLR2_ER2_FR2_Full_BIT,
    ETHTOOL_LINK_MODE_200000baseDR2_Full_BIT,
    ETHTOOL_LINK_MODE_200000baseCR2_Full_BIT,
    ETHTOOL_LINK_MODE_400000baseKR4_Full_BIT,
    ETHTOOL_LINK_MODE_400000baseSR4_Full_BIT,
    ETHTOOL_LINK_MODE_400000baseLR4_ER4_FR4_Full_BIT,
    ETHTOOL_LINK_MODE_400000baseDR4_Full_BIT,
    ETHTOOL_LINK_MODE_400000baseCR4_Full_BIT,
    ETHTOOL_LINK_MODE_100baseFX_Half_BIT,
    ETHTOOL_LINK_MODE_100baseFX_Full_BIT,
};

/* these are the bits from _nmp_link_mode_all_advertised_modes_bits set. */
const guint32 _nmp_link_mode_all_advertised_modes[] = {
    0xfffe903fu,
    0xfff1ffffu,
    0x0ffffbffu,
};

static NMOptionBool
set_link_settings_new(SocketHandle *           shandle,
                      gboolean                 autoneg,
                      guint32                  speed,
                      NMPlatformLinkDuplexType duplex)
{
    struct ethtool_link_settings          edata0;
    gs_free struct ethtool_link_settings *edata = NULL;
    gsize                                 edata_size;
    guint                                 nwords;
    guint                                 i;

    edata0 = (struct ethtool_link_settings){
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
        guint32 *      v_map_advertising    = &edata->link_mode_masks[nwords];
        guint32 *      v_map_lp_advertising = &edata->link_mode_masks[2 * nwords];

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
nmp_utils_ethtool_set_link_settings(int                      ifindex,
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
nmp_utils_ethtool_set_wake_on_lan(int                      ifindex,
                                  _NMSettingWiredWakeOnLan wol,
                                  const char *             wol_password)
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

/******************************************************************************
 * mii
 *****************************************************************************/

gboolean
nmp_utils_mii_supports_carrier_detect(int ifindex)
{
    nm_auto_socket_handle SocketHandle shandle = SOCKET_HANDLE_INIT(ifindex);
    int                                r;
    struct ifreq                       ifr;
    struct mii_ioctl_data *            mii;

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

/******************************************************************************
 * udev
 *****************************************************************************/

const char *
nmp_utils_udev_get_driver(struct udev_device *udevice)
{
    struct udev_device *parent = NULL, *grandparent = NULL;
    const char *        driver, *subsys;

    driver = udev_device_get_driver(udevice);
    if (driver)
        goto out;

    /* Try the parent */
    parent = udev_device_get_parent(udevice);
    if (parent) {
        driver = udev_device_get_driver(parent);
        if (!driver) {
            /* Try the grandparent if it's an ibmebus device or if the
             * subsys is NULL which usually indicates some sort of
             * platform device like a 'gadget' net interface.
             */
            subsys = udev_device_get_subsystem(parent);
            if ((g_strcmp0(subsys, "ibmebus") == 0) || (subsys == NULL)) {
                grandparent = udev_device_get_parent(parent);
                if (grandparent)
                    driver = udev_device_get_driver(grandparent);
            }
        }
    }

out:
    /* Intern the string so we don't have to worry about memory
     * management in NMPlatformLink. */
    return g_intern_string(driver);
}

/******************************************************************************
 * utils
 *****************************************************************************/

NMIPConfigSource
nmp_utils_ip_config_source_from_rtprot(guint8 rtprot)
{
    return ((int) rtprot) + 1;
}

NMIPConfigSource
nmp_utils_ip_config_source_round_trip_rtprot(NMIPConfigSource source)
{
    /* when adding a route to kernel for a give @source, the resulting route
     * will be put into the cache with a source of NM_IP_CONFIG_SOURCE_RTPROT_*.
     * This function returns that. */
    return nmp_utils_ip_config_source_from_rtprot(
        nmp_utils_ip_config_source_coerce_to_rtprot(source));
}

guint8
nmp_utils_ip_config_source_coerce_to_rtprot(NMIPConfigSource source)
{
    /* when adding a route to kernel, we coerce the @source field
     * to rtm_protocol. This is not lossless as we map different
     * source values to the same RTPROT uint8 value. */
    if (source <= NM_IP_CONFIG_SOURCE_UNKNOWN)
        return RTPROT_UNSPEC;

    if (source <= _NM_IP_CONFIG_SOURCE_RTPROT_LAST)
        return source - 1;

    switch (source) {
    case NM_IP_CONFIG_SOURCE_KERNEL:
        return RTPROT_KERNEL;
    case NM_IP_CONFIG_SOURCE_IP6LL:
        return RTPROT_KERNEL;
    case NM_IP_CONFIG_SOURCE_DHCP:
        return RTPROT_DHCP;
    case NM_IP_CONFIG_SOURCE_NDISC:
        return RTPROT_RA;

    default:
        return RTPROT_STATIC;
    }
}

NMIPConfigSource
nmp_utils_ip_config_source_coerce_from_rtprot(NMIPConfigSource source)
{
    /* When we receive a route from kernel and put it into the platform cache,
     * we preserve the protocol field by converting it to a NMIPConfigSource
     * via nmp_utils_ip_config_source_from_rtprot().
     *
     * However, that is not the inverse of nmp_utils_ip_config_source_coerce_to_rtprot().
     * Instead, to go back to the original value, you need another step:
     *   nmp_utils_ip_config_source_coerce_from_rtprot (nmp_utils_ip_config_source_from_rtprot (rtprot)).
     *
     * This might partly restore the original source value, but of course that
     * is not really possible because nmp_utils_ip_config_source_coerce_to_rtprot()
     * is not injective.
     * */
    switch (source) {
    case NM_IP_CONFIG_SOURCE_RTPROT_UNSPEC:
        return NM_IP_CONFIG_SOURCE_UNKNOWN;

    case NM_IP_CONFIG_SOURCE_RTPROT_KERNEL:
    case NM_IP_CONFIG_SOURCE_RTPROT_REDIRECT:
        return NM_IP_CONFIG_SOURCE_KERNEL;

    case NM_IP_CONFIG_SOURCE_RTPROT_RA:
        return NM_IP_CONFIG_SOURCE_NDISC;

    case NM_IP_CONFIG_SOURCE_RTPROT_DHCP:
        return NM_IP_CONFIG_SOURCE_DHCP;

    default:
        return NM_IP_CONFIG_SOURCE_USER;
    }
}

const char *
nmp_utils_ip_config_source_to_string(NMIPConfigSource source, char *buf, gsize len)
{
    const char *s = NULL;
    nm_utils_to_string_buffer_init(&buf, &len);

    if (!len)
        return buf;

    switch (source) {
    case NM_IP_CONFIG_SOURCE_UNKNOWN:
        s = "unknown";
        break;

    case NM_IP_CONFIG_SOURCE_RTPROT_UNSPEC:
        s = "rt-unspec";
        break;
    case NM_IP_CONFIG_SOURCE_RTPROT_REDIRECT:
        s = "rt-redirect";
        break;
    case NM_IP_CONFIG_SOURCE_RTPROT_KERNEL:
        s = "rt-kernel";
        break;
    case NM_IP_CONFIG_SOURCE_RTPROT_BOOT:
        s = "rt-boot";
        break;
    case NM_IP_CONFIG_SOURCE_RTPROT_STATIC:
        s = "rt-static";
        break;
    case NM_IP_CONFIG_SOURCE_RTPROT_DHCP:
        s = "rt-dhcp";
        break;
    case NM_IP_CONFIG_SOURCE_RTPROT_RA:
        s = "rt-ra";
        break;

    case NM_IP_CONFIG_SOURCE_KERNEL:
        s = "kernel";
        break;
    case NM_IP_CONFIG_SOURCE_SHARED:
        s = "shared";
        break;
    case NM_IP_CONFIG_SOURCE_IP4LL:
        s = "ipv4ll";
        break;
    case NM_IP_CONFIG_SOURCE_IP6LL:
        s = "ipv6ll";
        break;
    case NM_IP_CONFIG_SOURCE_PPP:
        s = "ppp";
        break;
    case NM_IP_CONFIG_SOURCE_WWAN:
        s = "wwan";
        break;
    case NM_IP_CONFIG_SOURCE_VPN:
        s = "vpn";
        break;
    case NM_IP_CONFIG_SOURCE_DHCP:
        s = "dhcp";
        break;
    case NM_IP_CONFIG_SOURCE_NDISC:
        s = "ndisc";
        break;
    case NM_IP_CONFIG_SOURCE_USER:
        s = "user";
        break;
    default:
        break;
    }

    if (source >= 1 && source <= 0x100) {
        if (s)
            g_snprintf(buf, len, "%s", s);
        else
            g_snprintf(buf, len, "rt-%d", ((int) source) - 1);
    } else {
        if (s)
            g_strlcpy(buf, s, len);
        else
            g_snprintf(buf, len, "(%d)", source);
    }
    return buf;
}

/**
 * nmp_utils_sysctl_open_netdir:
 * @ifindex: the ifindex for which to open "/sys/class/net/%s"
 * @ifname_guess: (allow-none): optional argument, if present used as initial
 *   guess as the current name for @ifindex. If guessed right,
 *   it saves an additional if_indextoname() call.
 * @out_ifname: (allow-none): if present, must be at least IFNAMSIZ
 *   characters. On success, this will contain the actual ifname
 *   found while opening the directory.
 *
 * Returns: a negative value on failure, on success returns the open fd
 *   to the "/sys/class/net/%s" directory for @ifindex.
 */
int
nmp_utils_sysctl_open_netdir(int ifindex, const char *ifname_guess, char *out_ifname)
{
#define SYS_CLASS_NET "/sys/class/net/"
    const char *ifname = ifname_guess;
    char        ifname_buf_last_try[IFNAMSIZ];
    char        ifname_buf[IFNAMSIZ];
    guint       try_count                                   = 0;
    char        sysdir[NM_STRLEN(SYS_CLASS_NET) + IFNAMSIZ] = SYS_CLASS_NET;
    char        fd_buf[256];
    ssize_t     nn;

    g_return_val_if_fail(ifindex >= 0, -1);

    ifname_buf_last_try[0] = '\0';

    for (try_count = 0; try_count < 10; try_count++, ifname = NULL) {
        nm_auto_close int fd_dir     = -1;
        nm_auto_close int fd_ifindex = -1;

        if (!ifname) {
            ifname = nmp_utils_if_indextoname(ifindex, ifname_buf);
            if (!ifname)
                return -1;
        }

        nm_assert(nm_utils_ifname_valid_kernel(ifname, NULL));

        if (g_strlcpy(&sysdir[NM_STRLEN(SYS_CLASS_NET)], ifname, IFNAMSIZ) >= IFNAMSIZ)
            g_return_val_if_reached(-1);

        /* we only retry, if the name changed since previous attempt.
         * Hence, it is extremely unlikely that this loop runes until the
         * end of the @try_count. */
        if (nm_streq(ifname, ifname_buf_last_try))
            return -1;

        if (g_strlcpy(ifname_buf_last_try, ifname, IFNAMSIZ) >= IFNAMSIZ)
            nm_assert_not_reached();

        fd_dir = open(sysdir, O_DIRECTORY | O_CLOEXEC);
        if (fd_dir < 0)
            continue;

        fd_ifindex = openat(fd_dir, "ifindex", O_CLOEXEC);
        if (fd_ifindex < 0)
            continue;

        nn = nm_utils_fd_read_loop(fd_ifindex, fd_buf, sizeof(fd_buf) - 2, FALSE);
        if (nn <= 0)
            continue;
        fd_buf[nn] = '\0';

        if (ifindex != (int) _nm_utils_ascii_str_to_int64(fd_buf, 10, 1, G_MAXINT, -1))
            continue;

        if (out_ifname)
            strcpy(out_ifname, ifname);

        return nm_steal_fd(&fd_dir);
    }

    return -1;
}

/*****************************************************************************/

char *
nmp_utils_new_vlan_name(const char *parent_iface, guint32 vlan_id)
{
    guint id_len;
    gsize parent_len;
    char *ifname;

    g_return_val_if_fail(parent_iface && *parent_iface, NULL);

    if (vlan_id < 10)
        id_len = 2;
    else if (vlan_id < 100)
        id_len = 3;
    else if (vlan_id < 1000)
        id_len = 4;
    else {
        g_return_val_if_fail(vlan_id < 4095, NULL);
        id_len = 5;
    }

    ifname = g_new(char, IFNAMSIZ);

    parent_len = strlen(parent_iface);
    parent_len = MIN(parent_len, IFNAMSIZ - 1 - id_len);
    memcpy(ifname, parent_iface, parent_len);
    g_snprintf(&ifname[parent_len], IFNAMSIZ - parent_len, ".%u", vlan_id);

    return ifname;
}

/*****************************************************************************/

/* nmp_utils_new_infiniband_name:
 * @name: the output-buffer where the value will be written. Must be
 *   not %NULL and point to a string buffer of at least IFNAMSIZ bytes.
 * @parent_name: the parent interface name
 * @p_key: the partition key.
 *
 * Returns: the infiniband name will be written to @name and @name
 *   is returned.
 */
const char *
nmp_utils_new_infiniband_name(char *name, const char *parent_name, int p_key)
{
    g_return_val_if_fail(name, NULL);
    g_return_val_if_fail(parent_name && parent_name[0], NULL);
    g_return_val_if_fail(strlen(parent_name) < IFNAMSIZ, NULL);

    /* technically, p_key of 0x0000 and 0x8000 is not allowed either. But we don't
     * want to assert against that in nmp_utils_new_infiniband_name(). So be more
     * resilient here, and accept those. */
    g_return_val_if_fail(p_key >= 0 && p_key <= 0xffff, NULL);

    /* If parent+suffix is too long, kernel would just truncate
     * the name. We do the same. See ipoib_vlan_add().  */
    g_snprintf(name, IFNAMSIZ, "%s.%04x", parent_name, p_key);
    return name;
}

/*****************************************************************************/

/**
 * Takes a pair @timestamp and @duration, and returns the remaining duration based
 * on the new timestamp @now.
 */
guint32
nmp_utils_lifetime_rebase_relative_time_on_now(guint32 timestamp, guint32 duration, gint32 now)
{
    gint64 t;

    nm_assert(now >= 0);

    if (duration == NM_PLATFORM_LIFETIME_PERMANENT)
        return NM_PLATFORM_LIFETIME_PERMANENT;

    if (timestamp == 0) {
        /* if the @timestamp is zero, assume it was just left unset and that the relative
         * @duration starts counting from @now. This is convenient to construct an address
         * and print it in nm_platform_ip4_address_to_string().
         *
         * In general it does not make sense to set the @duration without anchoring at
         * @timestamp because you don't know the absolute expiration time when looking
         * at the address at a later moment. */
        timestamp = now;
    }

    /* For timestamp > now, just accept it and calculate the expected(?) result. */
    t = (gint64) timestamp + (gint64) duration - (gint64) now;

    if (t <= 0)
        return 0;
    if (t >= NM_PLATFORM_LIFETIME_PERMANENT)
        return NM_PLATFORM_LIFETIME_PERMANENT - 1;
    return t;
}

guint32
nmp_utils_lifetime_get(guint32  timestamp,
                       guint32  lifetime,
                       guint32  preferred,
                       gint32   now,
                       guint32 *out_preferred)
{
    guint32 t_lifetime, t_preferred;

    nm_assert(now >= 0);

    if (timestamp == 0 && lifetime == 0) {
        /* We treat lifetime==0 && timestamp==0 addresses as permanent addresses to allow easy
         * creation of such addresses (without requiring to set the lifetime fields to
         * NM_PLATFORM_LIFETIME_PERMANENT). The real lifetime==0 addresses (E.g. DHCP6 telling us
         * to drop an address will have timestamp set.
         */
        NM_SET_OUT(out_preferred, NM_PLATFORM_LIFETIME_PERMANENT);
        g_return_val_if_fail(preferred == 0, NM_PLATFORM_LIFETIME_PERMANENT);
        return NM_PLATFORM_LIFETIME_PERMANENT;
    }

    if (now <= 0)
        now = nm_utils_get_monotonic_timestamp_sec();

    t_lifetime = nmp_utils_lifetime_rebase_relative_time_on_now(timestamp, lifetime, now);
    if (!t_lifetime) {
        NM_SET_OUT(out_preferred, 0);
        return 0;
    }

    t_preferred = nmp_utils_lifetime_rebase_relative_time_on_now(timestamp, preferred, now);

    NM_SET_OUT(out_preferred, MIN(t_preferred, t_lifetime));

    /* Assert that non-permanent addresses have a (positive) @timestamp. nmp_utils_lifetime_rebase_relative_time_on_now()
     * treats addresses with timestamp 0 as *now*. Addresses passed to _address_get_lifetime() always
     * should have a valid @timestamp, otherwise on every re-sync, their lifetime will be extended anew.
     */
    g_return_val_if_fail(timestamp != 0
                             || (lifetime == NM_PLATFORM_LIFETIME_PERMANENT
                                 && preferred == NM_PLATFORM_LIFETIME_PERMANENT),
                         t_lifetime);
    g_return_val_if_fail(t_preferred <= t_lifetime, t_lifetime);

    return t_lifetime;
}

/*****************************************************************************/

static const char *
_trunk_first_line(char *str)
{
    char *s;

    s = strchr(str, '\n');
    if (s)
        s[0] = '\0';
    return str;
}

int
nmp_utils_modprobe(GError **error, gboolean suppress_error_logging, const char *arg1, ...)
{
    gs_unref_ptrarray GPtrArray *argv = NULL;
    int                          exit_status;
    gs_free char *               _log_str = NULL;
#define ARGV_TO_STR(argv) \
    (_log_str ? _log_str : (_log_str = g_strjoinv(" ", (char **) argv->pdata)))
    GError *      local = NULL;
    va_list       ap;
    NMLogLevel    llevel  = suppress_error_logging ? LOGL_DEBUG : LOGL_ERR;
    gs_free char *std_out = NULL, *std_err = NULL;

    g_return_val_if_fail(!error || !*error, -1);
    g_return_val_if_fail(arg1, -1);

    /* construct the argument list */
    argv = g_ptr_array_sized_new(4);
    g_ptr_array_add(argv, "/sbin/modprobe");
    g_ptr_array_add(argv, "--use-blacklist");
    g_ptr_array_add(argv, (char *) arg1);

    va_start(ap, arg1);
    while ((arg1 = va_arg(ap, const char *)))
        g_ptr_array_add(argv, (char *) arg1);
    va_end(ap);

    g_ptr_array_add(argv, NULL);

    nm_log_dbg(LOGD_CORE, "modprobe: '%s'", ARGV_TO_STR(argv));
    if (!g_spawn_sync(NULL,
                      (char **) argv->pdata,
                      NULL,
                      0,
                      NULL,
                      NULL,
                      &std_out,
                      &std_err,
                      &exit_status,
                      &local)) {
        nm_log(llevel,
               LOGD_CORE,
               NULL,
               NULL,
               "modprobe: '%s' failed: %s",
               ARGV_TO_STR(argv),
               local->message);
        g_propagate_error(error, local);
        return -1;
    } else if (exit_status != 0) {
        nm_log(llevel,
               LOGD_CORE,
               NULL,
               NULL,
               "modprobe: '%s' exited with error %d%s%s%s%s%s%s",
               ARGV_TO_STR(argv),
               exit_status,
               std_out && *std_out ? " (" : "",
               std_out && *std_out ? _trunk_first_line(std_out) : "",
               std_out && *std_out ? ")" : "",
               std_err && *std_err ? " (" : "",
               std_err && *std_err ? _trunk_first_line(std_err) : "",
               std_err && *std_err ? ")" : "");
    }

    return exit_status;
}
