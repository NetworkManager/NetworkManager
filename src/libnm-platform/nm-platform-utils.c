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
#include <linux/if.h>
#include <linux/version.h>
#include <linux/rtnetlink.h>
#include <fcntl.h>
#include <libudev.h>

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

/******************************************************************************
 * udev
 *****************************************************************************/

const char *
nmp_utils_udev_get_driver(struct udev_device *udevice)
{
    struct udev_device *parent = NULL, *grandparent = NULL;
    const char         *driver, *subsys;

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
 * @ifname_guess: (nullable): optional argument, if present used as initial
 *   guess as the current name for @ifindex. If guessed right,
 *   it saves an additional if_indextoname() call.
 * @out_ifname: (optional): if present, must be at least IFNAMSIZ
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
    parent_len = NM_MIN(parent_len, IFNAMSIZ - 1 - id_len);
    memcpy(ifname, parent_iface, parent_len);
    g_snprintf(&ifname[parent_len], IFNAMSIZ - parent_len, ".%u", vlan_id);

    return ifname;
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
                       gint32  *cached_now,
                       guint32 *out_preferred)
{
    guint32 t_lifetime;
    guint32 t_preferred;
    gint32  now;

    nm_assert(cached_now);
    nm_assert(*cached_now >= 0);

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

    now = nm_utils_get_monotonic_timestamp_sec_cached(cached_now);

    t_lifetime = nmp_utils_lifetime_rebase_relative_time_on_now(timestamp, lifetime, now);
    if (!t_lifetime) {
        NM_SET_OUT(out_preferred, 0);
        return 0;
    }

    t_preferred = nmp_utils_lifetime_rebase_relative_time_on_now(timestamp, preferred, now);

    NM_SET_OUT(out_preferred, NM_MIN(t_preferred, t_lifetime));

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

static int
bridge_vlan_compare(gconstpointer a, gconstpointer b, gpointer user_data)
{
    const NMPlatformBridgeVlan *vlan_a = a;
    const NMPlatformBridgeVlan *vlan_b = b;

    return (int) vlan_a->vid_start - (int) vlan_b->vid_start;
}

/**
 * nmp_utils_bridge_vlan_normalize:
 * @vlans: the array of VLAN ranges
 * @num_vlans: the number of VLAN ranges in the array. On return, it contains
 *    the new number.
 *
 * Sort the VLAN ranges and merge those that are contiguous or overlapping. It
 * must not contain invalid data such as 2 overlapping ranges with different
 * flags.
 */
void
nmp_utils_bridge_vlan_normalize(NMPlatformBridgeVlan *vlans, guint *num_vlans)
{
    guint i;

    if (*num_vlans <= 1)
        return;

    g_qsort_with_data(vlans, *num_vlans, sizeof(NMPlatformBridgeVlan), bridge_vlan_compare, NULL);

    /* Merge VLAN ranges that are contiguous or overlap */
    i = 0;
    while (i < *num_vlans - 1) {
        guint    j         = i + 1;
        gboolean can_merge = vlans[j].vid_start <= vlans[i].vid_end + 1
                             && vlans[j].pvid == vlans[i].pvid
                             && vlans[j].untagged == vlans[i].untagged;

        if (can_merge) {
            vlans[i].vid_end = NM_MAX(vlans[i].vid_end, vlans[j].vid_end);
            for (; j < *num_vlans - 1; j++)
                vlans[j] = vlans[j + 1];
            *num_vlans -= 1;
        } else {
            i++;
        }
    }
}

/**
 * nmp_utils_bridge_normalized_vlans_equal:
 * @vlans_a: the first array of bridge VLANs
 * @num_vlans_a: the number of elements of first array
 * @vlans_b: the second array of bridge VLANs
 * @num_vlans_b: the number of elements of second array
 *
 * Given two arrays of bridge VLAN ranges, compare if they are equal,
 * i.e. if they represent the same set of VLANs with the same attributes.
 * The input arrays must be normalized (sorted and without overlapping or
 * duplicated ranges). Normalize with nmp_utils_bridge_vlan_normalize().
 */
gboolean
nmp_utils_bridge_normalized_vlans_equal(const NMPlatformBridgeVlan *vlans_a,
                                        guint                       num_vlans_a,
                                        const NMPlatformBridgeVlan *vlans_b,
                                        guint                       num_vlans_b)
{
    guint i;

    if (num_vlans_a != num_vlans_b)
        return FALSE;

    for (i = 0; i < num_vlans_a; i++) {
        if (vlans_a[i].vid_start != vlans_b[i].vid_start || vlans_a[i].vid_end != vlans_b[i].vid_end
            || vlans_a[i].pvid != vlans_b[i].pvid || vlans_a[i].untagged != vlans_b[i].untagged) {
            return FALSE;
        }
    }

    return TRUE;
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
    gs_free char                *_log_str = NULL;
#define ARGV_TO_STR(argv) \
    (_log_str ? _log_str : (_log_str = g_strjoinv(" ", (char **) argv->pdata)))
    GError       *local = NULL;
    va_list       ap;
    NMLogLevel    llevel  = suppress_error_logging ? LOGL_DEBUG : LOGL_ERR;
    gs_free char *std_out = NULL, *std_err = NULL;

    g_return_val_if_fail(!error || !*error, -1);
    g_return_val_if_fail(arg1, -1);

    /* construct the argument list */
    argv = g_ptr_array_sized_new(4);
    g_ptr_array_add(argv, MODPROBE_PATH);
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
