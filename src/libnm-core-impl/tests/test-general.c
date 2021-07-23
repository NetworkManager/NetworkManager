/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2008 - 2018 Red Hat, Inc.
 */

#define NM_GLIB_COMPAT_H_TEST

#include "libnm-core-impl/nm-default-libnm-core.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_infiniband.h>

#include "libnm-std-aux/c-list-util.h"
#include "libnm-glib-aux/nm-uuid.h"
#include "libnm-glib-aux/nm-enum-utils.h"
#include "libnm-glib-aux/nm-str-buf.h"
#include "libnm-glib-aux/nm-json-aux.h"
#include "libnm-base/nm-base.h"
#include "libnm-systemd-shared/nm-sd-utils-shared.h"

#include "nm-utils.h"
#include "nm-setting-private.h"
#include "nm-utils.h"
#include "nm-utils-private.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "nm-core-tests-enum-types.h"
#include "nm-team-utils.h"

#include "nm-setting-8021x.h"
#include "nm-setting-adsl.h"
#include "nm-setting-bluetooth.h"
#include "nm-setting-bond.h"
#include "nm-setting-bridge.h"
#include "nm-setting-bridge-port.h"
#include "nm-setting-cdma.h"
#include "nm-setting-connection.h"
#include "nm-setting-ethtool.h"
#include "nm-setting-generic.h"
#include "nm-setting-gsm.h"
#include "nm-setting-infiniband.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-olpc-mesh.h"
#include "nm-setting-ppp.h"
#include "nm-setting-pppoe.h"
#include "nm-setting-serial.h"
#include "nm-setting-team.h"
#include "nm-setting-team-port.h"
#include "nm-setting-user.h"
#include "nm-setting-vlan.h"
#include "nm-setting-vpn.h"
#include "nm-setting-wimax.h"
#include "nm-setting-wired.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-wpan.h"
#include "nm-simple-connection.h"
#include "libnm-core-intern/nm-keyfile-internal.h"
#include "libnm-glib-aux/nm-dedup-multi.h"
#include "libnm-base/nm-ethtool-base.h"
#include "libnm-base/nm-ethtool-utils-base.h"

#include "test-general-enums.h"

#include "libnm-glib-aux/nm-test-utils.h"

/* When passing a "bool" typed argument to a variadic function that
 * expects a gboolean, the compiler will promote the integer type
 * to have at least size (int). That way:
 *   g_object_set (obj, PROP_BOOL, bool_val, NULL);
 * will just work correctly. */
G_STATIC_ASSERT(sizeof(gboolean) == sizeof(int));
G_STATIC_ASSERT(sizeof(bool) <= sizeof(int));

/*****************************************************************************/

/* NM_UTILS_HWADDR_LEN_MAX is public API of libnm(-core) and _NM_UTILS_HWADDR_LEN_MAX
 * is internal API. They are the same, but the latter can be used without including libnm-core. */
G_STATIC_ASSERT(NM_UTILS_HWADDR_LEN_MAX == _NM_UTILS_HWADDR_LEN_MAX);

/*****************************************************************************/

static void
test_nm_ascii_spaces(void)
{
    int               i;
    const char *const S = NM_ASCII_SPACES;

    for (i = 0; S[i]; i++)
        g_assert(!strchr(&S[i + 1], S[i]));

    for (i = 0; S[i] != '\0'; i++)
        g_assert(g_ascii_isspace(S[i]));

    g_assert(!g_ascii_isspace((char) 0));
    for (i = 1; i < 0x100; i++) {
        if (g_ascii_isspace((char) i))
            g_assert(strchr(S, (char) i));
        else
            g_assert(!strchr(S, (char) i));
    }
}

/*****************************************************************************/

static void
test_wired_wake_on_lan_enum(void)
{
    nm_auto_unref_gtypeclass GFlagsClass *flags_class = NULL;
    gs_unref_hashtable GHashTable *vals               = g_hash_table_new(nm_direct_hash, NULL);
    guint                          i;

    G_STATIC_ASSERT_EXPR(sizeof(NMSettingWiredWakeOnLan) == sizeof(_NMSettingWiredWakeOnLan));
    G_STATIC_ASSERT_EXPR(sizeof(NMSettingWiredWakeOnLan) < sizeof(gint64));

    G_STATIC_ASSERT_EXPR(sizeof(NMSettingWiredWakeOnLan) < sizeof(gint64));
    g_assert((((gint64) ((NMSettingWiredWakeOnLan) -1)) < 0)
             == (((gint64) ((_NMSettingWiredWakeOnLan) -1)) < 0));

#define _E(n)                                                    \
    G_STMT_START                                                 \
    {                                                            \
        G_STATIC_ASSERT_EXPR(n == (gint64) _##n);                \
        G_STATIC_ASSERT_EXPR(_##n == (gint64) n);                \
        g_assert(_##n == _NM_SETTING_WIRED_WAKE_ON_LAN_CAST(n)); \
        if (!g_hash_table_add(vals, GUINT_TO_POINTER(n)))        \
            g_assert_not_reached();                              \
    }                                                            \
    G_STMT_END
    _E(NM_SETTING_WIRED_WAKE_ON_LAN_NONE);
    _E(NM_SETTING_WIRED_WAKE_ON_LAN_PHY);
    _E(NM_SETTING_WIRED_WAKE_ON_LAN_UNICAST);
    _E(NM_SETTING_WIRED_WAKE_ON_LAN_MULTICAST);
    _E(NM_SETTING_WIRED_WAKE_ON_LAN_BROADCAST);
    _E(NM_SETTING_WIRED_WAKE_ON_LAN_ARP);
    _E(NM_SETTING_WIRED_WAKE_ON_LAN_MAGIC);
    _E(NM_SETTING_WIRED_WAKE_ON_LAN_ALL);
    _E(NM_SETTING_WIRED_WAKE_ON_LAN_DEFAULT);
    _E(NM_SETTING_WIRED_WAKE_ON_LAN_IGNORE);
    _E(NM_SETTING_WIRED_WAKE_ON_LAN_EXCLUSIVE_FLAGS);
#undef _E

    flags_class = G_FLAGS_CLASS(g_type_class_ref(NM_TYPE_SETTING_WIRED_WAKE_ON_LAN));
    for (i = 0; i < flags_class->n_values; i++) {
        const GFlagsValue *value = &flags_class->values[i];

        if (!g_hash_table_contains(vals, GUINT_TO_POINTER(value->value))) {
            g_error("The enum value %s from NMSettingWiredWakeOnLan is not checked for "
                    "_NMSettingWiredWakeOnLan",
                    value->value_name);
        }
    }
}

/*****************************************************************************/

static void
test_wireless_wake_on_wlan_enum(void)
{
    nm_auto_unref_gtypeclass GFlagsClass *flags_class = NULL;
    gs_unref_hashtable GHashTable *vals               = g_hash_table_new(nm_direct_hash, NULL);
    guint                          i;

    G_STATIC_ASSERT_EXPR(sizeof(NMSettingWirelessWakeOnWLan)
                         == sizeof(_NMSettingWirelessWakeOnWLan));
    G_STATIC_ASSERT_EXPR(sizeof(NMSettingWirelessWakeOnWLan) < sizeof(gint64));

    G_STATIC_ASSERT_EXPR(sizeof(NMSettingWirelessWakeOnWLan) < sizeof(gint64));
    g_assert((((gint64) ((NMSettingWirelessWakeOnWLan) -1)) < 0)
             == (((gint64) ((_NMSettingWirelessWakeOnWLan) -1)) < 0));

#define _E(n)                                                        \
    G_STMT_START                                                     \
    {                                                                \
        G_STATIC_ASSERT_EXPR(n == (gint64) _##n);                    \
        G_STATIC_ASSERT_EXPR(_##n == (gint64) n);                    \
        g_assert(_##n == _NM_SETTING_WIRELESS_WAKE_ON_WLAN_CAST(n)); \
        if (!g_hash_table_add(vals, GUINT_TO_POINTER(n)))            \
            g_assert_not_reached();                                  \
    }                                                                \
    G_STMT_END
    _E(NM_SETTING_WIRELESS_WAKE_ON_WLAN_NONE);
    _E(NM_SETTING_WIRELESS_WAKE_ON_WLAN_ANY);
    _E(NM_SETTING_WIRELESS_WAKE_ON_WLAN_DISCONNECT);
    _E(NM_SETTING_WIRELESS_WAKE_ON_WLAN_MAGIC);
    _E(NM_SETTING_WIRELESS_WAKE_ON_WLAN_GTK_REKEY_FAILURE);
    _E(NM_SETTING_WIRELESS_WAKE_ON_WLAN_EAP_IDENTITY_REQUEST);
    _E(NM_SETTING_WIRELESS_WAKE_ON_WLAN_4WAY_HANDSHAKE);
    _E(NM_SETTING_WIRELESS_WAKE_ON_WLAN_RFKILL_RELEASE);
    _E(NM_SETTING_WIRELESS_WAKE_ON_WLAN_TCP);
    _E(NM_SETTING_WIRELESS_WAKE_ON_WLAN_ALL);
    _E(NM_SETTING_WIRELESS_WAKE_ON_WLAN_DEFAULT);
    _E(NM_SETTING_WIRELESS_WAKE_ON_WLAN_IGNORE);
    _E(NM_SETTING_WIRELESS_WAKE_ON_WLAN_EXCLUSIVE_FLAGS);
#undef _E

    flags_class = G_FLAGS_CLASS(g_type_class_ref(NM_TYPE_SETTING_WIRELESS_WAKE_ON_WLAN));
    for (i = 0; i < flags_class->n_values; i++) {
        const GFlagsValue *value = &flags_class->values[i];

        if (!g_hash_table_contains(vals, GUINT_TO_POINTER(value->value))) {
            g_error("The enum value %s from NMSettingWirelessWakeOnWLan is not checked for "
                    "_NMSettingWirelessWakeOnWLan",
                    value->value_name);
        }
    }
}

/*****************************************************************************/

static void
test_device_wifi_capabilities(void)
{
    nm_auto_unref_gtypeclass GFlagsClass *flags_class = NULL;
    gs_unref_hashtable GHashTable *vals               = g_hash_table_new(nm_direct_hash, NULL);
    guint                          i;

    G_STATIC_ASSERT_EXPR(sizeof(NMDeviceWifiCapabilities) == sizeof(_NMDeviceWifiCapabilities));
    G_STATIC_ASSERT_EXPR(sizeof(NMDeviceWifiCapabilities) < sizeof(gint64));

    G_STATIC_ASSERT_EXPR(sizeof(NMDeviceWifiCapabilities) < sizeof(gint64));
    g_assert((((gint64) ((NMDeviceWifiCapabilities) -1)) < 0)
             == (((gint64) ((_NMDeviceWifiCapabilities) -1)) < 0));

#define _E(n)                                             \
    G_STMT_START                                          \
    {                                                     \
        G_STATIC_ASSERT_EXPR(n == (gint64) _##n);         \
        G_STATIC_ASSERT_EXPR(_##n == (gint64) n);         \
        if (!g_hash_table_add(vals, GUINT_TO_POINTER(n))) \
            g_assert_not_reached();                       \
    }                                                     \
    G_STMT_END
    _E(NM_WIFI_DEVICE_CAP_NONE);
    _E(NM_WIFI_DEVICE_CAP_CIPHER_WEP40);
    _E(NM_WIFI_DEVICE_CAP_CIPHER_WEP104);
    _E(NM_WIFI_DEVICE_CAP_CIPHER_TKIP);
    _E(NM_WIFI_DEVICE_CAP_CIPHER_CCMP);
    _E(NM_WIFI_DEVICE_CAP_WPA);
    _E(NM_WIFI_DEVICE_CAP_RSN);
    _E(NM_WIFI_DEVICE_CAP_AP);
    _E(NM_WIFI_DEVICE_CAP_ADHOC);
    _E(NM_WIFI_DEVICE_CAP_FREQ_VALID);
    _E(NM_WIFI_DEVICE_CAP_FREQ_2GHZ);
    _E(NM_WIFI_DEVICE_CAP_FREQ_5GHZ);
    _E(NM_WIFI_DEVICE_CAP_MESH);
    _E(NM_WIFI_DEVICE_CAP_IBSS_RSN);
#undef _E

    flags_class = G_FLAGS_CLASS(g_type_class_ref(NM_TYPE_DEVICE_WIFI_CAPABILITIES));
    for (i = 0; i < flags_class->n_values; i++) {
        const GFlagsValue *value = &flags_class->values[i];

        if (!g_hash_table_contains(vals, GUINT_TO_POINTER(value->value))) {
            g_error("The enum value %s from NMDeviceWifiCapabilities is not checked for "
                    "_NMDeviceWifiCapabilities",
                    value->value_name);
        }
    }
}

/*****************************************************************************/

static void
test_80211_mode(void)
{
    nm_auto_unref_gtypeclass GEnumClass *enum_class = NULL;
    gs_unref_hashtable GHashTable *vals             = g_hash_table_new(nm_direct_hash, NULL);
    guint                          i;

    G_STATIC_ASSERT_EXPR(sizeof(NM80211Mode) == sizeof(_NM80211Mode));
    G_STATIC_ASSERT_EXPR(sizeof(NM80211Mode) < sizeof(gint64));

    G_STATIC_ASSERT_EXPR(sizeof(NM80211Mode) < sizeof(gint64));
    g_assert((((gint64) ((NM80211Mode) -1)) < 0) == (((gint64) ((_NM80211Mode) -1)) < 0));

#define _E(n)                                            \
    G_STMT_START                                         \
    {                                                    \
        G_STATIC_ASSERT_EXPR(n == (gint64) _##n);        \
        G_STATIC_ASSERT_EXPR(_##n == (gint64) n);        \
        g_assert(n == NM_802_11_MODE_CAST(_##n));        \
        if (!g_hash_table_add(vals, GINT_TO_POINTER(n))) \
            g_assert_not_reached();                      \
    }                                                    \
    G_STMT_END
    _E(NM_802_11_MODE_UNKNOWN);
    _E(NM_802_11_MODE_ADHOC);
    _E(NM_802_11_MODE_INFRA);
    _E(NM_802_11_MODE_AP);
    _E(NM_802_11_MODE_MESH);
#undef _E

    enum_class = G_ENUM_CLASS(g_type_class_ref(NM_TYPE_802_11_MODE));
    for (i = 0; i < enum_class->n_values; i++) {
        const GEnumValue *value = &enum_class->values[i];

        if (!g_hash_table_contains(vals, GINT_TO_POINTER(value->value))) {
            g_error("The enum value %s from NM80211Mode is not checked for "
                    "_NM80211Mode",
                    value->value_name);
        }
    }
}

/*****************************************************************************/

static void
test_vlan_flags(void)
{
    nm_auto_unref_gtypeclass GFlagsClass *flags_class = NULL;
    gs_unref_hashtable GHashTable *vals               = g_hash_table_new(nm_direct_hash, NULL);
    guint                          i;

    G_STATIC_ASSERT_EXPR(sizeof(NMVlanFlags) == sizeof(_NMVlanFlags));
    G_STATIC_ASSERT_EXPR(sizeof(NMVlanFlags) < sizeof(gint64));

    G_STATIC_ASSERT_EXPR(sizeof(NMVlanFlags) < sizeof(gint64));
    g_assert((((gint64) ((NMVlanFlags) -1)) < 0) == (((gint64) ((_NMVlanFlags) -1)) < 0));

#define _E(n)                                             \
    G_STMT_START                                          \
    {                                                     \
        G_STATIC_ASSERT_EXPR(n == (gint64) _##n);         \
        G_STATIC_ASSERT_EXPR(_##n == (gint64) n);         \
        g_assert(n == NM_VLAN_FLAGS_CAST(_##n));          \
        if (!g_hash_table_add(vals, GUINT_TO_POINTER(n))) \
            g_assert_not_reached();                       \
    }                                                     \
    G_STMT_END
    _E(NM_VLAN_FLAG_REORDER_HEADERS);
    _E(NM_VLAN_FLAG_GVRP);
    _E(NM_VLAN_FLAG_LOOSE_BINDING);
    _E(NM_VLAN_FLAG_MVRP);
    _E(NM_VLAN_FLAGS_ALL);
#undef _E

    flags_class = G_FLAGS_CLASS(g_type_class_ref(NM_TYPE_VLAN_FLAGS));
    for (i = 0; i < flags_class->n_values; i++) {
        const GFlagsValue *value = &flags_class->values[i];

        if (!g_hash_table_contains(vals, GUINT_TO_POINTER(value->value))) {
            g_error("The enum value %s from NMVlanFlags is not checked for "
                    "_NMVlanFlags",
                    value->value_name);
        }
    }
}

/*****************************************************************************/

typedef struct _nm_packed {
    int    v0;
    char   v1;
    double v2;
    guint8 v3;
} TestHashStruct;

static void
_test_hash_struct(int v0, char v1, double v2, guint8 v3)
{
    const TestHashStruct s = {
        .v0 = v0,
        .v1 = v1,
        .v2 = v2,
        .v3 = v3,
    };
    NMHashState h;
    guint       hh;

    nm_hash_init(&h, 100);
    nm_hash_update(&h, &s, sizeof(s));
    hh = nm_hash_complete(&h);

    nm_hash_init(&h, 100);
    nm_hash_update_val(&h, v0);
    nm_hash_update_val(&h, v1);
    nm_hash_update_val(&h, v2);
    nm_hash_update_val(&h, v3);
    g_assert_cmpint(hh, ==, nm_hash_complete(&h));

    nm_hash_init(&h, 100);
    nm_hash_update_vals(&h, v0, v1, v2, v3);
    g_assert_cmpint(hh, ==, nm_hash_complete(&h));
}

static guint
_test_hash_str(const char *str)
{
    NMHashState h;
    guint       v, v2;
    const guint SEED = 10;

    nm_hash_init(&h, SEED);
    nm_hash_update_str0(&h, str);
    v = nm_hash_complete(&h);

    /* assert that hashing a string and a buffer yields the
     * same result.
     *
     * I think that is a desirable property. */
    nm_hash_init(&h, SEED);
    nm_hash_update_mem(&h, str, strlen(str));
    v2 = nm_hash_complete(&h);

    g_assert(v == v2);
    return v;
}

#define _test_hash_vals(type, ...)                                                 \
    G_STMT_START                                                                   \
    {                                                                              \
        NMHashState h0, h1, h2, h3;                                                \
        const type  v[] = {__VA_ARGS__};                                           \
        guint       h;                                                             \
        guint       i;                                                             \
                                                                                   \
        nm_hash_init(&h0, 10);                                                     \
        nm_hash_init(&h1, 10);                                                     \
        nm_hash_init(&h2, 10);                                                     \
        nm_hash_init(&h3, 10);                                                     \
                                                                                   \
        /* assert that it doesn't matter, whether we hash the values individually,
         * or all at once, or via the convenience macros nm_hash_update_val()
         * and nm_hash_update_vals(). */ \
        for (i = 0; i < G_N_ELEMENTS(v); i++) {                                    \
            nm_hash_update(&h0, &v[i], sizeof(type));                              \
            nm_hash_update_val(&h1, v[i]);                                         \
        }                                                                          \
        nm_hash_update_vals(&h2, __VA_ARGS__);                                     \
        nm_hash_update(&h3, v, sizeof(v));                                         \
                                                                                   \
        h = nm_hash_complete(&h0);                                                 \
        g_assert_cmpint(h, ==, nm_hash_complete(&h1));                             \
        g_assert_cmpint(h, ==, nm_hash_complete(&h2));                             \
        g_assert_cmpint(h, ==, nm_hash_complete(&h3));                             \
    }                                                                              \
    G_STMT_END

static void
test_nm_hash(void)
{
    g_assert(nm_hash_static(0));
    g_assert(nm_hash_static(777));

    g_assert(nm_hash_str(NULL));
    g_assert(nm_hash_str(""));
    g_assert(nm_hash_str("a"));

    g_assert(nm_hash_ptr(NULL));
    g_assert(nm_hash_ptr(""));
    g_assert(nm_hash_ptr("a"));

    _test_hash_str("");
    _test_hash_str("a");
    _test_hash_str("aa");
    _test_hash_str("diceros bicornis longipes");

    /* assert that nm_hash_update_vals() is the same as calling nm_hash_update_val() multiple times. */
    _test_hash_vals(int, 1);
    _test_hash_vals(int, 1, 2);
    _test_hash_vals(int, 1, 2, 3);
    _test_hash_vals(int, 1, 2, 3, 4);
    _test_hash_vals(long, 1l);
    _test_hash_vals(long, 1l, 2l, 3l, 4l, 5l);

    _test_hash_struct(10, 'a', 5.4, 7);
    _test_hash_struct(-10, '\0', -5.4e49, 255);

    g_assert_cmpint(NM_HASH_COMBINE_BOOLS(guint8, 1, 0), ==, 0x002);
    g_assert_cmpint(NM_HASH_COMBINE_BOOLS(guint8, 1, 1), ==, 0x003);
    g_assert_cmpint(NM_HASH_COMBINE_BOOLS(guint8, 1, 1, 0, 0, 0, 0), ==, 0x030);
    g_assert_cmpint(NM_HASH_COMBINE_BOOLS(guint8, 1, 1, 0, 0, 0, 1), ==, 0x031);
    g_assert_cmpint(NM_HASH_COMBINE_BOOLS(guint8, 0, 0, 1, 1, 0, 0, 0, 1), ==, 0x031);
    g_assert_cmpint(NM_HASH_COMBINE_BOOLS(guint16, 0, 0, 1, 1, 0, 0, 0, 1), ==, 0x031);
    g_assert_cmpint(NM_HASH_COMBINE_BOOLS(guint16, 0, 0, 0, 1, 1, 0, 0, 0, 1), ==, 0x031);
    g_assert_cmpint(NM_HASH_COMBINE_BOOLS(guint16, 1, 0, 0, 1, 1, 0, 0, 0, 1), ==, 0x131);
    g_assert_cmpint(NM_HASH_COMBINE_BOOLS(guint16, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1),
                    ==,
                    0x131);
    g_assert_cmpint(NM_HASH_COMBINE_BOOLS(guint16, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1),
                    ==,
                    0x8131);
    g_assert_cmpint(
        NM_HASH_COMBINE_BOOLS(guint32, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1),
        ==,
        0x8131);
    g_assert_cmpint(
        NM_HASH_COMBINE_BOOLS(guint32, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1),
        ==,
        0x28131);

#if _NM_CC_SUPPORT_AUTO_TYPE
    {
        _nm_auto_type x = NM_HASH_COMBINE_BOOLS(guint8, 0, 0, 1, 1, 0, 0, 0, 1);

        G_STATIC_ASSERT(sizeof(x) == 1);
        g_assert(((typeof(x)) -1) > 0);
    }

    {
        _nm_auto_type x = NM_HASH_COMBINE_BOOLS(guint16, 0, 0, 1, 1, 0, 0, 0, 1);

        G_STATIC_ASSERT(sizeof(x) == 2);
        g_assert(((typeof(x)) -1) > 0);
    }
#endif

    NM_STATIC_ASSERT_EXPR_VOID(NM_HASH_COMBINE_BOOLS(int, 1, 0, 1) == 5);
}

/*****************************************************************************/

static void
test_nm_g_slice_free_fcn(void)
{
    gpointer p;
    struct {
        char a1;
        char a2;
    } xx;

    p = g_slice_new(gint64);
    (nm_g_slice_free_fcn(gint64))(p);

    p = g_slice_new(gint32);
    (nm_g_slice_free_fcn(gint32))(p);

    p = g_slice_new(int);
    (nm_g_slice_free_fcn(int))(p);

    p = g_slice_new(gint64);
    nm_g_slice_free_fcn_gint64(p);

    p = g_slice_alloc(sizeof(xx));
    (nm_g_slice_free_fcn(xx))(p);
}

/*****************************************************************************/

static void
_do_test_nm_utils_strsplit_set_f_one(NMUtilsStrsplitSetFlags flags,
                                     const char *            str,
                                     gsize                   words_len,
                                     const char *const *     exp_words)
{
#define DELIMITERS   " \n"
#define DELIMITERS_C ' ', '\n'

    gs_free const char **words = NULL;
    gsize                i, j, k;
    const gboolean       f_allow_escaping =
        NM_FLAGS_HAS(flags, NM_UTILS_STRSPLIT_SET_FLAGS_ALLOW_ESCAPING);
    const gboolean f_preserve_empty =
        NM_FLAGS_HAS(flags, NM_UTILS_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY);
    const char *       s1;
    gsize              initial_offset;
    gs_strfreev char **words_g = NULL;

    g_assert(!NM_FLAGS_ANY(flags,
                           ~(NM_UTILS_STRSPLIT_SET_FLAGS_ALLOW_ESCAPING
                             | NM_UTILS_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY)));

    /* assert that the expected words are valid (and don't contain unescaped delimiters). */
    for (i = 0; i < words_len; i++) {
        const char *w = exp_words[i];

        g_assert(w);
        if (!f_preserve_empty)
            g_assert(w[0]);
        for (k = 0; w[k];) {
            if (f_allow_escaping && w[k] == '\\') {
                k++;
                if (w[k] == '\0')
                    break;
                k++;
                continue;
            }
            g_assert(!NM_IN_SET(w[k], DELIMITERS_C));
            k++;
        }
        if (!f_allow_escaping)
            g_assert(!NM_STRCHAR_ANY(w, ch, NM_IN_SET(ch, DELIMITERS_C)));
    }

    initial_offset = (f_preserve_empty || !str) ? 0u : strspn(str, DELIMITERS);

    /* first compare our expected values with what g_strsplit_set() would
     * do. */
    words_g = str ? g_strsplit_set(str, DELIMITERS, -1) : NULL;
    if (str == NULL) {
        g_assert_cmpint(words_len, ==, 0);
        g_assert(!words_g);
    } else if (nm_streq0(str, "")) {
        g_assert_cmpint(words_len, ==, 0);
        g_assert(words_g);
        g_assert(!words_g[0]);
    } else {
        g_assert(words_g);
        g_assert(words_g[0]);
        if (!f_allow_escaping) {
            if (!f_preserve_empty) {
                for (i = 0, j = 0; words_g[i]; i++) {
                    if (words_g[i][0] == '\0')
                        g_free(words_g[i]);
                    else
                        words_g[j++] = words_g[i];
                }
                words_g[j] = NULL;
            }
            if (f_preserve_empty)
                g_assert_cmpint(words_len, >, 0);
            for (i = 0; i < words_len; i++) {
                g_assert(exp_words[i]);
                g_assert_cmpstr(exp_words[i], ==, words_g[i]);
            }
            g_assert(words_g[words_len] == NULL);
            g_assert_cmpint(NM_PTRARRAY_LEN(words_g), ==, words_len);
            g_assert(nm_utils_strv_cmp_n(exp_words, words_len, words_g, -1) == 0);
        }
    }

    if (flags == NM_UTILS_STRSPLIT_SET_FLAGS_NONE && nmtst_get_rand_bool())
        words = nm_utils_strsplit_set(str, DELIMITERS);
    else if (flags == NM_UTILS_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY && nmtst_get_rand_bool())
        words = nm_utils_strsplit_set_with_empty(str, DELIMITERS);
    else
        words = nm_utils_strsplit_set_full(str, DELIMITERS, flags);

    g_assert_cmpint(NM_PTRARRAY_LEN(words), ==, words_len);

    if (words_len == 0) {
        g_assert(!words);
        g_assert(!str || NM_STRCHAR_ALL(str, ch, NM_IN_SET(ch, DELIMITERS_C)));
        return;
    }

    g_assert(words);
    for (i = 0; i < words_len; i++)
        g_assert_cmpstr(exp_words[i], ==, words[i]);
    g_assert(words[words_len] == NULL);

    g_assert(nm_utils_strv_cmp_n(exp_words, words_len, words, -1) == 0);

    s1 = words[0];
    g_assert(s1 >= (char *) &words[words_len + 1]);
    s1 = &s1[strlen(str)];
    for (i = 1; i < words_len; i++) {
        g_assert(&(words[i - 1])[strlen(words[i - 1])] < words[i]);
        g_assert(words[i] <= s1);
    }

    /* while strsplit removes all delimiters, we can relatively easily find them
     * in the original string. Assert that the original string and the pointer offsets
     * of words correspond. In particular, find idx_delim_after and idx_delim_before
     * to determine which delimiter was after/before a word. */
    {
        gsize idx_word_start;
        gsize idx_delim_after_old = G_MAXSIZE;

        idx_word_start = initial_offset;
        for (i = 0; i < words_len; i++) {
            const gsize l_i = strlen(words[i]);
            gsize       idx_delim_after;
            gsize       idx_delim_before;

            /* find the delimiter *after* words[i]. We can do that by looking at the next
             * word and calculating the pointer difference.
             *
             * The delimiter after the very last word is '\0' and requires strlen() to find. */
            idx_delim_after = initial_offset + ((words[i] - words[0]) + l_i);
            if (idx_delim_after != idx_word_start + l_i) {
                g_assert(!f_preserve_empty);
                g_assert_cmpint(idx_word_start + l_i, <, idx_delim_after);
                idx_word_start = idx_delim_after - l_i;
            }
            if (i + 1 < words_len) {
                gsize x = initial_offset + ((words[i + 1] - words[0]) - 1);

                if (idx_delim_after != x) {
                    g_assert(!f_preserve_empty);
                    g_assert_cmpint(idx_delim_after, <, x);
                    for (k = idx_delim_after; k <= x; k++)
                        g_assert(NM_IN_SET(str[k], DELIMITERS_C));
                }
                g_assert(NM_IN_SET(str[idx_delim_after], DELIMITERS_C));
            } else {
                if (f_preserve_empty)
                    g_assert(NM_IN_SET(str[idx_delim_after], '\0'));
                else
                    g_assert(NM_IN_SET(str[idx_delim_after], '\0', DELIMITERS_C));
            }

            /* find the delimiter *before* words[i]. */
            if (i == 0) {
                /* there is only a delimiter *before*, with !f_preserve_empty and leading
                 * delimiters. */
                idx_delim_before = G_MAXSIZE;
                if (initial_offset > 0) {
                    g_assert(!f_preserve_empty);
                    idx_delim_before = initial_offset - 1;
                }
            } else
                idx_delim_before = initial_offset + (words[i] - words[0]) - 1;
            if (idx_delim_before != G_MAXSIZE)
                g_assert(NM_IN_SET(str[idx_delim_before], DELIMITERS_C));
            if (idx_delim_after_old != idx_delim_before) {
                g_assert(!f_preserve_empty);
                if (i == 0) {
                    g_assert_cmpint(initial_offset, >, 0);
                    g_assert_cmpint(idx_delim_before, !=, G_MAXSIZE);
                    g_assert_cmpint(idx_delim_before, ==, initial_offset - 1);
                } else {
                    g_assert_cmpint(idx_delim_after_old, !=, G_MAXSIZE);
                    g_assert_cmpint(idx_delim_before, !=, G_MAXSIZE);
                    g_assert_cmpint(idx_delim_after_old, <, idx_delim_before);
                    for (k = idx_delim_after_old; k <= idx_delim_before; k++)
                        g_assert(NM_IN_SET(str[k], DELIMITERS_C));
                }
            }

            for (k = 0; k < l_i;) {
                if (f_allow_escaping && str[idx_word_start + k] == '\\') {
                    k++;
                    if (k >= l_i)
                        break;
                    k++;
                    continue;
                }
                g_assert(!NM_IN_SET(str[idx_word_start + k], DELIMITERS_C));
                k++;
            }
            g_assert(strncmp(words[i], &str[idx_word_start], l_i) == 0);

            if (i > 0) {
                const char *s = &(words[i - 1])[strlen(words[i - 1]) + 1];

                if (s != words[i]) {
                    g_assert(!f_preserve_empty);
                    g_assert(s < words[i]);
                }
            }

            idx_word_start += l_i + 1;
            idx_delim_after_old = idx_delim_after;
        }
    }
}

static void
_do_test_nm_utils_strsplit_set_f(NMUtilsStrsplitSetFlags flags,
                                 const char *            str,
                                 gsize                   words_len,
                                 const char *const *     exp_words)
{
    _do_test_nm_utils_strsplit_set_f_one(flags, str, words_len, exp_words);

    if (NM_FLAGS_HAS(flags, NM_UTILS_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY)) {
        gs_unref_ptrarray GPtrArray *exp_words2 = NULL;
        gsize                        k;

        exp_words2 = g_ptr_array_new();
        for (k = 0; k < words_len; k++) {
            if (exp_words[k][0] != '\0')
                g_ptr_array_add(exp_words2, (gpointer) exp_words[k]);
        }

        _do_test_nm_utils_strsplit_set_f_one(flags & (~NM_UTILS_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY),
                                             str,
                                             exp_words2->len,
                                             (const char *const *) exp_words2->pdata);
    }
}

#define do_test_nm_utils_strsplit_set_f(flags, str, ...) \
    _do_test_nm_utils_strsplit_set_f(flags, str, NM_NARG(__VA_ARGS__), NM_MAKE_STRV(__VA_ARGS__))

#define do_test_nm_utils_strsplit_set(allow_escaping, str, ...)                                   \
    do_test_nm_utils_strsplit_set_f((allow_escaping) ? NM_UTILS_STRSPLIT_SET_FLAGS_ALLOW_ESCAPING \
                                                     : NM_UTILS_STRSPLIT_SET_FLAGS_NONE,          \
                                    str,                                                          \
                                    ##__VA_ARGS__)

static void
_do_test_nm_utils_strsplit_set_simple(NMUtilsStrsplitSetFlags flags,
                                      const char *            str,
                                      gsize                   words_len,
                                      const char *const *     exp_words)
{
    gs_free const char **tokens = NULL;
    gsize                n_tokens;

    tokens = nm_utils_strsplit_set_full(str, DELIMITERS, flags);

    if (!tokens) {
        g_assert_cmpint(words_len, ==, 0);
        return;
    }

    g_assert(str && str[0]);
    g_assert_cmpint(words_len, >, 0);
    n_tokens = NM_PTRARRAY_LEN(tokens);

    if (nm_utils_strv_cmp_n(exp_words, words_len, tokens, -1) != 0) {
        gsize i;

        g_print(">>> split \"%s\" (flags %x) got %zu tokens (%zu expected)\n",
                str,
                (guint) flags,
                n_tokens,
                words_len);
        for (i = 0; i < NM_MAX(n_tokens, words_len); i++) {
            const char *s1 = i < n_tokens ? tokens[i] : NULL;
            const char *s2 = i < words_len ? exp_words[i] : NULL;

            g_print(">>> [%zu]: %s - %s%s%s vs. %s%s%s\n",
                    i,
                    nm_streq0(s1, s2) ? "same" : "diff",
                    NM_PRINT_FMT_QUOTE_STRING(s1),
                    NM_PRINT_FMT_QUOTE_STRING(s2));
        }
        g_assert_not_reached();
    }
    g_assert_cmpint(words_len, ==, NM_PTRARRAY_LEN(tokens));
}
#define do_test_nm_utils_strsplit_set_simple(flags, str, ...)   \
    _do_test_nm_utils_strsplit_set_simple((flags),              \
                                          (str),                \
                                          NM_NARG(__VA_ARGS__), \
                                          NM_MAKE_STRV(__VA_ARGS__))

static void
test_nm_utils_strsplit_set(void)
{
    gs_unref_ptrarray GPtrArray *words_exp = NULL;
    guint                        test_run;

    do_test_nm_utils_strsplit_set_f(NM_UTILS_STRSPLIT_SET_FLAGS_NONE, NULL);
    do_test_nm_utils_strsplit_set_f(NM_UTILS_STRSPLIT_SET_FLAGS_NONE, "");
    do_test_nm_utils_strsplit_set_f(NM_UTILS_STRSPLIT_SET_FLAGS_NONE, " ");
    do_test_nm_utils_strsplit_set_f(NM_UTILS_STRSPLIT_SET_FLAGS_NONE, "a  b", "a", "b");

    do_test_nm_utils_strsplit_set_f(NM_UTILS_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY, NULL);
    do_test_nm_utils_strsplit_set_f(NM_UTILS_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY, "");
    do_test_nm_utils_strsplit_set_f(NM_UTILS_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY, " ", "", "");
    do_test_nm_utils_strsplit_set_f(NM_UTILS_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY, "  ", "", "", "");
    do_test_nm_utils_strsplit_set_f(NM_UTILS_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY, "a  ", "a", "", "");
    do_test_nm_utils_strsplit_set_f(NM_UTILS_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY,
                                    "a  b",
                                    "a",
                                    "",
                                    "b");
    do_test_nm_utils_strsplit_set_f(NM_UTILS_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY,
                                    " ab  b",
                                    "",
                                    "ab",
                                    "",
                                    "b");
    do_test_nm_utils_strsplit_set_f(NM_UTILS_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY,
                                    "ab  b",
                                    "ab",
                                    "",
                                    "b");
    do_test_nm_utils_strsplit_set_f(NM_UTILS_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY, "abb", "abb");
    do_test_nm_utils_strsplit_set_f(NM_UTILS_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY,
                                    "abb  bb ",
                                    "abb",
                                    "",
                                    "bb",
                                    "");
    do_test_nm_utils_strsplit_set_f(NM_UTILS_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY,
                                    "abb bcb ",
                                    "abb",
                                    "bcb",
                                    "");

    do_test_nm_utils_strsplit_set(FALSE, NULL);
    do_test_nm_utils_strsplit_set(FALSE, "");
    do_test_nm_utils_strsplit_set(FALSE, "\n");
    do_test_nm_utils_strsplit_set(TRUE, " \t\n", "\t");
    do_test_nm_utils_strsplit_set(FALSE, "a", "a");
    do_test_nm_utils_strsplit_set(FALSE, "a b", "a", "b");
    do_test_nm_utils_strsplit_set(FALSE, "a\rb", "a\rb");
    do_test_nm_utils_strsplit_set(FALSE, "  a\rb  ", "a\rb");
    do_test_nm_utils_strsplit_set(FALSE, "  a bbbd afds ere", "a", "bbbd", "afds", "ere");
    do_test_nm_utils_strsplit_set(FALSE,
                                  "1 2 3 4 5 6 7 8 9 0 "
                                  "1 2 3 4 5 6 7 8 9 0 "
                                  "1 2 3 4 5 6 7 8 9 0",
                                  "1",
                                  "2",
                                  "3",
                                  "4",
                                  "5",
                                  "6",
                                  "7",
                                  "8",
                                  "9",
                                  "0",
                                  "1",
                                  "2",
                                  "3",
                                  "4",
                                  "5",
                                  "6",
                                  "7",
                                  "8",
                                  "9",
                                  "0",
                                  "1",
                                  "2",
                                  "3",
                                  "4",
                                  "5",
                                  "6",
                                  "7",
                                  "8",
                                  "9",
                                  "0");
    do_test_nm_utils_strsplit_set(TRUE, "\\", "\\");
    do_test_nm_utils_strsplit_set(TRUE, "\\ ", "\\ ");
    do_test_nm_utils_strsplit_set(TRUE, "\\\\", "\\\\");
    do_test_nm_utils_strsplit_set(TRUE, "\\\t", "\\\t");
    do_test_nm_utils_strsplit_set(TRUE, "foo\\", "foo\\");
    do_test_nm_utils_strsplit_set(TRUE, "bar foo\\", "bar", "foo\\");
    do_test_nm_utils_strsplit_set(TRUE, "\\ a b\\ \\  c", "\\ a", "b\\ \\ ", "c");

    words_exp = g_ptr_array_new_with_free_func(g_free);
    for (test_run = 0; test_run < 100; test_run++) {
        gboolean      f_allow_escaping = nmtst_get_rand_bool();
        guint         words_len        = nmtst_get_rand_uint32() % 100;
        gs_free char *str              = NULL;
        guint         i;

        g_ptr_array_set_size(words_exp, 0);
        for (i = 0; i < words_len; i++) {
            guint word_len;
            char *word;
            guint j;

            word_len = nmtst_get_rand_uint32();
            if ((word_len % 100) < 30)
                word_len = 0;
            else
                word_len = (word_len >> 10) % 100;
            word = g_new(char, word_len + 3);
            for (j = 0; j < word_len;) {
                guint32           p                = nmtst_get_rand_uint32();
                static const char delimiters_arr[] = {DELIMITERS_C};
                static const char regular_chars[]  = "abcdefghijklmnopqrstuvwxyz";

                if (!f_allow_escaping || (p % 1000) < 700) {
                    if (((p >> 20) % 100) < 20)
                        word[j++] = '\\';
                    word[j++] = regular_chars[(p >> 11) % (G_N_ELEMENTS(regular_chars) - 1)];
                    continue;
                }
                word[j++] = '\\';
                word[j++] = delimiters_arr[(p >> 11) % G_N_ELEMENTS(delimiters_arr)];
            }
            word[j] = '\0';
            g_ptr_array_add(words_exp, word);
        }
        g_ptr_array_add(words_exp, NULL);

        str = g_strjoinv(" ", (char **) words_exp->pdata);

        if (str[0] == '\0' && words_len > 0) {
            g_assert(words_len == 1);
            g_assert_cmpstr(words_exp->pdata[0], ==, "");
            words_len = 0;
        }

        _do_test_nm_utils_strsplit_set_f((f_allow_escaping
                                              ? NM_UTILS_STRSPLIT_SET_FLAGS_ALLOW_ESCAPING
                                              : NM_UTILS_STRSPLIT_SET_FLAGS_NONE)
                                             | NM_UTILS_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY,
                                         str,
                                         words_len,
                                         (const char *const *) words_exp->pdata);
    }

    do_test_nm_utils_strsplit_set_simple(NM_UTILS_STRSPLIT_SET_FLAGS_ESCAPED, "\t", "\t");
    do_test_nm_utils_strsplit_set_simple(NM_UTILS_STRSPLIT_SET_FLAGS_ESCAPED
                                             | NM_UTILS_STRSPLIT_SET_FLAGS_STRSTRIP,
                                         "\t");
    do_test_nm_utils_strsplit_set_simple(NM_UTILS_STRSPLIT_SET_FLAGS_ESCAPED
                                             | NM_UTILS_STRSPLIT_SET_FLAGS_STRSTRIP
                                             | NM_UTILS_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY,
                                         "\t",
                                         "");
    do_test_nm_utils_strsplit_set_simple(NM_UTILS_STRSPLIT_SET_FLAGS_ESCAPED
                                             | NM_UTILS_STRSPLIT_SET_FLAGS_STRSTRIP
                                             | NM_UTILS_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY,
                                         "\t\\\t\t\t\\\t",
                                         "\t\t\t\t");

    do_test_nm_utils_strsplit_set_simple(NM_UTILS_STRSPLIT_SET_FLAGS_ESCAPED, "\ta", "\ta");
    do_test_nm_utils_strsplit_set_simple(NM_UTILS_STRSPLIT_SET_FLAGS_ESCAPED
                                             | NM_UTILS_STRSPLIT_SET_FLAGS_STRSTRIP,
                                         "\ta",
                                         "a");
    do_test_nm_utils_strsplit_set_simple(NM_UTILS_STRSPLIT_SET_FLAGS_ESCAPED,
                                         "\ta\\ b\t\\ ",
                                         "\ta b\t ");
    do_test_nm_utils_strsplit_set_simple(NM_UTILS_STRSPLIT_SET_FLAGS_ESCAPED
                                             | NM_UTILS_STRSPLIT_SET_FLAGS_STRSTRIP,
                                         "\ta\\ b\t\\ \t",
                                         "a b\t ");
    do_test_nm_utils_strsplit_set_simple(NM_UTILS_STRSPLIT_SET_FLAGS_ESCAPED, "a\\  b", "a ", "b");
    do_test_nm_utils_strsplit_set_simple(NM_UTILS_STRSPLIT_SET_FLAGS_ESCAPED,
                                         "\ta\\  b",
                                         "\ta ",
                                         "b");
    do_test_nm_utils_strsplit_set_simple(NM_UTILS_STRSPLIT_SET_FLAGS_ESCAPED
                                             | NM_UTILS_STRSPLIT_SET_FLAGS_STRSTRIP,
                                         "\ta\\  b",
                                         "a ",
                                         "b");
}

/*****************************************************************************/

static char *
_escaped_tokens_create_random_word_full(const char *const *tokens, gsize n_tokens, gsize len)
{
    GString *gstr = g_string_new(NULL);
    gsize    i;
    char     random_token[2] = {0};

    for (i = 0; i < len; i++) {
        const char *token = tokens[nmtst_get_rand_uint32() % n_tokens];

        if (!token[0]) {
            do {
                random_token[0] = nmtst_get_rand_uint32();
            } while (random_token[0] == '\0');
            token = random_token;
        }
        g_string_append(gstr, token);
    }

    /* reallocate the string, so that we don't have any excess memory from
     * the GString buffer. This is so that valgrind may better detect an out
     * or range access. */
    return nm_str_realloc(g_string_free(gstr, FALSE));
}

/* set to 1 to exclude characters that are annoying to see in the debugger
 * and printf() output. */
#define ESCAPED_TOKENS_ONLY_NICE_CHARS 0

static char *
_escaped_tokens_create_random_whitespace(void)
{
    static const char *tokens[] = {
        " ",
#if !ESCAPED_TOKENS_ONLY_NICE_CHARS
        "\n",
        "\t",
        "\r",
        "\f",
#endif
    };

    return _escaped_tokens_create_random_word_full(tokens,
                                                   G_N_ELEMENTS(tokens),
                                                   nmtst_get_rand_word_length(NULL) / 4u);
}

static char *
_escaped_tokens_create_random_word(void)
{
    static const char *tokens[] = {
        "a",
        "b",
        "c",
        " ",
        ",",
        "=",
        "\\",
#if !ESCAPED_TOKENS_ONLY_NICE_CHARS
        "\n",
        "\f",
        ":",
        "",
#endif
    };

    return _escaped_tokens_create_random_word_full(tokens,
                                                   G_N_ELEMENTS(tokens),
                                                   nmtst_get_rand_word_length(NULL));
}

static void
_escaped_tokens_str_append_delimiter(GString *str, gboolean strict, gboolean needs_delimiter)
{
    guint len = nmtst_get_rand_word_length(NULL) / 10u;
    char *s;

again:
    if (!strict) {
        g_string_append(str, (s = _escaped_tokens_create_random_whitespace()));
        nm_clear_g_free(&s);
    }

    if (needs_delimiter)
        g_string_append_c(str, ',');

    if (!strict) {
        g_string_append(str, (s = _escaped_tokens_create_random_whitespace()));
        nm_clear_g_free(&s);
        if (len-- > 0) {
            needs_delimiter = TRUE;
            goto again;
        }
    }
}

static void
_escaped_tokens_split(char *str, const char **out_key, const char **out_val)
{
    const char *key;
    const char *val;
    gsize       len = strlen(str);

    g_assert(str);

    nm_utils_escaped_tokens_options_split(str, &key, &val);
    g_assert(key);
    g_assert(key == str);
    if (val) {
        g_assert(val > str);
        g_assert(val > key);
        g_assert(val <= &str[len]);
    }
    NM_SET_OUT(out_key, key);
    NM_SET_OUT(out_val, val);
}

static void
_escaped_tokens_combine(GString *   combined,
                        const char *key,
                        const char *val,
                        gboolean    strict,
                        gboolean    allow_append_delimiter_before,
                        gboolean    needs_delimiter_after)
{
    gs_free char *escaped_key = NULL;
    gs_free char *escaped_val = NULL;

    if (allow_append_delimiter_before)
        _escaped_tokens_str_append_delimiter(combined, strict, FALSE);
    g_string_append(combined, nm_utils_escaped_tokens_options_escape_key(key, &escaped_key));
    if (val) {
        char *s;

        if (!strict) {
            g_string_append(combined, (s = _escaped_tokens_create_random_whitespace()));
            nm_clear_g_free(&s);
        }
        g_string_append_c(combined, '=');
        if (!strict) {
            g_string_append(combined, (s = _escaped_tokens_create_random_whitespace()));
            nm_clear_g_free(&s);
        }
        g_string_append(combined, nm_utils_escaped_tokens_options_escape_val(val, &escaped_val));
    }
    _escaped_tokens_str_append_delimiter(combined, strict, needs_delimiter_after);
}

static void
_escaped_tokens_check_one_impl(const char *       expected_key,
                               const char *       expected_val,
                               const char *       expected_combination,
                               const char *const *other,
                               gsize              n_other)
{
    nm_auto_free_gstring GString *combined = g_string_new(NULL);
    gsize                         i;

    g_assert(expected_key);
    g_assert(expected_combination);
    g_assert(other);

    _escaped_tokens_combine(combined, expected_key, expected_val, TRUE, TRUE, FALSE);

    g_assert_cmpstr(combined->str, ==, expected_combination);

    for (i = 0; i < n_other + 2u; i++) {
        nm_auto_free_gstring GString *str0        = NULL;
        gs_free const char **         strv_split  = NULL;
        gs_free char *                strv_split0 = NULL;
        const char *                  comb;
        const char *                  key;
        const char *                  val;

        if (i == 0)
            comb = expected_combination;
        else if (i == 1) {
            _escaped_tokens_combine(nm_gstring_prepare(&str0),
                                    expected_key,
                                    expected_val,
                                    FALSE,
                                    TRUE,
                                    FALSE);
            comb = str0->str;
        } else
            comb = other[i - 2];

        strv_split = nm_utils_escaped_tokens_options_split_list(comb);
        if (!strv_split) {
            g_assert_cmpstr(expected_key, ==, "");
            g_assert_cmpstr(expected_val, ==, NULL);
            continue;
        }
        g_assert(expected_val || expected_key[0]);

        g_assert_cmpuint(NM_PTRARRAY_LEN(strv_split), ==, 1u);

        strv_split0 = g_strdup(strv_split[0]);

        _escaped_tokens_split(strv_split0, &key, &val);
        g_assert_cmpstr(key, ==, expected_key);
        g_assert_cmpstr(val, ==, expected_val);
    }
}

#define _escaped_tokens_check_one(expected_key, expected_val, expected_combination, ...) \
    _escaped_tokens_check_one_impl(expected_key,                                         \
                                   expected_val,                                         \
                                   expected_combination,                                 \
                                   NM_MAKE_STRV(__VA_ARGS__),                            \
                                   NM_NARG(__VA_ARGS__))

static void
test_nm_utils_escaped_tokens(void)
{
    int i_run;

    for (i_run = 0; i_run < 1000; i_run++) {
        const guint       num_options            = nmtst_get_rand_word_length(NULL);
        gs_unref_ptrarray GPtrArray *options     = g_ptr_array_new_with_free_func(g_free);
        nm_auto_free_gstring GString *combined   = g_string_new(NULL);
        gs_free const char **         strv_split = NULL;
        guint                         i_option;
        guint                         i;

        /* Generate a list of random words for option key-value pairs. */
        for (i_option = 0; i_option < 2u * num_options; i_option++) {
            char *word = NULL;

            if (i_option % 2u == 1 && nmtst_get_rand_uint32() % 5 == 0
                && strlen(options->pdata[options->len - 1]) > 0u) {
                /* For some options, leave the value unset and only generate a key.
                 *
                 * If key is "", then we cannot do that, because the test below would try
                 * to append "" to the combined list, which the parser then would drop.
                 * Only test omitting the value, if strlen() of the key is positive. */
            } else
                word = _escaped_tokens_create_random_word();
            g_ptr_array_add(options, word);
        }

        /* Combine the options in one comma separated list, with proper escaping. */
        for (i_option = 0; i_option < num_options; i_option++) {
            _escaped_tokens_combine(combined,
                                    options->pdata[2u * i_option + 0u],
                                    options->pdata[2u * i_option + 1u],
                                    FALSE,
                                    i_option == 0,
                                    i_option != num_options - 1);
        }

        /* ensure that we can split and parse the options without difference. */
        strv_split = nm_utils_escaped_tokens_options_split_list(combined->str);
        for (i_option = 0; i_option < num_options; i_option++) {
            const char *  expected_key = options->pdata[2u * i_option + 0u];
            const char *  expected_val = options->pdata[2u * i_option + 1u];
            gs_free char *s_split =
                i_option < NM_PTRARRAY_LEN(strv_split) ? g_strdup(strv_split[i_option]) : NULL;
            const char *key = NULL;
            const char *val = NULL;

            if (s_split)
                _escaped_tokens_split(s_split, &key, &val);

            if (!nm_streq0(key, expected_key) || !nm_streq0(val, expected_val)) {
                g_print(">>> ASSERTION IS ABOUT TO FAIL for item %5d of %5d\n",
                        i_option,
                        num_options);
                g_print(">>> combined =  \"%s\"\n", combined->str);
                g_print(">>> %c   parsed[%5d].key = \"%s\"\n",
                        nm_streq0(key, expected_key) ? ' ' : 'X',
                        i_option,
                        key);
                g_print(">>> %c   parsed[%5d].val = %s%s%s\n",
                        nm_streq0(val, expected_val) ? ' ' : 'X',
                        i_option,
                        NM_PRINT_FMT_QUOTE_STRING(val));
                for (i = 0; i < num_options; i++) {
                    g_print(">>> %c original[%5d].key = \"%s\"\n",
                            i == i_option ? '*' : ' ',
                            i,
                            (char *) options->pdata[2u * i + 0u]);
                    g_print(">>> %c original[%5d].val = %s%s%s\n",
                            i == i_option ? '*' : ' ',
                            i,
                            NM_PRINT_FMT_QUOTE_STRING((char *) options->pdata[2u * i + 1u]));
                }
                for (i = 0; i < NM_PTRARRAY_LEN(strv_split); i++)
                    g_print(">>>      split[%5d]     = \"%s\"\n", i, strv_split[i]);
            }

            g_assert_cmpstr(key, ==, expected_key);
            g_assert_cmpstr(val, ==, expected_val);
        }
        g_assert_cmpint(NM_PTRARRAY_LEN(strv_split), ==, num_options);

        /* Above we show a full round-trip of random option key-value pairs, that they can
         * without loss escape, concatenate, split-list, and split. This proofed that every
         * option key-value pair can be represented as a combined string and parsed back.
         *
         * Now, just check that we can also parse arbitrary random words in nm_utils_escaped_tokens_options_split().
         * split() is a non-injective surjective function. As we check the round-trip above for random words, where
         * options-split() is the last step, we show that every random word can be the output of the function
         * (which shows, the surjective part).
         *
         * But multiple random input arguments, may map to the same output argument (non-injective).
         * Just test whether we can handle random input words without crashing. For that, just use the
         * above generate list of random words.
         */
        for (i = 0; i < 1u + 2u * i_option; i++) {
            gs_free char *str = NULL;
            const char *  cstr;

            if (i == 0)
                cstr = combined->str;
            else
                cstr = options->pdata[i - 1u];
            if (!cstr)
                continue;

            str = g_strdup(cstr);
            _escaped_tokens_split(str, NULL, NULL);
        }
    }

    _escaped_tokens_check_one("", NULL, "");
    _escaped_tokens_check_one("", "", "=", " =");
    _escaped_tokens_check_one("a", "b", "a=b", "a = b");
    _escaped_tokens_check_one("a\\=", "b\\=", "a\\\\\\==b\\\\=", "a\\\\\\==b\\\\\\=");
    _escaped_tokens_check_one("\\=", "\\=", "\\\\\\==\\\\=", "\\\\\\==\\\\\\=");
    _escaped_tokens_check_one(" ", "bb=", "\\ =bb=", "\\ =bb\\=");
    _escaped_tokens_check_one(" ", "bb\\=", "\\ =bb\\\\=", "\\ =bb\\\\\\=");
    _escaped_tokens_check_one("a b", "a  b", "a b=a  b");
    _escaped_tokens_check_one("a b", "a  b", "a b=a  b");
    _escaped_tokens_check_one("a = b", "a = b", "a \\= b=a = b", "a \\= b=a \\= b");
}

/*****************************************************************************/

typedef struct {
    int   val;
    CList lst;
} CListSort;

static int
_c_list_sort_cmp(const CList *lst_a, const CList *lst_b, const void *user_data)
{
    const CListSort *a, *b;

    g_assert(lst_a);
    g_assert(lst_b);
    g_assert(lst_a != lst_b);

    a = c_list_entry(lst_a, CListSort, lst);
    b = c_list_entry(lst_b, CListSort, lst);

    if (a->val < b->val)
        return -1;
    if (a->val > b->val)
        return 1;
    return 0;
}

static void
_do_test_c_list_sort(CListSort *elements, guint n_list, gboolean headless)
{
    CList            head, *iter, *iter_prev, *lst;
    guint            i;
    const CListSort *el_prev;
    CListSort *      el;

    c_list_init(&head);
    for (i = 0; i < n_list; i++) {
        el      = &elements[i];
        el->val = nmtst_get_rand_uint32() % (2 * n_list);
        c_list_link_tail(&head, &el->lst);
    }

    if (headless) {
        lst = head.next;
        c_list_unlink_stale(&head);
        lst = c_list_sort_headless(lst, _c_list_sort_cmp, NULL);
        g_assert(lst);
        g_assert(lst->next);
        g_assert(lst->prev);
        g_assert(c_list_length(lst) == n_list - 1);
        iter_prev = lst->prev;
        for (iter = lst; iter != lst; iter = iter->next) {
            g_assert(iter);
            g_assert(iter->next);
            g_assert(iter->prev == iter_prev);
        }
        c_list_link_before(lst, &head);
    } else
        c_list_sort(&head, _c_list_sort_cmp, NULL);

    g_assert(!c_list_is_empty(&head));
    g_assert(c_list_length(&head) == n_list);

    el_prev = NULL;
    c_list_for_each (iter, &head) {
        el = c_list_entry(iter, CListSort, lst);
        g_assert(el >= elements && el < &elements[n_list]);
        if (el_prev) {
            if (el_prev->val == el->val)
                g_assert(el_prev < el);
            else
                g_assert(el_prev->val < el->val);
            g_assert(iter->prev == &el_prev->lst);
            g_assert(el_prev->lst.next == iter);
        }
        el_prev = el;
    }
    g_assert(head.prev == &el_prev->lst);
}

static void
test_c_list_sort(void)
{
    const guint N_ELEMENTS = 10000;
    guint       n_list, repeat;
    gs_free CListSort *elements = NULL;

    {
        CList head;

        c_list_init(&head);
        c_list_sort(&head, _c_list_sort_cmp, NULL);
        g_assert(c_list_length(&head) == 0);
        g_assert(c_list_is_empty(&head));
    }

    elements = g_new0(CListSort, N_ELEMENTS);
    for (n_list = 1; n_list < N_ELEMENTS; n_list++) {
        if (n_list > 150) {
            n_list += nmtst_get_rand_uint32() % n_list;
            if (n_list >= N_ELEMENTS)
                break;
        }
        {
            const guint N_REPEAT = n_list > 50 ? 1 : 5;

            for (repeat = 0; repeat < N_REPEAT; repeat++)
                _do_test_c_list_sort(elements, n_list, nmtst_get_rand_uint32() % 2);
        }
    }
}

/*****************************************************************************/

typedef struct {
    NMDedupMultiObj parent;
    guint           val;
    guint           other;
} DedupObj;

static const NMDedupMultiObjClass dedup_obj_class;

static DedupObj *
_dedup_obj_assert(const NMDedupMultiObj *obj)
{
    DedupObj *o;

    g_assert(obj);
    o = (DedupObj *) obj;
    g_assert(o->parent.klass == &dedup_obj_class);
    g_assert(o->parent._ref_count > 0);
    g_assert(o->val > 0);
    return o;
}

static const NMDedupMultiObj *
_dedup_obj_clone(const NMDedupMultiObj *obj)
{
    DedupObj *o, *o2;

    o                     = _dedup_obj_assert(obj);
    o2                    = g_slice_new0(DedupObj);
    o2->parent.klass      = &dedup_obj_class;
    o2->parent._ref_count = 1;
    o2->val               = o->val;
    o2->other             = o->other;
    return (NMDedupMultiObj *) o2;
}

static void
_dedup_obj_destroy(NMDedupMultiObj *obj)
{
    DedupObj *o = (DedupObj *) obj;

    g_assert(o->parent._ref_count == 0);
    o->parent._ref_count = 1;
    o                    = _dedup_obj_assert(obj);
    g_slice_free(DedupObj, o);
}

static void
_dedup_obj_full_hash_update(const NMDedupMultiObj *obj, NMHashState *h)
{
    const DedupObj *o;

    o = _dedup_obj_assert(obj);
    nm_hash_update_vals(h, o->val, o->other);
}

static gboolean
_dedup_obj_full_equal(const NMDedupMultiObj *obj_a, const NMDedupMultiObj *obj_b)
{
    const DedupObj *o_a = _dedup_obj_assert(obj_a);
    const DedupObj *o_b = _dedup_obj_assert(obj_b);

    return o_a->val == o_b->val && o_a->other == o_b->other;
}

static const NMDedupMultiObjClass dedup_obj_class = {
    .obj_clone            = _dedup_obj_clone,
    .obj_destroy          = _dedup_obj_destroy,
    .obj_full_hash_update = _dedup_obj_full_hash_update,
    .obj_full_equal       = _dedup_obj_full_equal,
};

#define DEDUP_OBJ_INIT(val_val, other_other)              \
    (&((DedupObj){                                        \
        .parent =                                         \
            {                                             \
                .klass      = &dedup_obj_class,           \
                ._ref_count = NM_OBJ_REF_COUNT_STACKINIT, \
            },                                            \
        .val   = (val_val),                               \
        .other = (other_other),                           \
    }))

typedef struct {
    NMDedupMultiIdxType parent;
    guint               partition_size;
    guint               val_mod;
} DedupIdxType;

static const NMDedupMultiIdxTypeClass dedup_idx_type_class;

static const DedupIdxType *
_dedup_idx_assert(const NMDedupMultiIdxType *idx_type)
{
    DedupIdxType *t;

    g_assert(idx_type);
    t = (DedupIdxType *) idx_type;
    g_assert(t->parent.klass == &dedup_idx_type_class);
    g_assert(t->partition_size > 0);
    g_assert(t->val_mod > 0);
    return t;
}

static void
_dedup_idx_obj_id_hash_update(const NMDedupMultiIdxType *idx_type,
                              const NMDedupMultiObj *    obj,
                              NMHashState *              h)
{
    const DedupIdxType *t;
    const DedupObj *    o;

    t = _dedup_idx_assert(idx_type);
    o = _dedup_obj_assert(obj);

    nm_hash_update_val(h, o->val / t->partition_size);
    nm_hash_update_val(h, o->val % t->val_mod);
}

static gboolean
_dedup_idx_obj_id_equal(const NMDedupMultiIdxType *idx_type,
                        const NMDedupMultiObj *    obj_a,
                        const NMDedupMultiObj *    obj_b)
{
    const DedupIdxType *t;
    const DedupObj *    o_a;
    const DedupObj *    o_b;

    t   = _dedup_idx_assert(idx_type);
    o_a = _dedup_obj_assert(obj_a);
    o_b = _dedup_obj_assert(obj_b);

    return (o_a->val / t->partition_size) == (o_b->val / t->partition_size)
           && (o_a->val % t->val_mod) == (o_b->val % t->val_mod);
}

static void
_dedup_idx_obj_partition_hash_update(const NMDedupMultiIdxType *idx_type,
                                     const NMDedupMultiObj *    obj,
                                     NMHashState *              h)
{
    const DedupIdxType *t;
    const DedupObj *    o;

    t = _dedup_idx_assert(idx_type);
    o = _dedup_obj_assert(obj);

    nm_hash_update_val(h, o->val / t->partition_size);
}

static gboolean
_dedup_idx_obj_partition_equal(const NMDedupMultiIdxType *idx_type,
                               const NMDedupMultiObj *    obj_a,
                               const NMDedupMultiObj *    obj_b)
{
    const DedupIdxType *t;
    const DedupObj *    o_a;
    const DedupObj *    o_b;

    t   = _dedup_idx_assert(idx_type);
    o_a = _dedup_obj_assert(obj_a);
    o_b = _dedup_obj_assert(obj_b);

    return (o_a->val / t->partition_size) == (o_b->val / t->partition_size);
}

static const NMDedupMultiIdxTypeClass dedup_idx_type_class = {
    .idx_obj_id_hash_update        = _dedup_idx_obj_id_hash_update,
    .idx_obj_id_equal              = _dedup_idx_obj_id_equal,
    .idx_obj_partition_hash_update = _dedup_idx_obj_partition_hash_update,
    .idx_obj_partition_equal       = _dedup_idx_obj_partition_equal,
};

static const DedupIdxType *
DEDUP_IDX_TYPE_INIT(DedupIdxType *idx_type, guint partition_size, guint val_mod)
{
    nm_dedup_multi_idx_type_init((NMDedupMultiIdxType *) idx_type, &dedup_idx_type_class);
    idx_type->val_mod        = val_mod;
    idx_type->partition_size = partition_size;
    return idx_type;
}

static gboolean
_dedup_idx_add(NMDedupMultiIndex *       idx,
               const DedupIdxType *      idx_type,
               const DedupObj *          obj,
               NMDedupMultiIdxMode       mode,
               const NMDedupMultiEntry **out_entry)
{
    g_assert(idx);
    _dedup_idx_assert((NMDedupMultiIdxType *) idx_type);
    if (obj)
        _dedup_obj_assert((NMDedupMultiObj *) obj);
    return nm_dedup_multi_index_add(idx,
                                    (NMDedupMultiIdxType *) idx_type,
                                    obj,
                                    mode,
                                    out_entry,
                                    NULL);
}

static void
_dedup_head_entry_assert(const NMDedupMultiHeadEntry *entry)
{
    g_assert(entry);
    g_assert(entry->len > 0);
    g_assert(entry->len == c_list_length(&entry->lst_entries_head));
    g_assert(entry->idx_type);
    g_assert(entry->is_head);
}

static const DedupObj *
_dedup_entry_assert(const NMDedupMultiEntry *entry)
{
    g_assert(entry);
    g_assert(!c_list_is_empty(&entry->lst_entries));
    g_assert(entry->head);
    g_assert(!entry->is_head);
    g_assert(entry->head != (gpointer) entry);
    _dedup_head_entry_assert(entry->head);
    return _dedup_obj_assert(entry->obj);
}

static const DedupIdxType *
_dedup_entry_get_idx_type(const NMDedupMultiEntry *entry)
{
    _dedup_entry_assert(entry);

    g_assert(entry->head);
    g_assert(entry->head->idx_type);
    return _dedup_idx_assert(entry->head->idx_type);
}

static void
_dedup_entry_assert_all(const NMDedupMultiEntry *entry,
                        gssize                   expected_idx,
                        const DedupObj *const *  expected_obj)
{
    gsize  n, i;
    CList *iter;

    g_assert(entry);
    _dedup_entry_assert(entry);

    g_assert(expected_obj);
    n = NM_PTRARRAY_LEN(expected_obj);

    g_assert(n == c_list_length(&entry->lst_entries));

    g_assert(expected_idx >= -1 && expected_idx < n);
    g_assert(entry->head);
    if (expected_idx == -1)
        g_assert(entry->head == (gpointer) entry);
    else
        g_assert(entry->head != (gpointer) entry);

    i = 0;
    c_list_for_each (iter, &entry->head->lst_entries_head) {
        const NMDedupMultiEntry *entry_current = c_list_entry(iter, NMDedupMultiEntry, lst_entries);
        const DedupObj *         obj_current;
        const DedupIdxType *     idx_type = _dedup_entry_get_idx_type(entry_current);

        obj_current = _dedup_entry_assert(entry_current);
        g_assert(obj_current);
        g_assert(i < n);
        if (expected_idx == i)
            g_assert(entry_current == entry);
        g_assert(idx_type->parent.klass->idx_obj_partition_equal(
            &idx_type->parent,
            entry_current->obj,
            c_list_entry(entry->head->lst_entries_head.next, NMDedupMultiEntry, lst_entries)->obj));
        i++;
    }
}
#define _dedup_entry_assert_all(entry, expected_idx, ...) \
    _dedup_entry_assert_all(entry, expected_idx, (const DedupObj *const[]){__VA_ARGS__, NULL})

static void
test_dedup_multi(void)
{
    NMDedupMultiIndex *       idx;
    DedupIdxType              IDX_20_3_a_stack;
    const DedupIdxType *const IDX_20_3_a = DEDUP_IDX_TYPE_INIT(&IDX_20_3_a_stack, 20, 3);
    const NMDedupMultiEntry * entry1;

    idx = nm_dedup_multi_index_new();

    g_assert(_dedup_idx_add(idx,
                            IDX_20_3_a,
                            DEDUP_OBJ_INIT(1, 1),
                            NM_DEDUP_MULTI_IDX_MODE_APPEND,
                            &entry1));
    _dedup_entry_assert_all(entry1, 0, DEDUP_OBJ_INIT(1, 1));

    g_assert(nm_dedup_multi_index_obj_find(idx, (NMDedupMultiObj *) DEDUP_OBJ_INIT(1, 1)));
    g_assert(!nm_dedup_multi_index_obj_find(idx, (NMDedupMultiObj *) DEDUP_OBJ_INIT(1, 2)));

    g_assert(_dedup_idx_add(idx,
                            IDX_20_3_a,
                            DEDUP_OBJ_INIT(1, 2),
                            NM_DEDUP_MULTI_IDX_MODE_APPEND,
                            &entry1));
    _dedup_entry_assert_all(entry1, 0, DEDUP_OBJ_INIT(1, 2));

    g_assert(!nm_dedup_multi_index_obj_find(idx, (NMDedupMultiObj *) DEDUP_OBJ_INIT(1, 1)));
    g_assert(nm_dedup_multi_index_obj_find(idx, (NMDedupMultiObj *) DEDUP_OBJ_INIT(1, 2)));

    g_assert(_dedup_idx_add(idx,
                            IDX_20_3_a,
                            DEDUP_OBJ_INIT(2, 2),
                            NM_DEDUP_MULTI_IDX_MODE_APPEND,
                            &entry1));
    _dedup_entry_assert_all(entry1, 1, DEDUP_OBJ_INIT(1, 2), DEDUP_OBJ_INIT(2, 2));

    nm_dedup_multi_index_unref(idx);
}

/*****************************************************************************/

static NMConnection *
_connection_new_from_dbus(GVariant *dict, GError **error)
{
    return _nm_simple_connection_new_from_dbus(dict, NM_SETTING_PARSE_FLAGS_NORMALIZE, error);
}

static void
vpn_check_func(const char *key, const char *value, gpointer user_data)
{
    if (!strcmp(key, "foobar1")) {
        g_assert_cmpstr(value, ==, "blahblah1");
        return;
    }

    if (!strcmp(key, "foobar2")) {
        g_assert_cmpstr(value, ==, "blahblah2");
        return;
    }

    if (!strcmp(key, "foobar3")) {
        g_assert_cmpstr(value, ==, "blahblah3");
        return;
    }

    if (!strcmp(key, "foobar4")) {
        g_assert_cmpstr(value, ==, "blahblah4");
        return;
    }

    g_assert_not_reached();
}

static void
vpn_check_empty_func(const char *key, const char *value, gpointer user_data)
{
    g_assert_not_reached();
}

static void
test_setting_vpn_items(void)
{
    gs_unref_object NMConnection *connection = NULL;
    NMSettingVpn *                s_vpn;

    connection =
        nmtst_create_minimal_connection("vpn-items", NULL, NM_SETTING_VPN_SETTING_NAME, NULL);

    s_vpn = nm_connection_get_setting_vpn(connection);

    nm_setting_vpn_add_data_item(s_vpn, "foobar1", "blahblah1");
    nm_setting_vpn_add_data_item(s_vpn, "foobar2", "blahblah2");
    nm_setting_vpn_add_data_item(s_vpn, "foobar3", "blahblah3");
    nm_setting_vpn_add_data_item(s_vpn, "foobar4", "blahblah4");

    /* Ensure that added values are all present */
    nm_setting_vpn_foreach_data_item(s_vpn, vpn_check_func, NULL);
    nm_setting_vpn_remove_data_item(s_vpn, "foobar1");
    nm_setting_vpn_remove_data_item(s_vpn, "foobar2");
    nm_setting_vpn_remove_data_item(s_vpn, "foobar3");
    nm_setting_vpn_remove_data_item(s_vpn, "foobar4");

    g_assert(!_nm_connection_aggregate(connection, NM_CONNECTION_AGGREGATE_ANY_SECRETS, NULL));
    g_assert(!_nm_connection_aggregate(connection,
                                       NM_CONNECTION_AGGREGATE_ANY_SYSTEM_SECRET_FLAGS,
                                       NULL));

    nm_setting_vpn_add_secret(s_vpn, "foobar1", "blahblah1");

    g_assert(_nm_connection_aggregate(connection, NM_CONNECTION_AGGREGATE_ANY_SECRETS, NULL));
    g_assert(_nm_connection_aggregate(connection,
                                      NM_CONNECTION_AGGREGATE_ANY_SYSTEM_SECRET_FLAGS,
                                      NULL));

    nm_setting_vpn_add_secret(s_vpn, "foobar2", "blahblah2");
    nm_setting_vpn_add_secret(s_vpn, "foobar3", "blahblah3");
    nm_setting_vpn_add_secret(s_vpn, "foobar4", "blahblah4");

    /* Ensure that added values are all present */
    nm_setting_vpn_foreach_secret(s_vpn, vpn_check_func, NULL);
    nm_setting_vpn_remove_secret(s_vpn, "foobar1");
    nm_setting_vpn_remove_secret(s_vpn, "foobar2");
    nm_setting_vpn_remove_secret(s_vpn, "foobar3");

    g_assert(_nm_connection_aggregate(connection, NM_CONNECTION_AGGREGATE_ANY_SECRETS, NULL));
    g_assert(_nm_connection_aggregate(connection,
                                      NM_CONNECTION_AGGREGATE_ANY_SYSTEM_SECRET_FLAGS,
                                      NULL));

    nm_setting_vpn_add_data_item(s_vpn, "foobar4-flags", "blahblah4");

    g_assert(_nm_connection_aggregate(connection,
                                      NM_CONNECTION_AGGREGATE_ANY_SYSTEM_SECRET_FLAGS,
                                      NULL));

    nm_setting_vpn_add_data_item(s_vpn, "foobar4-flags", "2");

    g_assert(!_nm_connection_aggregate(connection,
                                       NM_CONNECTION_AGGREGATE_ANY_SYSTEM_SECRET_FLAGS,
                                       NULL));

    nm_setting_vpn_remove_secret(s_vpn, "foobar4");

    g_assert(!_nm_connection_aggregate(connection, NM_CONNECTION_AGGREGATE_ANY_SECRETS, NULL));
    g_assert(!_nm_connection_aggregate(connection,
                                       NM_CONNECTION_AGGREGATE_ANY_SYSTEM_SECRET_FLAGS,
                                       NULL));

    nm_setting_vpn_remove_data_item(s_vpn, "foobar4-flags");

    /* Try to add some blank values and make sure they are rejected */
    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(key && key[0]));
    nm_setting_vpn_add_data_item(s_vpn, NULL, NULL);
    g_test_assert_expected_messages();

    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(key && key[0]));
    nm_setting_vpn_add_data_item(s_vpn, "", "");
    g_test_assert_expected_messages();

    nm_setting_vpn_add_data_item(s_vpn, "foobar1", "");
    g_assert_cmpstr(nm_setting_vpn_get_data_item(s_vpn, "foobar1"), ==, "");

    nm_setting_vpn_add_data_item(s_vpn, "foobar1", NULL);
    g_assert_cmpstr(nm_setting_vpn_get_data_item(s_vpn, "foobar1"), ==, NULL);

    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(key && key[0]));
    nm_setting_vpn_add_data_item(s_vpn, NULL, "blahblah1");
    g_test_assert_expected_messages();

    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(key && key[0]));
    nm_setting_vpn_add_data_item(s_vpn, "", "blahblah1");
    g_test_assert_expected_messages();

    nm_setting_vpn_foreach_data_item(s_vpn, vpn_check_empty_func, NULL);

    /* Try to add some blank secrets and make sure they are rejected */
    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(key && key[0]));
    nm_setting_vpn_add_secret(s_vpn, NULL, NULL);
    g_test_assert_expected_messages();

    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(key && key[0]));
    nm_setting_vpn_add_secret(s_vpn, "", "");
    g_test_assert_expected_messages();

    nm_setting_vpn_add_secret(s_vpn, "foobar1", "");

    nm_setting_vpn_add_secret(s_vpn, "foobar1", NULL);

    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(key && key[0]));
    nm_setting_vpn_add_secret(s_vpn, NULL, "blahblah1");
    g_test_assert_expected_messages();

    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(key && key[0]));
    nm_setting_vpn_add_secret(s_vpn, "", "blahblah1");
    g_test_assert_expected_messages();

    nm_setting_vpn_foreach_secret(s_vpn, vpn_check_empty_func, NULL);
}

static void
test_setting_vpn_update_secrets(void)
{
    NMConnection *  connection;
    NMSettingVpn *  s_vpn;
    GVariantBuilder settings_builder, vpn_builder, secrets_builder;
    GVariant *      settings;
    gboolean        success;
    GError *        error = NULL;
    const char *    tmp;
    const char *    key1 = "foobar";
    const char *    key2 = "blahblah";
    const char *    val1 = "value1";
    const char *    val2 = "value2";

    connection = nm_simple_connection_new();
    s_vpn      = (NMSettingVpn *) nm_setting_vpn_new();
    nm_connection_add_setting(connection, NM_SETTING(s_vpn));

    g_variant_builder_init(&settings_builder, NM_VARIANT_TYPE_CONNECTION);
    g_variant_builder_init(&vpn_builder, NM_VARIANT_TYPE_SETTING);
    g_variant_builder_init(&secrets_builder, G_VARIANT_TYPE("a{ss}"));

    g_variant_builder_add(&secrets_builder, "{ss}", key1, val1);
    g_variant_builder_add(&secrets_builder, "{ss}", key2, val2);

    g_variant_builder_add(&vpn_builder,
                          "{sv}",
                          NM_SETTING_VPN_SECRETS,
                          g_variant_builder_end(&secrets_builder));
    g_variant_builder_add(&settings_builder, "{sa{sv}}", NM_SETTING_VPN_SETTING_NAME, &vpn_builder);
    settings = g_variant_builder_end(&settings_builder);

    success =
        nm_connection_update_secrets(connection, NM_SETTING_VPN_SETTING_NAME, settings, &error);
    g_assert_no_error(error);
    g_assert(success);

    /* Read the secrets back out */
    tmp = nm_setting_vpn_get_secret(s_vpn, key1);
    g_assert(tmp);
    g_assert_cmpstr(tmp, ==, val1);

    tmp = nm_setting_vpn_get_secret(s_vpn, key2);
    g_assert(tmp);
    g_assert_cmpstr(tmp, ==, val2);

    g_variant_unref(settings);
    g_object_unref(connection);
}

#define TO_DEL_NUM 50
typedef struct {
    NMSettingVpn *s_vpn;
    char *        to_del[TO_DEL_NUM];
    guint         called;
} IterInfo;

static void
del_iter_func(const char *key, const char *value, gpointer user_data)
{
    IterInfo *info = user_data;
    int       i;

    /* Record how many times this function gets called; it should get called
     * exactly as many times as there are keys in the hash table, regardless
     * of what keys we delete from the table.
     */
    info->called++;

    /* During the iteration, remove a bunch of stuff from the table */
    if (info->called == 1) {
        for (i = 0; i < TO_DEL_NUM; i++)
            nm_setting_vpn_remove_data_item(info->s_vpn, info->to_del[i]);
    }
}

static void
test_setting_vpn_modify_during_foreach(void)
{
    NMSettingVpn *s_vpn;
    IterInfo      info;
    char *        key, *val;
    int           i, u = 0;

    s_vpn = (NMSettingVpn *) nm_setting_vpn_new();
    g_assert(s_vpn);

    for (i = 0; i < TO_DEL_NUM * 2; i++) {
        key = g_strdup_printf("adsfasdfadf%d", i);
        val = g_strdup_printf("42263236236awt%d", i);
        nm_setting_vpn_add_data_item(s_vpn, key, val);

        /* Cache some keys to delete */
        if (i % 2)
            info.to_del[u++] = g_strdup(key);

        g_free(key);
        g_free(val);
    }

    /* Iterate over current table keys */
    info.s_vpn  = s_vpn;
    info.called = 0;
    nm_setting_vpn_foreach_data_item(s_vpn, del_iter_func, &info);

    /* Make sure all the things we removed during iteration are really gone */
    for (i = 0; i < TO_DEL_NUM; i++) {
        g_assert_cmpstr(nm_setting_vpn_get_data_item(s_vpn, info.to_del[i]), ==, NULL);
        g_free(info.to_del[i]);
    }

    /* And make sure the foreach callback was called the same number of times
     * as there were keys in the table at the beginning of the foreach.
     */
    g_assert_cmpint(info.called, ==, TO_DEL_NUM * 2);

    g_object_unref(s_vpn);
}

static void
test_setting_ip4_config_labels(void)
{
    NMSettingIPConfig *s_ip4;
    NMIPAddress *      addr;
    GVariant *         label;
    GPtrArray *        addrs;
    char **            labels;
    NMConnection *     conn;
    GVariant *         dict, *dict2, *setting_dict, *value;
    GError *           error = NULL;

    s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new();
    g_object_set(G_OBJECT(s_ip4),
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
                 NULL);

    /* addr 1 */
    addr = nm_ip_address_new(AF_INET, "1.2.3.4", 24, &error);
    g_assert_no_error(error);

    nm_setting_ip_config_add_address(s_ip4, addr);
    nm_ip_address_unref(addr);
    nmtst_assert_setting_verifies(NM_SETTING(s_ip4));

    addr  = nm_setting_ip_config_get_address(s_ip4, 0);
    label = nm_ip_address_get_attribute(addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
    g_assert(label == NULL);

    /* The 'address-labels' property should be omitted from the serialization if
     * there are no non-NULL labels.
     */
    conn = nmtst_create_minimal_connection("label test", NULL, NM_SETTING_WIRED_SETTING_NAME, NULL);
    nm_connection_add_setting(conn, nm_setting_duplicate(NM_SETTING(s_ip4)));
    dict = nm_connection_to_dbus(conn, NM_CONNECTION_SERIALIZE_ALL);
    g_object_unref(conn);

    setting_dict =
        g_variant_lookup_value(dict, NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_VARIANT_TYPE_SETTING);
    g_assert(setting_dict != NULL);

    value = g_variant_lookup_value(setting_dict, "address-labels", NULL);
    g_assert(value == NULL);

    g_variant_unref(setting_dict);
    g_variant_unref(dict);

    /* Now back to constructing the original s_ip4... */

    /* addr 2 */
    addr = nm_ip_address_new(AF_INET, "2.3.4.5", 24, &error);
    g_assert_no_error(error);
    nm_ip_address_set_attribute(addr,
                                NM_IP_ADDRESS_ATTRIBUTE_LABEL,
                                g_variant_new_string("eth0:1"));

    nm_setting_ip_config_add_address(s_ip4, addr);
    nm_ip_address_unref(addr);
    nmtst_assert_setting_verifies(NM_SETTING(s_ip4));

    addr  = nm_setting_ip_config_get_address(s_ip4, 1);
    label = nm_ip_address_get_attribute(addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
    g_assert(label != NULL);
    g_assert_cmpstr(g_variant_get_string(label, NULL), ==, "eth0:1");

    /* addr 3 */
    addr = nm_ip_address_new(AF_INET, "3.4.5.6", 24, &error);
    g_assert_no_error(error);
    nm_ip_address_set_attribute(addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL, NULL);

    nm_setting_ip_config_add_address(s_ip4, addr);
    nm_ip_address_unref(addr);
    nmtst_assert_setting_verifies(NM_SETTING(s_ip4));

    addr  = nm_setting_ip_config_get_address(s_ip4, 2);
    label = nm_ip_address_get_attribute(addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
    g_assert(label == NULL);

    /* Remove addr 1 and re-verify remaining addresses */
    nm_setting_ip_config_remove_address(s_ip4, 0);
    nmtst_assert_setting_verifies(NM_SETTING(s_ip4));

    addr = nm_setting_ip_config_get_address(s_ip4, 0);
    g_assert_cmpstr(nm_ip_address_get_address(addr), ==, "2.3.4.5");
    label = nm_ip_address_get_attribute(addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
    g_assert(label != NULL);
    g_assert_cmpstr(g_variant_get_string(label, NULL), ==, "eth0:1");

    addr = nm_setting_ip_config_get_address(s_ip4, 1);
    g_assert_cmpstr(nm_ip_address_get_address(addr), ==, "3.4.5.6");
    label = nm_ip_address_get_attribute(addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
    g_assert(label == NULL);

    /* If we serialize as the daemon, the labels should appear in the D-Bus
     * serialization under both 'address-labels' and 'address-data'.
     */
    conn = nmtst_create_minimal_connection("label test", NULL, NM_SETTING_WIRED_SETTING_NAME, NULL);
    nm_connection_add_setting(conn, NM_SETTING(s_ip4));
    _nm_utils_is_manager_process = TRUE;
    dict                         = nm_connection_to_dbus(conn, NM_CONNECTION_SERIALIZE_ALL);
    _nm_utils_is_manager_process = FALSE;
    g_object_unref(conn);

    setting_dict =
        g_variant_lookup_value(dict, NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_VARIANT_TYPE_SETTING);
    g_assert(setting_dict != NULL);

    value = g_variant_lookup_value(setting_dict, "address-labels", G_VARIANT_TYPE_STRING_ARRAY);
    g_assert(value != NULL);
    g_variant_get(value, "^as", &labels);
    g_assert_cmpint(g_strv_length(labels), ==, 2);
    g_assert_cmpstr(labels[0], ==, "eth0:1");
    g_assert_cmpstr(labels[1], ==, "");
    g_variant_unref(value);
    g_strfreev(labels);

    value = g_variant_lookup_value(setting_dict, "address-data", G_VARIANT_TYPE("aa{sv}"));
    addrs = nm_utils_ip_addresses_from_variant(value, AF_INET);
    g_variant_unref(value);
    g_assert(addrs != NULL);
    g_assert_cmpint(addrs->len, ==, 2);
    addr  = addrs->pdata[0];
    label = nm_ip_address_get_attribute(addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
    g_assert(label != NULL);
    g_assert_cmpstr(g_variant_get_string(label, NULL), ==, "eth0:1");
    addr  = addrs->pdata[1];
    label = nm_ip_address_get_attribute(addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
    g_assert(label == NULL);
    g_ptr_array_unref(addrs);

    g_variant_unref(setting_dict);

    /* We should be able to deserialize the labels from either 'address-labels'
     * or 'address-data'.
     */
    dict2 = g_variant_ref(dict);

    NMTST_VARIANT_EDITOR(
        dict, NMTST_VARIANT_DROP_PROPERTY(NM_SETTING_IP4_CONFIG_SETTING_NAME, "address-data"););
    conn = _connection_new_from_dbus(dict, &error);
    g_assert_no_error(error);
    g_variant_unref(dict);

    s_ip4 = nm_connection_get_setting_ip4_config(conn);

    addr = nm_setting_ip_config_get_address(s_ip4, 0);
    g_assert_cmpstr(nm_ip_address_get_address(addr), ==, "2.3.4.5");
    label = nm_ip_address_get_attribute(addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
    g_assert(label != NULL);
    g_assert_cmpstr(g_variant_get_string(label, NULL), ==, "eth0:1");

    addr = nm_setting_ip_config_get_address(s_ip4, 1);
    g_assert_cmpstr(nm_ip_address_get_address(addr), ==, "3.4.5.6");
    label = nm_ip_address_get_attribute(addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
    g_assert(label == NULL);

    g_object_unref(conn);

    NMTST_VARIANT_EDITOR(
        dict2, NMTST_VARIANT_DROP_PROPERTY(NM_SETTING_IP4_CONFIG_SETTING_NAME, "address-labels"););
    conn = _connection_new_from_dbus(dict2, &error);
    g_assert_no_error(error);
    g_variant_unref(dict2);

    s_ip4 = nm_connection_get_setting_ip4_config(conn);

    addr = nm_setting_ip_config_get_address(s_ip4, 0);
    g_assert_cmpstr(nm_ip_address_get_address(addr), ==, "2.3.4.5");
    label = nm_ip_address_get_attribute(addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
    g_assert_cmpstr(g_variant_get_string(label, NULL), ==, "eth0:1");

    addr = nm_setting_ip_config_get_address(s_ip4, 1);
    g_assert_cmpstr(nm_ip_address_get_address(addr), ==, "3.4.5.6");
    label = nm_ip_address_get_attribute(addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
    g_assert(label == NULL);

    /* Test explicit property assignment */
    g_object_get(G_OBJECT(s_ip4), NM_SETTING_IP_CONFIG_ADDRESSES, &addrs, NULL);

    nm_setting_ip_config_clear_addresses(s_ip4);
    g_assert_cmpint(nm_setting_ip_config_get_num_addresses(s_ip4), ==, 0);

    g_object_set(G_OBJECT(s_ip4), NM_SETTING_IP_CONFIG_ADDRESSES, addrs, NULL);
    g_ptr_array_unref(addrs);
    nmtst_assert_setting_verifies(NM_SETTING(s_ip4));
    g_assert_cmpint(nm_setting_ip_config_get_num_addresses(s_ip4), ==, 2);

    addr = nm_setting_ip_config_get_address(s_ip4, 0);
    g_assert_cmpstr(nm_ip_address_get_address(addr), ==, "2.3.4.5");
    label = nm_ip_address_get_attribute(addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
    g_assert(label != NULL);
    g_assert_cmpstr(g_variant_get_string(label, NULL), ==, "eth0:1");

    addr = nm_setting_ip_config_get_address(s_ip4, 1);
    g_assert_cmpstr(nm_ip_address_get_address(addr), ==, "3.4.5.6");
    label = nm_ip_address_get_attribute(addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
    g_assert(label == NULL);

    g_object_unref(conn);
}

static void
test_setting_ip4_config_address_data(void)
{
    NMSettingIPConfig *s_ip4;
    NMIPAddress *      addr;
    GPtrArray *        addrs;
    NMConnection *     conn;
    GVariant *         dict, *setting_dict, *value;
    GError *           error = NULL;

    s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new();
    g_object_set(G_OBJECT(s_ip4),
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
                 NULL);

    /* addr 1 */
    addr = nm_ip_address_new(AF_INET, "1.2.3.4", 24, &error);
    g_assert_no_error(error);
    nm_ip_address_set_attribute(addr, "one", g_variant_new_string("foo"));
    nm_ip_address_set_attribute(addr, "two", g_variant_new_int32(42));

    nm_setting_ip_config_add_address(s_ip4, addr);
    nm_ip_address_unref(addr);
    nmtst_assert_setting_verifies(NM_SETTING(s_ip4));

    /* addr 2 */
    addr = nm_ip_address_new(AF_INET, "2.3.4.5", 24, &error);
    g_assert_no_error(error);

    nm_setting_ip_config_add_address(s_ip4, addr);
    nm_ip_address_unref(addr);
    nmtst_assert_setting_verifies(NM_SETTING(s_ip4));

    /* The client-side D-Bus serialization should include the attributes in
     * "address-data", and should not have an "addresses" property.
     */
    conn = nmtst_create_minimal_connection("address-data test",
                                           NULL,
                                           NM_SETTING_WIRED_SETTING_NAME,
                                           NULL);
    nm_connection_add_setting(conn, NM_SETTING(s_ip4));
    dict = nm_connection_to_dbus(conn, NM_CONNECTION_SERIALIZE_ALL);

    setting_dict =
        g_variant_lookup_value(dict, NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_VARIANT_TYPE_SETTING);
    g_assert(setting_dict != NULL);

    value = g_variant_lookup_value(setting_dict, "addresses", NULL);
    g_assert(value == NULL);

    value = g_variant_lookup_value(setting_dict, "address-data", G_VARIANT_TYPE("aa{sv}"));
    addrs = nm_utils_ip_addresses_from_variant(value, AF_INET);
    g_variant_unref(value);
    g_assert(addrs != NULL);
    g_assert_cmpint(addrs->len, ==, 2);

    addr = addrs->pdata[0];
    g_assert_cmpstr(nm_ip_address_get_address(addr), ==, "1.2.3.4");
    value = nm_ip_address_get_attribute(addr, "one");
    g_assert(value != NULL);
    g_assert_cmpstr(g_variant_get_string(value, NULL), ==, "foo");
    value = nm_ip_address_get_attribute(addr, "two");
    g_assert(value != NULL);
    g_assert_cmpint(g_variant_get_int32(value), ==, 42);

    g_ptr_array_unref(addrs);
    g_variant_unref(setting_dict);
    g_variant_unref(dict);

    /* The daemon-side serialization should include both 'addresses' and 'address-data' */
    _nm_utils_is_manager_process = TRUE;
    dict                         = nm_connection_to_dbus(conn, NM_CONNECTION_SERIALIZE_ALL);
    _nm_utils_is_manager_process = FALSE;

    setting_dict =
        g_variant_lookup_value(dict, NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_VARIANT_TYPE_SETTING);
    g_assert(setting_dict != NULL);

    value = g_variant_lookup_value(setting_dict, "addresses", G_VARIANT_TYPE("aau"));
    g_assert(value != NULL);
    g_variant_unref(value);

    value = g_variant_lookup_value(setting_dict, "address-data", G_VARIANT_TYPE("aa{sv}"));
    g_assert(value != NULL);
    g_variant_unref(value);

    g_variant_unref(setting_dict);
    g_object_unref(conn);

    /* When we reserialize that dictionary as a client, 'address-data' will be preferred. */
    conn = _connection_new_from_dbus(dict, &error);
    g_assert_no_error(error);

    s_ip4 = nm_connection_get_setting_ip4_config(conn);

    addr = nm_setting_ip_config_get_address(s_ip4, 0);
    g_assert_cmpstr(nm_ip_address_get_address(addr), ==, "1.2.3.4");
    value = nm_ip_address_get_attribute(addr, "one");
    g_assert(value != NULL);
    g_assert_cmpstr(g_variant_get_string(value, NULL), ==, "foo");
    value = nm_ip_address_get_attribute(addr, "two");
    g_assert(value != NULL);
    g_assert_cmpint(g_variant_get_int32(value), ==, 42);

    /* But on the server side, 'addresses' will have precedence. */
    _nm_utils_is_manager_process = TRUE;
    conn                         = _connection_new_from_dbus(dict, &error);
    _nm_utils_is_manager_process = FALSE;
    g_assert_no_error(error);
    g_variant_unref(dict);

    s_ip4 = nm_connection_get_setting_ip4_config(conn);

    addr = nm_setting_ip_config_get_address(s_ip4, 0);
    g_assert_cmpstr(nm_ip_address_get_address(addr), ==, "1.2.3.4");
    value = nm_ip_address_get_attribute(addr, "one");
    g_assert(value == NULL);
    value = nm_ip_address_get_attribute(addr, "two");
    g_assert(value == NULL);

    g_object_unref(conn);
}

static void
test_setting_ip_route_attributes(void)
{
    GVariant *variant;
    gboolean  res, known;

#define TEST_ATTR(name, type, value, family, exp_res, exp_known)                   \
    variant = g_variant_new_##type(value);                                         \
    res     = nm_ip_route_attribute_validate(name, variant, family, &known, NULL); \
    g_assert(res == exp_res);                                                      \
    g_assert(known == exp_known);                                                  \
    g_variant_unref(variant);

    TEST_ATTR("foo", uint32, 12, AF_INET, FALSE, FALSE);

    TEST_ATTR("tos", byte, 127, AF_INET, TRUE, TRUE);
    TEST_ATTR("tos", string, "0x28", AF_INET, FALSE, TRUE);

    TEST_ATTR("cwnd", uint32, 10, AF_INET, TRUE, TRUE);
    TEST_ATTR("cwnd", string, "11", AF_INET, FALSE, TRUE);

    TEST_ATTR("lock-mtu", boolean, TRUE, AF_INET, TRUE, TRUE);
    TEST_ATTR("lock-mtu", uint32, 1, AF_INET, FALSE, TRUE);

    TEST_ATTR("from", string, "fd01::1", AF_INET6, TRUE, TRUE);
    TEST_ATTR("from", string, "fd01::1/64", AF_INET6, TRUE, TRUE);
    TEST_ATTR("from", string, "fd01::1/128", AF_INET6, TRUE, TRUE);
    TEST_ATTR("from", string, "fd01::1/129", AF_INET6, FALSE, TRUE);
    TEST_ATTR("from", string, "fd01::1/a", AF_INET6, FALSE, TRUE);
    TEST_ATTR("from", string, "abc/64", AF_INET6, FALSE, TRUE);
    TEST_ATTR("from", string, "1.2.3.4", AF_INET, FALSE, TRUE);
    TEST_ATTR("from", string, "1.2.3.4", AF_INET6, FALSE, TRUE);

    TEST_ATTR("src", string, "1.2.3.4", AF_INET, TRUE, TRUE);
    TEST_ATTR("src", string, "1.2.3.4", AF_INET6, FALSE, TRUE);
    TEST_ATTR("src", string, "1.2.3.0/24", AF_INET, FALSE, TRUE);
    TEST_ATTR("src", string, "fd01::12", AF_INET6, TRUE, TRUE);

    TEST_ATTR("type", string, "local", AF_INET, TRUE, TRUE);
    TEST_ATTR("type", string, "local", AF_INET6, TRUE, TRUE);
    TEST_ATTR("type", string, "unicast", AF_INET, TRUE, TRUE);
    TEST_ATTR("type", string, "unicast", AF_INET6, TRUE, TRUE);

#undef TEST_ATTR
}

static void
test_setting_gsm_apn_spaces(void)
{
    gs_unref_object NMSettingGsm *s_gsm = NULL;
    const char *                  tmp;

    s_gsm = (NMSettingGsm *) nm_setting_gsm_new();
    g_assert(s_gsm);

    /* Trailing space */
    g_object_set(s_gsm, NM_SETTING_GSM_APN, "foobar ", NULL);
    tmp = nm_setting_gsm_get_apn(s_gsm);
    g_assert_cmpstr(tmp, ==, "foobar");

    /* Leading space */
    g_object_set(s_gsm, NM_SETTING_GSM_APN, " foobar", NULL);
    tmp = nm_setting_gsm_get_apn(s_gsm);
    g_assert_cmpstr(tmp, ==, "foobar");
}

static void
test_setting_gsm_apn_bad_chars(void)
{
    gs_unref_object NMSettingGsm *s_gsm = NULL;

    s_gsm = (NMSettingGsm *) nm_setting_gsm_new();
    g_assert(s_gsm);

    /* Make sure a valid APN works */
    g_object_set(s_gsm, NM_SETTING_GSM_APN, "foobar123.-baz", NULL);
    g_assert(nm_setting_verify(NM_SETTING(s_gsm), NULL, NULL));

    /* Random invalid chars */
    g_object_set(s_gsm, NM_SETTING_GSM_APN, "@#%$@#%@#%", NULL);
    g_assert(!nm_setting_verify(NM_SETTING(s_gsm), NULL, NULL));

    /* Spaces */
    g_object_set(s_gsm, NM_SETTING_GSM_APN, "foobar baz", NULL);
    g_assert(!nm_setting_verify(NM_SETTING(s_gsm), NULL, NULL));

    /* 0 characters long */
    g_object_set(s_gsm, NM_SETTING_GSM_APN, "", NULL);
    g_assert(nm_setting_verify(NM_SETTING(s_gsm), NULL, NULL));

    /* 65-character long */
    g_object_set(s_gsm,
                 NM_SETTING_GSM_APN,
                 "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl1",
                 NULL);
    g_assert(!nm_setting_verify(NM_SETTING(s_gsm), NULL, NULL));
}

static void
test_setting_gsm_apn_underscore(void)
{
    gs_unref_object NMSettingGsm *s_gsm = NULL;

    s_gsm = (NMSettingGsm *) nm_setting_gsm_new();
    g_assert(s_gsm);

    /* 65-character long */
    g_object_set(s_gsm, NM_SETTING_GSM_APN, "foobar_baz", NULL);
    nmtst_assert_setting_verifies(NM_SETTING(s_gsm));
}

static void
test_setting_gsm_without_number(void)
{
    gs_unref_object NMSettingGsm *s_gsm = NULL;

    s_gsm = (NMSettingGsm *) nm_setting_gsm_new();
    g_assert(s_gsm);

    g_object_set(s_gsm, NM_SETTING_GSM_NUMBER, NULL, NULL);
    nmtst_assert_setting_verifies(NM_SETTING(s_gsm));

    g_object_set(s_gsm, NM_SETTING_GSM_NUMBER, "", NULL);
    nmtst_assert_setting_verify_fails(NM_SETTING(s_gsm),
                                      NM_CONNECTION_ERROR,
                                      NM_CONNECTION_ERROR_INVALID_PROPERTY);
}

static void
test_setting_gsm_sim_operator_id(void)
{
    gs_unref_object NMSettingGsm *s_gsm = NULL;

    s_gsm = (NMSettingGsm *) nm_setting_gsm_new();
    g_assert(s_gsm);

    /* Valid */
    g_object_set(s_gsm, NM_SETTING_GSM_SIM_OPERATOR_ID, "12345", NULL);
    nmtst_assert_setting_verifies(NM_SETTING(s_gsm));

    g_object_set(s_gsm, NM_SETTING_GSM_SIM_OPERATOR_ID, "123456", NULL);
    nmtst_assert_setting_verifies(NM_SETTING(s_gsm));

    /* Invalid */
    g_object_set(s_gsm, NM_SETTING_GSM_SIM_OPERATOR_ID, "", NULL);
    nmtst_assert_setting_verify_fails(NM_SETTING(s_gsm),
                                      NM_CONNECTION_ERROR,
                                      NM_CONNECTION_ERROR_INVALID_PROPERTY);

    g_object_set(s_gsm, NM_SETTING_GSM_SIM_OPERATOR_ID, "     ", NULL);
    nmtst_assert_setting_verify_fails(NM_SETTING(s_gsm),
                                      NM_CONNECTION_ERROR,
                                      NM_CONNECTION_ERROR_INVALID_PROPERTY);

    g_object_set(s_gsm, NM_SETTING_GSM_SIM_OPERATOR_ID, "abcdef", NULL);
    nmtst_assert_setting_verify_fails(NM_SETTING(s_gsm),
                                      NM_CONNECTION_ERROR,
                                      NM_CONNECTION_ERROR_INVALID_PROPERTY);
}

static NMSettingWirelessSecurity *
make_test_wsec_setting(const char *detail)
{
    NMSettingWirelessSecurity *s_wsec;

    s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new();
    g_assert(s_wsec);

    g_object_set(s_wsec,
                 NM_SETTING_WIRELESS_SECURITY_KEY_MGMT,
                 "wpa-psk",
                 NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME,
                 "foobarbaz",
                 NM_SETTING_WIRELESS_SECURITY_PSK,
                 "random psk",
                 NM_SETTING_WIRELESS_SECURITY_PSK_FLAGS,
                 NM_SETTING_SECRET_FLAG_NOT_SAVED,
                 NM_SETTING_WIRELESS_SECURITY_WEP_KEY0,
                 "aaaaaaaaaa",
                 NULL);
    return s_wsec;
}

static gboolean
_variant_contains(GVariant *vardict, const char *key)
{
    gs_unref_variant GVariant *value = NULL;

    value = g_variant_lookup_value(vardict, key, NULL);
    return !!value;
}

static void
test_setting_to_dbus_all(void)
{
    NMSettingWirelessSecurity *s_wsec;
    GVariant *                 dict;

    s_wsec = make_test_wsec_setting("setting-to-dbus-all");

    dict = _nm_setting_to_dbus(NM_SETTING(s_wsec), NULL, NM_CONNECTION_SERIALIZE_ALL, NULL);

    /* Make sure all keys are there */
    g_assert(_variant_contains(dict, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT));
    g_assert(_variant_contains(dict, NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME));
    g_assert(_variant_contains(dict, NM_SETTING_WIRELESS_SECURITY_PSK));
    g_assert(_variant_contains(dict, NM_SETTING_WIRELESS_SECURITY_WEP_KEY0));

    g_variant_unref(dict);
    g_object_unref(s_wsec);
}

static void
test_setting_to_dbus_no_secrets(void)
{
    NMSettingWirelessSecurity *s_wsec;
    GVariant *                 dict;

    s_wsec = make_test_wsec_setting("setting-to-dbus-no-secrets");

    dict = _nm_setting_to_dbus(NM_SETTING(s_wsec),
                               NULL,
                               NM_CONNECTION_SERIALIZE_WITH_NON_SECRET,
                               NULL);

    /* Make sure non-secret keys are there */
    g_assert(_variant_contains(dict, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT));
    g_assert(_variant_contains(dict, NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME));

    /* Make sure secrets are not there */
    g_assert(!_variant_contains(dict, NM_SETTING_WIRELESS_SECURITY_PSK));
    g_assert(!_variant_contains(dict, NM_SETTING_WIRELESS_SECURITY_WEP_KEY0));

    g_variant_unref(dict);
    g_object_unref(s_wsec);
}

static void
test_setting_to_dbus_only_secrets(void)
{
    NMSettingWirelessSecurity *s_wsec;
    GVariant *                 dict;

    s_wsec = make_test_wsec_setting("setting-to-dbus-only-secrets");

    dict =
        _nm_setting_to_dbus(NM_SETTING(s_wsec), NULL, NM_CONNECTION_SERIALIZE_WITH_SECRETS, NULL);

    /* Make sure non-secret keys are not there */
    g_assert(!_variant_contains(dict, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT));
    g_assert(!_variant_contains(dict, NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME));

    /* Make sure secrets are there */
    g_assert(_variant_contains(dict, NM_SETTING_WIRELESS_SECURITY_PSK));
    g_assert(_variant_contains(dict, NM_SETTING_WIRELESS_SECURITY_WEP_KEY0));

    g_variant_unref(dict);
    g_object_unref(s_wsec);
}

static void
test_setting_to_dbus_transform(void)
{
    NMSetting *   s_wired;
    GVariant *    dict, *val;
    const char *  test_mac_address = "11:22:33:44:55:66";
    const guint8 *dbus_mac_address;
    guint8        cmp_mac_address[ETH_ALEN];
    gsize         len;

    s_wired = nm_setting_wired_new();
    g_object_set(s_wired, NM_SETTING_WIRED_MAC_ADDRESS, test_mac_address, NULL);

    g_assert_cmpstr(nm_setting_wired_get_mac_address(NM_SETTING_WIRED(s_wired)),
                    ==,
                    test_mac_address);

    dict = _nm_setting_to_dbus(s_wired, NULL, NM_CONNECTION_SERIALIZE_ALL, NULL);
    g_assert(dict != NULL);

    val = g_variant_lookup_value(dict, NM_SETTING_WIRED_MAC_ADDRESS, G_VARIANT_TYPE_BYTESTRING);
    g_assert(val != NULL);

    dbus_mac_address = g_variant_get_fixed_array(val, &len, 1);
    g_assert_cmpint(len, ==, ETH_ALEN);

    nm_utils_hwaddr_aton(test_mac_address, cmp_mac_address, ETH_ALEN);
    g_assert(memcmp(dbus_mac_address, cmp_mac_address, ETH_ALEN) == 0);

    g_variant_unref(val);
    g_variant_unref(dict);
    g_object_unref(s_wired);
}

static void
test_setting_to_dbus_enum(void)
{
    NMSetting *s_ip6, *s_wsec, *s_serial;
    GVariant * dict, *val;

    /* enum */
    s_ip6 = nm_setting_ip6_config_new();
    g_object_set(s_ip6,
                 NM_SETTING_IP6_CONFIG_IP6_PRIVACY,
                 NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR,
                 NULL);

    dict = _nm_setting_to_dbus(s_ip6, NULL, NM_CONNECTION_SERIALIZE_ALL, NULL);
    g_assert(dict != NULL);

    val = g_variant_lookup_value(dict, NM_SETTING_IP6_CONFIG_IP6_PRIVACY, G_VARIANT_TYPE_INT32);
    g_assert(val != NULL);
    g_assert_cmpint(g_variant_get_int32(val), ==, NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR);
    g_variant_unref(val);

    g_variant_unref(dict);
    g_object_unref(s_ip6);

    /* flags (and a transformed enum) */
    s_wsec = nm_setting_wireless_security_new();
    g_object_set(s_wsec,
                 NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE,
                 NM_WEP_KEY_TYPE_KEY,
                 NM_SETTING_WIRELESS_SECURITY_WEP_KEY_FLAGS,
                 (NM_SETTING_SECRET_FLAG_AGENT_OWNED | NM_SETTING_SECRET_FLAG_NOT_SAVED),
                 NULL);

    dict = _nm_setting_to_dbus(s_wsec, NULL, NM_CONNECTION_SERIALIZE_ALL, NULL);
    g_assert(dict != NULL);

    val = g_variant_lookup_value(dict,
                                 NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE,
                                 G_VARIANT_TYPE_UINT32);
    g_assert(val != NULL);
    g_assert_cmpint(g_variant_get_uint32(val), ==, NM_WEP_KEY_TYPE_KEY);
    g_variant_unref(val);

    val = g_variant_lookup_value(dict,
                                 NM_SETTING_WIRELESS_SECURITY_WEP_KEY_FLAGS,
                                 G_VARIANT_TYPE_UINT32);
    g_assert(val != NULL);
    g_assert_cmpint(g_variant_get_uint32(val),
                    ==,
                    (NM_SETTING_SECRET_FLAG_AGENT_OWNED | NM_SETTING_SECRET_FLAG_NOT_SAVED));
    g_variant_unref(val);

    g_variant_unref(dict);
    g_object_unref(s_wsec);

    /* another transformed enum */
    s_serial = nm_setting_serial_new();
    g_object_set(s_serial, NM_SETTING_SERIAL_PARITY, NM_SETTING_SERIAL_PARITY_ODD, NULL);

    dict = _nm_setting_to_dbus(s_serial, NULL, NM_CONNECTION_SERIALIZE_ALL, NULL);
    g_assert(dict != NULL);

    val = g_variant_lookup_value(dict, NM_SETTING_SERIAL_PARITY, G_VARIANT_TYPE_BYTE);
    g_assert(val != NULL);
    g_assert_cmpint(g_variant_get_byte(val), ==, 'o');
    g_variant_unref(val);

    g_variant_unref(dict);
    g_object_unref(s_serial);
}

static void
test_connection_to_dbus_setting_name(void)
{
    NMConnection *             connection;
    NMSettingWirelessSecurity *s_wsec;
    GVariant *                 dict;

    connection = nm_simple_connection_new();
    s_wsec     = make_test_wsec_setting("connection-to-dbus-setting-name");
    nm_connection_add_setting(connection, NM_SETTING(s_wsec));

    g_assert(_nm_connection_aggregate(connection, NM_CONNECTION_AGGREGATE_ANY_SECRETS, NULL));
    g_assert(_nm_connection_aggregate(connection,
                                      NM_CONNECTION_AGGREGATE_ANY_SYSTEM_SECRET_FLAGS,
                                      NULL));

    g_object_set(s_wsec,
                 NM_SETTING_WIRELESS_SECURITY_WEP_KEY_FLAGS,
                 NM_SETTING_SECRET_FLAG_NOT_SAVED,
                 NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD_FLAGS,
                 NM_SETTING_SECRET_FLAG_NOT_SAVED,
                 NULL);

    g_assert(_nm_connection_aggregate(connection, NM_CONNECTION_AGGREGATE_ANY_SECRETS, NULL));
    g_assert(!_nm_connection_aggregate(connection,
                                       NM_CONNECTION_AGGREGATE_ANY_SYSTEM_SECRET_FLAGS,
                                       NULL));

    g_object_set(s_wsec,
                 NM_SETTING_WIRELESS_SECURITY_WEP_KEY_FLAGS,
                 NM_SETTING_SECRET_FLAG_NONE,
                 NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD_FLAGS,
                 NM_SETTING_SECRET_FLAG_NONE,
                 NULL);

    g_assert(_nm_connection_aggregate(connection, NM_CONNECTION_AGGREGATE_ANY_SECRETS, NULL));
    g_assert(_nm_connection_aggregate(connection,
                                      NM_CONNECTION_AGGREGATE_ANY_SYSTEM_SECRET_FLAGS,
                                      NULL));

    dict = nm_connection_to_dbus(connection, NM_CONNECTION_SERIALIZE_ALL);

    /* Make sure the keys of the first level dict are setting names, not
     * the GType name of the setting objects.
     */
    g_assert(_variant_contains(dict, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME));

    g_variant_unref(dict);
    g_object_unref(connection);
}

static void
test_connection_to_dbus_deprecated_props(void)
{
    NMConnection *             connection;
    NMSetting *                s_wireless;
    GBytes *                   ssid;
    NMSettingWirelessSecurity *s_wsec;
    GVariant *                 dict, *wireless_dict, *sec_val;

    connection = nmtst_create_minimal_connection("test-connection-to-dbus-deprecated-props",
                                                 NULL,
                                                 NM_SETTING_WIRELESS_SETTING_NAME,
                                                 NULL);

    s_wireless = nm_setting_wireless_new();
    ssid       = g_bytes_new("1234567", 7);
    g_object_set(s_wireless, NM_SETTING_WIRELESS_SSID, ssid, NULL);
    g_bytes_unref(ssid);
    nm_connection_add_setting(connection, s_wireless);

    /* Serialization should not have an 802-11-wireless.security property */
    dict = nm_connection_to_dbus(connection, NM_CONNECTION_SERIALIZE_ALL);
    g_assert(dict != NULL);

    wireless_dict =
        g_variant_lookup_value(dict, NM_SETTING_WIRELESS_SETTING_NAME, NM_VARIANT_TYPE_SETTING);
    g_assert(wireless_dict != NULL);

    sec_val = g_variant_lookup_value(wireless_dict, "security", NULL);
    g_assert(sec_val == NULL);

    g_variant_unref(wireless_dict);
    g_variant_unref(dict);

    /* Now add an NMSettingWirelessSecurity and try again */
    s_wsec = make_test_wsec_setting("test-connection-to-dbus-deprecated-props");
    nm_connection_add_setting(connection, NM_SETTING(s_wsec));

    dict = nm_connection_to_dbus(connection, NM_CONNECTION_SERIALIZE_ALL);
    g_assert(dict != NULL);

    wireless_dict =
        g_variant_lookup_value(dict, NM_SETTING_WIRELESS_SETTING_NAME, NM_VARIANT_TYPE_SETTING);
    g_assert(wireless_dict != NULL);

    sec_val = g_variant_lookup_value(wireless_dict, "security", NULL);
    g_assert(g_variant_is_of_type(sec_val, G_VARIANT_TYPE_STRING));
    g_assert_cmpstr(g_variant_get_string(sec_val, NULL),
                    ==,
                    NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);

    g_variant_unref(sec_val);
    g_variant_unref(wireless_dict);
    g_variant_unref(dict);
    g_object_unref(connection);
}

static void
test_setting_new_from_dbus(void)
{
    NMSettingWirelessSecurity *s_wsec;
    GVariant *                 dict;

    s_wsec = make_test_wsec_setting("setting-new-from-dbus");
    dict   = _nm_setting_to_dbus(NM_SETTING(s_wsec), NULL, NM_CONNECTION_SERIALIZE_ALL, NULL);
    g_object_unref(s_wsec);

    s_wsec =
        (NMSettingWirelessSecurity *) _nm_setting_new_from_dbus(NM_TYPE_SETTING_WIRELESS_SECURITY,
                                                                dict,
                                                                NULL,
                                                                NM_SETTING_PARSE_FLAGS_NONE,
                                                                NULL);
    g_variant_unref(dict);

    g_assert(s_wsec);
    g_assert_cmpstr(nm_setting_wireless_security_get_key_mgmt(s_wsec), ==, "wpa-psk");
    g_assert_cmpstr(nm_setting_wireless_security_get_leap_username(s_wsec), ==, "foobarbaz");
    g_assert_cmpstr(nm_setting_wireless_security_get_psk(s_wsec), ==, "random psk");
    g_object_unref(s_wsec);
}

static void
test_setting_new_from_dbus_transform(void)
{
    NMSetting *     s_wired;
    GVariant *      dict;
    GVariantBuilder builder;
    const char *    test_mac_address = "11:22:33:44:55:66";
    guint8          dbus_mac_address[ETH_ALEN];
    GError *        error = NULL;

    nm_utils_hwaddr_aton(test_mac_address, dbus_mac_address, ETH_ALEN);

    g_variant_builder_init(&builder, NM_VARIANT_TYPE_SETTING);
    g_variant_builder_add(
        &builder,
        "{sv}",
        NM_SETTING_WIRED_MAC_ADDRESS,
        g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, dbus_mac_address, ETH_ALEN, 1));
    dict = g_variant_builder_end(&builder);

    s_wired = _nm_setting_new_from_dbus(NM_TYPE_SETTING_WIRED,
                                        dict,
                                        NULL,
                                        NM_SETTING_PARSE_FLAGS_NONE,
                                        &error);
    g_assert_no_error(error);

    g_assert_cmpstr(nm_setting_wired_get_mac_address(NM_SETTING_WIRED(s_wired)),
                    ==,
                    test_mac_address);

    g_variant_unref(dict);
    g_object_unref(s_wired);
}

static void
test_setting_new_from_dbus_enum(void)
{
    NMSettingIP6Config *       s_ip6;
    NMSettingWirelessSecurity *s_wsec;
    NMSettingSerial *          s_serial;
    GVariant *                 dict;
    GVariantBuilder            builder;
    GError *                   error = NULL;

    /* enum */
    g_variant_builder_init(&builder, NM_VARIANT_TYPE_SETTING);
    g_variant_builder_add(&builder,
                          "{sv}",
                          NM_SETTING_IP6_CONFIG_IP6_PRIVACY,
                          g_variant_new_int32(NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR));
    dict = g_variant_builder_end(&builder);

    s_ip6 = (NMSettingIP6Config *) _nm_setting_new_from_dbus(NM_TYPE_SETTING_IP6_CONFIG,
                                                             dict,
                                                             NULL,
                                                             NM_SETTING_PARSE_FLAGS_NONE,
                                                             &error);
    g_assert_no_error(error);

    g_assert_cmpint(nm_setting_ip6_config_get_ip6_privacy(s_ip6),
                    ==,
                    NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR);

    g_variant_unref(dict);
    g_object_unref(s_ip6);

    /* flags (and a transformed enum) */
    g_variant_builder_init(&builder, NM_VARIANT_TYPE_SETTING);
    g_variant_builder_add(&builder,
                          "{sv}",
                          NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE,
                          g_variant_new_uint32(NM_WEP_KEY_TYPE_KEY));
    g_variant_builder_add(&builder,
                          "{sv}",
                          NM_SETTING_WIRELESS_SECURITY_WEP_KEY_FLAGS,
                          g_variant_new_uint32(NM_SETTING_SECRET_FLAG_AGENT_OWNED
                                               | NM_SETTING_SECRET_FLAG_NOT_SAVED));
    dict = g_variant_builder_end(&builder);

    s_wsec =
        (NMSettingWirelessSecurity *) _nm_setting_new_from_dbus(NM_TYPE_SETTING_WIRELESS_SECURITY,
                                                                dict,
                                                                NULL,
                                                                NM_SETTING_PARSE_FLAGS_NONE,
                                                                &error);
    g_assert_no_error(error);

    g_assert_cmpint(nm_setting_wireless_security_get_wep_key_type(s_wsec), ==, NM_WEP_KEY_TYPE_KEY);
    g_assert_cmpint(nm_setting_wireless_security_get_wep_key_flags(s_wsec),
                    ==,
                    (NM_SETTING_SECRET_FLAG_AGENT_OWNED | NM_SETTING_SECRET_FLAG_NOT_SAVED));

    g_variant_unref(dict);
    g_object_unref(s_wsec);

    /* another transformed enum */
    g_variant_builder_init(&builder, NM_VARIANT_TYPE_SETTING);
    g_variant_builder_add(&builder, "{sv}", NM_SETTING_SERIAL_PARITY, g_variant_new_byte('E'));
    dict = g_variant_builder_end(&builder);

    s_serial = (NMSettingSerial *) _nm_setting_new_from_dbus(NM_TYPE_SETTING_SERIAL,
                                                             dict,
                                                             NULL,
                                                             NM_SETTING_PARSE_FLAGS_NONE,
                                                             &error);
    g_assert_no_error(error);

    g_assert_cmpint(nm_setting_serial_get_parity(s_serial), ==, NM_SETTING_SERIAL_PARITY_EVEN);

    g_variant_unref(dict);
    g_object_unref(s_serial);
}

static void
test_setting_new_from_dbus_bad(void)
{
    NMSetting *   setting;
    NMConnection *conn;
    GBytes *      ssid;
    GPtrArray *   addrs;
    GVariant *    orig_dict, *dict;
    GError *      error = NULL;

    /* We want to test:
     * - ordinary scalar properties
     * - string properties
     * - GBytes-valued properties (which are handled specially by set_property_from_dbus())
     * - enum/flags-valued properties
     * - overridden properties
     * - transformed properties
     *
     * No single setting class has examples of all of these, so we need two settings.
     */

    conn = nm_simple_connection_new();

    setting = nm_setting_connection_new();
    g_object_set(setting,
                 NM_SETTING_CONNECTION_ID,
                 "test",
                 NM_SETTING_CONNECTION_UUID,
                 "83c5a841-1759-4cdb-bfce-8d4087956497",
                 NULL);
    nm_connection_add_setting(conn, setting);

    setting = nm_setting_wireless_new();
    ssid    = g_bytes_new("my-ssid", 7);
    g_object_set(setting,
                 /* scalar */
                 NM_SETTING_WIRELESS_RATE,
                 100,
                 /* string */
                 NM_SETTING_WIRELESS_MODE,
                 NM_SETTING_WIRELESS_MODE_INFRA,
                 /* GBytes */
                 NM_SETTING_WIRELESS_SSID,
                 ssid,
                 /* transformed */
                 NM_SETTING_WIRELESS_BSSID,
                 "00:11:22:33:44:55",
                 NULL);
    g_bytes_unref(ssid);
    nm_connection_add_setting(conn, setting);

    setting = nm_setting_ip6_config_new();
    addrs   = g_ptr_array_new_with_free_func((GDestroyNotify) nm_ip_address_unref);
    g_ptr_array_add(addrs, nm_ip_address_new(AF_INET6, "1234::5678", 64, NULL));
    g_object_set(setting,
                 /* enum */
                 NM_SETTING_IP6_CONFIG_IP6_PRIVACY,
                 NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR,
                 /* overridden */
                 NM_SETTING_IP_CONFIG_ADDRESSES,
                 addrs,
                 /* (needed in order to verify()) */
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP6_CONFIG_METHOD_AUTO,
                 NULL);
    g_ptr_array_unref(addrs);
    nm_connection_add_setting(conn, setting);

    orig_dict = nm_connection_to_dbus(conn, NM_CONNECTION_SERIALIZE_ALL);
    g_object_unref(conn);

    /* sanity-check */
    conn = _connection_new_from_dbus(orig_dict, &error);
    g_assert_no_error(error);
    g_assert(conn);
    g_object_unref(conn);

    /* Compatible mismatches */

    dict = g_variant_ref(orig_dict);
    NMTST_VARIANT_EDITOR(dict,
                         NMTST_VARIANT_CHANGE_PROPERTY(NM_SETTING_WIRELESS_SETTING_NAME,
                                                       NM_SETTING_WIRELESS_RATE,
                                                       "i",
                                                       10););
    conn = _connection_new_from_dbus(dict, &error);
    nmtst_assert_success(conn, error);
    setting = nm_connection_get_setting(conn, NM_TYPE_SETTING_WIRELESS);
    g_assert(setting);
    g_assert_cmpint(nm_setting_wireless_get_rate(NM_SETTING_WIRELESS(setting)), ==, 10);
    g_object_unref(conn);
    g_variant_unref(dict);

    dict = g_variant_ref(orig_dict);
    NMTST_VARIANT_EDITOR(
        dict,
        NMTST_VARIANT_CHANGE_PROPERTY(NM_SETTING_IP6_CONFIG_SETTING_NAME,
                                      NM_SETTING_IP6_CONFIG_IP6_PRIVACY,
                                      "i",
                                      NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR););
    conn = _connection_new_from_dbus(dict, &error);
    g_assert(conn);
    g_assert_no_error(error);
    setting = nm_connection_get_setting(conn, NM_TYPE_SETTING_IP6_CONFIG);
    g_assert(setting);
    g_assert_cmpint(nm_setting_ip6_config_get_ip6_privacy(NM_SETTING_IP6_CONFIG(setting)),
                    ==,
                    NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR);
    g_object_unref(conn);
    g_variant_unref(dict);

    /* Incompatible mismatches */

    dict = g_variant_ref(orig_dict);
    NMTST_VARIANT_EDITOR(dict,
                         NMTST_VARIANT_CHANGE_PROPERTY(NM_SETTING_WIRELESS_SETTING_NAME,
                                                       NM_SETTING_WIRELESS_RATE,
                                                       "s",
                                                       "ten"););
    conn = _connection_new_from_dbus(dict, &error);
    g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
    g_assert(g_str_has_prefix(error->message, "802-11-wireless.rate:"));
    g_clear_error(&error);
    g_variant_unref(dict);

    dict = g_variant_ref(orig_dict);
    NMTST_VARIANT_EDITOR(dict,
                         NMTST_VARIANT_CHANGE_PROPERTY(NM_SETTING_WIRELESS_SETTING_NAME,
                                                       NM_SETTING_WIRELESS_MODE,
                                                       "b",
                                                       FALSE););
    conn = _connection_new_from_dbus(dict, &error);
    g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
    g_assert(g_str_has_prefix(error->message, "802-11-wireless.mode:"));
    g_clear_error(&error);
    g_variant_unref(dict);

    dict = g_variant_ref(orig_dict);
    NMTST_VARIANT_EDITOR(dict,
                         NMTST_VARIANT_CHANGE_PROPERTY(NM_SETTING_WIRELESS_SETTING_NAME,
                                                       NM_SETTING_WIRELESS_SSID,
                                                       "s",
                                                       "fred"););
    conn = _connection_new_from_dbus(dict, &error);
    g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
    g_assert(g_str_has_prefix(error->message, "802-11-wireless.ssid:"));
    g_clear_error(&error);
    g_variant_unref(dict);

    dict = g_variant_ref(orig_dict);
    NMTST_VARIANT_EDITOR(dict,
                         NMTST_VARIANT_CHANGE_PROPERTY(NM_SETTING_WIRELESS_SETTING_NAME,
                                                       NM_SETTING_WIRELESS_BSSID,
                                                       "i",
                                                       42););
    conn = _connection_new_from_dbus(dict, &error);
    g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
    g_assert(g_str_has_prefix(error->message, "802-11-wireless.bssid:"));
    g_clear_error(&error);
    g_variant_unref(dict);

    dict = g_variant_ref(orig_dict);
    NMTST_VARIANT_EDITOR(dict,
                         NMTST_VARIANT_CHANGE_PROPERTY(NM_SETTING_IP6_CONFIG_SETTING_NAME,
                                                       NM_SETTING_IP6_CONFIG_IP6_PRIVACY,
                                                       "s",
                                                       "private"););
    conn = _connection_new_from_dbus(dict, &error);
    g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
    g_assert(g_str_has_prefix(error->message, "ipv6.ip6-privacy:"));
    g_clear_error(&error);
    g_variant_unref(dict);

    dict = g_variant_ref(orig_dict);
    NMTST_VARIANT_EDITOR(dict,
                         NMTST_VARIANT_CHANGE_PROPERTY(NM_SETTING_IP6_CONFIG_SETTING_NAME,
                                                       NM_SETTING_IP_CONFIG_ADDRESSES,
                                                       "s",
                                                       "1234::5678"););
    conn = _connection_new_from_dbus(dict, &error);
    g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
    g_assert(g_str_has_prefix(error->message, "ipv6.addresses:"));
    g_clear_error(&error);
    g_variant_unref(dict);

    g_variant_unref(orig_dict);
}

static NMConnection *
new_test_connection(void)
{
    NMConnection *connection;
    NMSetting *   setting;
    char *        uuid;
    guint64       timestamp = time(NULL);

    connection = nm_simple_connection_new();

    setting = nm_setting_connection_new();
    uuid    = nm_utils_uuid_generate();
    g_object_set(G_OBJECT(setting),
                 NM_SETTING_CONNECTION_ID,
                 "foobar",
                 NM_SETTING_CONNECTION_UUID,
                 uuid,
                 NM_SETTING_CONNECTION_TYPE,
                 NM_SETTING_WIRED_SETTING_NAME,
                 NM_SETTING_CONNECTION_TIMESTAMP,
                 timestamp,
                 NULL);
    g_free(uuid);
    nm_connection_add_setting(connection, setting);

    setting = nm_setting_wired_new();
    g_object_set(G_OBJECT(setting), NM_SETTING_WIRED_MTU, 1592, NULL);
    nm_connection_add_setting(connection, setting);

    setting = nm_setting_ip4_config_new();
    g_object_set(G_OBJECT(setting),
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP4_CONFIG_METHOD_AUTO,
                 NM_SETTING_IP_CONFIG_DHCP_HOSTNAME,
                 "eyeofthetiger",
                 NULL);
    nm_connection_add_setting(connection, setting);

    return connection;
}

static GVariant *
new_connection_dict(char **      out_uuid,
                    const char **out_expected_id,
                    const char **out_expected_ip6_method)
{
    GVariantBuilder conn_builder, setting_builder;

    g_variant_builder_init(&conn_builder, NM_VARIANT_TYPE_CONNECTION);

    *out_uuid                = nm_utils_uuid_generate();
    *out_expected_id         = "My happy connection";
    *out_expected_ip6_method = NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL;

    /* Connection setting */
    g_variant_builder_init(&setting_builder, NM_VARIANT_TYPE_SETTING);
    g_variant_builder_add(&setting_builder,
                          "{sv}",
                          NM_SETTING_NAME,
                          g_variant_new_string(NM_SETTING_CONNECTION_SETTING_NAME));
    g_variant_builder_add(&setting_builder,
                          "{sv}",
                          NM_SETTING_CONNECTION_ID,
                          g_variant_new_string(*out_expected_id));
    g_variant_builder_add(&setting_builder,
                          "{sv}",
                          NM_SETTING_CONNECTION_UUID,
                          g_variant_new_string(*out_uuid));
    g_variant_builder_add(&setting_builder,
                          "{sv}",
                          NM_SETTING_CONNECTION_TYPE,
                          g_variant_new_string(NM_SETTING_WIRED_SETTING_NAME));

    g_variant_builder_add(&conn_builder,
                          "{sa{sv}}",
                          NM_SETTING_CONNECTION_SETTING_NAME,
                          &setting_builder);

    /* Wired setting */
    g_variant_builder_init(&setting_builder, NM_VARIANT_TYPE_SETTING);
    g_variant_builder_add(&conn_builder,
                          "{sa{sv}}",
                          NM_SETTING_WIRED_SETTING_NAME,
                          &setting_builder);

    /* IP6 */
    g_variant_builder_init(&setting_builder, NM_VARIANT_TYPE_SETTING);
    g_variant_builder_add(&setting_builder,
                          "{sv}",
                          NM_SETTING_IP_CONFIG_METHOD,
                          g_variant_new_string(*out_expected_ip6_method));
    g_variant_builder_add(&conn_builder,
                          "{sa{sv}}",
                          NM_SETTING_IP6_CONFIG_SETTING_NAME,
                          &setting_builder);

    return g_variant_builder_end(&conn_builder);
}

static void
test_connection_replace_settings(void)
{
    NMConnection *       connection;
    GVariant *           new_settings;
    GError *             error = NULL;
    gboolean             success;
    NMSettingConnection *s_con;
    NMSettingIPConfig *  s_ip6;
    char *               uuid        = NULL;
    const char *         expected_id = NULL, *expected_method = NULL;

    connection = new_test_connection();

    new_settings = new_connection_dict(&uuid, &expected_id, &expected_method);
    g_assert(new_settings);

    /* Replace settings and test */
    success = nm_connection_replace_settings(connection, new_settings, &error);
    g_assert_no_error(error);
    g_assert(success);

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, expected_id);
    g_assert_cmpstr(nm_setting_connection_get_uuid(s_con), ==, uuid);

    g_assert(nm_connection_get_setting_wired(connection));
    g_assert(!nm_connection_get_setting_ip4_config(connection));

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6), ==, expected_method);

    g_free(uuid);
    g_variant_unref(new_settings);
    g_object_unref(connection);
}

static void
test_connection_replace_settings_from_connection(void)
{
    NMConnection *       connection, *replacement;
    NMSettingConnection *s_con;
    NMSetting *          setting;
    GBytes *             ssid;
    char *               uuid        = NULL;
    const char *         expected_id = "Awesome connection";

    connection = new_test_connection();
    g_assert(connection);

    replacement = nm_simple_connection_new();
    g_assert(replacement);

    /* New connection setting */
    setting = nm_setting_connection_new();
    g_assert(setting);

    uuid = nm_utils_uuid_generate();
    g_object_set(setting,
                 NM_SETTING_CONNECTION_ID,
                 expected_id,
                 NM_SETTING_CONNECTION_UUID,
                 uuid,
                 NM_SETTING_CONNECTION_TYPE,
                 NM_SETTING_WIRELESS_SETTING_NAME,
                 NULL);
    nm_connection_add_setting(replacement, setting);

    /* New wifi setting */
    setting = nm_setting_wireless_new();
    g_assert(setting);

    ssid = g_bytes_new("1234567", 7);
    g_object_set(setting,
                 NM_SETTING_WIRELESS_SSID,
                 ssid,
                 NM_SETTING_WIRELESS_MODE,
                 "infrastructure",
                 NULL);
    g_bytes_unref(ssid);
    nm_connection_add_setting(replacement, setting);

    /* Replace settings and test */
    nm_connection_replace_settings_from_connection(connection, replacement);

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, expected_id);
    g_assert_cmpstr(nm_setting_connection_get_uuid(s_con), ==, uuid);

    g_assert(!nm_connection_get_setting_wired(connection));
    g_assert(!nm_connection_get_setting_ip6_config(connection));
    g_assert(nm_connection_get_setting_wireless(connection));

    g_free(uuid);
    g_object_unref(replacement);
    g_object_unref(connection);
}

static void
test_connection_replace_settings_bad(void)
{
    NMConnection *       connection, *new_connection;
    GVariant *           new_settings;
    GVariantBuilder      builder, setting_builder;
    GError *             error = NULL;
    gboolean             success;
    NMSettingConnection *s_con;

    new_connection = new_test_connection();
    g_assert(nm_connection_verify(new_connection, NULL));
    s_con = nm_connection_get_setting_connection(new_connection);
    g_object_set(s_con,
                 NM_SETTING_CONNECTION_UUID,
                 NULL,
                 NM_SETTING_CONNECTION_ID,
                 "bad-connection",
                 NULL);
    g_assert(!nm_connection_verify(new_connection, NULL));

    /* nm_connection_replace_settings_from_connection() should succeed */
    connection = new_test_connection();
    nm_connection_replace_settings_from_connection(connection, new_connection);
    g_assert_cmpstr(nm_connection_get_id(connection), ==, "bad-connection");
    g_assert(!nm_connection_verify(connection, NULL));
    g_object_unref(connection);

    /* nm_connection_replace_settings() should succeed */
    new_settings = nm_connection_to_dbus(new_connection, NM_CONNECTION_SERIALIZE_ALL);
    g_assert(new_settings != NULL);

    connection = new_test_connection();
    success    = nm_connection_replace_settings(connection, new_settings, &error);
    g_assert_no_error(error);
    g_assert(success);

    g_assert_cmpstr(nm_connection_get_id(connection), ==, "bad-connection");
    g_assert(!nm_connection_verify(connection, NULL));
    g_object_unref(connection);
    g_variant_unref(new_settings);

    /* But given an invalid dict, it should fail */
    g_variant_builder_init(&builder, NM_VARIANT_TYPE_CONNECTION);
    g_variant_builder_init(&setting_builder, NM_VARIANT_TYPE_SETTING);
    g_variant_builder_add(&builder, "{sa{sv}}", "ip-over-avian-carrier", &setting_builder);
    new_settings = g_variant_builder_end(&builder);

    connection = new_test_connection();
    success    = nm_connection_replace_settings(connection, new_settings, &error);
    g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_SETTING);
    g_clear_error(&error);
    g_assert(!success);

    g_assert(nm_connection_verify(connection, NULL));
    g_object_unref(connection);

    g_variant_unref(new_settings);
    g_object_unref(new_connection);
}

static void
test_connection_new_from_dbus(void)
{
    NMConnection *       connection;
    GVariant *           new_settings;
    GError *             error = NULL;
    NMSettingConnection *s_con;
    NMSettingIPConfig *  s_ip6;
    char *               uuid        = NULL;
    const char *         expected_id = NULL, *expected_method = NULL;

    new_settings = new_connection_dict(&uuid, &expected_id, &expected_method);
    g_assert(new_settings);

    /* Replace settings and test */
    connection = _connection_new_from_dbus(new_settings, &error);
    g_assert_no_error(error);
    g_assert(connection);

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, expected_id);
    g_assert_cmpstr(nm_setting_connection_get_uuid(s_con), ==, uuid);

    g_assert(nm_connection_get_setting_wired(connection));
    g_assert(nm_connection_get_setting_ip4_config(connection));

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6), ==, expected_method);

    g_free(uuid);
    g_variant_unref(new_settings);
    g_object_unref(connection);
}

static void
check_permission(NMSettingConnection *s_con, guint32 idx, const char *expected_uname)
{
    gboolean    success;
    const char *ptype = NULL, *pitem = NULL, *detail = NULL;

    success = nm_setting_connection_get_permission(s_con, idx, &ptype, &pitem, &detail);
    g_assert(success);

    g_assert_cmpstr(ptype, ==, "user");

    g_assert(pitem);
    g_assert_cmpstr(pitem, ==, expected_uname);

    g_assert(!detail);
}

#define TEST_UNAME "asdfasfasdf"

static void
test_setting_connection_permissions_helpers(void)
{
    NMSettingConnection *s_con;
    gboolean             success;
    char                 buf[9] = {0x61, 0x62, 0x63, 0xff, 0xfe, 0xfd, 0x23, 0x01, 0x00};
    char **              perms;
    const char *         expected_perm = "user:" TEST_UNAME ":";

    s_con = NM_SETTING_CONNECTION(nm_setting_connection_new());

    /* Ensure a bad [type] is rejected */
    success = nm_setting_connection_add_permission(s_con, "foobar", "blah", NULL);
    g_assert(!success);
    g_assert_cmpint(nm_setting_connection_get_num_permissions(s_con), ==, 0);

    /* Ensure a bad [type] is rejected */
    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(ptype));
    success = nm_setting_connection_add_permission(s_con, NULL, "blah", NULL);
    g_test_assert_expected_messages();
    g_assert(!success);
    g_assert_cmpint(nm_setting_connection_get_num_permissions(s_con), ==, 0);

    /* Ensure a bad [item] is rejected */
    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(pitem));
    success = nm_setting_connection_add_permission(s_con, "user", NULL, NULL);
    g_test_assert_expected_messages();
    g_assert(!success);
    g_assert_cmpint(nm_setting_connection_get_num_permissions(s_con), ==, 0);

    /* Ensure a bad [item] is rejected */
    success = nm_setting_connection_add_permission(s_con, "user", "", NULL);
    g_assert(!success);
    g_assert_cmpint(nm_setting_connection_get_num_permissions(s_con), ==, 0);

    /* Ensure an [item] with ':' is rejected */
    success = nm_setting_connection_add_permission(s_con, "user", "ad:asdf", NULL);
    g_assert(!success);
    g_assert_cmpint(nm_setting_connection_get_num_permissions(s_con), ==, 0);

    /* Ensure a non-UTF-8 [item] is rejected */
    success = nm_setting_connection_add_permission(s_con, "user", buf, NULL);
    g_assert(!success);
    g_assert_cmpint(nm_setting_connection_get_num_permissions(s_con), ==, 0);

    /* Ensure a non-NULL [detail] is rejected */
    success = nm_setting_connection_add_permission(s_con, "user", "dafasdf", "asdf");
    g_assert(!success);
    g_assert_cmpint(nm_setting_connection_get_num_permissions(s_con), ==, 0);

    /* Ensure a valid call results in success */
    success = nm_setting_connection_add_permission(s_con, "user", TEST_UNAME, NULL);
    g_assert(success);

    g_assert_cmpint(nm_setting_connection_get_num_permissions(s_con), ==, 1);

    check_permission(s_con, 0, TEST_UNAME);

    /* Check the actual GObject property just to be paranoid */
    g_object_get(G_OBJECT(s_con), NM_SETTING_CONNECTION_PERMISSIONS, &perms, NULL);
    g_assert(perms);
    g_assert_cmpint(g_strv_length(perms), ==, 1);
    g_assert_cmpstr(perms[0], ==, expected_perm);
    g_strfreev(perms);

    /* Now remove that permission and ensure we have 0 permissions */
    nm_setting_connection_remove_permission(s_con, 0);
    g_assert_cmpint(nm_setting_connection_get_num_permissions(s_con), ==, 0);

    g_object_unref(s_con);
}

static void
add_permission_property(NMSettingConnection *s_con,
                        const char *         ptype,
                        const char *         pitem,
                        int                  pitem_len,
                        const char *         detail)
{
    GString *str;
    char *   perms[2];

    str = g_string_sized_new(50);
    if (ptype)
        g_string_append(str, ptype);
    g_string_append_c(str, ':');

    if (pitem) {
        if (pitem_len >= 0)
            g_string_append_len(str, pitem, pitem_len);
        else
            g_string_append(str, pitem);
    }

    g_string_append_c(str, ':');

    if (detail)
        g_string_append(str, detail);

    perms[0] = str->str;
    perms[1] = NULL;
    g_object_set(G_OBJECT(s_con), NM_SETTING_CONNECTION_PERMISSIONS, perms, NULL);

    g_string_free(str, TRUE);
}

static void
test_setting_connection_permissions_property(void)
{
    gs_unref_object NMSettingConnection *s_con = NULL;
    gboolean                             success;
    char buf[9] = {0x61, 0x62, 0x63, 0xff, 0xfe, 0xfd, 0x23, 0x01, 0x00};

    s_con = NM_SETTING_CONNECTION(nm_setting_connection_new());

#define _assert_permission_invalid_at_idx(s_con, idx, expected_item)                            \
    G_STMT_START                                                                                \
    {                                                                                           \
        NMSettingConnection *_s_con = (s_con);                                                  \
        guint                _idx   = (idx);                                                    \
        const char *         _ptype;                                                            \
        const char *         _pitem;                                                            \
        const char *         _detail;                                                           \
        const char **        _p_ptype  = nmtst_get_rand_bool() ? &_ptype : NULL;                \
        const char **        _p_pitem  = nmtst_get_rand_bool() ? &_pitem : NULL;                \
        const char **        _p_detail = nmtst_get_rand_bool() ? &_detail : NULL;               \
                                                                                                \
        g_assert_cmpint(_idx, <, nm_setting_connection_get_num_permissions(_s_con));            \
        g_assert(                                                                               \
            nm_setting_connection_get_permission(_s_con, _idx, _p_ptype, _p_pitem, _p_detail)); \
        if (_p_ptype)                                                                           \
            g_assert_cmpstr(_ptype, ==, "invalid");                                             \
        if (_p_pitem) {                                                                         \
            const char *_expected_item = (expected_item);                                       \
                                                                                                \
            if (!_expected_item)                                                                \
                g_assert_cmpstr(_pitem, !=, NULL);                                              \
            else                                                                                \
                g_assert_cmpstr(_pitem, ==, _expected_item);                                    \
        }                                                                                       \
        if (_p_detail)                                                                          \
            g_assert_cmpstr(_detail, ==, NULL);                                                 \
    }                                                                                           \
    G_STMT_END

    /* Ensure a bad [type] is rejected */
    add_permission_property(s_con, "foobar", "blah", -1, NULL);
    g_assert_cmpint(nm_setting_connection_get_num_permissions(s_con), ==, 1);
    _assert_permission_invalid_at_idx(s_con, 0, "foobar:blah:");

    /* Ensure a bad [type] is rejected */
    add_permission_property(s_con, NULL, "blah", -1, NULL);
    g_assert_cmpint(nm_setting_connection_get_num_permissions(s_con), ==, 1);
    _assert_permission_invalid_at_idx(s_con, 0, ":blah:");

    /* Ensure a bad [item] is rejected */
    add_permission_property(s_con, "user", NULL, -1, NULL);
    g_assert_cmpint(nm_setting_connection_get_num_permissions(s_con), ==, 1);
    _assert_permission_invalid_at_idx(s_con, 0, "user::");

    /* Ensure a bad [item] is rejected */
    add_permission_property(s_con, "user", "", -1, NULL);
    g_assert_cmpint(nm_setting_connection_get_num_permissions(s_con), ==, 1);
    _assert_permission_invalid_at_idx(s_con, 0, "user::");

    /* Ensure an [item] with ':' in the middle is rejected */
    add_permission_property(s_con, "user", "ad:asdf", -1, NULL);
    g_assert_cmpint(nm_setting_connection_get_num_permissions(s_con), ==, 1);
    _assert_permission_invalid_at_idx(s_con, 0, "user:ad:asdf:");

    /* Ensure an [item] with ':' at the end is rejected */
    add_permission_property(s_con, "user", "adasdfaf:", -1, NULL);
    g_assert_cmpint(nm_setting_connection_get_num_permissions(s_con), ==, 1);
    _assert_permission_invalid_at_idx(s_con, 0, "user:adasdfaf::");

    /* Ensure a non-UTF-8 [item] is rejected */
    add_permission_property(s_con, "user", buf, (int) sizeof(buf), NULL);
    g_assert_cmpint(nm_setting_connection_get_num_permissions(s_con), ==, 1);
    _assert_permission_invalid_at_idx(s_con, 0, NULL);

    /* Ensure a non-NULL [detail] is rejected */
    add_permission_property(s_con, "user", "dafasdf", -1, "asdf");
    g_assert_cmpint(nm_setting_connection_get_num_permissions(s_con), ==, 1);
    _assert_permission_invalid_at_idx(s_con, 0, "user:dafasdf:asdf");

    /* Ensure a valid call results in success */
    success = nm_setting_connection_add_permission(s_con, "user", TEST_UNAME, NULL);
    g_assert(success);
    g_assert_cmpint(nm_setting_connection_get_num_permissions(s_con), ==, 2);
    _assert_permission_invalid_at_idx(s_con, 0, "user:dafasdf:asdf");
    check_permission(s_con, 1, TEST_UNAME);

    /* Now remove that permission and ensure we have 0 permissions */
    nm_setting_connection_remove_permission(s_con, 0);
    g_assert_cmpint(nm_setting_connection_get_num_permissions(s_con), ==, 1);
}

static void
test_connection_compare_same(void)
{
    NMConnection *a, *b;

    a = new_test_connection();
    b = nm_simple_connection_new_clone(a);
    g_assert(nm_connection_compare(a, b, NM_SETTING_COMPARE_FLAG_EXACT));
    g_object_unref(a);
    g_object_unref(b);
}

static void
test_connection_compare_key_only_in_a(void)
{
    NMConnection *       a, *b;
    NMSettingConnection *s_con;

    a     = new_test_connection();
    b     = nm_simple_connection_new_clone(a);
    s_con = (NMSettingConnection *) nm_connection_get_setting(b, NM_TYPE_SETTING_CONNECTION);
    g_assert(s_con);
    g_object_set(s_con, NM_SETTING_CONNECTION_TIMESTAMP, (guint64) 0, NULL);

    g_assert(!nm_connection_compare(a, b, NM_SETTING_COMPARE_FLAG_EXACT));
    g_object_unref(a);
    g_object_unref(b);
}

static void
test_connection_compare_setting_only_in_a(void)
{
    NMConnection *a, *b;

    a = new_test_connection();
    b = nm_simple_connection_new_clone(a);
    nm_connection_remove_setting(b, NM_TYPE_SETTING_IP4_CONFIG);
    g_assert(!nm_connection_compare(a, b, NM_SETTING_COMPARE_FLAG_EXACT));
    g_object_unref(a);
    g_object_unref(b);
}

static void
test_connection_compare_key_only_in_b(void)
{
    NMConnection *       a, *b;
    NMSettingConnection *s_con;

    a     = new_test_connection();
    b     = nm_simple_connection_new_clone(a);
    s_con = (NMSettingConnection *) nm_connection_get_setting(b, NM_TYPE_SETTING_CONNECTION);
    g_assert(s_con);
    g_object_set(s_con, NM_SETTING_CONNECTION_TIMESTAMP, (guint64) 0, NULL);

    g_assert(!nm_connection_compare(a, b, NM_SETTING_COMPARE_FLAG_EXACT));
    g_object_unref(a);
    g_object_unref(b);
}

static void
test_connection_compare_setting_only_in_b(void)
{
    NMConnection *a, *b;

    a = new_test_connection();
    b = nm_simple_connection_new_clone(a);
    nm_connection_remove_setting(a, NM_TYPE_SETTING_IP4_CONFIG);
    g_assert(!nm_connection_compare(a, b, NM_SETTING_COMPARE_FLAG_EXACT));
    g_object_unref(a);
    g_object_unref(b);
}

typedef struct {
    const char *key_name;
    guint32     result;
} DiffKey;

typedef struct {
    const char *name;
    DiffKey     keys[30];
} DiffSetting;

#define ARRAY_LEN(a) (sizeof(a) / sizeof(a[0]))

static void
ensure_diffs(GHashTable *diffs, const DiffSetting *check, gsize n_check)
{
    guint i;

    g_assert(g_hash_table_size(diffs) == n_check);

    /* Loop through the settings */
    for (i = 0; i < n_check; i++) {
        GHashTable *setting_hash;
        guint       z = 0;

        setting_hash = g_hash_table_lookup(diffs, check[i].name);
        g_assert(setting_hash);

        /* Get the number of keys to check */
        while (check[i].keys[z].key_name)
            z++;
        g_assert(g_hash_table_size(setting_hash) == z);

        /* Now compare the actual keys */
        for (z = 0; check[i].keys[z].key_name; z++) {
            NMSettingDiffResult result;

            result = GPOINTER_TO_UINT(g_hash_table_lookup(setting_hash, check[i].keys[z].key_name));
            g_assert(result == check[i].keys[z].result);
        }
    }
}

static void
test_connection_diff_a_only(void)
{
    NMConnection *    connection;
    GHashTable *      out_diffs = NULL;
    gboolean          same;
    const DiffSetting settings[] = {
        {NM_SETTING_CONNECTION_SETTING_NAME,
         {{NM_SETTING_CONNECTION_ID, NM_SETTING_DIFF_RESULT_IN_A},
          {NM_SETTING_CONNECTION_UUID, NM_SETTING_DIFF_RESULT_IN_A},
          {NM_SETTING_CONNECTION_STABLE_ID, NM_SETTING_DIFF_RESULT_IN_A},
          {NM_SETTING_CONNECTION_INTERFACE_NAME, NM_SETTING_DIFF_RESULT_IN_A},
          {NM_SETTING_CONNECTION_TYPE, NM_SETTING_DIFF_RESULT_IN_A},
          {NM_SETTING_CONNECTION_TIMESTAMP, NM_SETTING_DIFF_RESULT_IN_A},
          {NM_SETTING_CONNECTION_AUTOCONNECT, NM_SETTING_DIFF_RESULT_IN_A},
          {NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY, NM_SETTING_DIFF_RESULT_IN_A},
          {NM_SETTING_CONNECTION_AUTOCONNECT_RETRIES, NM_SETTING_DIFF_RESULT_IN_A},
          {NM_SETTING_CONNECTION_MULTI_CONNECT, NM_SETTING_DIFF_RESULT_IN_A},
          {NM_SETTING_CONNECTION_READ_ONLY, NM_SETTING_DIFF_RESULT_IN_A},
          {NM_SETTING_CONNECTION_PERMISSIONS, NM_SETTING_DIFF_RESULT_IN_A},
          {NM_SETTING_CONNECTION_ZONE, NM_SETTING_DIFF_RESULT_IN_A},
          {NM_SETTING_CONNECTION_MASTER, NM_SETTING_DIFF_RESULT_IN_A},
          {NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_DIFF_RESULT_IN_A},
          {NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES, NM_SETTING_DIFF_RESULT_IN_A},
          {NM_SETTING_CONNECTION_SECONDARIES, NM_SETTING_DIFF_RESULT_IN_A},
          {NM_SETTING_CONNECTION_GATEWAY_PING_TIMEOUT, NM_SETTING_DIFF_RESULT_IN_A},
          {NM_SETTING_CONNECTION_METERED, NM_SETTING_DIFF_RESULT_IN_A},
          {NM_SETTING_CONNECTION_LLDP, NM_SETTING_DIFF_RESULT_IN_A},
          {NM_SETTING_CONNECTION_AUTH_RETRIES, NM_SETTING_DIFF_RESULT_IN_A},
          {NM_SETTING_CONNECTION_MDNS, NM_SETTING_DIFF_RESULT_IN_A},
          {NM_SETTING_CONNECTION_LLMNR, NM_SETTING_DIFF_RESULT_IN_A},
          {NM_SETTING_CONNECTION_MUD_URL, NM_SETTING_DIFF_RESULT_IN_A},
          {NM_SETTING_CONNECTION_WAIT_DEVICE_TIMEOUT, NM_SETTING_DIFF_RESULT_IN_A},
          {NULL, NM_SETTING_DIFF_RESULT_UNKNOWN}}},
        {NM_SETTING_WIRED_SETTING_NAME,
         {
             {NM_SETTING_WIRED_PORT, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_WIRED_SPEED, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_WIRED_DUPLEX, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_WIRED_AUTO_NEGOTIATE, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_WIRED_MAC_ADDRESS, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_WIRED_CLONED_MAC_ADDRESS, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_WIRED_GENERATE_MAC_ADDRESS_MASK, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_WIRED_MAC_ADDRESS_BLACKLIST, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_WIRED_MTU, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_WIRED_S390_SUBCHANNELS, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_WIRED_S390_NETTYPE, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_WIRED_S390_OPTIONS, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_WIRED_WAKE_ON_LAN, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_WIRED_WAKE_ON_LAN_PASSWORD, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_WIRED_ACCEPT_ALL_MAC_ADDRESSES, NM_SETTING_DIFF_RESULT_IN_A},
             {NULL, NM_SETTING_DIFF_RESULT_UNKNOWN},
         }},
        {NM_SETTING_IP4_CONFIG_SETTING_NAME,
         {
             {NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_IP_CONFIG_DNS, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_IP_CONFIG_DNS_SEARCH, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_IP_CONFIG_DNS_OPTIONS, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_IP_CONFIG_ADDRESSES, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_IP_CONFIG_GATEWAY, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_IP_CONFIG_ROUTES, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_IP_CONFIG_ROUTE_METRIC, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_IP_CONFIG_ROUTE_TABLE, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_IP_CONFIG_ROUTING_RULES, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_IP_CONFIG_DHCP_TIMEOUT, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_IP_CONFIG_DHCP_HOSTNAME_FLAGS, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_IP4_CONFIG_DHCP_FQDN, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_IP_CONFIG_NEVER_DEFAULT, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_IP_CONFIG_MAY_FAIL, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_IP_CONFIG_DAD_TIMEOUT, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_IP_CONFIG_REQUIRED_TIMEOUT, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_IP_CONFIG_DNS_PRIORITY, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_IP_CONFIG_DHCP_IAID, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_IP4_CONFIG_DHCP_VENDOR_CLASS_IDENTIFIER, NM_SETTING_DIFF_RESULT_IN_A},
             {NM_SETTING_IP_CONFIG_DHCP_REJECT_SERVERS, NM_SETTING_DIFF_RESULT_IN_A},
             {NULL, NM_SETTING_DIFF_RESULT_UNKNOWN},
         }},
    };

    connection = new_test_connection();

    same = nm_connection_diff(connection, NULL, NM_SETTING_COMPARE_FLAG_EXACT, &out_diffs);
    g_assert(same == FALSE);
    g_assert(out_diffs != NULL);
    g_assert(g_hash_table_size(out_diffs) > 0);

    ensure_diffs(out_diffs, settings, ARRAY_LEN(settings));

    g_hash_table_destroy(out_diffs);
    g_object_unref(connection);
}

static void
test_connection_diff_same(void)
{
    NMConnection *a, *b;
    GHashTable *  out_diffs = NULL;
    gboolean      same;

    a = new_test_connection();
    b = nm_simple_connection_new_clone(a);

    same = nm_connection_diff(a, b, NM_SETTING_COMPARE_FLAG_EXACT, &out_diffs);
    g_assert(same == TRUE);
    g_assert(out_diffs == NULL);
    g_object_unref(a);
    g_object_unref(b);
}

static void
test_connection_diff_different(void)
{
    NMConnection *     a, *b;
    GHashTable *       out_diffs = NULL;
    NMSettingIPConfig *s_ip4;
    gboolean           same;
    const DiffSetting  settings[] = {
        {NM_SETTING_IP4_CONFIG_SETTING_NAME,
         {
             {NM_SETTING_IP_CONFIG_METHOD,
              NM_SETTING_DIFF_RESULT_IN_A | NM_SETTING_DIFF_RESULT_IN_B},
             {NULL, NM_SETTING_DIFF_RESULT_UNKNOWN},
         }},
    };

    a     = new_test_connection();
    b     = nm_simple_connection_new_clone(a);
    s_ip4 = nm_connection_get_setting_ip4_config(a);
    g_assert(s_ip4);
    g_object_set(G_OBJECT(s_ip4),
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
                 NULL);

    same = nm_connection_diff(a, b, NM_SETTING_COMPARE_FLAG_EXACT, &out_diffs);
    g_assert(same == FALSE);
    g_assert(out_diffs != NULL);
    g_assert(g_hash_table_size(out_diffs) > 0);

    ensure_diffs(out_diffs, settings, ARRAY_LEN(settings));

    g_hash_table_destroy(out_diffs);
    g_object_unref(a);
    g_object_unref(b);
}

static void
test_connection_diff_no_secrets(void)
{
    NMConnection *    a, *b;
    GHashTable *      out_diffs = NULL;
    NMSetting *       s_pppoe;
    gboolean          same;
    const DiffSetting settings[] = {
        {NM_SETTING_PPPOE_SETTING_NAME,
         {
             {NM_SETTING_PPPOE_PASSWORD, NM_SETTING_DIFF_RESULT_IN_B},
             {NULL, NM_SETTING_DIFF_RESULT_UNKNOWN},
         }},
    };

    a       = new_test_connection();
    s_pppoe = nm_setting_pppoe_new();
    g_object_set(G_OBJECT(s_pppoe), NM_SETTING_PPPOE_USERNAME, "thomas", NULL);
    nm_connection_add_setting(a, s_pppoe);

    b = nm_simple_connection_new_clone(a);

    /* Add a secret to B */
    s_pppoe = NM_SETTING(nm_connection_get_setting_pppoe(b));
    g_assert(s_pppoe);
    g_object_set(G_OBJECT(s_pppoe), NM_SETTING_PPPOE_PASSWORD, "secretpassword", NULL);

    /* Make sure the diff returns no results as secrets are ignored */
    same = nm_connection_diff(a, b, NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS, &out_diffs);
    g_assert(same == TRUE);
    g_assert(out_diffs == NULL);

    /* Now make sure the diff returns results if secrets are not ignored */
    same = nm_connection_diff(a, b, NM_SETTING_COMPARE_FLAG_EXACT, &out_diffs);
    g_assert(same == FALSE);
    g_assert(out_diffs != NULL);
    g_assert(g_hash_table_size(out_diffs) > 0);

    ensure_diffs(out_diffs, settings, ARRAY_LEN(settings));

    g_hash_table_destroy(out_diffs);
    g_object_unref(a);
    g_object_unref(b);
}

static void
test_connection_diff_inferrable(void)
{
    NMConnection *       a, *b;
    GHashTable *         out_diffs = NULL;
    gboolean             same;
    NMSettingConnection *s_con;
    NMSettingWired *     s_wired;
    NMSettingIPConfig *  s_ip4;
    char *               uuid;
    const DiffSetting    settings[] = {
        {NM_SETTING_CONNECTION_SETTING_NAME,
         {
             {NM_SETTING_CONNECTION_INTERFACE_NAME, NM_SETTING_DIFF_RESULT_IN_A},
             {NULL, NM_SETTING_DIFF_RESULT_UNKNOWN},
         }},
    };

    a = new_test_connection();
    b = nm_simple_connection_new_clone(a);

    /* Change the UUID, wired MTU, and set ignore-auto-dns */
    s_con = nm_connection_get_setting_connection(a);
    g_assert(s_con);
    uuid = nm_utils_uuid_generate();
    g_object_set(G_OBJECT(s_con),
                 NM_SETTING_CONNECTION_UUID,
                 uuid,
                 NM_SETTING_CONNECTION_ID,
                 "really neat connection",
                 NULL);
    g_free(uuid);

    s_wired = nm_connection_get_setting_wired(a);
    g_assert(s_wired);
    g_object_set(G_OBJECT(s_wired), NM_SETTING_WIRED_MTU, 300, NULL);

    s_ip4 = nm_connection_get_setting_ip4_config(a);
    g_assert(s_ip4);
    g_object_set(G_OBJECT(s_ip4), NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS, TRUE, NULL);

    /* Make sure the diff returns no results as secrets are ignored */
    same = nm_connection_diff(a, b, NM_SETTING_COMPARE_FLAG_INFERRABLE, &out_diffs);
    g_assert(same == TRUE);
    g_assert(out_diffs == NULL);

    /* And change a INFERRABLE property to ensure that it shows up in the diff results */
    g_object_set(G_OBJECT(s_con), NM_SETTING_CONNECTION_INTERFACE_NAME, "usb0", NULL);

    /* Make sure the diff returns no results as secrets are ignored */
    same = nm_connection_diff(a, b, NM_SETTING_COMPARE_FLAG_INFERRABLE, &out_diffs);
    g_assert(same == FALSE);
    g_assert(out_diffs != NULL);
    g_assert(g_hash_table_size(out_diffs) > 0);

    ensure_diffs(out_diffs, settings, ARRAY_LEN(settings));

    g_hash_table_destroy(out_diffs);
    g_object_unref(a);
    g_object_unref(b);
}

static void
add_generic_settings(NMConnection *connection, const char *ctype)
{
    NMSetting *setting;
    char *     uuid;

    uuid = nm_utils_uuid_generate();

    setting = nm_setting_connection_new();
    g_object_set(setting,
                 NM_SETTING_CONNECTION_ID,
                 "asdfasdfadf",
                 NM_SETTING_CONNECTION_TYPE,
                 ctype,
                 NM_SETTING_CONNECTION_UUID,
                 uuid,
                 NULL);
    nm_connection_add_setting(connection, setting);

    g_free(uuid);

    setting = nm_setting_ip4_config_new();
    g_object_set(setting, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);
    nm_connection_add_setting(connection, setting);

    setting = nm_setting_ip6_config_new();
    g_object_set(setting, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO, NULL);
    nm_connection_add_setting(connection, setting);
}

static void
test_connection_good_base_types(void)
{
    NMConnection *connection;
    NMSetting *   setting;
    gboolean      success;
    GError *      error = NULL;
    GBytes *      ssid;
    const char *  bdaddr = "11:22:33:44:55:66";

    /* Try a basic wired connection */
    connection = nm_simple_connection_new();
    add_generic_settings(connection, NM_SETTING_WIRED_SETTING_NAME);
    setting = nm_setting_wired_new();
    nm_connection_add_setting(connection, setting);

    success = nm_connection_verify(connection, &error);
    g_assert_no_error(error);
    g_assert(success);
    g_object_unref(connection);

    /* Try a wired PPPoE connection */
    connection = nm_simple_connection_new();
    add_generic_settings(connection, NM_SETTING_PPPOE_SETTING_NAME);
    setting = nm_setting_pppoe_new();
    g_object_set(setting, NM_SETTING_PPPOE_USERNAME, "bob smith", NULL);
    nm_connection_add_setting(connection, setting);

    success = nm_connection_verify(connection, &error);
    g_assert_no_error(error);
    g_assert(success);
    g_object_unref(connection);

    /* Wifi connection */
    connection = nm_simple_connection_new();
    add_generic_settings(connection, NM_SETTING_WIRELESS_SETTING_NAME);

    setting = nm_setting_wireless_new();
    ssid    = g_bytes_new("1234567", 7);
    g_object_set(setting,
                 NM_SETTING_WIRELESS_SSID,
                 ssid,
                 NM_SETTING_WIRELESS_MODE,
                 "infrastructure",
                 NULL);
    g_bytes_unref(ssid);
    nm_connection_add_setting(connection, setting);

    success = nm_connection_verify(connection, &error);
    g_assert_no_error(error);
    g_assert(success);
    g_object_unref(connection);

    /* Bluetooth connection */
    connection = nm_simple_connection_new();
    add_generic_settings(connection, NM_SETTING_BLUETOOTH_SETTING_NAME);

    setting = nm_setting_bluetooth_new();
    g_object_set(setting,
                 NM_SETTING_BLUETOOTH_BDADDR,
                 bdaddr,
                 NM_SETTING_CONNECTION_TYPE,
                 NM_SETTING_BLUETOOTH_TYPE_PANU,
                 NULL);
    nm_connection_add_setting(connection, setting);

    success = nm_connection_verify(connection, &error);
    g_assert_no_error(error);
    g_assert(success);
    g_object_unref(connection);

    /* WiMAX connection */
    connection = nm_simple_connection_new();
    add_generic_settings(connection, NM_SETTING_WIMAX_SETTING_NAME);
    setting = nm_setting_wimax_new();
    g_object_set(setting, NM_SETTING_WIMAX_NETWORK_NAME, "CLEAR", NULL);
    nm_connection_add_setting(connection, setting);

    success = nm_connection_verify(connection, &error);
    g_assert_no_error(error);
    g_assert(success);
    g_object_unref(connection);

    /* GSM connection */
    connection = nm_simple_connection_new();
    add_generic_settings(connection, NM_SETTING_GSM_SETTING_NAME);

    setting = nm_setting_gsm_new();
    g_object_set(setting, NM_SETTING_GSM_APN, "metered.billing.sucks", NULL);
    nm_connection_add_setting(connection, setting);

    /* CDMA connection */
    connection = nm_simple_connection_new();
    add_generic_settings(connection, NM_SETTING_CDMA_SETTING_NAME);

    setting = nm_setting_cdma_new();
    g_object_set(setting,
                 NM_SETTING_CDMA_NUMBER,
                 "#777",
                 NM_SETTING_CDMA_USERNAME,
                 "foobar@vzw.com",
                 NULL);
    nm_connection_add_setting(connection, setting);

    success = nm_connection_verify(connection, &error);
    g_assert_no_error(error);
    g_assert(success);
    g_object_unref(connection);
}

static void
test_connection_bad_base_types(void)
{
    NMConnection *connection;
    NMSetting *   setting;
    gboolean      success;
    GError *      error = NULL;

    /* Test various non-base connection types to make sure they are rejected;
     * using a fake 'wired' connection so the rest of it verifies
     */

    /* Connection setting */
    connection = nm_simple_connection_new();
    add_generic_settings(connection, NM_SETTING_CONNECTION_SETTING_NAME);
    setting = nm_setting_wired_new();
    nm_connection_add_setting(connection, setting);

    success = nm_connection_verify(connection, &error);
    g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
    g_assert(g_str_has_prefix(error->message, "connection.type: "));
    g_assert(success == FALSE);
    g_object_unref(connection);
    g_clear_error(&error);

    /* PPP setting */
    connection = nm_simple_connection_new();
    add_generic_settings(connection, NM_SETTING_PPP_SETTING_NAME);
    setting = nm_setting_wired_new();
    nm_connection_add_setting(connection, setting);
    setting = nm_setting_ppp_new();
    nm_connection_add_setting(connection, setting);

    success = nm_connection_verify(connection, &error);
    g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
    g_assert(g_str_has_prefix(error->message, "connection.type: "));
    g_assert(success == FALSE);
    g_object_unref(connection);
    g_clear_error(&error);

    /* Serial setting */
    connection = nm_simple_connection_new();
    add_generic_settings(connection, NM_SETTING_SERIAL_SETTING_NAME);
    setting = nm_setting_wired_new();
    nm_connection_add_setting(connection, setting);
    setting = nm_setting_serial_new();
    nm_connection_add_setting(connection, setting);

    success = nm_connection_verify(connection, &error);
    g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
    g_assert(g_str_has_prefix(error->message, "connection.type: "));
    g_assert(success == FALSE);
    g_object_unref(connection);
    g_clear_error(&error);

    /* IP4 setting */
    connection = nm_simple_connection_new();
    add_generic_settings(connection, NM_SETTING_IP4_CONFIG_SETTING_NAME);
    setting = nm_setting_wired_new();
    nm_connection_add_setting(connection, setting);

    success = nm_connection_verify(connection, &error);
    g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
    g_assert(g_str_has_prefix(error->message, "connection.type: "));
    g_assert(success == FALSE);
    g_object_unref(connection);
    g_clear_error(&error);

    /* IP6 setting */
    connection = nm_simple_connection_new();
    add_generic_settings(connection, NM_SETTING_IP6_CONFIG_SETTING_NAME);
    setting = nm_setting_wired_new();
    nm_connection_add_setting(connection, setting);

    success = nm_connection_verify(connection, &error);
    g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
    g_assert(g_str_has_prefix(error->message, "connection.type: "));
    g_assert(success == FALSE);
    g_object_unref(connection);
    g_clear_error(&error);
}

static void
test_setting_compare_id(void)
{
    gs_unref_object NMSetting *old = NULL, *new = NULL;
    gboolean                   success;

    old = nm_setting_connection_new();
    g_object_set(old,
                 NM_SETTING_CONNECTION_ID,
                 "really awesome cool connection",
                 NM_SETTING_CONNECTION_UUID,
                 "fbbd59d5-acab-4e30-8f86-258d272617e7",
                 NM_SETTING_CONNECTION_AUTOCONNECT,
                 FALSE,
                 NULL);

    new = nm_setting_duplicate(old);
    g_object_set(new, NM_SETTING_CONNECTION_ID, "some different connection id", NULL);

    /* First make sure they are different */
    success = nm_setting_compare(old, new, NM_SETTING_COMPARE_FLAG_EXACT);
    g_assert(success == FALSE);

    success = nm_setting_compare(old, new, NM_SETTING_COMPARE_FLAG_IGNORE_ID);
    g_assert(success);
}

static void
test_setting_compare_addresses(void)
{
    gs_unref_object NMSetting *s1 = NULL, *s2 = NULL;
    gboolean                   success;
    NMIPAddress *              a;
    GHashTable *               result = NULL;

    s1 = nm_setting_ip4_config_new();
    s2 = nm_setting_ip4_config_new();

    a = nm_ip_address_new(AF_INET, "192.168.7.5", 24, NULL);

    nm_ip_address_set_attribute(a, NM_IP_ADDRESS_ATTRIBUTE_LABEL, g_variant_new_string("xoxoxo"));
    nm_setting_ip_config_add_address((NMSettingIPConfig *) s1, a);

    nm_ip_address_set_attribute(a, NM_IP_ADDRESS_ATTRIBUTE_LABEL, g_variant_new_string("hello"));
    nm_setting_ip_config_add_address((NMSettingIPConfig *) s2, a);

    nm_ip_address_unref(a);

    if (nmtst_get_rand_uint32() % 2)
        NM_SWAP(&s1, &s2);

    success = nm_setting_compare(s1, s2, NM_SETTING_COMPARE_FLAG_EXACT);
    g_assert(!success);

    success = nm_setting_diff(s1, s2, NM_SETTING_COMPARE_FLAG_EXACT, FALSE, &result);
    g_assert(!success);
    nm_clear_pointer(&result, g_hash_table_unref);
}

static void
test_setting_compare_routes(void)
{
    gs_unref_object NMSetting *s1 = NULL, *s2 = NULL;
    gboolean                   success;
    NMIPRoute *                r;
    GHashTable *               result = NULL;

    s1 = nm_setting_ip4_config_new();
    s2 = nm_setting_ip4_config_new();

    r = nm_ip_route_new(AF_INET, "192.168.12.0", 24, "192.168.11.1", 473, NULL);

    nm_ip_route_set_attribute(r, NM_IP_ADDRESS_ATTRIBUTE_LABEL, g_variant_new_string("xoxoxo"));
    nm_setting_ip_config_add_route((NMSettingIPConfig *) s1, r);

    nm_ip_route_set_attribute(r, NM_IP_ADDRESS_ATTRIBUTE_LABEL, g_variant_new_string("hello"));
    nm_setting_ip_config_add_route((NMSettingIPConfig *) s2, r);

    nm_ip_route_unref(r);

    if (nmtst_get_rand_uint32() % 2)
        NM_SWAP(&s1, &s2);

    success = nm_setting_compare(s1, s2, NM_SETTING_COMPARE_FLAG_EXACT);
    g_assert(!success);

    success = nm_setting_diff(s1, s2, NM_SETTING_COMPARE_FLAG_EXACT, FALSE, &result);
    g_assert(!success);
    nm_clear_pointer(&result, g_hash_table_unref);
}

static void
test_setting_compare_wired_cloned_mac_address(void)
{
    gs_unref_object NMSetting *old = NULL, *new = NULL;
    gboolean                   success;
    gs_free char *             str1 = NULL;

    old = nm_setting_wired_new();
    g_object_set(old, NM_SETTING_WIRED_CLONED_MAC_ADDRESS, "stable", NULL);

    g_assert_cmpstr("stable", ==, nm_setting_wired_get_cloned_mac_address((NMSettingWired *) old));
    g_object_get(old, NM_SETTING_WIRED_CLONED_MAC_ADDRESS, &str1, NULL);
    g_assert_cmpstr("stable", ==, str1);
    nm_clear_g_free(&str1);

    new = nm_setting_duplicate(old);
    g_object_set(new, NM_SETTING_WIRED_CLONED_MAC_ADDRESS, "11:22:33:44:55:66", NULL);

    g_assert_cmpstr("11:22:33:44:55:66",
                    ==,
                    nm_setting_wired_get_cloned_mac_address((NMSettingWired *) new));
    g_object_get(new, NM_SETTING_WIRED_CLONED_MAC_ADDRESS, &str1, NULL);
    g_assert_cmpstr("11:22:33:44:55:66", ==, str1);
    nm_clear_g_free(&str1);

    success = nm_setting_compare(old, new, NM_SETTING_COMPARE_FLAG_EXACT);
    g_assert(!success);
    g_clear_object(&new);

    new = nm_setting_duplicate(old);
    g_object_set(new, NM_SETTING_WIRED_CLONED_MAC_ADDRESS, "stable-bia", NULL);

    g_assert_cmpstr("stable-bia",
                    ==,
                    nm_setting_wired_get_cloned_mac_address((NMSettingWired *) new));
    g_object_get(new, NM_SETTING_WIRED_CLONED_MAC_ADDRESS, &str1, NULL);
    g_assert_cmpstr("stable-bia", ==, str1);
    nm_clear_g_free(&str1);

    success = nm_setting_compare(old, new, NM_SETTING_COMPARE_FLAG_EXACT);
    g_assert(!success);
    g_clear_object(&new);
}

static void
test_setting_compare_wireless_cloned_mac_address(void)
{
    gs_unref_object NMSetting *old = NULL, *new = NULL;
    gboolean                   success;
    gs_free char *             str1 = NULL;

    old = nm_setting_wireless_new();
    g_object_set(old, NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS, "stable", NULL);

    g_assert_cmpstr("stable",
                    ==,
                    nm_setting_wireless_get_cloned_mac_address((NMSettingWireless *) old));
    g_object_get(old, NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS, &str1, NULL);
    g_assert_cmpstr("stable", ==, str1);
    nm_clear_g_free(&str1);

    new = nm_setting_duplicate(old);
    g_object_set(new, NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS, "11:22:33:44:55:66", NULL);

    g_assert_cmpstr("11:22:33:44:55:66",
                    ==,
                    nm_setting_wireless_get_cloned_mac_address((NMSettingWireless *) new));
    g_object_get(new, NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS, &str1, NULL);
    g_assert_cmpstr("11:22:33:44:55:66", ==, str1);
    nm_clear_g_free(&str1);

    success = nm_setting_compare(old, new, NM_SETTING_COMPARE_FLAG_EXACT);
    g_assert(!success);
    g_clear_object(&new);

    new = nm_setting_duplicate(old);
    g_object_set(new, NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS, "stable-bia", NULL);

    g_assert_cmpstr("stable-bia",
                    ==,
                    nm_setting_wireless_get_cloned_mac_address((NMSettingWireless *) new));
    g_object_get(new, NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS, &str1, NULL);
    g_assert_cmpstr("stable-bia", ==, str1);
    nm_clear_g_free(&str1);

    success = nm_setting_compare(old, new, NM_SETTING_COMPARE_FLAG_EXACT);
    g_assert(!success);
    g_clear_object(&new);
}

static void
test_setting_compare_timestamp(void)
{
    gs_unref_object NMSetting *old = NULL, *new = NULL;
    gboolean                   success;

    old = nm_setting_connection_new();
    g_object_set(old,
                 NM_SETTING_CONNECTION_ID,
                 "ignore timestamp connection",
                 NM_SETTING_CONNECTION_UUID,
                 "b047a198-0e0a-4f0e-a653-eea09bb35e40",
                 NM_SETTING_CONNECTION_AUTOCONNECT,
                 FALSE,
                 NM_SETTING_CONNECTION_TIMESTAMP,
                 (guint64) 1234567890,
                 NULL);

    new = nm_setting_duplicate(old);
    g_object_set(new, NM_SETTING_CONNECTION_TIMESTAMP, (guint64) 1416316539, NULL);

    /* First make sure they are different */
    success = nm_setting_compare(old, new, NM_SETTING_COMPARE_FLAG_EXACT);
    g_assert(success == FALSE);

    success = nm_setting_compare(old, new, NM_SETTING_COMPARE_FLAG_IGNORE_TIMESTAMP);
    g_assert(success);
}

typedef struct {
    NMSettingSecretFlags  secret_flags;
    NMSettingCompareFlags comp_flags;
    gboolean              remove_secret;
} TestDataCompareSecrets;

static TestDataCompareSecrets *
test_data_compare_secrets_new(NMSettingSecretFlags  secret_flags,
                              NMSettingCompareFlags comp_flags,
                              gboolean              remove_secret)
{
    TestDataCompareSecrets *data = g_new0(TestDataCompareSecrets, 1);

    data->secret_flags  = secret_flags;
    data->comp_flags    = comp_flags;
    data->remove_secret = remove_secret;
    return data;
}

static void
_test_compare_secrets_check_diff(NMSetting *           a,
                                 NMSetting *           b,
                                 NMSettingCompareFlags flags,
                                 gboolean              exp_same_psk,
                                 gboolean              exp_same_psk_flags)
{
    gs_unref_hashtable GHashTable *h            = NULL;
    NMSettingDiffResult            _RESULT_IN_A = NM_SETTING_DIFF_RESULT_IN_A;
    NMSettingDiffResult            _RESULT_IN_B = NM_SETTING_DIFF_RESULT_IN_B;
    gboolean                       invert_results;
    gboolean                       diff_result;
    NMSettingSecretFlags           a_psk_flags =
        nm_setting_wireless_security_get_psk_flags(NM_SETTING_WIRELESS_SECURITY(a));
    NMSettingSecretFlags b_psk_flags =
        nm_setting_wireless_security_get_psk_flags(NM_SETTING_WIRELESS_SECURITY(b));
    const char *a_psk = nm_setting_wireless_security_get_psk(NM_SETTING_WIRELESS_SECURITY(a));
    const char *b_psk = nm_setting_wireless_security_get_psk(NM_SETTING_WIRELESS_SECURITY(b));

    g_assert(NM_IS_SETTING_WIRELESS_SECURITY(a));
    g_assert(NM_IS_SETTING_WIRELESS_SECURITY(b));

    invert_results = nmtst_get_rand_bool();
    if (invert_results) {
        _RESULT_IN_A = NM_SETTING_DIFF_RESULT_IN_B;
        _RESULT_IN_B = NM_SETTING_DIFF_RESULT_IN_A;
    }

    diff_result = nm_setting_diff(a, b, flags, invert_results, &h);

    g_assert(exp_same_psk_flags == (a_psk_flags == b_psk_flags));

    if (nm_streq0(a_psk, b_psk))
        g_assert(exp_same_psk);
    else {
        if (flags == NM_SETTING_COMPARE_FLAG_EXACT)
            g_assert(!exp_same_psk);
        else if (flags == NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS) {
            if (!NM_FLAGS_HAS(a_psk_flags, NM_SETTING_SECRET_FLAG_AGENT_OWNED)
                && !NM_FLAGS_HAS(b_psk_flags, NM_SETTING_SECRET_FLAG_AGENT_OWNED))
                g_assert(!exp_same_psk);
            else if (!NM_FLAGS_HAS(a_psk_flags, NM_SETTING_SECRET_FLAG_AGENT_OWNED)
                     && NM_FLAGS_HAS(b_psk_flags, NM_SETTING_SECRET_FLAG_AGENT_OWNED))
                g_assert(!exp_same_psk);
            else
                g_assert(exp_same_psk);
        } else if (flags == NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS) {
            if (!NM_FLAGS_HAS(a_psk_flags, NM_SETTING_SECRET_FLAG_NOT_SAVED)
                && !NM_FLAGS_HAS(b_psk_flags, NM_SETTING_SECRET_FLAG_NOT_SAVED))
                g_assert(!exp_same_psk);
            else if (!NM_FLAGS_HAS(a_psk_flags, NM_SETTING_SECRET_FLAG_NOT_SAVED)
                     && NM_FLAGS_HAS(b_psk_flags, NM_SETTING_SECRET_FLAG_NOT_SAVED))
                g_assert(!exp_same_psk);
            else
                g_assert(exp_same_psk);
        } else if (flags == NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS)
            g_assert(exp_same_psk);
        else
            g_assert_not_reached();
    }

    g_assert(diff_result == (exp_same_psk && exp_same_psk_flags));
    g_assert(diff_result == (!h));

    if (!diff_result) {
        if (flags == NM_SETTING_COMPARE_FLAG_EXACT)
            g_assert(!exp_same_psk);
        else if (NM_IN_SET(flags,
                           NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS,
                           NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS)
                 && (a_psk_flags != b_psk_flags)
                 && nm_setting_wireless_security_get_psk_flags(NM_SETTING_WIRELESS_SECURITY(a))
                        == NM_SETTING_SECRET_FLAG_NONE)
            g_assert(!exp_same_psk);
        else
            g_assert(exp_same_psk);

        g_assert((!exp_same_psk) == g_hash_table_contains(h, NM_SETTING_WIRELESS_SECURITY_PSK));
        if (!exp_same_psk) {
            if (nm_setting_wireless_security_get_psk(NM_SETTING_WIRELESS_SECURITY(a)))
                g_assert_cmpint(
                    GPOINTER_TO_UINT(g_hash_table_lookup(h, NM_SETTING_WIRELESS_SECURITY_PSK)),
                    ==,
                    _RESULT_IN_A);
            else
                g_assert_cmpint(
                    GPOINTER_TO_UINT(g_hash_table_lookup(h, NM_SETTING_WIRELESS_SECURITY_PSK)),
                    ==,
                    _RESULT_IN_B);
        }

        g_assert((!exp_same_psk_flags)
                 == g_hash_table_contains(h, NM_SETTING_WIRELESS_SECURITY_PSK_FLAGS));
        if (!exp_same_psk_flags) {
            if (nm_setting_wireless_security_get_psk_flags(NM_SETTING_WIRELESS_SECURITY(a))
                != NM_SETTING_SECRET_FLAG_NONE)
                g_assert_cmpint(GPOINTER_TO_UINT(
                                    g_hash_table_lookup(h, NM_SETTING_WIRELESS_SECURITY_PSK_FLAGS)),
                                ==,
                                _RESULT_IN_A);
            else
                g_assert_cmpint(GPOINTER_TO_UINT(
                                    g_hash_table_lookup(h, NM_SETTING_WIRELESS_SECURITY_PSK_FLAGS)),
                                ==,
                                _RESULT_IN_B);
        }

        g_assert_cmpint(g_hash_table_size(h), ==, (!exp_same_psk) + (!exp_same_psk_flags));
    }

    g_assert(diff_result == nm_setting_compare(a, b, flags));
    g_assert(diff_result == nm_setting_compare(b, a, flags));
}

static void
test_setting_compare_secrets(gconstpointer test_data)
{
    const TestDataCompareSecrets *data        = test_data;
    gs_unref_object NMConnection *conn_old    = NULL;
    gs_unref_object NMConnection *conn_new    = NULL;
    gs_unref_object NMSetting *old            = NULL;
    gs_unref_object            NMSetting *new = NULL;

    /* Make sure that a connection with transient/unsaved secrets compares
     * successfully to the same connection without those secrets.
     */

    old = nm_setting_wireless_security_new();
    g_object_set(old,
                 NM_SETTING_WIRELESS_SECURITY_KEY_MGMT,
                 "wpa-psk",
                 NM_SETTING_WIRELESS_SECURITY_PSK,
                 "really cool psk",
                 NULL);
    nm_setting_set_secret_flags(old, NM_SETTING_WIRELESS_SECURITY_PSK, data->secret_flags, NULL);

    new = nm_setting_duplicate(old);
    if (data->remove_secret)
        g_object_set(new, NM_SETTING_WIRELESS_SECURITY_PSK, NULL, NULL);

    g_assert((!data->remove_secret) == nm_setting_compare(old, new, NM_SETTING_COMPARE_FLAG_EXACT));
    g_assert((!data->remove_secret) == nm_setting_compare(new, old, NM_SETTING_COMPARE_FLAG_EXACT));

    _test_compare_secrets_check_diff(old,
                                     new,
                                     NM_SETTING_COMPARE_FLAG_EXACT,
                                     !data->remove_secret,
                                     TRUE);
    _test_compare_secrets_check_diff(new,
                                     old,
                                     NM_SETTING_COMPARE_FLAG_EXACT,
                                     !data->remove_secret,
                                     TRUE);

    g_assert(nm_setting_compare(old, new, data->comp_flags));
    g_assert(nm_setting_compare(new, old, data->comp_flags));

    _test_compare_secrets_check_diff(old, new, data->comp_flags, TRUE, TRUE);
    _test_compare_secrets_check_diff(new, old, data->comp_flags, TRUE, TRUE);

    /* OK. Try again, but this time not only change the secret, also let the secret flags differ... */
    if (data->secret_flags != NM_SETTING_SECRET_FLAG_NONE) {
        nm_setting_set_secret_flags(new,
                                    NM_SETTING_WIRELESS_SECURITY_PSK,
                                    NM_SETTING_SECRET_FLAG_NONE,
                                    NULL);

        _test_compare_secrets_check_diff(old, new, NM_SETTING_COMPARE_FLAG_EXACT, FALSE, FALSE);
        _test_compare_secrets_check_diff(new, old, NM_SETTING_COMPARE_FLAG_EXACT, FALSE, FALSE);

        _test_compare_secrets_check_diff(old, new, data->comp_flags, TRUE, FALSE);
        _test_compare_secrets_check_diff(new, old, data->comp_flags, FALSE, FALSE);

        nm_setting_set_secret_flags(new,
                                    NM_SETTING_WIRELESS_SECURITY_PSK,
                                    data->secret_flags,
                                    NULL);
    }

    conn_old = nmtst_create_minimal_connection("test-compare-secrets",
                                               NULL,
                                               NM_SETTING_WIRELESS_SETTING_NAME,
                                               NULL);
    nm_connection_add_setting(conn_old, nm_setting_duplicate(old));
    conn_new = nm_simple_connection_new_clone(conn_old);
    nm_connection_add_setting(conn_new, nm_setting_duplicate(new));

    g_assert((!data->remove_secret)
             == nm_connection_compare(conn_old, conn_new, NM_SETTING_COMPARE_FLAG_EXACT));
    g_assert((!data->remove_secret)
             == nm_connection_compare(conn_new, conn_old, NM_SETTING_COMPARE_FLAG_EXACT));

    g_assert(nm_connection_compare(conn_old, conn_new, data->comp_flags));
    g_assert(nm_connection_compare(conn_new, conn_old, data->comp_flags));
}

static void
test_setting_compare_vpn_secrets(gconstpointer test_data)
{
    const TestDataCompareSecrets *data = test_data;
    gs_unref_object NMSetting *old = NULL, *new = NULL;
    gboolean                   success;

    /* Make sure that a connection with transient/unsaved secrets compares
     * successfully to the same connection without those secrets.
     */

    old = nm_setting_vpn_new();
    nm_setting_vpn_add_secret(NM_SETTING_VPN(old), "foobarbaz", "really secret password");
    nm_setting_vpn_add_secret(NM_SETTING_VPN(old), "asdfasdfasdf", "really adfasdfasdfasdf");
    nm_setting_vpn_add_secret(NM_SETTING_VPN(old), "0123456778", "abcdefghijklmnpqrstuvqxyz");
    nm_setting_vpn_add_secret(NM_SETTING_VPN(old),
                              "borkbork",
                              "yet another really secret password");
    nm_setting_set_secret_flags(old, "borkbork", data->secret_flags, NULL);

    /* Clear "borkbork" from the duplicated setting */
    new = nm_setting_duplicate(old);
    if (data->remove_secret) {
        nm_setting_vpn_remove_secret(NM_SETTING_VPN(new), "borkbork");

        /* First make sure they are different */
        success = nm_setting_compare(old, new, NM_SETTING_COMPARE_FLAG_EXACT);
        g_assert(success == FALSE);
    }

    success = nm_setting_compare(old, new, data->comp_flags);
    g_assert(success);
}

static void
test_hwaddr_aton_ether_normal(void)
{
    guint8 buf[100];
    guint8 expected[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};

    g_assert(nm_utils_hwaddr_aton("00:11:22:33:44:55", buf, ETH_ALEN) != NULL);
    g_assert(memcmp(buf, expected, sizeof(expected)) == 0);
}

static void
test_hwaddr_aton_ib_normal(void)
{
    guint8      buf[100];
    const char *source = "00:11:22:33:44:55:66:77:88:99:01:12:23:34:45:56:67:78:89:90";
    guint8 expected[INFINIBAND_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                                        0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90};

    g_assert(nm_utils_hwaddr_aton(source, buf, INFINIBAND_ALEN) != NULL);
    g_assert(memcmp(buf, expected, sizeof(expected)) == 0);
}

static void
test_hwaddr_aton_no_leading_zeros(void)
{
    guint8 buf[100];
    guint8 expected[ETH_ALEN] = {0x00, 0x1A, 0x2B, 0x03, 0x44, 0x05};

    g_assert(nm_utils_hwaddr_aton("0:1a:2B:3:44:5", buf, ETH_ALEN) != NULL);
    g_assert(memcmp(buf, expected, sizeof(expected)) == 0);
}

static void
test_hwaddr_aton_malformed(void)
{
    guint8 buf[100];

    g_assert(nm_utils_hwaddr_aton("0:1a:2B:3:a@%%", buf, ETH_ALEN) == NULL);
}

static void
test_hwaddr_equal(void)
{
    const char * string                 = "00:1a:2b:03:44:05";
    const char * upper_string           = "00:1A:2B:03:44:05";
    const char * bad_string             = "0:1a:2b:3:44:5";
    const guint8 binary[ETH_ALEN]       = {0x00, 0x1A, 0x2B, 0x03, 0x44, 0x05};
    const char * other_string           = "1a:2b:03:44:05:00";
    const guint8 other_binary[ETH_ALEN] = {0x1A, 0x2B, 0x03, 0x44, 0x05, 0x00};
    const char * long_string            = "00:1a:2b:03:44:05:06:07";
    const guint8 long_binary[8]         = {0x00, 0x1A, 0x2B, 0x03, 0x44, 0x05, 0x06, 0x07};
    const char * null_string            = "00:00:00:00:00:00";
    const guint8 null_binary[ETH_ALEN]  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    g_assert(nm_utils_hwaddr_matches(string, -1, string, -1));
    g_assert(nm_utils_hwaddr_matches(string, -1, upper_string, -1));
    g_assert(nm_utils_hwaddr_matches(string, -1, bad_string, -1));
    g_assert(nm_utils_hwaddr_matches(string, -1, binary, sizeof(binary)));
    g_assert(!nm_utils_hwaddr_matches(string, -1, other_string, -1));
    g_assert(!nm_utils_hwaddr_matches(string, -1, other_binary, sizeof(other_binary)));
    g_assert(!nm_utils_hwaddr_matches(string, -1, long_string, -1));
    g_assert(!nm_utils_hwaddr_matches(string, -1, long_binary, sizeof(long_binary)));
    g_assert(!nm_utils_hwaddr_matches(string, -1, null_string, -1));
    g_assert(!nm_utils_hwaddr_matches(string, -1, null_binary, sizeof(null_binary)));
    g_assert(!nm_utils_hwaddr_matches(string, -1, NULL, ETH_ALEN));

    g_assert(nm_utils_hwaddr_matches(binary, sizeof(binary), string, -1));
    g_assert(nm_utils_hwaddr_matches(binary, sizeof(binary), upper_string, -1));
    g_assert(nm_utils_hwaddr_matches(binary, sizeof(binary), bad_string, -1));
    g_assert(nm_utils_hwaddr_matches(binary, sizeof(binary), binary, sizeof(binary)));
    g_assert(!nm_utils_hwaddr_matches(binary, sizeof(binary), other_string, -1));
    g_assert(!nm_utils_hwaddr_matches(binary, sizeof(binary), other_binary, sizeof(other_binary)));
    g_assert(!nm_utils_hwaddr_matches(binary, sizeof(binary), long_string, -1));
    g_assert(!nm_utils_hwaddr_matches(binary, sizeof(binary), long_binary, sizeof(long_binary)));
    g_assert(!nm_utils_hwaddr_matches(binary, sizeof(binary), null_string, -1));
    g_assert(!nm_utils_hwaddr_matches(binary, sizeof(binary), null_binary, sizeof(null_binary)));
    g_assert(!nm_utils_hwaddr_matches(binary, sizeof(binary), NULL, ETH_ALEN));

    g_assert(!nm_utils_hwaddr_matches(null_string, -1, string, -1));
    g_assert(!nm_utils_hwaddr_matches(null_string, -1, upper_string, -1));
    g_assert(!nm_utils_hwaddr_matches(null_string, -1, bad_string, -1));
    g_assert(!nm_utils_hwaddr_matches(null_string, -1, binary, sizeof(binary)));
    g_assert(!nm_utils_hwaddr_matches(null_string, -1, other_string, -1));
    g_assert(!nm_utils_hwaddr_matches(null_string, -1, other_binary, sizeof(other_binary)));
    g_assert(!nm_utils_hwaddr_matches(null_string, -1, long_string, -1));
    g_assert(!nm_utils_hwaddr_matches(null_string, -1, long_binary, sizeof(long_binary)));
    g_assert(nm_utils_hwaddr_matches(null_string, -1, null_string, -1));
    g_assert(nm_utils_hwaddr_matches(null_string, -1, null_binary, sizeof(null_binary)));
    g_assert(nm_utils_hwaddr_matches(null_string, -1, NULL, ETH_ALEN));

    g_assert(!nm_utils_hwaddr_matches(null_binary, sizeof(null_binary), string, -1));
    g_assert(!nm_utils_hwaddr_matches(null_binary, sizeof(null_binary), upper_string, -1));
    g_assert(!nm_utils_hwaddr_matches(null_binary, sizeof(null_binary), bad_string, -1));
    g_assert(!nm_utils_hwaddr_matches(null_binary, sizeof(null_binary), binary, sizeof(binary)));
    g_assert(!nm_utils_hwaddr_matches(null_binary, sizeof(null_binary), other_string, -1));
    g_assert(!nm_utils_hwaddr_matches(null_binary,
                                      sizeof(null_binary),
                                      other_binary,
                                      sizeof(other_binary)));
    g_assert(!nm_utils_hwaddr_matches(null_binary, sizeof(null_binary), long_string, -1));
    g_assert(!nm_utils_hwaddr_matches(null_binary,
                                      sizeof(null_binary),
                                      long_binary,
                                      sizeof(long_binary)));
    g_assert(nm_utils_hwaddr_matches(null_binary, sizeof(null_binary), null_string, -1));
    g_assert(nm_utils_hwaddr_matches(null_binary,
                                     sizeof(null_binary),
                                     null_binary,
                                     sizeof(null_binary)));
    g_assert(nm_utils_hwaddr_matches(null_binary, sizeof(null_binary), NULL, ETH_ALEN));

    g_assert(!nm_utils_hwaddr_matches(NULL, -1, NULL, -1));
    g_assert(!nm_utils_hwaddr_matches(NULL, -1, string, -1));
    g_assert(!nm_utils_hwaddr_matches(string, -1, NULL, -1));
    g_assert(!nm_utils_hwaddr_matches(NULL, -1, null_string, -1));
    g_assert(!nm_utils_hwaddr_matches(null_string, -1, NULL, -1));
    g_assert(!nm_utils_hwaddr_matches(NULL, -1, binary, sizeof(binary)));
    g_assert(!nm_utils_hwaddr_matches(binary, sizeof(binary), NULL, -1));
    g_assert(!nm_utils_hwaddr_matches(NULL, -1, null_binary, sizeof(null_binary)));
    g_assert(!nm_utils_hwaddr_matches(null_binary, sizeof(null_binary), NULL, -1));
}

static void
test_hwaddr_canonical(void)
{
    const char *string         = "00:1A:2B:03:44:05";
    const char *lower_string   = "00:1a:2b:03:44:05";
    const char *short_string   = "0:1a:2b:3:44:5";
    const char *hyphen_string  = "00-1a-2b-03-44-05";
    const char *invalid_string = "00:1A:2B";
    char *      canonical;

    canonical = nm_utils_hwaddr_canonical(string, ETH_ALEN);
    g_assert_cmpstr(canonical, ==, string);
    g_free(canonical);

    canonical = nm_utils_hwaddr_canonical(lower_string, ETH_ALEN);
    g_assert_cmpstr(canonical, ==, string);
    g_free(canonical);

    canonical = nm_utils_hwaddr_canonical(short_string, ETH_ALEN);
    g_assert_cmpstr(canonical, ==, string);
    g_free(canonical);

    canonical = nm_utils_hwaddr_canonical(hyphen_string, ETH_ALEN);
    g_assert_cmpstr(canonical, ==, string);
    g_free(canonical);

    canonical = nm_utils_hwaddr_canonical(invalid_string, ETH_ALEN);
    g_assert_cmpstr(canonical, ==, NULL);

    canonical = nm_utils_hwaddr_canonical(invalid_string, -1);
    g_assert_cmpstr(canonical, ==, invalid_string);
    g_free(canonical);
}

static void
test_connection_changed_cb(NMConnection *connection, gboolean *data)
{
    *data = TRUE;
}

static guint32
_netmask_to_prefix(guint32 netmask)
{
    guint32       prefix;
    guint8        v;
    const guint8 *p = (guint8 *) &netmask;

    if (p[3]) {
        prefix = 24;
        v      = p[3];
    } else if (p[2]) {
        prefix = 16;
        v      = p[2];
    } else if (p[1]) {
        prefix = 8;
        v      = p[1];
    } else {
        prefix = 0;
        v      = p[0];
    }

    while (v) {
        prefix++;
        v <<= 1;
    }

    g_assert_cmpint(prefix, <=, 32);

    /* we re-implemented the netmask-to-prefix code differently. Check
     * that they agree. */
    g_assert_cmpint(prefix, ==, nm_utils_ip4_netmask_to_prefix(netmask));

    return prefix;
}

static void
test_ip4_prefix_to_netmask(void)
{
    int i;

    for (i = 0; i <= 32; i++) {
        guint32 netmask = _nm_utils_ip4_prefix_to_netmask(i);
        int     plen    = _netmask_to_prefix(netmask);

        g_assert_cmpint(i, ==, plen);
        {
            guint32 msk      = 0x80000000;
            guint32 netmask2 = 0;
            guint32 prefix   = i;
            while (prefix > 0) {
                netmask2 |= msk;
                msk >>= 1;
                prefix--;
            }
            g_assert_cmpint(netmask, ==, (guint32) htonl(netmask2));
        }
    }
}

static void
test_ip4_netmask_to_prefix(void)
{
    int i, j;

    GRand *rand = g_rand_new();

    g_rand_set_seed(rand, 1);

    for (i = 2; i <= 32; i++) {
        guint32 netmask            = _nm_utils_ip4_prefix_to_netmask(i);
        guint32 netmask_lowest_bit = netmask & ~_nm_utils_ip4_prefix_to_netmask(i - 1);

        g_assert_cmpint(i, ==, _netmask_to_prefix(netmask));

        for (j = 0; j < 2 * i; j++) {
            guint32 r = g_rand_int(rand);
            guint32 netmask_holey;
            guint32 prefix_holey;

            netmask_holey = (netmask & r) | netmask_lowest_bit;

            if (netmask_holey == netmask)
                continue;

            /* create an invalid netmask with holes and check that the function
             * returns the longest prefix. */
            prefix_holey = _netmask_to_prefix(netmask_holey);

            g_assert_cmpint(i, ==, prefix_holey);
        }
    }

    g_rand_free(rand);
}

#define ASSERT_CHANGED(statement) \
    G_STMT_START                  \
    {                             \
        changed = FALSE;          \
        statement;                \
        g_assert(changed);        \
    }                             \
    G_STMT_END

#define ASSERT_UNCHANGED(statement) \
    G_STMT_START                    \
    {                               \
        changed = FALSE;            \
        statement;                  \
        g_assert(!changed);         \
    }                               \
    G_STMT_END

static void
test_connection_changed_signal(void)
{
    NMConnection *connection;
    gboolean      changed = FALSE;

    connection = new_test_connection();
    g_signal_connect(connection,
                     NM_CONNECTION_CHANGED,
                     (GCallback) test_connection_changed_cb,
                     &changed);

    /* Add new setting */
    ASSERT_CHANGED(nm_connection_add_setting(connection, nm_setting_vlan_new()));

    /* Remove existing setting */
    ASSERT_CHANGED(nm_connection_remove_setting(connection, NM_TYPE_SETTING_VLAN));

    /* Remove non-existing setting */
    ASSERT_UNCHANGED(nm_connection_remove_setting(connection, NM_TYPE_SETTING_VLAN));

    g_object_unref(connection);
}

static void
test_setting_connection_changed_signal(void)
{
    NMConnection *       connection;
    gboolean             changed = FALSE;
    NMSettingConnection *s_con;
    gs_free char *       uuid = NULL;

    connection = nm_simple_connection_new();
    g_signal_connect(connection,
                     NM_CONNECTION_CHANGED,
                     (GCallback) test_connection_changed_cb,
                     &changed);

    s_con = (NMSettingConnection *) nm_setting_connection_new();
    nm_connection_add_setting(connection, NM_SETTING(s_con));

    ASSERT_CHANGED(g_object_set(s_con, NM_SETTING_CONNECTION_ID, "adfadfasdfaf", NULL));

    ASSERT_CHANGED(nm_setting_connection_add_permission(s_con, "user", "billsmith", NULL));
    ASSERT_CHANGED(nm_setting_connection_remove_permission(s_con, 0));

    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(idx < nm_g_array_len(priv->permissions)));
    ASSERT_UNCHANGED(nm_setting_connection_remove_permission(s_con, 1));
    g_test_assert_expected_messages();

    uuid = nm_utils_uuid_generate();
    ASSERT_CHANGED(nm_setting_connection_add_secondary(s_con, uuid));
    ASSERT_CHANGED(nm_setting_connection_remove_secondary(s_con, 0));

    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(idx < nm_g_array_len(priv->secondaries)));
    ASSERT_UNCHANGED(nm_setting_connection_remove_secondary(s_con, 1));
    g_test_assert_expected_messages();

    g_object_unref(connection);
}

static void
test_setting_bond_changed_signal(void)
{
    NMConnection * connection;
    gboolean       changed = FALSE;
    NMSettingBond *s_bond;

    connection = nm_simple_connection_new();
    g_signal_connect(connection,
                     NM_CONNECTION_CHANGED,
                     (GCallback) test_connection_changed_cb,
                     &changed);

    s_bond = (NMSettingBond *) nm_setting_bond_new();
    nm_connection_add_setting(connection, NM_SETTING(s_bond));

    ASSERT_CHANGED(nm_setting_bond_add_option(s_bond, NM_SETTING_BOND_OPTION_DOWNDELAY, "10"));
    ASSERT_CHANGED(nm_setting_bond_remove_option(s_bond, NM_SETTING_BOND_OPTION_DOWNDELAY));
    ASSERT_UNCHANGED(nm_setting_bond_remove_option(s_bond, NM_SETTING_BOND_OPTION_UPDELAY));

    g_object_unref(connection);
}

static void
test_setting_ip4_changed_signal(void)
{
    NMConnection *     connection;
    gboolean           changed = FALSE;
    NMSettingIPConfig *s_ip4;
    NMIPAddress *      addr;
    NMIPRoute *        route;
    GError *           error = NULL;

    connection = nm_simple_connection_new();
    g_signal_connect(connection,
                     NM_CONNECTION_CHANGED,
                     (GCallback) test_connection_changed_cb,
                     &changed);

    s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new();
    nm_connection_add_setting(connection, NM_SETTING(s_ip4));

    ASSERT_CHANGED(nm_setting_ip_config_add_dns(s_ip4, "11.22.0.0"));
    ASSERT_CHANGED(nm_setting_ip_config_remove_dns(s_ip4, 0));

    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(idx >= 0 && idx < priv->dns->len));
    ASSERT_UNCHANGED(nm_setting_ip_config_remove_dns(s_ip4, 1));
    g_test_assert_expected_messages();

    nm_setting_ip_config_add_dns(s_ip4, "33.44.0.0");
    ASSERT_CHANGED(nm_setting_ip_config_clear_dns(s_ip4));

    ASSERT_CHANGED(nm_setting_ip_config_add_dns_search(s_ip4, "foobar.com"));
    ASSERT_CHANGED(nm_setting_ip_config_remove_dns_search(s_ip4, 0));

    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(idx >= 0 && idx < priv->dns_search->len));
    ASSERT_UNCHANGED(nm_setting_ip_config_remove_dns_search(s_ip4, 1));
    g_test_assert_expected_messages();

    ASSERT_CHANGED(nm_setting_ip_config_add_dns_search(s_ip4, "foobar.com"));
    ASSERT_CHANGED(nm_setting_ip_config_clear_dns_searches(s_ip4));

    addr = nm_ip_address_new(AF_INET, "22.33.0.0", 24, &error);
    g_assert_no_error(error);
    ASSERT_CHANGED(nm_setting_ip_config_add_address(s_ip4, addr));
    ASSERT_CHANGED(nm_setting_ip_config_remove_address(s_ip4, 0));

    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(idx >= 0 && idx < priv->addresses->len));
    ASSERT_UNCHANGED(nm_setting_ip_config_remove_address(s_ip4, 1));
    g_test_assert_expected_messages();

    nm_setting_ip_config_add_address(s_ip4, addr);
    ASSERT_CHANGED(nm_setting_ip_config_clear_addresses(s_ip4));

    route = nm_ip_route_new(AF_INET, "22.33.0.0", 24, NULL, 0, &error);
    g_assert_no_error(error);

    ASSERT_CHANGED(nm_setting_ip_config_add_route(s_ip4, route));
    ASSERT_CHANGED(nm_setting_ip_config_remove_route(s_ip4, 0));

    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(idx >= 0 && idx < priv->routes->len));
    ASSERT_UNCHANGED(nm_setting_ip_config_remove_route(s_ip4, 1));
    g_test_assert_expected_messages();

    nm_setting_ip_config_add_route(s_ip4, route);
    ASSERT_CHANGED(nm_setting_ip_config_clear_routes(s_ip4));

    ASSERT_CHANGED(nm_setting_ip_config_add_dns_option(s_ip4, "debug"));
    ASSERT_CHANGED(nm_setting_ip_config_remove_dns_option(s_ip4, 0));

    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(idx >= 0 && idx < priv->dns_options->len));
    ASSERT_UNCHANGED(nm_setting_ip_config_remove_dns_option(s_ip4, 1));
    g_test_assert_expected_messages();

    nm_ip_address_unref(addr);
    nm_ip_route_unref(route);
    g_object_unref(connection);
}

static void
test_setting_ip6_changed_signal(void)
{
    NMConnection *     connection;
    gboolean           changed = FALSE;
    NMSettingIPConfig *s_ip6;
    NMIPAddress *      addr;
    NMIPRoute *        route;
    GError *           error = NULL;

    connection = nm_simple_connection_new();
    g_signal_connect(connection,
                     NM_CONNECTION_CHANGED,
                     (GCallback) test_connection_changed_cb,
                     &changed);

    s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new();
    nm_connection_add_setting(connection, NM_SETTING(s_ip6));

    ASSERT_CHANGED(nm_setting_ip_config_add_dns(s_ip6, "1:2:3::4:5:6"));
    ASSERT_CHANGED(nm_setting_ip_config_remove_dns(s_ip6, 0));

    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(idx >= 0 && idx < priv->dns->len));
    ASSERT_UNCHANGED(nm_setting_ip_config_remove_dns(s_ip6, 1));
    g_test_assert_expected_messages();

    nm_setting_ip_config_add_dns(s_ip6, "1:2:3::4:5:6");
    ASSERT_CHANGED(nm_setting_ip_config_clear_dns(s_ip6));

    ASSERT_CHANGED(nm_setting_ip_config_add_dns_search(s_ip6, "foobar.com"));
    ASSERT_CHANGED(nm_setting_ip_config_remove_dns_search(s_ip6, 0));

    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(idx >= 0 && idx < priv->dns_search->len));
    ASSERT_UNCHANGED(nm_setting_ip_config_remove_dns_search(s_ip6, 1));
    g_test_assert_expected_messages();

    nm_setting_ip_config_add_dns_search(s_ip6, "foobar.com");
    ASSERT_CHANGED(nm_setting_ip_config_clear_dns_searches(s_ip6));

    addr = nm_ip_address_new(AF_INET6, "1:2:3::4:5:6", 64, &error);
    g_assert_no_error(error);

    ASSERT_CHANGED(nm_setting_ip_config_add_address(s_ip6, addr));
    ASSERT_CHANGED(nm_setting_ip_config_remove_address(s_ip6, 0));

    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(idx >= 0 && idx < priv->addresses->len));
    ASSERT_UNCHANGED(nm_setting_ip_config_remove_address(s_ip6, 1));
    g_test_assert_expected_messages();

    nm_setting_ip_config_add_address(s_ip6, addr);
    ASSERT_CHANGED(nm_setting_ip_config_clear_addresses(s_ip6));

    route = nm_ip_route_new(AF_INET6, "1:2:3::4:5:6", 128, NULL, 0, &error);
    g_assert_no_error(error);

    ASSERT_CHANGED(nm_setting_ip_config_add_route(s_ip6, route));
    ASSERT_CHANGED(nm_setting_ip_config_remove_route(s_ip6, 0));

    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(idx >= 0 && idx < priv->routes->len));
    ASSERT_UNCHANGED(nm_setting_ip_config_remove_route(s_ip6, 1));
    g_test_assert_expected_messages();

    nm_setting_ip_config_add_route(s_ip6, route);
    ASSERT_CHANGED(nm_setting_ip_config_clear_routes(s_ip6));

    nm_ip_address_unref(addr);
    nm_ip_route_unref(route);
    g_object_unref(connection);
}

static void
test_setting_vlan_changed_signal(void)
{
    NMConnection * connection;
    gboolean       changed = FALSE;
    NMSettingVlan *s_vlan;

    connection = nm_simple_connection_new();
    g_signal_connect(connection,
                     NM_CONNECTION_CHANGED,
                     (GCallback) test_connection_changed_cb,
                     &changed);

    s_vlan = (NMSettingVlan *) nm_setting_vlan_new();
    nm_connection_add_setting(connection, NM_SETTING(s_vlan));

    ASSERT_CHANGED(nm_setting_vlan_add_priority(s_vlan, NM_VLAN_INGRESS_MAP, 1, 3));
    ASSERT_CHANGED(nm_setting_vlan_remove_priority(s_vlan, NM_VLAN_INGRESS_MAP, 0));
    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(idx < g_slist_length(list)));
    ASSERT_UNCHANGED(nm_setting_vlan_remove_priority(s_vlan, NM_VLAN_INGRESS_MAP, 1));
    g_test_assert_expected_messages();
    ASSERT_CHANGED(nm_setting_vlan_add_priority_str(s_vlan, NM_VLAN_INGRESS_MAP, "1:3"));
    ASSERT_CHANGED(nm_setting_vlan_clear_priorities(s_vlan, NM_VLAN_INGRESS_MAP));

    ASSERT_CHANGED(nm_setting_vlan_add_priority(s_vlan, NM_VLAN_EGRESS_MAP, 1, 3));
    ASSERT_CHANGED(nm_setting_vlan_remove_priority(s_vlan, NM_VLAN_EGRESS_MAP, 0));
    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(idx < g_slist_length(list)));
    ASSERT_UNCHANGED(nm_setting_vlan_remove_priority(s_vlan, NM_VLAN_EGRESS_MAP, 1));
    g_test_assert_expected_messages();
    ASSERT_CHANGED(nm_setting_vlan_add_priority_str(s_vlan, NM_VLAN_EGRESS_MAP, "1:3"));
    ASSERT_CHANGED(nm_setting_vlan_clear_priorities(s_vlan, NM_VLAN_EGRESS_MAP));

    g_object_unref(connection);
}

static void
test_setting_vpn_changed_signal(void)
{
    NMConnection *connection;
    gboolean      changed = FALSE;
    NMSettingVpn *s_vpn;

    connection = nm_simple_connection_new();
    g_signal_connect(connection,
                     NM_CONNECTION_CHANGED,
                     (GCallback) test_connection_changed_cb,
                     &changed);

    s_vpn = (NMSettingVpn *) nm_setting_vpn_new();
    nm_connection_add_setting(connection, NM_SETTING(s_vpn));

    ASSERT_CHANGED(nm_setting_vpn_add_data_item(s_vpn, "foobar", "baz"));
    ASSERT_CHANGED(nm_setting_vpn_remove_data_item(s_vpn, "foobar"));
    ASSERT_UNCHANGED(nm_setting_vpn_remove_data_item(s_vpn, "not added"));

    ASSERT_CHANGED(nm_setting_vpn_add_secret(s_vpn, "foobar", "baz"));
    ASSERT_CHANGED(nm_setting_vpn_remove_secret(s_vpn, "foobar"));
    ASSERT_UNCHANGED(nm_setting_vpn_remove_secret(s_vpn, "not added"));

    g_object_unref(connection);
}

static void
test_setting_wired_changed_signal(void)
{
    NMConnection *  connection;
    gboolean        changed = FALSE;
    NMSettingWired *s_wired;

    connection = nm_simple_connection_new();
    g_signal_connect(connection,
                     NM_CONNECTION_CHANGED,
                     (GCallback) test_connection_changed_cb,
                     &changed);

    s_wired = (NMSettingWired *) nm_setting_wired_new();
    nm_connection_add_setting(connection, NM_SETTING(s_wired));

    ASSERT_CHANGED(nm_setting_wired_add_s390_option(s_wired, "portno", "1"));
    ASSERT_CHANGED(nm_setting_wired_remove_s390_option(s_wired, "portno"));
    ASSERT_UNCHANGED(nm_setting_wired_remove_s390_option(s_wired, "layer2"));

    g_object_unref(connection);
}

static void
test_setting_wireless_changed_signal(void)
{
    NMConnection *     connection;
    gboolean           changed = FALSE;
    NMSettingWireless *s_wifi;

    connection = nm_simple_connection_new();
    g_signal_connect(connection,
                     NM_CONNECTION_CHANGED,
                     (GCallback) test_connection_changed_cb,
                     &changed);

    s_wifi = (NMSettingWireless *) nm_setting_wireless_new();
    nm_connection_add_setting(connection, NM_SETTING(s_wifi));

    ASSERT_CHANGED(nm_setting_wireless_add_seen_bssid(s_wifi, "00:11:22:33:44:55"));

    g_object_unref(connection);
}

static void
test_setting_wireless_security_changed_signal(void)
{
    NMConnection *             connection;
    gboolean                   changed = FALSE;
    NMSettingWirelessSecurity *s_wsec;

    connection = nm_simple_connection_new();
    g_signal_connect(connection,
                     NM_CONNECTION_CHANGED,
                     (GCallback) test_connection_changed_cb,
                     &changed);

    s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new();
    nm_connection_add_setting(connection, NM_SETTING(s_wsec));

    /* Protos */
    ASSERT_CHANGED(nm_setting_wireless_security_add_proto(s_wsec, "wpa"));
    ASSERT_CHANGED(nm_setting_wireless_security_remove_proto(s_wsec, 0));
    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(elt != NULL));
    ASSERT_UNCHANGED(nm_setting_wireless_security_remove_proto(s_wsec, 1));
    g_test_assert_expected_messages();

    nm_setting_wireless_security_add_proto(s_wsec, "wep");
    ASSERT_CHANGED(nm_setting_wireless_security_clear_protos(s_wsec));

    /* Pairwise ciphers */
    ASSERT_CHANGED(nm_setting_wireless_security_add_pairwise(s_wsec, "tkip"));
    ASSERT_CHANGED(nm_setting_wireless_security_remove_pairwise(s_wsec, 0));
    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(elt != NULL));
    ASSERT_UNCHANGED(nm_setting_wireless_security_remove_pairwise(s_wsec, 1));
    g_test_assert_expected_messages();

    nm_setting_wireless_security_add_pairwise(s_wsec, "tkip");
    ASSERT_CHANGED(nm_setting_wireless_security_clear_pairwise(s_wsec));

    /* Group ciphers */
    ASSERT_CHANGED(nm_setting_wireless_security_add_group(s_wsec, "ccmp"));
    ASSERT_CHANGED(nm_setting_wireless_security_remove_group(s_wsec, 0));
    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(elt != NULL));
    ASSERT_UNCHANGED(nm_setting_wireless_security_remove_group(s_wsec, 1));
    g_test_assert_expected_messages();

    nm_setting_wireless_security_add_group(s_wsec, "tkip");
    ASSERT_CHANGED(nm_setting_wireless_security_clear_groups(s_wsec));

    /* WEP key secret flags */
    ASSERT_CHANGED(g_assert(nm_setting_set_secret_flags(NM_SETTING(s_wsec),
                                                        "wep-key0",
                                                        NM_SETTING_SECRET_FLAG_AGENT_OWNED,
                                                        NULL)));
    ASSERT_CHANGED(g_assert(nm_setting_set_secret_flags(NM_SETTING(s_wsec),
                                                        "wep-key1",
                                                        NM_SETTING_SECRET_FLAG_AGENT_OWNED,
                                                        NULL)));
    ASSERT_CHANGED(g_assert(nm_setting_set_secret_flags(NM_SETTING(s_wsec),
                                                        "wep-key2",
                                                        NM_SETTING_SECRET_FLAG_AGENT_OWNED,
                                                        NULL)));
    ASSERT_CHANGED(g_assert(nm_setting_set_secret_flags(NM_SETTING(s_wsec),
                                                        "wep-key3",
                                                        NM_SETTING_SECRET_FLAG_AGENT_OWNED,
                                                        NULL)));

    g_object_unref(connection);
}

static void
test_setting_802_1x_changed_signal(void)
{
    NMConnection *  connection;
    gboolean        changed = FALSE;
    NMSetting8021x *s_8021x;

    connection = nm_simple_connection_new();
    g_signal_connect(connection,
                     NM_CONNECTION_CHANGED,
                     (GCallback) test_connection_changed_cb,
                     &changed);

    s_8021x = (NMSetting8021x *) nm_setting_802_1x_new();
    nm_connection_add_setting(connection, NM_SETTING(s_8021x));

    /* EAP methods */
    ASSERT_CHANGED(nm_setting_802_1x_add_eap_method(s_8021x, "tls"));
    ASSERT_CHANGED(nm_setting_802_1x_remove_eap_method(s_8021x, 0));
    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(elt != NULL));
    ASSERT_UNCHANGED(nm_setting_802_1x_remove_eap_method(s_8021x, 1));
    g_test_assert_expected_messages();

    nm_setting_802_1x_add_eap_method(s_8021x, "ttls");
    ASSERT_CHANGED(nm_setting_802_1x_clear_eap_methods(s_8021x));

    /* alternate subject matches */
    ASSERT_CHANGED(nm_setting_802_1x_add_altsubject_match(s_8021x, "EMAIL:server@example.com"));
    ASSERT_CHANGED(nm_setting_802_1x_remove_altsubject_match(s_8021x, 0));
    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(elt != NULL));
    ASSERT_UNCHANGED(nm_setting_802_1x_remove_altsubject_match(s_8021x, 1));
    g_test_assert_expected_messages();

    nm_setting_802_1x_add_altsubject_match(s_8021x, "EMAIL:server@example.com");
    ASSERT_CHANGED(nm_setting_802_1x_clear_altsubject_matches(s_8021x));

    /* phase2 alternate subject matches */
    ASSERT_CHANGED(
        nm_setting_802_1x_add_phase2_altsubject_match(s_8021x, "EMAIL:server@example.com"));
    ASSERT_CHANGED(nm_setting_802_1x_remove_phase2_altsubject_match(s_8021x, 0));
    NMTST_EXPECT_LIBNM_CRITICAL(NMTST_G_RETURN_MSG(elt != NULL));
    ASSERT_UNCHANGED(nm_setting_802_1x_remove_phase2_altsubject_match(s_8021x, 1));
    g_test_assert_expected_messages();

    nm_setting_802_1x_add_phase2_altsubject_match(s_8021x, "EMAIL:server@example.com");
    ASSERT_CHANGED(nm_setting_802_1x_clear_phase2_altsubject_matches(s_8021x));

    g_object_unref(connection);
}

static void
test_setting_old_uuid(void)
{
    gs_unref_object NMSetting *setting = NULL;

    /* NetworkManager-0.9.4.0 generated 40-character UUIDs with no dashes,
     * like this one. Test that we maintain compatibility. */
    const char *uuid = "f43bec2cdd60e5da381ebb1eb1fa39f3cc52660c";

    setting = nm_setting_connection_new();
    g_object_set(G_OBJECT(setting),
                 NM_SETTING_CONNECTION_ID,
                 "uuidtest",
                 NM_SETTING_CONNECTION_UUID,
                 uuid,
                 NM_SETTING_CONNECTION_TYPE,
                 NM_SETTING_WIRED_SETTING_NAME,
                 NULL);

    nmtst_assert_setting_verifies(NM_SETTING(setting));
}

/*****************************************************************************/

static void
test_connection_normalize_uuid(void)
{
    gs_unref_object NMConnection *con = NULL;

    con = nmtst_create_minimal_connection("test1", NULL, NM_SETTING_WIRED_SETTING_NAME, NULL);

    nmtst_assert_connection_verifies_and_normalizable(con);

    g_object_set(nm_connection_get_setting_connection(con), NM_SETTING_CONNECTION_UUID, NULL, NULL);
    nmtst_assert_connection_verifies_after_normalization(con,
                                                         NM_CONNECTION_ERROR,
                                                         NM_CONNECTION_ERROR_MISSING_PROPERTY);
}

/*****************************************************************************/

/*
 * Test normalization of interface-name
 */
static void
test_connection_normalize_virtual_iface_name(void)
{
    NMConnection *       con = NULL;
    NMSettingConnection *s_con;
    NMSettingVlan *      s_vlan;
    GVariant *           connection_dict, *setting_dict, *var;
    GError *             error      = NULL;
    const char *         IFACE_NAME = "iface";
    const char *         IFACE_VIRT = "iface-X";

    con = nmtst_create_minimal_connection("test1",
                                          "22001632-bbb4-4616-b277-363dce3dfb5b",
                                          NM_SETTING_VLAN_SETTING_NAME,
                                          &s_con);

    nm_connection_add_setting(con,
                              g_object_new(NM_TYPE_SETTING_IP4_CONFIG,
                                           NM_SETTING_IP_CONFIG_METHOD,
                                           NM_SETTING_IP4_CONFIG_METHOD_AUTO,
                                           NULL));

    nm_connection_add_setting(con,
                              g_object_new(NM_TYPE_SETTING_IP6_CONFIG,
                                           NM_SETTING_IP_CONFIG_METHOD,
                                           NM_SETTING_IP4_CONFIG_METHOD_AUTO,
                                           NULL));

    s_vlan = nm_connection_get_setting_vlan(con);

    g_object_set(G_OBJECT(s_vlan), NM_SETTING_VLAN_PARENT, "eth0", NULL);

    g_object_set(G_OBJECT(s_con), NM_SETTING_CONNECTION_INTERFACE_NAME, IFACE_NAME, NULL);

    g_assert_cmpstr(nm_connection_get_interface_name(con), ==, IFACE_NAME);

    connection_dict = nm_connection_to_dbus(con, NM_CONNECTION_SERIALIZE_ALL);
    g_object_unref(con);

    /* Serialized form should include vlan.interface-name as well. */
    setting_dict = g_variant_lookup_value(connection_dict,
                                          NM_SETTING_VLAN_SETTING_NAME,
                                          NM_VARIANT_TYPE_SETTING);
    g_assert(setting_dict != NULL);
    var = g_variant_lookup_value(setting_dict, "interface-name", NULL);
    g_assert(var != NULL);
    g_assert(g_variant_is_of_type(var, G_VARIANT_TYPE_STRING));
    g_assert_cmpstr(g_variant_get_string(var, NULL), ==, IFACE_NAME);

    g_variant_unref(setting_dict);
    g_variant_unref(var);

    /* If vlan.interface-name will be ignored. */
    NMTST_VARIANT_EDITOR(
        connection_dict,
        NMTST_VARIANT_CHANGE_PROPERTY(NM_SETTING_VLAN_SETTING_NAME,
                                      "interface-name",
                                      "s",
                                      ":::this-is-not-a-valid-interface-name:::"););

    con = _connection_new_from_dbus(connection_dict, &error);
    nmtst_assert_success(con, error);
    g_assert_cmpstr(nm_connection_get_interface_name(con), ==, IFACE_NAME);
    g_clear_object(&con);

    /* If vlan.interface-name is valid, but doesn't match, it will be ignored. */
    NMTST_VARIANT_EDITOR(connection_dict,
                         NMTST_VARIANT_CHANGE_PROPERTY(NM_SETTING_VLAN_SETTING_NAME,
                                                       "interface-name",
                                                       "s",
                                                       IFACE_VIRT););

    con = _connection_new_from_dbus(connection_dict, &error);
    g_assert_no_error(error);

    g_assert_cmpstr(nm_connection_get_interface_name(con), ==, IFACE_NAME);
    s_con = nm_connection_get_setting_connection(con);
    g_assert_cmpstr(nm_setting_connection_get_interface_name(s_con), ==, IFACE_NAME);
    g_object_unref(con);

    /* But removing connection.interface-name should result in vlan.connection-name
     * being "promoted".
     */
    NMTST_VARIANT_EDITOR(connection_dict,
                         NMTST_VARIANT_DROP_PROPERTY(NM_SETTING_CONNECTION_SETTING_NAME,
                                                     NM_SETTING_CONNECTION_INTERFACE_NAME););

    con = _connection_new_from_dbus(connection_dict, &error);
    g_assert_no_error(error);

    g_assert_cmpstr(nm_connection_get_interface_name(con), ==, IFACE_VIRT);
    s_con = nm_connection_get_setting_connection(con);
    g_assert_cmpstr(nm_setting_connection_get_interface_name(s_con), ==, IFACE_VIRT);
    g_object_unref(con);

    g_variant_unref(connection_dict);
}

static void
_test_connection_normalize_type_normalizable_setting(
    const char *type,
    void (*prepare_normalizable_fcn)(NMConnection *con))
{
    NMSettingConnection *s_con;
    NMSetting *          s_base;
    GType                base_type;
    gs_unref_object NMConnection *con = NULL;
    gs_free char *                id  = g_strdup_printf("%s[%s]", G_STRFUNC, type);

    base_type = nm_setting_lookup_type(type);
    g_assert(base_type != G_TYPE_INVALID);
    g_assert(_nm_setting_type_get_base_type_priority(base_type) != NM_SETTING_PRIORITY_INVALID);

    con = nmtst_create_minimal_connection(id, NULL, NULL, &s_con);

    nmtst_assert_connection_unnormalizable(con,
                                           NM_CONNECTION_ERROR,
                                           NM_CONNECTION_ERROR_MISSING_PROPERTY);

    g_object_set(s_con, NM_SETTING_CONNECTION_TYPE, type, NULL);

    if (prepare_normalizable_fcn)
        prepare_normalizable_fcn(con);

    g_assert(!nm_connection_get_setting_by_name(con, type));
    nmtst_assert_connection_verifies_after_normalization(con,
                                                         NM_CONNECTION_ERROR,
                                                         NM_CONNECTION_ERROR_MISSING_SETTING);
    nmtst_connection_normalize(con);

    s_base = nm_connection_get_setting_by_name(con, type);
    g_assert(s_base);
    g_assert(G_OBJECT_TYPE(s_base) == base_type);
}

static void
_test_connection_normalize_type_unnormalizable_setting(const char *type)
{
    NMSettingConnection *s_con;
    GType                base_type;
    gs_unref_object NMConnection *con = NULL;
    gs_free char *                id  = g_strdup_printf("%s[%s]", G_STRFUNC, type);

    base_type = nm_setting_lookup_type(type);
    g_assert(base_type != G_TYPE_INVALID);
    g_assert(_nm_setting_type_get_base_type_priority(base_type) != NM_SETTING_PRIORITY_INVALID);

    con = nmtst_create_minimal_connection(id, NULL, NULL, &s_con);

    nmtst_assert_connection_unnormalizable(con,
                                           NM_CONNECTION_ERROR,
                                           NM_CONNECTION_ERROR_MISSING_PROPERTY);

    g_object_set(s_con, NM_SETTING_CONNECTION_TYPE, type, NULL);

    nmtst_assert_connection_unnormalizable(con,
                                           NM_CONNECTION_ERROR,
                                           NM_CONNECTION_ERROR_MISSING_SETTING);
}

static void
_test_connection_normalize_type_normalizable_type(const char *type,
                                                  NMSetting *(*add_setting_fcn)(NMConnection *con))
{
    NMSettingConnection *s_con;
    NMSetting *          s_base;
    GType                base_type;
    gs_unref_object NMConnection *con = NULL;
    gs_free char *                id  = g_strdup_printf("%s[%s]", G_STRFUNC, type);

    base_type = nm_setting_lookup_type(type);
    g_assert(base_type != G_TYPE_INVALID);
    g_assert(_nm_setting_type_get_base_type_priority(base_type) != NM_SETTING_PRIORITY_INVALID);

    con = nmtst_create_minimal_connection(id, NULL, NULL, &s_con);

    nmtst_assert_connection_unnormalizable(con,
                                           NM_CONNECTION_ERROR,
                                           NM_CONNECTION_ERROR_MISSING_PROPERTY);

    if (add_setting_fcn)
        s_base = add_setting_fcn(con);
    else {
        s_base = g_object_new(base_type, NULL);
        nm_connection_add_setting(con, s_base);
    }

    g_assert(!nm_setting_connection_get_connection_type(s_con));
    g_assert(nm_connection_get_setting_by_name(con, type) == s_base);

    nmtst_assert_connection_verifies_after_normalization(con,
                                                         NM_CONNECTION_ERROR,
                                                         NM_CONNECTION_ERROR_MISSING_PROPERTY);
    nmtst_connection_normalize(con);

    g_assert_cmpstr(nm_connection_get_connection_type(con), ==, type);
    g_assert(nm_connection_get_setting_by_name(con, type) == s_base);
}

static NMSetting *
_add_setting_fcn_adsl(NMConnection *con)
{
    NMSetting *setting;

    setting = g_object_new(NM_TYPE_SETTING_ADSL,
                           NM_SETTING_ADSL_USERNAME,
                           "test-user",
                           NM_SETTING_ADSL_PROTOCOL,
                           NM_SETTING_ADSL_PROTOCOL_PPPOA,
                           NM_SETTING_ADSL_ENCAPSULATION,
                           NM_SETTING_ADSL_ENCAPSULATION_VCMUX,
                           NULL);

    nm_connection_add_setting(con, setting);
    return setting;
}

static NMSetting *
_add_setting_fcn_bluetooth(NMConnection *con)
{
    NMSetting *setting;

    setting = g_object_new(NM_TYPE_SETTING_BLUETOOTH,
                           NM_SETTING_BLUETOOTH_BDADDR,
                           "11:22:33:44:55:66",
                           NM_SETTING_BLUETOOTH_TYPE,
                           NM_SETTING_BLUETOOTH_TYPE_PANU,
                           NULL);

    nm_connection_add_setting(con, setting);
    return setting;
}

static NMSetting *
_add_setting_fcn_bond(NMConnection *con)
{
    NMSetting *          setting;
    NMSettingConnection *s_con;

    setting = g_object_new(NM_TYPE_SETTING_BOND, NULL);

    nm_connection_add_setting(con, setting);

    s_con = nm_connection_get_setting_connection(con);

    g_object_set(s_con, NM_SETTING_CONNECTION_INTERFACE_NAME, "test-bond", NULL);

    return setting;
}

static NMSetting *
_add_setting_fcn_bridge(NMConnection *con)
{
    NMSetting *          setting;
    NMSettingConnection *s_con;

    setting = g_object_new(NM_TYPE_SETTING_BRIDGE, NULL);

    nm_connection_add_setting(con, setting);

    s_con = nm_connection_get_setting_connection(con);

    g_object_set(s_con, NM_SETTING_CONNECTION_INTERFACE_NAME, "test-bridge", NULL);

    return setting;
}

static NMSetting *
_add_setting_fcn_cdma(NMConnection *con)
{
    NMSetting *setting;

    setting = g_object_new(NM_TYPE_SETTING_CDMA, NM_SETTING_CDMA_NUMBER, "test-number", NULL);

    nm_connection_add_setting(con, setting);
    return setting;
}

static NMSetting *
_add_setting_fcn_infiniband(NMConnection *con)
{
    NMSetting *setting;

    setting = g_object_new(NM_TYPE_SETTING_INFINIBAND,
                           NM_SETTING_INFINIBAND_TRANSPORT_MODE,
                           "connected",
                           NULL);

    nm_connection_add_setting(con, setting);
    return setting;
}

static NMSetting *
_add_setting_fcn_olpc_mesh(NMConnection *con)
{
    NMSetting * setting;
    const char *ssid_data = "ssid-test";
    GBytes *    ssid;

    ssid    = g_bytes_new(ssid_data, strlen(ssid_data));
    setting = g_object_new(NM_TYPE_SETTING_OLPC_MESH,
                           NM_SETTING_OLPC_MESH_SSID,
                           ssid,
                           NM_SETTING_OLPC_MESH_CHANNEL,
                           1,
                           NULL);
    g_bytes_unref(ssid);

    nm_connection_add_setting(con, setting);
    return setting;
}

static NMSetting *
_add_setting_fcn_team(NMConnection *con)
{
    NMSetting *          setting;
    NMSettingConnection *s_con;

    setting = g_object_new(NM_TYPE_SETTING_TEAM, NULL);

    nm_connection_add_setting(con, setting);

    s_con = nm_connection_get_setting_connection(con);

    g_object_set(s_con, NM_SETTING_CONNECTION_INTERFACE_NAME, "test-team", NULL);

    return setting;
}

static NMSetting *
_add_setting_fcn_vlan(NMConnection *con)
{
    NMSetting *setting;

    setting = g_object_new(NM_TYPE_SETTING_VLAN, NM_SETTING_VLAN_PARENT, "test-parent", NULL);

    nm_connection_add_setting(con, setting);
    return setting;
}

static NMSetting *
_add_setting_fcn_vpn(NMConnection *con)
{
    NMSetting *setting;

    setting = g_object_new(NM_TYPE_SETTING_VPN,
                           NM_SETTING_VPN_SERVICE_TYPE,
                           "test-vpn-service-type",
                           NULL);

    nm_connection_add_setting(con, setting);
    return setting;
}

static NMSetting *
_add_setting_fcn_wimax(NMConnection *con)
{
    NMSetting *setting;

    setting =
        g_object_new(NM_TYPE_SETTING_WIMAX, NM_SETTING_WIMAX_NETWORK_NAME, "test-network", NULL);

    nm_connection_add_setting(con, setting);
    return setting;
}

static NMSetting *
_add_setting_fcn_wireless(NMConnection *con)
{
    NMSetting * setting;
    const char *ssid_data = "ssid-test";
    GBytes *    ssid;

    ssid    = g_bytes_new(ssid_data, strlen(ssid_data));
    setting = g_object_new(NM_TYPE_SETTING_WIRELESS, NM_SETTING_WIRELESS_SSID, ssid, NULL);
    g_bytes_unref(ssid);

    nm_connection_add_setting(con, setting);
    return setting;
}

static void
_prepare_normalizable_fcn_vlan(NMConnection *con)
{
    nm_connection_add_setting(con,
                              g_object_new(NM_TYPE_SETTING_WIRED,
                                           NM_SETTING_WIRED_MAC_ADDRESS,
                                           "11:22:33:44:55:66",
                                           NULL));
}

static void
test_connection_normalize_type(void)
{
    guint i;
    struct {
        const char *type;
        gboolean    normalizable;
        NMSetting *(*add_setting_fcn)(NMConnection *con);
        void (*prepare_normalizable_fcn)(NMConnection *con);
    } types[] = {
        {NM_SETTING_GENERIC_SETTING_NAME, TRUE},
        {NM_SETTING_GSM_SETTING_NAME, TRUE},
        {NM_SETTING_WIRED_SETTING_NAME, TRUE},
        {NM_SETTING_VLAN_SETTING_NAME, TRUE, _add_setting_fcn_vlan, _prepare_normalizable_fcn_vlan},

        {NM_SETTING_ADSL_SETTING_NAME, FALSE, _add_setting_fcn_adsl},
        {NM_SETTING_BLUETOOTH_SETTING_NAME, FALSE, _add_setting_fcn_bluetooth},
        {NM_SETTING_BOND_SETTING_NAME, FALSE, _add_setting_fcn_bond},
        {NM_SETTING_BRIDGE_SETTING_NAME, FALSE, _add_setting_fcn_bridge},
        {NM_SETTING_CDMA_SETTING_NAME, FALSE, _add_setting_fcn_cdma},
        {NM_SETTING_INFINIBAND_SETTING_NAME, FALSE, _add_setting_fcn_infiniband},
        {NM_SETTING_OLPC_MESH_SETTING_NAME, FALSE, _add_setting_fcn_olpc_mesh},
        {NM_SETTING_TEAM_SETTING_NAME, FALSE, _add_setting_fcn_team},
        {NM_SETTING_VLAN_SETTING_NAME, FALSE, _add_setting_fcn_vlan},
        {NM_SETTING_VPN_SETTING_NAME, FALSE, _add_setting_fcn_vpn},
        {NM_SETTING_WIMAX_SETTING_NAME, FALSE, _add_setting_fcn_wimax},
        {NM_SETTING_WIRELESS_SETTING_NAME, FALSE, _add_setting_fcn_wireless},
        {0},
    };

    for (i = 0; types[i].type; i++) {
        const char *type = types[i].type;

        if (types[i].normalizable)
            _test_connection_normalize_type_normalizable_setting(type,
                                                                 types[i].prepare_normalizable_fcn);
        else
            _test_connection_normalize_type_unnormalizable_setting(type);
        _test_connection_normalize_type_normalizable_type(type, types[i].add_setting_fcn);
    }
}

static void
test_connection_normalize_slave_type_1(void)
{
    gs_unref_object NMConnection *con = NULL;
    NMSettingConnection *         s_con;

    con = nmtst_create_minimal_connection("test_connection_normalize_slave_type_1",
                                          "cc4cd5df-45dc-483e-b291-6b76c2338ecb",
                                          NM_SETTING_WIRED_SETTING_NAME,
                                          &s_con);

    g_object_set(s_con,
                 NM_SETTING_CONNECTION_MASTER,
                 "master0",
                 NM_SETTING_CONNECTION_SLAVE_TYPE,
                 "invalid-type",
                 NULL);

    nmtst_assert_connection_unnormalizable(con,
                                           NM_CONNECTION_ERROR,
                                           NM_CONNECTION_ERROR_INVALID_PROPERTY);
    g_assert(!nm_connection_get_setting_by_name(con, NM_SETTING_BRIDGE_PORT_SETTING_NAME));

    g_object_set(s_con, NM_SETTING_CONNECTION_SLAVE_TYPE, "bridge", NULL);

    g_assert(!nm_connection_get_setting_by_name(con, NM_SETTING_BRIDGE_PORT_SETTING_NAME));
    nmtst_assert_connection_verifies_after_normalization(con,
                                                         NM_CONNECTION_ERROR,
                                                         NM_CONNECTION_ERROR_MISSING_SETTING);
    nmtst_connection_normalize(con);
    g_assert(nm_connection_get_setting_by_name(con, NM_SETTING_BRIDGE_PORT_SETTING_NAME));
    g_assert_cmpstr(nm_setting_connection_get_slave_type(s_con),
                    ==,
                    NM_SETTING_BRIDGE_SETTING_NAME);
}

static void
test_connection_normalize_slave_type_2(void)
{
    gs_unref_object NMConnection *con = NULL;
    NMSettingConnection *         s_con;

    con = nmtst_create_minimal_connection("test_connection_normalize_slave_type_2",
                                          "40bea008-ca72-439a-946b-e65f827656f9",
                                          NM_SETTING_WIRED_SETTING_NAME,
                                          &s_con);

    g_object_set(s_con,
                 NM_SETTING_CONNECTION_MASTER,
                 "master0",
                 NM_SETTING_CONNECTION_SLAVE_TYPE,
                 "invalid-type",
                 NULL);

    nmtst_assert_connection_unnormalizable(con,
                                           NM_CONNECTION_ERROR,
                                           NM_CONNECTION_ERROR_INVALID_PROPERTY);
    g_assert(!nm_connection_get_setting_by_name(con, NM_SETTING_BRIDGE_PORT_SETTING_NAME));

    g_object_set(s_con, NM_SETTING_CONNECTION_SLAVE_TYPE, NULL, NULL);
    nm_connection_add_setting(con, nm_setting_bridge_port_new());

    g_assert(nm_connection_get_setting_by_name(con, NM_SETTING_BRIDGE_PORT_SETTING_NAME));
    g_assert_cmpstr(nm_setting_connection_get_slave_type(s_con), ==, NULL);
    nmtst_assert_connection_verifies_after_normalization(con,
                                                         NM_CONNECTION_ERROR,
                                                         NM_CONNECTION_ERROR_MISSING_PROPERTY);
    nmtst_connection_normalize(con);
    g_assert(nm_connection_get_setting_by_name(con, NM_SETTING_BRIDGE_PORT_SETTING_NAME));
    g_assert_cmpstr(nm_setting_connection_get_slave_type(s_con),
                    ==,
                    NM_SETTING_BRIDGE_SETTING_NAME);
}

static void
test_connection_normalize_infiniband_mtu(void)
{
    gs_unref_object NMConnection *con = NULL;
    NMSettingInfiniband *         s_infini;
    guint                         mtu_regular = nmtst_rand_select(2044, 2045, 65520);

    con = nmtst_create_minimal_connection("test_connection_normalize_infiniband_mtu",
                                          NULL,
                                          NM_SETTING_INFINIBAND_SETTING_NAME,
                                          NULL);

    s_infini = nm_connection_get_setting_infiniband(con);
    g_object_set(s_infini, NM_SETTING_INFINIBAND_TRANSPORT_MODE, "connected", NULL);
    nmtst_assert_connection_verifies_and_normalizable(con);

    g_object_set(s_infini,
                 NM_SETTING_INFINIBAND_TRANSPORT_MODE,
                 "datagram",
                 NM_SETTING_INFINIBAND_MTU,
                 (guint) mtu_regular,
                 NULL);
    nmtst_assert_connection_verifies_and_normalizable(con);
    nmtst_connection_normalize(con);
    g_assert_cmpint(mtu_regular, ==, nm_setting_infiniband_get_mtu(s_infini));

    g_object_set(s_infini,
                 NM_SETTING_INFINIBAND_TRANSPORT_MODE,
                 "datagram",
                 NM_SETTING_INFINIBAND_MTU,
                 (guint) 65521,
                 NULL);
    nmtst_assert_connection_verifies_after_normalization(con,
                                                         NM_CONNECTION_ERROR,
                                                         NM_CONNECTION_ERROR_INVALID_PROPERTY);
    nmtst_connection_normalize(con);
    g_assert_cmpint(65520, ==, nm_setting_infiniband_get_mtu(s_infini));

    g_object_set(s_infini,
                 NM_SETTING_INFINIBAND_TRANSPORT_MODE,
                 "connected",
                 NM_SETTING_INFINIBAND_MTU,
                 (guint) mtu_regular,
                 NULL);
    nmtst_assert_connection_verifies_without_normalization(con);
    g_assert_cmpint(mtu_regular, ==, nm_setting_infiniband_get_mtu(s_infini));

    g_object_set(s_infini,
                 NM_SETTING_INFINIBAND_TRANSPORT_MODE,
                 "connected",
                 NM_SETTING_INFINIBAND_MTU,
                 (guint) 65521,
                 NULL);
    nmtst_assert_connection_verifies_after_normalization(con,
                                                         NM_CONNECTION_ERROR,
                                                         NM_CONNECTION_ERROR_INVALID_PROPERTY);
    nmtst_connection_normalize(con);
    g_assert_cmpint(65520, ==, nm_setting_infiniband_get_mtu(s_infini));
}

static void
test_connection_normalize_gateway_never_default(void)
{
    gs_unref_object NMConnection *con = NULL;
    NMSettingIPConfig *           s_ip4, *s_ip6;
    NMIPAddress *                 addr;
    gs_free_error GError *error = NULL;

    con = nmtst_create_minimal_connection("test1", NULL, NM_SETTING_WIRED_SETTING_NAME, NULL);
    nmtst_assert_connection_verifies_and_normalizable(con);

    s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new();
    g_object_set(G_OBJECT(s_ip4),
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
                 NULL);

    addr = nm_ip_address_new(AF_INET, "1.1.1.1", 24, &error);
    g_assert_no_error(error);
    nm_setting_ip_config_add_address(s_ip4, addr);
    nm_ip_address_unref(addr);

    g_object_set(s_ip4,
                 NM_SETTING_IP_CONFIG_GATEWAY,
                 "1.1.1.254",
                 NM_SETTING_IP_CONFIG_NEVER_DEFAULT,
                 FALSE,
                 NULL);

    s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new();
    g_object_set(s_ip6, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO, NULL);

    nm_connection_add_setting(con, (NMSetting *) s_ip4);
    nm_connection_add_setting(con, (NMSetting *) s_ip6);
    nm_connection_add_setting(con, nm_setting_proxy_new());

    nmtst_assert_connection_verifies_without_normalization(con);
    g_assert_cmpstr("1.1.1.254", ==, nm_setting_ip_config_get_gateway(s_ip4));

    /* Now set never-default to TRUE and check that the gateway is
     * removed during normalization
     * */
    g_object_set(s_ip4, NM_SETTING_IP_CONFIG_NEVER_DEFAULT, TRUE, NULL);

    nmtst_assert_connection_verifies_after_normalization(con,
                                                         NM_CONNECTION_ERROR,
                                                         NM_CONNECTION_ERROR_INVALID_PROPERTY);
    nmtst_connection_normalize(con);
    g_assert_cmpstr(NULL, ==, nm_setting_ip_config_get_gateway(s_ip4));
}

static void
test_connection_normalize_may_fail(void)
{
    gs_unref_object NMConnection *con = NULL;
    NMSettingIPConfig *           s_ip4, *s_ip6;

    con = nmtst_create_minimal_connection("test2", NULL, NM_SETTING_WIRED_SETTING_NAME, NULL);
    nmtst_assert_connection_verifies_and_normalizable(con);

    s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new();
    g_object_set(G_OBJECT(s_ip4),
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP4_CONFIG_METHOD_AUTO,
                 NM_SETTING_IP_CONFIG_MAY_FAIL,
                 FALSE,
                 NULL);

    s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new();
    g_object_set(s_ip6,
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP6_CONFIG_METHOD_AUTO,
                 NM_SETTING_IP_CONFIG_MAY_FAIL,
                 FALSE,
                 NULL);

    nm_connection_add_setting(con, (NMSetting *) s_ip4);
    nm_connection_add_setting(con, (NMSetting *) s_ip6);

    nmtst_assert_connection_verifies_and_normalizable(con);

    /* Now set method=disabled/ignore and check that may-fail becomes TRUE
     * after normalization
     * */
    g_object_set(s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_DISABLED, NULL);
    g_object_set(s_ip6, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE, NULL);

    nmtst_assert_connection_verifies(con);
    nmtst_connection_normalize(con);
    g_assert_cmpint(nm_setting_ip_config_get_may_fail(s_ip4), ==, TRUE);
    g_assert_cmpint(nm_setting_ip_config_get_may_fail(s_ip6), ==, TRUE);
}

static void
test_connection_normalize_shared_addresses(void)
{
    gs_unref_object NMConnection *con = NULL;
    NMSettingIPConfig *           s_ip4, *s_ip6;
    NMIPAddress *                 addr;
    gs_free_error GError *error = NULL;

    con = nmtst_create_minimal_connection("test1", NULL, NM_SETTING_WIRED_SETTING_NAME, NULL);
    nmtst_assert_connection_verifies_and_normalizable(con);

    s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new();
    g_object_set(G_OBJECT(s_ip4),
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP4_CONFIG_METHOD_SHARED,
                 NULL);

    addr = nm_ip_address_new(AF_INET, "1.1.1.1", 24, &error);
    g_assert_no_error(error);
    nm_setting_ip_config_add_address(s_ip4, addr);
    nm_ip_address_unref(addr);

    s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new();
    g_object_set(s_ip6, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO, NULL);

    nm_connection_add_setting(con, (NMSetting *) s_ip4);
    nm_connection_add_setting(con, (NMSetting *) s_ip6);

    nmtst_assert_connection_verifies_and_normalizable(con);

    /* Now we add other addresses and check that they are
     * removed during normalization
     * */
    addr = nm_ip_address_new(AF_INET, "2.2.2.2", 24, &error);
    g_assert_no_error(error);
    nm_setting_ip_config_add_address(s_ip4, addr);
    nm_ip_address_unref(addr);

    addr = nm_ip_address_new(AF_INET, "3.3.3.3", 24, &error);
    g_assert_no_error(error);
    nm_setting_ip_config_add_address(s_ip4, addr);
    nm_ip_address_unref(addr);

    nmtst_assert_connection_verifies_after_normalization(con,
                                                         NM_CONNECTION_ERROR,
                                                         NM_CONNECTION_ERROR_INVALID_PROPERTY);
    nmtst_connection_normalize(con);
    g_assert_cmpuint(nm_setting_ip_config_get_num_addresses(s_ip4), ==, 1);
    addr = nm_setting_ip_config_get_address(s_ip4, 0);
    g_assert_cmpstr(nm_ip_address_get_address(addr), ==, "1.1.1.1");
}

static void
test_connection_normalize_ovs_interface_type_system(gconstpointer test_data)
{
    const guint     TEST_CASE         = GPOINTER_TO_UINT(test_data);
    gs_unref_object NMConnection *con = NULL;
    NMSettingConnection *         s_con;
    NMSettingOvsInterface *       s_ovs_if;

    con = nmtst_create_minimal_connection("test_connection_normalize_ovs_interface_type_system",
                                          NULL,
                                          NM_SETTING_WIRED_SETTING_NAME,
                                          &s_con);

    switch (TEST_CASE) {
    case 1:
        g_object_set(s_con,
                     NM_SETTING_CONNECTION_MASTER,
                     "master0",
                     NM_SETTING_CONNECTION_SLAVE_TYPE,
                     NM_SETTING_OVS_PORT_SETTING_NAME,
                     NULL);

        nmtst_assert_connection_verifies_after_normalization(con,
                                                             NM_CONNECTION_ERROR,
                                                             NM_CONNECTION_ERROR_MISSING_SETTING);

        nmtst_connection_normalize(con);
        nmtst_assert_connection_has_settings(con,
                                             NM_SETTING_CONNECTION_SETTING_NAME,
                                             NM_SETTING_WIRED_SETTING_NAME,
                                             NM_SETTING_OVS_INTERFACE_SETTING_NAME);
        s_ovs_if = nm_connection_get_setting_ovs_interface(con);
        g_assert(s_ovs_if);
        g_assert_cmpstr(nm_setting_ovs_interface_get_interface_type(s_ovs_if), ==, "system");
        break;
    case 2:
        g_object_set(s_con,
                     NM_SETTING_CONNECTION_MASTER,
                     "master0",
                     NM_SETTING_CONNECTION_SLAVE_TYPE,
                     NM_SETTING_OVS_PORT_SETTING_NAME,
                     NULL);

        s_ovs_if = NM_SETTING_OVS_INTERFACE(nm_setting_ovs_interface_new());
        nm_connection_add_setting(con, NM_SETTING(s_ovs_if));

        nmtst_assert_connection_verifies_after_normalization(con,
                                                             NM_CONNECTION_ERROR,
                                                             NM_CONNECTION_ERROR_MISSING_PROPERTY);

        nmtst_connection_normalize(con);
        nmtst_assert_connection_has_settings(con,
                                             NM_SETTING_CONNECTION_SETTING_NAME,
                                             NM_SETTING_WIRED_SETTING_NAME,
                                             NM_SETTING_OVS_INTERFACE_SETTING_NAME);
        g_assert(s_ovs_if == nm_connection_get_setting_ovs_interface(con));
        g_assert_cmpstr(nm_setting_ovs_interface_get_interface_type(s_ovs_if), ==, "system");
        break;
    case 3:
        g_object_set(s_con,
                     NM_SETTING_CONNECTION_MASTER,
                     "master0",
                     NM_SETTING_CONNECTION_SLAVE_TYPE,
                     NM_SETTING_OVS_PORT_SETTING_NAME,
                     NULL);

        s_ovs_if = NM_SETTING_OVS_INTERFACE(nm_setting_ovs_interface_new());
        nm_connection_add_setting(con, NM_SETTING(s_ovs_if));

        g_object_set(s_ovs_if, NM_SETTING_OVS_INTERFACE_TYPE, "system", NULL);
        nmtst_assert_connection_verifies_without_normalization(con);
        nmtst_assert_connection_has_settings(con,
                                             NM_SETTING_CONNECTION_SETTING_NAME,
                                             NM_SETTING_WIRED_SETTING_NAME,
                                             NM_SETTING_OVS_INTERFACE_SETTING_NAME);
        break;
    case 4:
        g_object_set(s_con,
                     NM_SETTING_CONNECTION_MASTER,
                     "master0",
                     NM_SETTING_CONNECTION_SLAVE_TYPE,
                     NM_SETTING_OVS_PORT_SETTING_NAME,
                     NULL);

        s_ovs_if = NM_SETTING_OVS_INTERFACE(nm_setting_ovs_interface_new());
        nm_connection_add_setting(con, NM_SETTING(s_ovs_if));

        g_object_set(s_ovs_if, NM_SETTING_OVS_INTERFACE_TYPE, "internal", NULL);
        /* the setting doesn't verify, because the interface-type must be "system". */
        nmtst_assert_connection_unnormalizable(con,
                                               NM_CONNECTION_ERROR,
                                               NM_CONNECTION_ERROR_INVALID_PROPERTY);
        break;
    case 5:
        g_object_set(s_con, NM_SETTING_CONNECTION_MASTER, "master0", NULL);

        s_ovs_if = NM_SETTING_OVS_INTERFACE(nm_setting_ovs_interface_new());
        nm_connection_add_setting(con, NM_SETTING(s_ovs_if));

        g_object_set(s_ovs_if, NM_SETTING_OVS_INTERFACE_TYPE, "system", NULL);
        nmtst_assert_connection_verifies_after_normalization(con,
                                                             NM_CONNECTION_ERROR,
                                                             NM_CONNECTION_ERROR_MISSING_PROPERTY);
        nmtst_connection_normalize(con);
        nmtst_assert_connection_has_settings(con,
                                             NM_SETTING_CONNECTION_SETTING_NAME,
                                             NM_SETTING_WIRED_SETTING_NAME,
                                             NM_SETTING_OVS_INTERFACE_SETTING_NAME);
        g_assert(s_con == nm_connection_get_setting_connection(con));
        g_assert_cmpstr(nm_setting_connection_get_slave_type(s_con),
                        ==,
                        NM_SETTING_OVS_PORT_SETTING_NAME);
        break;
    case 6:
        g_object_set(s_con,
                     NM_SETTING_CONNECTION_MASTER,
                     "master0",
                     NM_SETTING_CONNECTION_SLAVE_TYPE,
                     NM_SETTING_BRIDGE_SETTING_NAME,
                     NULL);

        s_ovs_if = NM_SETTING_OVS_INTERFACE(nm_setting_ovs_interface_new());
        nm_connection_add_setting(con, NM_SETTING(s_ovs_if));

        g_object_set(s_ovs_if, NM_SETTING_OVS_INTERFACE_TYPE, "system", NULL);
        nmtst_assert_connection_unnormalizable(con,
                                               NM_CONNECTION_ERROR,
                                               NM_CONNECTION_ERROR_INVALID_PROPERTY);
        break;
    case 7:
        g_object_set(s_con,
                     NM_SETTING_CONNECTION_MASTER,
                     "master0",
                     NM_SETTING_CONNECTION_SLAVE_TYPE,
                     NM_SETTING_BRIDGE_SETTING_NAME,
                     NULL);

        nm_connection_add_setting(con, nm_setting_bridge_port_new());

        s_ovs_if = NM_SETTING_OVS_INTERFACE(nm_setting_ovs_interface_new());
        nm_connection_add_setting(con, NM_SETTING(s_ovs_if));

        g_object_set(s_ovs_if, NM_SETTING_OVS_INTERFACE_TYPE, "system", NULL);
        nmtst_assert_connection_unnormalizable(con,
                                               NM_CONNECTION_ERROR,
                                               NM_CONNECTION_ERROR_INVALID_PROPERTY);
        break;
    default:
        g_assert_not_reached();
        break;
    }
}

static void
test_connection_normalize_ovs_interface_type_ovs_interface(gconstpointer test_data)
{
    const guint     TEST_CASE         = GPOINTER_TO_UINT(test_data);
    gs_unref_object NMConnection *con = NULL;
    NMSettingConnection *         s_con;
    NMSettingOvsInterface *       s_ovs_if;
    NMSettingOvsPatch *           s_ovs_patch;
    NMSettingIP4Config *          s_ip4;
    NMSettingIP6Config *          s_ip6;

    con = nmtst_create_minimal_connection(
        "test_connection_normalize_ovs_interface_type_ovs_interface",
        NULL,
        NM_SETTING_OVS_INTERFACE_SETTING_NAME,
        &s_con);
    s_ovs_if = nm_connection_get_setting_ovs_interface(con);
    g_assert(s_ovs_if);

    switch (TEST_CASE) {
    case 1:
        nmtst_assert_connection_unnormalizable(con,
                                               NM_CONNECTION_ERROR,
                                               NM_CONNECTION_ERROR_INVALID_PROPERTY);
        break;
    case 2:
        g_object_set(s_con, NM_SETTING_CONNECTION_MASTER, "master0", NULL);
        nmtst_assert_connection_verifies_after_normalization(con,
                                                             NM_CONNECTION_ERROR,
                                                             NM_CONNECTION_ERROR_MISSING_PROPERTY);
        nmtst_connection_normalize(con);
        nmtst_assert_connection_has_settings(con,
                                             NM_SETTING_CONNECTION_SETTING_NAME,
                                             NM_SETTING_IP4_CONFIG_SETTING_NAME,
                                             NM_SETTING_IP6_CONFIG_SETTING_NAME,
                                             NM_SETTING_PROXY_SETTING_NAME,
                                             NM_SETTING_OVS_INTERFACE_SETTING_NAME);
        g_assert(s_con == nm_connection_get_setting_connection(con));
        g_assert(s_ovs_if == nm_connection_get_setting_ovs_interface(con));
        g_assert_cmpstr(nm_setting_connection_get_slave_type(s_con),
                        ==,
                        NM_SETTING_OVS_PORT_SETTING_NAME);
        g_assert_cmpstr(nm_setting_ovs_interface_get_interface_type(s_ovs_if), ==, "internal");
        break;
    case 3:
        g_object_set(s_con,
                     NM_SETTING_CONNECTION_MASTER,
                     "master0",
                     NM_SETTING_CONNECTION_SLAVE_TYPE,
                     NM_SETTING_OVS_PORT_SETTING_NAME,
                     NULL);
        nmtst_assert_connection_verifies_after_normalization(con,
                                                             NM_CONNECTION_ERROR,
                                                             NM_CONNECTION_ERROR_MISSING_PROPERTY);
        nmtst_connection_normalize(con);
        nmtst_assert_connection_has_settings(con,
                                             NM_SETTING_CONNECTION_SETTING_NAME,
                                             NM_SETTING_IP4_CONFIG_SETTING_NAME,
                                             NM_SETTING_IP6_CONFIG_SETTING_NAME,
                                             NM_SETTING_PROXY_SETTING_NAME,
                                             NM_SETTING_OVS_INTERFACE_SETTING_NAME);
        g_assert(s_con == nm_connection_get_setting_connection(con));
        g_assert(s_ovs_if == nm_connection_get_setting_ovs_interface(con));
        g_assert_cmpstr(nm_setting_connection_get_slave_type(s_con),
                        ==,
                        NM_SETTING_OVS_PORT_SETTING_NAME);
        g_assert_cmpstr(nm_setting_ovs_interface_get_interface_type(s_ovs_if), ==, "internal");
        break;
    case 4:
        g_object_set(s_con, NM_SETTING_CONNECTION_MASTER, "master0", NULL);
        g_object_set(s_ovs_if, NM_SETTING_OVS_INTERFACE_TYPE, "internal", NULL);
        nmtst_assert_connection_verifies_after_normalization(con,
                                                             NM_CONNECTION_ERROR,
                                                             NM_CONNECTION_ERROR_MISSING_PROPERTY);
        nmtst_connection_normalize(con);
        nmtst_assert_connection_has_settings(con,
                                             NM_SETTING_CONNECTION_SETTING_NAME,
                                             NM_SETTING_IP4_CONFIG_SETTING_NAME,
                                             NM_SETTING_IP6_CONFIG_SETTING_NAME,
                                             NM_SETTING_PROXY_SETTING_NAME,
                                             NM_SETTING_OVS_INTERFACE_SETTING_NAME);
        g_assert(s_con == nm_connection_get_setting_connection(con));
        g_assert(s_ovs_if == nm_connection_get_setting_ovs_interface(con));
        g_assert_cmpstr(nm_setting_connection_get_slave_type(s_con),
                        ==,
                        NM_SETTING_OVS_PORT_SETTING_NAME);
        g_assert_cmpstr(nm_setting_ovs_interface_get_interface_type(s_ovs_if), ==, "internal");
        break;
    case 5:
        g_object_set(s_con,
                     NM_SETTING_CONNECTION_MASTER,
                     "master0",
                     NM_SETTING_CONNECTION_SLAVE_TYPE,
                     NM_SETTING_OVS_PORT_SETTING_NAME,
                     NULL);
        g_object_set(s_ovs_if, NM_SETTING_OVS_INTERFACE_TYPE, "internal", NULL);
        nm_connection_add_setting(con, nm_setting_ip4_config_new());
        nm_connection_add_setting(con, nm_setting_ip6_config_new());
        nm_connection_add_setting(con, nm_setting_proxy_new());
        s_ip4 = NM_SETTING_IP4_CONFIG(nm_connection_get_setting_ip4_config(con));
        s_ip6 = NM_SETTING_IP6_CONFIG(nm_connection_get_setting_ip6_config(con));
        g_object_set(s_ip4, NM_SETTING_IP_CONFIG_METHOD, "auto", NULL);
        g_object_set(s_ip6, NM_SETTING_IP_CONFIG_METHOD, "auto", NULL);
        nmtst_assert_connection_verifies_without_normalization(con);
        nmtst_assert_connection_has_settings(con,
                                             NM_SETTING_CONNECTION_SETTING_NAME,
                                             NM_SETTING_IP4_CONFIG_SETTING_NAME,
                                             NM_SETTING_IP6_CONFIG_SETTING_NAME,
                                             NM_SETTING_PROXY_SETTING_NAME,
                                             NM_SETTING_OVS_INTERFACE_SETTING_NAME);
        break;
    case 6:
        g_object_set(s_con,
                     NM_SETTING_CONNECTION_MASTER,
                     "master0",
                     NM_SETTING_CONNECTION_SLAVE_TYPE,
                     NM_SETTING_OVS_PORT_SETTING_NAME,
                     NULL);
        g_object_set(s_ovs_if, NM_SETTING_OVS_INTERFACE_TYPE, "internal", NULL);
        nmtst_assert_connection_verifies_and_normalizable(con);
        nmtst_connection_normalize(con);
        nmtst_assert_connection_has_settings(con,
                                             NM_SETTING_CONNECTION_SETTING_NAME,
                                             NM_SETTING_IP4_CONFIG_SETTING_NAME,
                                             NM_SETTING_IP6_CONFIG_SETTING_NAME,
                                             NM_SETTING_PROXY_SETTING_NAME,
                                             NM_SETTING_OVS_INTERFACE_SETTING_NAME);
        g_assert(s_con == nm_connection_get_setting_connection(con));
        g_assert(s_ovs_if == nm_connection_get_setting_ovs_interface(con));
        g_assert_cmpstr(nm_setting_connection_get_slave_type(s_con),
                        ==,
                        NM_SETTING_OVS_PORT_SETTING_NAME);
        g_assert_cmpstr(nm_setting_ovs_interface_get_interface_type(s_ovs_if), ==, "internal");
        break;
    case 7:
        g_object_set(s_con,
                     NM_SETTING_CONNECTION_MASTER,
                     "master0",
                     NM_SETTING_CONNECTION_SLAVE_TYPE,
                     NM_SETTING_OVS_PORT_SETTING_NAME,
                     NULL);
        g_object_set(s_ovs_if, NM_SETTING_OVS_INTERFACE_TYPE, "system", NULL);
        nmtst_assert_connection_unnormalizable(con,
                                               NM_CONNECTION_ERROR,
                                               NM_CONNECTION_ERROR_INVALID_PROPERTY);
        break;
    case 8:
        g_object_set(s_con,
                     NM_SETTING_CONNECTION_MASTER,
                     "master0",
                     NM_SETTING_CONNECTION_SLAVE_TYPE,
                     NM_SETTING_OVS_PORT_SETTING_NAME,
                     NULL);
        g_object_set(s_ovs_if, NM_SETTING_OVS_INTERFACE_TYPE, "bogus", NULL);
        nmtst_assert_connection_unnormalizable(con,
                                               NM_CONNECTION_ERROR,
                                               NM_CONNECTION_ERROR_INVALID_PROPERTY);
        break;
    case 9:
        g_object_set(s_con,
                     NM_SETTING_CONNECTION_MASTER,
                     "master0",
                     NM_SETTING_CONNECTION_SLAVE_TYPE,
                     NM_SETTING_OVS_PORT_SETTING_NAME,
                     NULL);
        g_object_set(s_ovs_if, NM_SETTING_OVS_INTERFACE_TYPE, "patch", NULL);
        nmtst_assert_connection_unnormalizable(con,
                                               NM_CONNECTION_ERROR,
                                               NM_CONNECTION_ERROR_MISSING_SETTING);
        break;
    case 10:
        g_object_set(s_con,
                     NM_SETTING_CONNECTION_MASTER,
                     "master0",
                     NM_SETTING_CONNECTION_SLAVE_TYPE,
                     NM_SETTING_OVS_PORT_SETTING_NAME,
                     NULL);
        g_object_set(s_ovs_if, NM_SETTING_OVS_INTERFACE_TYPE, "patch", NULL);
        nm_connection_add_setting(con, nm_setting_ovs_patch_new());
        nmtst_assert_connection_unnormalizable(con,
                                               NM_CONNECTION_ERROR,
                                               NM_CONNECTION_ERROR_MISSING_PROPERTY);
        break;
    case 11:
        g_object_set(s_con,
                     NM_SETTING_CONNECTION_MASTER,
                     "master0",
                     NM_SETTING_CONNECTION_SLAVE_TYPE,
                     NM_SETTING_OVS_PORT_SETTING_NAME,
                     NM_SETTING_CONNECTION_INTERFACE_NAME,
                     "adsf",
                     NULL);
        g_object_set(s_ovs_if, NM_SETTING_OVS_INTERFACE_TYPE, "patch", NULL);
        nm_connection_add_setting(con, nm_setting_ovs_patch_new());
        nmtst_assert_connection_unnormalizable(con,
                                               NM_CONNECTION_ERROR,
                                               NM_CONNECTION_ERROR_MISSING_PROPERTY);
        break;
    case 12:
        g_object_set(s_con,
                     NM_SETTING_CONNECTION_MASTER,
                     "master0",
                     NM_SETTING_CONNECTION_SLAVE_TYPE,
                     NM_SETTING_OVS_PORT_SETTING_NAME,
                     NM_SETTING_CONNECTION_INTERFACE_NAME,
                     "adsf",
                     NULL);
        g_object_set(s_ovs_if, NM_SETTING_OVS_INTERFACE_TYPE, "patch", NULL);
        s_ovs_patch = NM_SETTING_OVS_PATCH(nm_setting_ovs_patch_new());
        nm_connection_add_setting(con, NM_SETTING(s_ovs_patch));
        g_object_set(s_ovs_patch, NM_SETTING_OVS_PATCH_PEER, "1.2.3.4", NULL);
        nmtst_assert_connection_verifies_and_normalizable(con);
        nmtst_connection_normalize(con);
        nmtst_assert_connection_has_settings(con,
                                             NM_SETTING_CONNECTION_SETTING_NAME,
                                             NM_SETTING_IP4_CONFIG_SETTING_NAME,
                                             NM_SETTING_IP6_CONFIG_SETTING_NAME,
                                             NM_SETTING_PROXY_SETTING_NAME,
                                             NM_SETTING_OVS_INTERFACE_SETTING_NAME,
                                             NM_SETTING_OVS_PATCH_SETTING_NAME);
        g_assert(s_con == nm_connection_get_setting_connection(con));
        g_assert(s_ovs_if == nm_connection_get_setting_ovs_interface(con));
        g_assert_cmpstr(nm_setting_connection_get_slave_type(s_con),
                        ==,
                        NM_SETTING_OVS_PORT_SETTING_NAME);
        g_assert_cmpstr(nm_setting_ovs_interface_get_interface_type(s_ovs_if), ==, "patch");
        break;
    default:
        g_assert_not_reached();
    }
}

static void
test_setting_ip4_gateway(void)
{
    NMConnection *     conn;
    NMSettingIPConfig *s_ip4;
    NMIPAddress *      addr;
    GVariant *         conn_dict, *ip4_dict, *value;
    GVariantIter       iter;
    GVariant *         addr_var;
    guint32            addr_vals_0[] = {htonl(0xc0a8010a), 0x00000018, htonl(0x00000000)};
    guint32            addr_vals_1[] = {htonl(0xc0a8010b), 0x00000018, htonl(0xc0a80101)};
    GVariantBuilder    addrs_builder;
    GError *           error = NULL;

    nmtst_assert_ip4_address(addr_vals_0[0], "192.168.1.10");

    /* When serializing on the daemon side, ipv4.gateway is copied to the first
     * entry of ipv4.addresses
     */
    conn  = nmtst_create_minimal_connection("test_setting_ip4_gateway",
                                           NULL,
                                           NM_SETTING_WIRED_SETTING_NAME,
                                           NULL);
    s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new();
    g_object_set(s_ip4,
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
                 NM_SETTING_IP_CONFIG_GATEWAY,
                 "192.168.1.1",
                 NULL);
    nm_connection_add_setting(conn, NM_SETTING(s_ip4));

    addr = nm_ip_address_new(AF_INET, "192.168.1.10", 24, &error);
    g_assert_no_error(error);
    nm_setting_ip_config_add_address(s_ip4, addr);
    nm_ip_address_unref(addr);

    _nm_utils_is_manager_process = TRUE;
    conn_dict                    = nm_connection_to_dbus(conn, NM_CONNECTION_SERIALIZE_ALL);
    _nm_utils_is_manager_process = FALSE;
    g_object_unref(conn);

    ip4_dict = g_variant_lookup_value(conn_dict,
                                      NM_SETTING_IP4_CONFIG_SETTING_NAME,
                                      NM_VARIANT_TYPE_SETTING);
    g_assert(ip4_dict != NULL);

    value = g_variant_lookup_value(ip4_dict, NM_SETTING_IP_CONFIG_GATEWAY, G_VARIANT_TYPE_STRING);
    g_assert(value != NULL);
    g_assert_cmpstr(g_variant_get_string(value, NULL), ==, "192.168.1.1");
    g_variant_unref(value);

    value = g_variant_lookup_value(ip4_dict, NM_SETTING_IP_CONFIG_ADDRESSES, G_VARIANT_TYPE("aau"));
    g_assert(value != NULL);

    g_variant_iter_init(&iter, value);
    while (g_variant_iter_next(&iter, "@au", &addr_var)) {
        const guint32 *addr_array;
        gsize          length;

        addr_array = g_variant_get_fixed_array(addr_var, &length, sizeof(guint32));
        g_assert_cmpint(length, ==, 3);
        nmtst_assert_ip4_address(addr_array[2], "192.168.1.1");
        g_variant_unref(addr_var);
    }
    g_variant_unref(value);

    g_variant_unref(ip4_dict);

    /* When deserializing an old-style connection, the first non-0 gateway in
     * ipv4.addresses is copied to :gateway.
     */
    NMTST_VARIANT_EDITOR(
        conn_dict,
        NMTST_VARIANT_DROP_PROPERTY(NM_SETTING_IP4_CONFIG_SETTING_NAME,
                                    NM_SETTING_IP_CONFIG_GATEWAY);
        NMTST_VARIANT_DROP_PROPERTY(NM_SETTING_IP4_CONFIG_SETTING_NAME, "address-data"););

    conn = _connection_new_from_dbus(conn_dict, &error);
    g_assert_no_error(error);

    s_ip4 = (NMSettingIPConfig *) nm_connection_get_setting_ip4_config(conn);
    g_assert_cmpstr(nm_setting_ip_config_get_gateway(s_ip4), ==, "192.168.1.1");

    g_object_unref(conn);

    /* Try again with the gateway in the second address. */
    g_variant_builder_init(&addrs_builder, G_VARIANT_TYPE("aau"));
    g_variant_builder_add(&addrs_builder,
                          "@au",
                          g_variant_new_fixed_array(G_VARIANT_TYPE_UINT32, addr_vals_0, 3, 4));
    g_variant_builder_add(&addrs_builder,
                          "@au",
                          g_variant_new_fixed_array(G_VARIANT_TYPE_UINT32, addr_vals_1, 3, 4));

    NMTST_VARIANT_EDITOR(conn_dict,
                         NMTST_VARIANT_CHANGE_PROPERTY(NM_SETTING_IP4_CONFIG_SETTING_NAME,
                                                       "addresses",
                                                       "aau",
                                                       &addrs_builder););

    conn = _connection_new_from_dbus(conn_dict, &error);
    g_assert_no_error(error);
    g_variant_unref(conn_dict);

    s_ip4 = (NMSettingIPConfig *) nm_connection_get_setting_ip4_config(conn);
    g_assert_cmpstr(nm_setting_ip_config_get_gateway(s_ip4), ==, "192.168.1.1");

    g_object_unref(conn);
}

static void
test_setting_ip6_gateway(void)
{
    NMConnection *     conn;
    NMSettingIPConfig *s_ip6;
    NMIPAddress *      addr;
    GVariant *         conn_dict, *ip6_dict, *value;
    GVariantIter       iter;
    GVariant *         gateway_var;
    GVariantBuilder    addrs_builder;
    guint8             addr_bytes_0[]    = {0xab,
                             0xcd,
                             0x00,
                             0x00,
                             0x00,
                             0x00,
                             0x00,
                             0x00,
                             0x00,
                             0x00,
                             0x00,
                             0x00,
                             0x00,
                             0x00,
                             0x00,
                             0x0a};
    guint8             addr_bytes_1[]    = {0xab,
                             0xcd,
                             0x00,
                             0x00,
                             0x00,
                             0x00,
                             0x00,
                             0x00,
                             0x00,
                             0x00,
                             0x00,
                             0x00,
                             0x00,
                             0x00,
                             0x00,
                             0x0b};
    guint8             gateway_bytes_1[] = {0xab,
                                0xcd,
                                0x00,
                                0x00,
                                0x00,
                                0x00,
                                0x00,
                                0x00,
                                0x00,
                                0x00,
                                0x00,
                                0x00,
                                0x00,
                                0x00,
                                0x00,
                                0x01};
    GError *           error             = NULL;

    /* When serializing on the daemon side, ipv6.gateway is copied to the first
     * entry of ipv6.addresses
     */
    conn  = nmtst_create_minimal_connection("test_setting_ip6_gateway",
                                           NULL,
                                           NM_SETTING_WIRED_SETTING_NAME,
                                           NULL);
    s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new();
    g_object_set(s_ip6,
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
                 NM_SETTING_IP_CONFIG_GATEWAY,
                 "abcd::1",
                 NULL);
    nm_connection_add_setting(conn, NM_SETTING(s_ip6));

    addr = nm_ip_address_new(AF_INET6, "abcd::10", 64, &error);
    g_assert_no_error(error);
    nm_setting_ip_config_add_address(s_ip6, addr);
    nm_ip_address_unref(addr);

    _nm_utils_is_manager_process = TRUE;
    conn_dict                    = nm_connection_to_dbus(conn, NM_CONNECTION_SERIALIZE_ALL);
    _nm_utils_is_manager_process = FALSE;
    g_object_unref(conn);

    ip6_dict = g_variant_lookup_value(conn_dict,
                                      NM_SETTING_IP6_CONFIG_SETTING_NAME,
                                      NM_VARIANT_TYPE_SETTING);
    g_assert(ip6_dict != NULL);

    value = g_variant_lookup_value(ip6_dict, NM_SETTING_IP_CONFIG_GATEWAY, G_VARIANT_TYPE_STRING);
    g_assert(value != NULL);
    g_assert_cmpstr(g_variant_get_string(value, NULL), ==, "abcd::1");
    g_variant_unref(value);

    value = g_variant_lookup_value(ip6_dict,
                                   NM_SETTING_IP_CONFIG_ADDRESSES,
                                   G_VARIANT_TYPE("a(ayuay)"));
    g_assert(value != NULL);

    g_variant_iter_init(&iter, value);
    while (g_variant_iter_next(&iter, "(@ayu@ay)", NULL, NULL, &gateway_var)) {
        const guint8 *gateway_bytes;
        gsize         length;

        gateway_bytes = g_variant_get_fixed_array(gateway_var, &length, 1);
        g_assert_cmpint(length, ==, 16);
        nmtst_assert_ip6_address((struct in6_addr *) gateway_bytes, "abcd::1");
        g_variant_unref(gateway_var);
    }
    g_variant_unref(value);

    g_variant_unref(ip6_dict);

    /* When deserializing an old-style connection, the first non-0 gateway in
     * ipv6.addresses is copied to :gateway.
     */
    NMTST_VARIANT_EDITOR(
        conn_dict,
        NMTST_VARIANT_DROP_PROPERTY(NM_SETTING_IP6_CONFIG_SETTING_NAME,
                                    NM_SETTING_IP_CONFIG_GATEWAY);
        NMTST_VARIANT_DROP_PROPERTY(NM_SETTING_IP6_CONFIG_SETTING_NAME, "address-data"););

    conn = _connection_new_from_dbus(conn_dict, &error);
    g_assert_no_error(error);

    s_ip6 = (NMSettingIPConfig *) nm_connection_get_setting_ip6_config(conn);
    g_assert_cmpstr(nm_setting_ip_config_get_gateway(s_ip6), ==, "abcd::1");

    g_object_unref(conn);

    /* Try again with the gateway in the second address. */
    g_variant_builder_init(&addrs_builder, G_VARIANT_TYPE("a(ayuay)"));
    g_variant_builder_add(&addrs_builder,
                          "(@ayu@ay)",
                          g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, addr_bytes_0, 16, 1),
                          64,
                          g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, &in6addr_any, 16, 1));
    g_variant_builder_add(&addrs_builder,
                          "(@ayu@ay)",
                          g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, addr_bytes_1, 16, 1),
                          64,
                          g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, gateway_bytes_1, 16, 1));

    NMTST_VARIANT_EDITOR(conn_dict,
                         NMTST_VARIANT_CHANGE_PROPERTY(NM_SETTING_IP6_CONFIG_SETTING_NAME,
                                                       "addresses",
                                                       "a(ayuay)",
                                                       &addrs_builder););

    conn = _connection_new_from_dbus(conn_dict, &error);
    g_assert_no_error(error);
    g_variant_unref(conn_dict);

    s_ip6 = (NMSettingIPConfig *) nm_connection_get_setting_ip6_config(conn);
    g_assert_cmpstr(nm_setting_ip_config_get_gateway(s_ip6), ==, "abcd::1");

    g_object_unref(conn);
}

typedef struct {
    const char * str;
    const guint8 expected[20];
    const guint  expected_len;
} HexItem;

static void
test_setting_compare_default_strv(void)
{
    gs_unref_object NMConnection *c1 = NULL, *c2 = NULL;
    char **                       strv;
    NMSettingIPConfig *           s_ip2, *s_ip1;
    gboolean                      compare;
    GHashTable *                  out_settings = NULL;

    c1 = nmtst_create_minimal_connection("test_compare_default_strv",
                                         NULL,
                                         NM_SETTING_WIRED_SETTING_NAME,
                                         NULL);
    nmtst_assert_connection_verifies_and_normalizable(c1);
    nmtst_connection_normalize(c1);

    c2 = nm_simple_connection_new_clone(c1);
    nmtst_assert_connection_verifies_without_normalization(c2);

    nmtst_assert_connection_equals(c1, FALSE, c2, FALSE);

    s_ip1 = nm_connection_get_setting_ip4_config(c1);
    s_ip2 = nm_connection_get_setting_ip4_config(c2);

    nm_setting_ip_config_clear_dns_options(s_ip2, FALSE);
    g_object_get(G_OBJECT(s_ip2), NM_SETTING_IP_CONFIG_DNS_OPTIONS, &strv, NULL);
    g_assert(!strv);
    nmtst_assert_connection_equals(c1, FALSE, c2, FALSE);

    nm_setting_ip_config_clear_dns_options(s_ip2, TRUE);
    g_object_get(G_OBJECT(s_ip2), NM_SETTING_IP_CONFIG_DNS_OPTIONS, &strv, NULL);
    g_assert(strv && !strv[0]);
    g_strfreev(strv);

    compare = nm_setting_diff((NMSetting *) s_ip1,
                              (NMSetting *) s_ip2,
                              NM_SETTING_COMPARE_FLAG_EXACT,
                              FALSE,
                              &out_settings);
    g_assert(!compare);
    g_assert(out_settings);
    g_assert(g_hash_table_contains(out_settings, NM_SETTING_IP_CONFIG_DNS_OPTIONS));
    g_hash_table_unref(out_settings);
    out_settings = NULL;

    compare = nm_connection_diff(c1, c2, NM_SETTING_COMPARE_FLAG_EXACT, &out_settings);
    g_assert(!compare);
    g_assert(out_settings);
    g_hash_table_unref(out_settings);
    out_settings = NULL;
}

/*****************************************************************************/

static void
test_setting_user_data(void)
{
    gs_unref_object NMSettingUser *s_user = NULL;

    s_user = NM_SETTING_USER(nm_setting_user_new());
}

/*****************************************************************************/

typedef union {
    struct sockaddr     sa;
    struct sockaddr_in  in;
    struct sockaddr_in6 in6;
} SockAddrUnion;

static void
_sock_addr_endpoint(const char *endpoint, const char *host, gint32 port)
{
    nm_auto_unref_sockaddrendpoint NMSockAddrEndpoint *ep = NULL;
    const char *                                       s_endpoint;
    const char *                                       s_host;
    gint32                                             s_port;
    SockAddrUnion                                      sockaddr = {};

    g_assert(endpoint);
    g_assert((!host) == (port == -1));
    g_assert(port >= -1 && port <= G_MAXUINT16);

    ep = nm_sock_addr_endpoint_new(endpoint);
    g_assert(ep);

    s_endpoint = nm_sock_addr_endpoint_get_endpoint(ep);
    s_host     = nm_sock_addr_endpoint_get_host(ep);
    s_port     = nm_sock_addr_endpoint_get_port(ep);
    g_assert_cmpstr(endpoint, ==, s_endpoint);
    g_assert_cmpstr(host, ==, s_host);
    g_assert_cmpint(port, ==, s_port);

    g_assert(!nm_sock_addr_endpoint_get_fixed_sockaddr(ep, &sockaddr));

    if (endpoint[0] != ' ') {
        gs_free char *endpoint2 = NULL;

        /* also test with a leading space */
        endpoint2 = g_strdup_printf(" %s", endpoint);
        _sock_addr_endpoint(endpoint2, host, port);
    }

    if (endpoint[0] && endpoint[strlen(endpoint) - 1] != ' ') {
        gs_free char *endpoint2 = NULL;

        /* also test with a trailing space */
        endpoint2 = g_strdup_printf("%s ", endpoint);
        _sock_addr_endpoint(endpoint2, host, port);
    }
}

static void
_sock_addr_endpoint_fixed(const char *endpoint, const char *host, guint16 port, guint scope_id)
{
    nm_auto_unref_sockaddrendpoint NMSockAddrEndpoint *ep = NULL;
    const char *                                       s_endpoint;
    const char *                                       s_host;
    gint32                                             s_port;
    int                                                addr_family;
    NMIPAddr                                           addrbin;
    SockAddrUnion                                      sockaddr = {};

    g_assert(endpoint);
    g_assert(host);
    g_assert(port > 0);

    if (!nm_utils_parse_inaddr_bin(AF_UNSPEC, host, &addr_family, &addrbin))
        g_assert_not_reached();

    ep = nm_sock_addr_endpoint_new(endpoint);
    g_assert(ep);

    s_endpoint = nm_sock_addr_endpoint_get_endpoint(ep);
    s_host     = nm_sock_addr_endpoint_get_host(ep);
    s_port     = nm_sock_addr_endpoint_get_port(ep);
    g_assert_cmpstr(endpoint, ==, s_endpoint);
    g_assert_cmpstr(NULL, !=, s_host);
    g_assert_cmpint(port, ==, s_port);

    if (!nm_sock_addr_endpoint_get_fixed_sockaddr(ep, &sockaddr))
        g_assert_not_reached();

    g_assert_cmpint(sockaddr.sa.sa_family, ==, addr_family);
    if (addr_family == AF_INET) {
        const SockAddrUnion s = {
            .in =
                {
                    .sin_family = AF_INET,
                    .sin_addr   = addrbin.addr4_struct,
                    .sin_port   = htons(port),
                },
        };

        g_assert_cmpint(sockaddr.in.sin_addr.s_addr, ==, addrbin.addr4);
        g_assert_cmpint(sockaddr.in.sin_port, ==, htons(port));
        g_assert(memcmp(&s, &sockaddr, sizeof(s.in)) == 0);
    } else if (addr_family == AF_INET6) {
        const SockAddrUnion s = {
            .in6 =
                {
                    .sin6_family   = AF_INET6,
                    .sin6_addr     = addrbin.addr6,
                    .sin6_scope_id = scope_id,
                    .sin6_port     = htons(port),
                },
        };

        g_assert(memcmp(&sockaddr.in6.sin6_addr, &addrbin, sizeof(addrbin.addr6)) == 0);
        g_assert_cmpint(sockaddr.in6.sin6_port, ==, htons(port));
        g_assert_cmpint(sockaddr.in6.sin6_scope_id, ==, scope_id);
        g_assert_cmpint(sockaddr.in6.sin6_flowinfo, ==, 0);
        g_assert(memcmp(&s, &sockaddr, sizeof(s.in6)) == 0);
    } else
        g_assert_not_reached();
}

static void
test_sock_addr_endpoint(void)
{
    _sock_addr_endpoint("", NULL, -1);
    _sock_addr_endpoint(":", NULL, -1);
    _sock_addr_endpoint("a", NULL, -1);
    _sock_addr_endpoint("a:", NULL, -1);
    _sock_addr_endpoint(":a", NULL, -1);
    _sock_addr_endpoint("[]:a", NULL, -1);
    _sock_addr_endpoint("[]a", NULL, -1);
    _sock_addr_endpoint("[]:", NULL, -1);
    _sock_addr_endpoint("[a]b", NULL, -1);
    _sock_addr_endpoint("[a:b", NULL, -1);
    _sock_addr_endpoint("[a[:b", NULL, -1);
    _sock_addr_endpoint("a:6", "a", 6);
    _sock_addr_endpoint("a:6", "a", 6);
    _sock_addr_endpoint("[a]:6", "a", 6);
    _sock_addr_endpoint("[a]:6", "a", 6);
    _sock_addr_endpoint("[a]:655", "a", 655);
    _sock_addr_endpoint("[ab]:][6", NULL, -1);
    _sock_addr_endpoint("[ab]:]:[6", NULL, -1);
    _sock_addr_endpoint("[a[]:b", NULL, -1);
    _sock_addr_endpoint("[192.169.6.x]:6", "192.169.6.x", 6);
    _sock_addr_endpoint("[192.169.6.x]:0", NULL, -1);
    _sock_addr_endpoint("192.169.6.7:0", NULL, -1);

    _sock_addr_endpoint_fixed("192.169.6.7:6", "192.169.6.7", 6, 0);
    _sock_addr_endpoint_fixed("[192.169.6.7]:6", "192.169.6.7", 6, 0);
    _sock_addr_endpoint_fixed("[a:b::]:6", "a:b::", 6, 0);
    _sock_addr_endpoint_fixed("[a:b::%7]:6", "a:b::", 6, 7);
    _sock_addr_endpoint_fixed("a:b::1%75:6", "a:b::1", 6, 75);
    _sock_addr_endpoint_fixed("a:b::1%0:64", "a:b::1", 64, 0);
}

/*****************************************************************************/

static void
test_hexstr2bin(void)
{
    static const HexItem items[] = {
        {"aaBBCCddDD10496a", {0xaa, 0xbb, 0xcc, 0xdd, 0xdd, 0x10, 0x49, 0x6a}, 8},
        {"aa:bb:cc:dd:10:49:6a", {0xaa, 0xbb, 0xcc, 0xdd, 0x10, 0x49, 0x6a}, 7},
        {"0xccddeeff", {0xcc, 0xdd, 0xee, 0xff}, 4},
        {"1:2:66:77:80", {0x01, 0x02, 0x66, 0x77, 0x80}, 5},
        {"e", {0x0e}, 1},
        {"ef", {0xef}, 1},
        {"efa"},
        {"efad", {0xef, 0xad}, 2},
        {"ef:a", {0xef, 0x0a}, 2},
        {"aabb1199:"},
        {":aabb1199"},
        {"aabb$$dd"},
        {"aab:ccc:ddd"},
        {"aab::ccc:ddd"},
    };
    guint i;

    for (i = 0; i < G_N_ELEMENTS(items); i++) {
        gs_unref_bytes GBytes *b = NULL;

        b = nm_utils_hexstr2bin(items[i].str);
        if (items[i].expected_len)
            g_assert(b);
        else
            g_assert(!b);
        g_assert(nm_utils_gbytes_equal_mem(b, items[i].expected, items[i].expected_len));
    }
}

/*****************************************************************************/

static void
_do_strquote(const char *str, gsize buf_len, const char *expected)
{
    char          canary   = (char) nmtst_get_rand_uint32();
    gs_free char *buf_full = g_malloc(buf_len + 2);
    char *        buf      = &buf_full[1];
    const char *  b;

    buf[-1]      = canary;
    buf[buf_len] = canary;

    if (buf_len == 0) {
        b = nm_strquote(NULL, 0, str);
        g_assert(b == NULL);
        g_assert(expected == NULL);
        b = nm_strquote(buf, 0, str);
        g_assert(b == buf);
    } else {
        b = nm_strquote(buf, buf_len, str);
        g_assert(b == buf);
        g_assert(strlen(b) < buf_len);
        g_assert_cmpstr(expected, ==, b);
    }

    g_assert(buf[-1] == canary);
    g_assert(buf[buf_len] == canary);
}

static void
test_nm_strquote(void)
{
    _do_strquote(NULL, 0, NULL);
    _do_strquote("", 0, NULL);
    _do_strquote("a", 0, NULL);
    _do_strquote("ab", 0, NULL);

    _do_strquote(NULL, 1, "");
    _do_strquote(NULL, 2, "(");
    _do_strquote(NULL, 3, "(n");
    _do_strquote(NULL, 4, "(nu");
    _do_strquote(NULL, 5, "(nul");
    _do_strquote(NULL, 6, "(null");
    _do_strquote(NULL, 7, "(null)");
    _do_strquote(NULL, 8, "(null)");
    _do_strquote(NULL, 100, "(null)");

    _do_strquote("", 1, "");
    _do_strquote("", 2, "^");
    _do_strquote("", 3, "\"\"");
    _do_strquote("", 4, "\"\"");
    _do_strquote("", 5, "\"\"");
    _do_strquote("", 100, "\"\"");

    _do_strquote("a", 1, "");
    _do_strquote("a", 2, "^");
    _do_strquote("a", 3, "\"^");
    _do_strquote("a", 4, "\"a\"");
    _do_strquote("a", 5, "\"a\"");
    _do_strquote("a", 6, "\"a\"");
    _do_strquote("a", 100, "\"a\"");

    _do_strquote("ab", 1, "");
    _do_strquote("ab", 2, "^");
    _do_strquote("ab", 3, "\"^");
    _do_strquote("ab", 4, "\"a^");
    _do_strquote("ab", 5, "\"ab\"");
    _do_strquote("ab", 6, "\"ab\"");
    _do_strquote("ab", 7, "\"ab\"");
    _do_strquote("ab", 100, "\"ab\"");

    _do_strquote("abc", 1, "");
    _do_strquote("abc", 2, "^");
    _do_strquote("abc", 3, "\"^");
    _do_strquote("abc", 4, "\"a^");
    _do_strquote("abc", 5, "\"ab^");
    _do_strquote("abc", 6, "\"abc\"");
    _do_strquote("abc", 7, "\"abc\"");
    _do_strquote("abc", 100, "\"abc\"");
}

/*****************************************************************************/

#define NM_UUID_NS_DNS  "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
#define NM_UUID_NS_URL  "6ba7b811-9dad-11d1-80b4-00c04fd430c8"
#define NM_UUID_NS_OID  "6ba7b812-9dad-11d1-80b4-00c04fd430c8"
#define NM_UUID_NS_X500 "6ba7b814-9dad-11d1-80b4-00c04fd430c8"

static const NMUuid *
_uuid(const char *str)
{
    static NMUuid u;

    g_assert(str);
    g_assert(nm_uuid_parse(str, &u));
    return &u;
}

static void
_test_uuid(int         uuid_type,
           const char *expected_uuid,
           const char *str,
           gssize      slen,
           const char *type_args)
{
    gs_free char *uuid_test   = NULL;
    NMUuid        type_args_u = NM_UUID_INIT_ZERO();

    if (type_args) {
        if (!nm_uuid_parse(type_args, &type_args_u))
            g_assert_not_reached();
    }

    uuid_test =
        nm_uuid_generate_from_string_str(str, slen, uuid_type, type_args ? &type_args_u : NULL);

    g_assert(uuid_test);
    g_assert(nm_utils_is_uuid(uuid_test));

    if (!nm_streq(uuid_test, expected_uuid)) {
        g_error("UUID test failed: type=%d; text=%s, len=%lld, ns=%s, uuid=%s, expected=%s",
                uuid_type,
                str,
                (long long) slen,
                NM_IN_SET(uuid_type, NM_UUID_TYPE_VERSION3, NM_UUID_TYPE_VERSION5)
                    ? (type_args ?: "(all-zero)")
                    : (type_args ? "(unknown)" : "(null)"),
                uuid_test,
                expected_uuid);
    }

    if (slen < 0) {
        /* also test that passing slen==-1 yields the same result as passing strlen(str). */
        _test_uuid(uuid_type, expected_uuid, str, strlen(str), type_args);
    } else if (str && slen == 0) {
        /* also test if we accept NULL for slen==0 */
        _test_uuid(uuid_type, expected_uuid, NULL, 0, type_args);
    }

    if (NM_IN_SET(uuid_type, NM_UUID_TYPE_VERSION3, NM_UUID_TYPE_VERSION5) && !type_args) {
        /* For version3 and version5, a missing @type_args is equal to NM_UUID_NS_ZERO */
        _test_uuid(uuid_type, expected_uuid, str, slen, NM_UUID_NS_ZERO);
    }
}

typedef struct {
    const char *uuid3;
    const char *uuid5;
} ExpectedUuids;

static void
test_nm_utils_uuid_generate_from_string(void)
{
    const ExpectedUuids zero_uuids[] = {
        {
            .uuid3 = "19826852-5007-3022-a72a-212f66e9fac3",
            .uuid5 = "b6c54489-38a0-5f50-a60a-fd8d76219cae",
        },
        {
            .uuid3 = "9153af2e-fc8e-34f3-9e8b-81f73b33d0cb",
            .uuid5 = "11116e73-1c03-5de6-9130-5f9925ae8ab4",
        },
        {
            .uuid3 = "2f06a3ae-d78d-30d7-b898-088a0e0b76f6",
            .uuid5 = "1087ebe8-1ef8-5d97-8873-735b4949004d",
        },
        {
            .uuid3 = "aca948e0-1468-3a51-9f2e-c688a484efd7",
            .uuid5 = "7e57d004-2b97-5e7a-b45f-5387367791cd",
        },
        {
            .uuid3 = "b74e537a-53e8-3808-9abd-58546a6542bd",
            .uuid5 = "1dd80df1-492c-5dc5-aec2-6bf0e104f923",
        },
        {
            .uuid3 = "1b00958a-7d76-3d08-8aba-c66c5828658c",
            .uuid5 = "f797f61e-a392-5acf-af25-b46057f1c8e8",
        },
        {
            .uuid3 = "7ba18f7d-c9cf-3b48-a89e-ad79243135cc",
            .uuid5 = "e02c9780-2fc5-5d57-b92f-4cc3a64bff16",
        },
        {
            .uuid3 = "9baf0978-1a60-35c5-9e9b-bec8d259fd4e",
            .uuid5 = "94167980-f909-527e-a4af-bc3155f586d3",
        },
        {
            .uuid3 = "588668c0-7631-39c7-9976-c7d414adf7ba",
            .uuid5 = "9e3eefda-b56e-56bd-8a3a-0b8009d4a536",
        },
        {
            .uuid3 = "8edb3613-9612-3b32-9dd7-0a01aa8ed453",
            .uuid5 = "9b75648e-d38c-54e8-adee-1fb295a079c9",
        },
        {
            .uuid3 = "f3b34394-63a5-3773-9014-1f8a50d765b8",
            .uuid5 = "dd56b598-9e74-58c3-b3e8-2c623780b8ed",
        },
        {
            .uuid3 = "0572965f-05b8-342b-b225-d5c29d449eee",
            .uuid5 = "5666449a-fb7e-55b7-ae9f-0552e6513a10",
        },
        {
            .uuid3 = "6f7177c3-77b0-3f42-82a8-7031e25fcccf",
            .uuid5 = "10b38db9-82fc-528e-9ddb-1f09b7dbf907",
        },
        {
            .uuid3 = "d1e0f845-bc1b-368c-b8c8-49ab0b9e486b",
            .uuid5 = "85492596-9468-5845-9c7f-d4ae999cb751",
        },
        {
            .uuid3 = "46371ea3-c8a3-34d8-b2cf-2fa90bda4378",
            .uuid5 = "22b1c0dd-aa5d-54a4-8768-5adfd0d112bd",
        },
        {
            .uuid3 = "f1e6b499-9b68-343b-a5c5-ece7acc49a68",
            .uuid5 = "9cc429f8-200e-52a3-9e3b-ef134afa1e29",
        },
        {
            .uuid3 = "9ed06458-c712-31dd-aba5-6cf79879fabe",
            .uuid5 = "3949f95c-5d76-5ee2-af60-8e2d8fcf649d",
        },
        {
            .uuid3 = "4ddd5cd7-bc83-36aa-909c-4e660f57c830",
            .uuid5 = "0e994a02-069b-58fb-b3a4-d7dc94e90fca",
        },
        {
            .uuid3 = "335fa537-0909-395d-a696-6f41827dcbeb",
            .uuid5 = "17db3a41-de9b-5c6b-904d-833943209b3c",
        },
        {
            .uuid3 = "dbd58444-05ad-3edd-adc7-4393ecbcb43c",
            .uuid5 = "1bd906f2-05f9-5ab5-a39a-4c17a188f886",
        },
        {
            .uuid3 = "a1c62d82-d13c-361b-8f4e-ca91bc2f7fc5",
            .uuid5 = "ce6550fd-95b7-57e4-9aa7-461522666be4",
        },
        {
            .uuid3 = "e943d83e-3f82-307f-81ed-b7a7bcd0743e",
            .uuid5 = "04aa09ee-b420-57ac-8a23-5d99907fb0a1",
        },
        {
            .uuid3 = "cabf46dd-9f09-375c-8f6e-f2a8cf114709",
            .uuid5 = "8ece2c62-0c31-5c55-b7c6-155381e3780e",
        },
        {
            .uuid3 = "19beddf3-f2fb-340f-96ac-4f394960b7a7",
            .uuid5 = "5762a9f9-9a21-59ab-b0d2-2cb90027ef7f",
        },
        {
            .uuid3 = "08d835c2-f4ca-394c-ba7f-2494d8b60c6c",
            .uuid5 = "23c8409d-4b5f-5b6a-b946-41e49bad6c78",
        },
        {
            .uuid3 = "3b8c6847-5331-35bf-9cd9-ced50e53cd7c",
            .uuid5 = "e8e396be-95d5-5569-8edc-e0b64c2b7613",
        },
        {
            .uuid3 = "e601f160-484b-3254-8f3b-0a25c7203d8a",
            .uuid5 = "bc8b3cbc-ad5b-5808-a1b0-e0f7a1ad68a3",
        },
        {
            .uuid3 = "e5e492ed-5349-379d-b7de-a370a51e44a3",
            .uuid5 = "62c5ed3f-9afa-59ad-874f-a9dd8afc69d4",
        },
        {
            .uuid3 = "c40111f6-fe97-305e-bfce-7db730c3d2ec",
            .uuid5 = "66877a72-7243-59ed-b9e3-b5023b6da9c2",
        },
        {
            .uuid3 = "21e18ea8-95c2-362b-9ca9-25d6a0ff2dff",
            .uuid5 = "49a49eee-7e86-5d66-837a-8a8810cb5562",
        },
        {
            .uuid3 = "adab623b-1343-307f-80d8-58d005376ad9",
            .uuid5 = "e4a2a7ed-3bf3-53cf-a2bb-154dbb39a38c",
        },
        {
            .uuid3 = "67e9fc7c-dafe-356d-ac1a-a63ce3f44813",
            .uuid5 = "50cacfc9-f5d2-52dd-897c-a25a0927b816",
        },
        {
            .uuid3 = "36cc7f20-126c-3e40-94e7-737ac7486547",
            .uuid5 = "ca629991-3f2b-5e86-9bb7-37a335f7d809",
        },
        {
            .uuid3 = "fe282996-ac5e-3d13-b478-5def30007a8e",
            .uuid5 = "c1adf8a7-f72a-58ae-82d5-d18807f12e2e",
        },
        {
            .uuid3 = "3bfe339c-05ae-3233-a1a5-ebf1ead589db",
            .uuid5 = "6120c3cd-24e1-5ce4-987b-f8bfee2e4633",
        },
        {
            .uuid3 = "d1d90bc7-da4a-3cd7-a7c8-a1a89765d8ee",
            .uuid5 = "433d6a26-c319-5fcf-9a30-5ec6ad59d109",
        },
        {
            .uuid3 = "10b88a02-0102-359b-81e9-7e3b0ff7d25e",
            .uuid5 = "77d228d9-1b96-59e2-a07e-a8fdd4f62884",
        },
        {
            .uuid3 = "7da5e4f2-6df0-3aca-a1b0-b7f8b1340e1d",
            .uuid5 = "698259bf-a32b-5e00-9ec6-88b12278c4ad",
        },
        {
            .uuid3 = "cbe24d98-ca20-3058-86b6-24a6b36ceff0",
            .uuid5 = "60dbca63-704f-5666-9f64-f4e1a630c4aa",
        },
        {
            .uuid3 = "04d84e6a-b793-3993-afbf-bae7cfc42b49",
            .uuid5 = "79d63ec0-a39d-557d-8299-f4c97acfadc3",
        },
        {
            .uuid3 = "fdd157d8-a537-350a-9cc9-1930e8666c63",
            .uuid5 = "7df7f75e-a146-5a76-828b-bac052db312b",
        },
        {
            .uuid3 = "0bea36bb-24a7-3ee6-a98d-116433c14cd4",
            .uuid5 = "2bcca2e9-2879-53e3-b09d-cbbfd58771b2",
        },
        {
            .uuid3 = "52b040a4-1b84-32d2-b758-f82386f7e0f0",
            .uuid5 = "cb7bdca3-e9f7-50cd-b72e-73cb9ff24f62",
        },
        {
            .uuid3 = "0f0a4e26-e034-3021-acf2-4e886af43092",
            .uuid5 = "8e428e2b-5da3-5368-b760-5ca07ccbd819",
        },
        {
            .uuid3 = "819d3cd1-afe5-3e4a-9f0c-945e25d09879",
            .uuid5 = "f340ef4d-139c-567a-b0fc-7c495336674e",
        },
        {
            .uuid3 = "e7df1a3b-c9f8-3e5a-88d6-ba72b2a0f27b",
            .uuid5 = "7e3f5fd2-3c93-58d6-9f35-6e0192445b11",
        },
        {
            .uuid3 = "0854bedf-74ba-3f2b-b823-dc2c90d27c76",
            .uuid5 = "bc112b6b-c5de-5ee9-b816-808792743a20",
        },
        {
            .uuid3 = "a1b8c3ba-f821-32ef-a3fd-b97b3855efa8",
            .uuid5 = "47f8f82d-9fcd-553c-90c5-3f3cb3ad00ad",
        },
        {
            .uuid3 = "9458f819-079b-3033-9430-ba10f576c067",
            .uuid5 = "bee5c091-5f01-51fa-86bb-e9488fd3b4da",
        },
        {
            .uuid3 = "8e1f240a-e386-3e00-866a-6f9da1e3503f",
            .uuid5 = "8ea92cea-d741-566f-a44a-d51e65b4c5e4",
        },
    };
    const ExpectedUuids dns_uuids[] = {
        {
            .uuid3 = "4385125b-dd1e-3025-880f-3311517cc8d5",
            .uuid5 = "6af613b6-569c-5c22-9c37-2ed93f31d3af",
        },
        {
            .uuid3 = "afd0b036-625a-3aa8-b639-9dc8c8fff0ff",
            .uuid5 = "b04965e6-a9bb-591f-8f8a-1adcb2c8dc39",
        },
        {
            .uuid3 = "9c45c2f1-1761-3daa-ad31-1ff8703ae846",
            .uuid5 = "4b166dbe-d99d-5091-abdd-95b83330ed3a",
        },
        {
            .uuid3 = "15e0ba07-10e4-3d7f-aaff-c00fed873c88",
            .uuid5 = "98123fde-012f-5ff3-8b50-881449dac91a",
        },
        {
            .uuid3 = "bc27b4db-bc0f-34f9-ae8e-4b72f2d51b60",
            .uuid5 = "6ed955c6-506a-5343-9be4-2c0afae02eef",
        },
        {
            .uuid3 = "7586bfed-b8b8-3bb3-9c95-09a4a79dc0f7",
            .uuid5 = "c8691da2-158a-5ed6-8537-0e6f140801f2",
        },
        {
            .uuid3 = "881430b6-8d28-3175-b87d-e81f2f5978c6",
            .uuid5 = "a6c4fc8f-6950-51de-a9ae-2c519c465071",
        },
        {
            .uuid3 = "24075675-98ae-354e-89ca-0126a9ad36e3",
            .uuid5 = "a9f96b98-dd44-5216-ab0d-dbfc6b262edf",
        },
        {
            .uuid3 = "2c269ea4-dbfd-32dd-9bd7-a5c22677d18b",
            .uuid5 = "e99caacd-6c45-5906-bd9f-b79e62f25963",
        },
        {
            .uuid3 = "44eb0948-118f-3f28-87e4-f61c8f889aba",
            .uuid5 = "e4d80b30-151e-51b5-9f4f-18a3b82718e6",
        },
        {
            .uuid3 = "fc72beeb-f790-36ee-a73d-33888c9d8880",
            .uuid5 = "0159d6c7-973f-5e7a-a9a0-d195d0ea6fe2",
        },
        {
            .uuid3 = "1e46afa2-6176-3cd3-9750-3015846723df",
            .uuid5 = "7fef88f7-411d-5669-b42d-bf5fc7f9b58b",
        },
        {
            .uuid3 = "0042b01d-95bd-343f-bd9f-3186bfd63508",
            .uuid5 = "52524d6e-10dc-5261-aa36-8b2efcbaa5f0",
        },
        {
            .uuid3 = "115ff52f-d605-3b4b-98fe-c0ea57f4930c",
            .uuid5 = "91c274f2-9a0d-5ce6-ac3d-7529f452df21",
        },
        {
            .uuid3 = "ed0221e8-ac7d-393b-821d-25183567885b",
            .uuid5 = "0ff1e264-520d-543a-87dd-181a491e667e",
        },
        {
            .uuid3 = "508ef333-85a6-314c-bcf3-17ddc32b2216",
            .uuid5 = "23986425-d3a5-5e13-8bab-299745777a8d",
        },
        {
            .uuid3 = "a4715ee0-524a-37cc-beb2-a0b5030757b7",
            .uuid5 = "c15b38c9-9a3e-543c-a703-dd742f25b4d5",
        },
        {
            .uuid3 = "d1c72756-aaec-3470-a2f2-97415f44d72f",
            .uuid5 = "db680066-c83d-5ed7-89a4-1d79466ea62d",
        },
        {
            .uuid3 = "7aec2f01-586e-3d53-b8f3-6cf7e6b649a4",
            .uuid5 = "cadb7952-2bba-5609-88d4-8e47ec4e7920",
        },
        {
            .uuid3 = "3d234b88-8d6f-319a-91ea-edb6059fc825",
            .uuid5 = "35140057-a2a4-5adb-a500-46f8ed8b66a9",
        },
        {
            .uuid3 = "d2568554-93ec-30c7-9e15-f383be19e5bb",
            .uuid5 = "66e549b7-01e2-5d07-98d5-430f74d8d3b2",
        },
        {
            .uuid3 = "800e59a7-dd0f-3114-8e58-ab7e213895ca",
            .uuid5 = "292c8e99-2378-55aa-83d8-350e0ac3f1cc",
        },
        {
            .uuid3 = "3b7d03f0-e067-3d72-84f4-e410ac36ef57",
            .uuid5 = "0e3b230a-0509-55d8-96a0-9875f387a2be",
        },
        {
            .uuid3 = "8762be68-de95-391a-94a0-c5fd0446e037",
            .uuid5 = "4c507660-a83b-55c0-9b2b-83eccb07723d",
        },
        {
            .uuid3 = "2bd8b4c9-01af-3cd0-aced-94ee6e2004b8",
            .uuid5 = "a1b9b633-da11-58be-b1a9-5cfa2848f186",
        },
        {
            .uuid3 = "a627d6a4-394a-33f5-b68e-22bfb6488d01",
            .uuid5 = "c2708a8b-120a-56f5-a30d-990048af87cc",
        },
        {
            .uuid3 = "6a592510-17d9-3925-b321-4a8d4927f8d0",
            .uuid5 = "e7263999-68b6-5a23-b530-af25b7efd632",
        },
        {
            .uuid3 = "9ee72491-59c4-333c-bb93-fe733a842fdb",
            .uuid5 = "ce1ae2d5-3454-5952-97ff-36ff935bcfe9",
        },
        {
            .uuid3 = "2591c62c-0a9d-3c28-97bc-fa0401556a3c",
            .uuid5 = "33677b87-bc8d-5ff6-9a25-fe60225e4bf0",
        },
        {
            .uuid3 = "7912be1e-4562-373b-92e2-3d6d2123bc8e",
            .uuid5 = "ed2305ae-e8f9-5387-b860-3d80ae6c02f7",
        },
        {
            .uuid3 = "09370cda-89a4-3a48-b592-9c0486e0d5e4",
            .uuid5 = "604ed872-ae2d-5d91-8e3e-572f3a3aaaa5",
        },
        {
            .uuid3 = "de5980d3-a137-373c-850b-ca3e5f100779",
            .uuid5 = "8f8173d9-2f8d-5636-a693-24d9f79ba651",
        },
        {
            .uuid3 = "9441501d-f633-365a-8955-9df443edc762",
            .uuid5 = "36eb8d4d-b854-51f1-9fdf-3735964225d5",
        },
        {
            .uuid3 = "434ada18-13ce-3c08-8b40-a1a1ae030569",
            .uuid5 = "3493b6ca-f84b-56a9-97cc-c0bd1c46c4c0",
        },
        {
            .uuid3 = "a13b6160-bd23-3710-a150-41d800dd30b4",
            .uuid5 = "f413ea13-fcd9-5b44-9d22-1fa1f7b063a5",
        },
        {
            .uuid3 = "73a67c12-c5f0-3288-ad6a-c78aea0917b0",
            .uuid5 = "f468d924-d23b-56c2-b90f-3d1cf4b45337",
        },
        {
            .uuid3 = "a126ee4f-a222-357d-b71b-7d3f226c559f",
            .uuid5 = "8828c9d6-ed76-5c09-bf64-ba9e9cd90896",
        },
        {
            .uuid3 = "48f4f36b-b015-3137-9b6e-351bb175c7f7",
            .uuid5 = "facb7618-55ca-5c30-9cba-fd567b6c0611",
        },
        {
            .uuid3 = "3fe8f6a3-fe4a-3487-89d6-dd06c6ad02e3",
            .uuid5 = "96f3de0e-6412-5434-b406-67ef3352ab85",
        },
        {
            .uuid3 = "d68fa2d4-adc9-3b20-ac77-42585cd1d59f",
            .uuid5 = "9ebacb89-40ab-52b3-93a2-9054611d8f55",
        },
        {
            .uuid3 = "819f86a3-31d5-3e72-a83e-142c3a3e4832",
            .uuid5 = "681046ff-9129-5ade-b11c-769864e02184",
        },
        {
            .uuid3 = "9957b433-ddc8-3113-a3e6-5512cf13dab1",
            .uuid5 = "c13d0b5d-1ca3-57b6-a23f-8586bca44928",
        },
        {
            .uuid3 = "5aab6e0c-b7d3-379c-92e3-2bfbb5572511",
            .uuid5 = "7c411b5e-9d3f-50b5-9c28-62096e41c4ed",
        },
        {
            .uuid3 = "11c8ff30-3a7d-3547-80a7-d61b8abeeda8",
            .uuid5 = "f825aafe-6696-5121-b263-6b2c408b7f43",
        },
        {
            .uuid3 = "98799b9f-1c5e-30b3-930f-e412b862cbe4",
            .uuid5 = "f2b4caea-61c3-5bed-8ce7-d8b9d16e129e",
        },
        {
            .uuid3 = "9bdf2544-31d8-3555-94b0-6a749118a996",
            .uuid5 = "3593855a-6557-5736-8cab-172c6987f949",
        },
        {
            .uuid3 = "ddcfb9b3-e990-3985-9021-546a2711e7e5",
            .uuid5 = "36392431-d554-5385-b876-7bc6e1cb26b3",
        },
        {
            .uuid3 = "190d7a78-1484-3136-80a6-40f28852785c",
            .uuid5 = "7e645493-0898-5501-8155-e8578b4f5224",
        },
        {
            .uuid3 = "6ed693e4-7dc0-3210-856b-a6eb4cc73e13",
            .uuid5 = "14dc6a81-0491-5683-baaf-7582a61c5798",
        },
        {
            .uuid3 = "b6a14b21-e73a-3ce2-9076-a804c434f5c6",
            .uuid5 = "883e0a9c-e3b3-5f9c-8073-2913cbbb99ec",
        },
    };
    char  i_str[30];
    guint i;

    _test_uuid(NM_UUID_TYPE_LEGACY, "d41d8cd9-8f00-b204-e980-0998ecf8427e", "", -1, NULL);
    _test_uuid(NM_UUID_TYPE_LEGACY, "0cc175b9-c0f1-b6a8-31c3-99e269772661", "a", -1, NULL);
    _test_uuid(NM_UUID_TYPE_LEGACY, "098f6bcd-4621-d373-cade-4e832627b4f6", "test", -1, NULL);
    _test_uuid(NM_UUID_TYPE_LEGACY, "70350f60-27bc-e371-3f6b-76473084309b", "a\0b", 3, NULL);
    _test_uuid(NM_UUID_TYPE_LEGACY,
               "59c0547b-7fe2-1c15-2cce-e328e8bf6742",
               "/etc/NetworkManager/system-connections/em1",
               -1,
               NULL);

    _test_uuid(NM_UUID_TYPE_VERSION3, "4ae71336-e44b-39bf-b9d2-752e234818a5", "", -1, NULL);
    _test_uuid(NM_UUID_TYPE_VERSION3, "0531103a-d8fc-3dd4-b972-d98e4750994e", "a", -1, NULL);
    _test_uuid(NM_UUID_TYPE_VERSION3, "96e17d7a-ac89-38cf-95e1-bf5098da34e1", "test", -1, NULL);
    _test_uuid(NM_UUID_TYPE_VERSION3, "8156568e-4ae6-3f34-a93e-18e2c6cbbf78", "a\0b", 3, NULL);

    _test_uuid(NM_UUID_TYPE_VERSION3,
               "c87ee674-4ddc-3efe-a74e-dfe25da5d7b3",
               "",
               -1,
               NM_UUID_NS_DNS);
    _test_uuid(NM_UUID_TYPE_VERSION3,
               "4c104dd0-4821-30d5-9ce3-0e7a1f8b7c0d",
               "a",
               -1,
               NM_UUID_NS_DNS);
    _test_uuid(NM_UUID_TYPE_VERSION3,
               "45a113ac-c7f2-30b0-90a5-a399ab912716",
               "test",
               -1,
               NM_UUID_NS_DNS);
    _test_uuid(NM_UUID_TYPE_VERSION3,
               "002a0ada-f547-375a-bab5-896a11d1927e",
               "a\0b",
               3,
               NM_UUID_NS_DNS);
    _test_uuid(NM_UUID_TYPE_VERSION3,
               "9a75f5f2-195e-31a9-9d07-8c18b5d3b285",
               "test123",
               -1,
               NM_UUID_NS_DNS);
    _test_uuid(NM_UUID_TYPE_VERSION3,
               "ec794efe-a384-3b11-a0b6-ec8995bc6acc",
               "x",
               -1,
               NM_UUID_NS_DNS);

    _test_uuid(NM_UUID_TYPE_VERSION5, "a7650b9f-f19f-5300-8a13-91160ea8de2c", "a\0b", 3, NULL);
    _test_uuid(NM_UUID_TYPE_VERSION5,
               "4f3f2898-69e3-5a0d-820a-c4e87987dbce",
               "a",
               -1,
               NM_UUID_NS_DNS);
    _test_uuid(NM_UUID_TYPE_VERSION5,
               "05b16a01-46c6-56dd-bd6e-c6dfb4a1427a",
               "x",
               -1,
               NM_UUID_NS_DNS);
    _test_uuid(NM_UUID_TYPE_VERSION5,
               "c9ed566a-6b79-5d3a-b2b7-96a936b48cf3",
               "test123",
               -1,
               NM_UUID_NS_DNS);

    for (i = 0; i < G_N_ELEMENTS(zero_uuids); i++) {
        nm_sprintf_buf(i_str, "%u", i),
            _test_uuid(NM_UUID_TYPE_VERSION3, zero_uuids[i].uuid3, i_str, -1, NULL);
        _test_uuid(NM_UUID_TYPE_VERSION5, zero_uuids[i].uuid5, i_str, -1, NULL);
    }
    for (i = 0; i < G_N_ELEMENTS(dns_uuids); i++) {
        nm_sprintf_buf(i_str, "%u", i),
            _test_uuid(NM_UUID_TYPE_VERSION3, dns_uuids[i].uuid3, i_str, -1, NM_UUID_NS_DNS);
        _test_uuid(NM_UUID_TYPE_VERSION5, dns_uuids[i].uuid5, i_str, -1, NM_UUID_NS_DNS);
    }

    /* examples from cpython unit tests: */
    _test_uuid(NM_UUID_TYPE_VERSION3,
               "6fa459ea-ee8a-3ca4-894e-db77e160355e",
               "python.org",
               -1,
               NM_UUID_NS_DNS);
    _test_uuid(NM_UUID_TYPE_VERSION5,
               "886313e1-3b8a-5372-9b90-0c9aee199e5d",
               "python.org",
               -1,
               NM_UUID_NS_DNS);
    _test_uuid(NM_UUID_TYPE_VERSION3,
               "9fe8e8c4-aaa8-32a9-a55c-4535a88b748d",
               "http://python.org/",
               -1,
               NM_UUID_NS_URL);
    _test_uuid(NM_UUID_TYPE_VERSION5,
               "4c565f0d-3f5a-5890-b41b-20cf47701c5e",
               "http://python.org/",
               -1,
               NM_UUID_NS_URL);
    _test_uuid(NM_UUID_TYPE_VERSION3,
               "dd1a1cef-13d5-368a-ad82-eca71acd4cd1",
               "1.3.6.1",
               -1,
               NM_UUID_NS_OID);
    _test_uuid(NM_UUID_TYPE_VERSION5,
               "1447fa61-5277-5fef-a9b3-fbc6e44f4af3",
               "1.3.6.1",
               -1,
               NM_UUID_NS_OID);
    _test_uuid(NM_UUID_TYPE_VERSION3,
               "658d3002-db6b-3040-a1d1-8ddd7d189a4d",
               "c=ca",
               -1,
               NM_UUID_NS_X500);
    _test_uuid(NM_UUID_TYPE_VERSION5,
               "cc957dd1-a972-5349-98cd-874190002798",
               "c=ca",
               -1,
               NM_UUID_NS_X500);

    _test_uuid(NM_UUID_TYPE_VERSION5,
               "74738ff5-5367-5958-9aee-98fffdcd1876",
               "www.example.org",
               -1,
               NM_UUID_NS_DNS);
}

/*****************************************************************************/

static void
__test_uuid(const char *expected_uuid, const char *str, gssize slen, char *uuid_test)
{
    g_assert(uuid_test);
    g_assert(nm_uuid_is_normalized(uuid_test));

    if (strcmp(uuid_test, expected_uuid)) {
        g_error("UUID test failed (1): text=%s, len=%lld, expected=%s, uuid_test=%s",
                str,
                (long long) slen,
                expected_uuid,
                uuid_test);
    }
    g_free(uuid_test);

    uuid_test = nm_uuid_generate_from_string_str(str, slen, NM_UUID_TYPE_VERSION3, &nm_uuid_ns_1);

    g_assert(uuid_test);
    g_assert(nm_utils_is_uuid(uuid_test));

    if (strcmp(uuid_test, expected_uuid)) {
        g_error("UUID test failed (2): text=%s; len=%lld, expected=%s, uuid2=%s",
                str,
                (long long) slen,
                expected_uuid,
                uuid_test);
    }
    g_free(uuid_test);
}

#define _test_uuid(expected_uuid, str, strlen, ...) \
    __test_uuid(expected_uuid, str, strlen, nm_uuid_generate_from_strings(__VA_ARGS__, NULL))

static void
test_nm_utils_uuid_generate_from_strings(void)
{
    const NMUuid uuid0 = NM_UUID_INIT_ZERO();
    const NMUuid uuid1 = {};
    char         buf[37];

    g_assert_cmpmem(&uuid0, sizeof(uuid0), _uuid("00000000-0000-0000-0000-000000000000"), 16);

    g_assert_cmpmem(&uuid0, sizeof(NMUuid), &uuid1, sizeof(NMUuid));

    g_assert(nm_uuid_is_null(NULL));
    g_assert(nm_uuid_is_null(&uuid0));
    g_assert(nm_uuid_is_null(&nm_uuid_ns_zero));
    g_assert(nm_uuid_is_null(_uuid("00000000-0000-0000-0000-000000000000")));
    g_assert(!nm_uuid_is_null(_uuid("10000000-0000-0000-0000-000000000000")));

    g_assert_cmpstr(NM_UUID_NS_1, ==, nm_uuid_unparse(&nm_uuid_ns_1, buf));
    g_assert_cmpstr(NM_UUID_NS_ZERO, ==, nm_uuid_unparse(&nm_uuid_ns_zero, buf));

    _test_uuid("b07c334a-399b-32de-8d50-58e4e08f98e3", "", 0, NULL);
    _test_uuid("b8a426cb-bcb5-30a3-bd8f-6786fea72df9", "\0", 1, "");
    _test_uuid("12a4a982-7aae-39e1-951e-41aeb1250959", "a\0", 2, "a");
    _test_uuid("69e22c7e-f89f-3a43-b239-1cb52ed8db69", "aa\0", 3, "aa");
    _test_uuid("59829fd3-5ad5-3d90-a7b0-4911747e4088", "\0\0", 2, "", "");
    _test_uuid("01ad0e06-6c50-3384-8d86-ddab81421425", "a\0\0", 3, "a", "");
    _test_uuid("e1ed8647-9ed3-3ec8-8c6d-e8204524d71d", "aa\0\0", 4, "aa", "");
    _test_uuid("fb1c7cd6-275c-3489-9382-83b900da8af0", "\0a\0", 3, "", "a");
    _test_uuid("5d79494e-c4ba-31a6-80a2-d6016ccd7e17", "a\0a\0", 4, "a", "a");
    _test_uuid("fd698d86-1b60-3ebe-855f-7aada9950a8d", "aa\0a\0", 5, "aa", "a");
    _test_uuid("8c573b48-0f01-30ba-bb94-c5f59f4fe517", "\0aa\0", 4, "", "aa");
    _test_uuid("2bdd3d46-eb83-3c53-a41b-a724d04b5544", "a\0aa\0", 5, "a", "aa");
    _test_uuid("13d4b780-07c1-3ba7-b449-81c4844ef039", "aa\0aa\0", 6, "aa", "aa");
    _test_uuid("dd265bf7-c05a-3037-9939-b9629858a477", "a\0b\0", 4, "a", "b");
}

static void
test_nm_uuid_init(void)
{
    char buf[37];

    {
        NMUuid u;

        u = NM_UUID_INIT(47, c4, d7, f9, 2c, 81, 4f, 7b, be, ed, 63, 0a, 7f, 65, cc, 02);
        g_assert_cmpstr("47c4d7f9-2c81-4f7b-beed-630a7f65cc02", ==, nm_uuid_unparse(&u, buf));
    }
    {
        const NMUuid u =
            NM_UUID_INIT(47, c4, d7, f9, 2c, 81, 4f, 7b, be, ed, 63, 0a, 7f, 65, cc, 02);

        g_assert_cmpstr("47c4d7f9-2c81-4f7b-beed-630a7f65cc02", ==, nm_uuid_unparse(&u, buf));
    }
    {
        const struct {
            NMUuid u;
        } u = {NM_UUID_INIT(47, c4, d7, f9, 2c, 81, 4f, 7b, be, ed, 63, 0a, 7f, 65, cc, 02)};

        g_assert_cmpstr("47c4d7f9-2c81-4f7b-beed-630a7f65cc02", ==, nm_uuid_unparse(&u.u, buf));
    }
}

/*****************************************************************************/

static void
test_nm_utils_ascii_str_to_int64_check(const char *str,
                                       guint       base,
                                       gint64      min,
                                       gint64      max,
                                       gint64      fallback,
                                       int         exp_errno,
                                       gint64      exp_val)
{
    gint64 v;

    errno = 1;
    v     = _nm_utils_ascii_str_to_int64(str, base, min, max, fallback);
    g_assert_cmpint(errno, ==, exp_errno);
    g_assert_cmpint(v, ==, exp_val);
}

static void
test_nm_utils_ascii_str_to_int64_do(const char *str,
                                    guint       base,
                                    gint64      min,
                                    gint64      max,
                                    gint64      fallback,
                                    int         exp_errno,
                                    gint64      exp_val)
{
    const char *       sign = "";
    const char *       val;
    static const char *whitespaces[] = {
        "",
        " ",
        "\r\n\t",
        " \r\n\t ",
        " \r\n\t \t\r\n\t",
        NULL,
    };
    static const char *nulls[] = {
        "",
        "0",
        "00",
        "0000",
        "0000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000",
        NULL,
    };
    const char **ws_pre, **ws_post, **null;
    guint        i;

    if (str == NULL || exp_errno != 0) {
        test_nm_utils_ascii_str_to_int64_check(str, base, min, max, fallback, exp_errno, exp_val);
        return;
    }

    if (strncmp(str, "-", 1) == 0)
        sign = "-";

    val = str + strlen(sign);

    for (ws_pre = whitespaces; *ws_pre; ws_pre++) {
        for (ws_post = whitespaces; *ws_post; ws_post++) {
            for (null = nulls; *null; null++) {
                for (i = 0;; i++) {
                    char *      s;
                    const char *str_base = "";

                    if (base == 16) {
                        if (i == 1)
                            str_base = "0x";
                        else if (i > 1)
                            break;
                    } else if (base == 8) {
                        if (i == 1)
                            str_base = "0";
                        else if (i > 1)
                            break;
                    } else if (base == 0) {
                        if (i > 0)
                            break;
                        /* with base==0, a leading zero would be interpreted as octal. Only test without *null */
                        if ((*null)[0])
                            break;
                    } else {
                        if (i > 0)
                            break;
                    }

                    s = g_strdup_printf("%s%s%s%s%s%s",
                                        *ws_pre,
                                        sign,
                                        str_base,
                                        *null,
                                        val,
                                        *ws_post);

                    test_nm_utils_ascii_str_to_int64_check(s,
                                                           base,
                                                           min,
                                                           max,
                                                           fallback,
                                                           exp_errno,
                                                           exp_val);
                    g_free(s);
                }
            }
        }
    }
}

static void
test_nm_utils_ascii_str_to_int64(void)
{
    test_nm_utils_ascii_str_to_int64_do(NULL, 10, 0, 10000, -1, EINVAL, -1);
    test_nm_utils_ascii_str_to_int64_do("", 10, 0, 10000, -1, EINVAL, -1);
    test_nm_utils_ascii_str_to_int64_do("1x", 10, 0, 10000, -1, EINVAL, -1);
    test_nm_utils_ascii_str_to_int64_do("4711", 10, 0, 10000, -1, 0, 4711);
    test_nm_utils_ascii_str_to_int64_do("10000", 10, 0, 10000, -1, 0, 10000);
    test_nm_utils_ascii_str_to_int64_do("10001", 10, 0, 10000, -1, ERANGE, -1);
    test_nm_utils_ascii_str_to_int64_do("FF", 16, 0, 10000, -1, 0, 255);
    test_nm_utils_ascii_str_to_int64_do("FF", 10, 0, 10000, -2, EINVAL, -2);
    test_nm_utils_ascii_str_to_int64_do("9223372036854775807",
                                        10,
                                        0,
                                        G_MAXINT64,
                                        -2,
                                        0,
                                        G_MAXINT64);
    test_nm_utils_ascii_str_to_int64_do("7FFFFFFFFFFFFFFF", 16, 0, G_MAXINT64, -2, 0, G_MAXINT64);
    test_nm_utils_ascii_str_to_int64_do("9223372036854775808", 10, 0, G_MAXINT64, -2, ERANGE, -2);
    test_nm_utils_ascii_str_to_int64_do("-9223372036854775808",
                                        10,
                                        G_MININT64,
                                        0,
                                        -2,
                                        0,
                                        G_MININT64);
    test_nm_utils_ascii_str_to_int64_do("-9223372036854775808",
                                        10,
                                        G_MININT64 + 1,
                                        0,
                                        -2,
                                        ERANGE,
                                        -2);
    test_nm_utils_ascii_str_to_int64_do("-9223372036854775809", 10, G_MININT64, 0, -2, ERANGE, -2);
    test_nm_utils_ascii_str_to_int64_do("1.0", 10, 1, 1, -1, EINVAL, -1);
    test_nm_utils_ascii_str_to_int64_do("1x0", 16, -10, 10, -100, EINVAL, -100);
    test_nm_utils_ascii_str_to_int64_do("0", 16, -10, 10, -100, 0, 0);
    test_nm_utils_ascii_str_to_int64_do("10001111", 2, -1000, 1000, -100000, 0, 0x8F);
    test_nm_utils_ascii_str_to_int64_do("-10001111", 2, -1000, 1000, -100000, 0, -0x8F);
    test_nm_utils_ascii_str_to_int64_do("1111111", 2, G_MININT64, G_MAXINT64, -1, 0, 0x7F);
    test_nm_utils_ascii_str_to_int64_do("111111111111111",
                                        2,
                                        G_MININT64,
                                        G_MAXINT64,
                                        -1,
                                        0,
                                        0x7FFF);
    test_nm_utils_ascii_str_to_int64_do("11111111111111111111111111111111111111111111111",
                                        2,
                                        G_MININT64,
                                        G_MAXINT64,
                                        -1,
                                        0,
                                        0x7FFFFFFFFFFF);
    test_nm_utils_ascii_str_to_int64_do(
        "111111111111111111111111111111111111111111111111111111111111111",
        2,
        G_MININT64,
        G_MAXINT64,
        -1,
        0,
        0x7FFFFFFFFFFFFFFF);
    test_nm_utils_ascii_str_to_int64_do(
        "100000000000000000000000000000000000000000000000000000000000000",
        2,
        G_MININT64,
        G_MAXINT64,
        -1,
        0,
        0x4000000000000000);
    test_nm_utils_ascii_str_to_int64_do(
        "1000000000000000000000000000000000000000000000000000000000000000",
        2,
        G_MININT64,
        G_MAXINT64,
        -1,
        ERANGE,
        -1);
    test_nm_utils_ascii_str_to_int64_do(
        "-100000000000000000000000000000000000000000000000000000000000000",
        2,
        G_MININT64,
        G_MAXINT64,
        -1,
        0,
        -0x4000000000000000);
    test_nm_utils_ascii_str_to_int64_do(
        "111111111111111111111111111111111111111111111111111111111111111",
        2,
        G_MININT64,
        G_MAXINT64,
        -1,
        0,
        0x7FFFFFFFFFFFFFFF);
    test_nm_utils_ascii_str_to_int64_do(
        "-100000000000000000000000000000000000000000000000000000000000000",
        2,
        G_MININT64,
        G_MAXINT64,
        -1,
        0,
        -0x4000000000000000);
    test_nm_utils_ascii_str_to_int64_do("0x70", 10, G_MININT64, G_MAXINT64, -1, EINVAL, -1);
    test_nm_utils_ascii_str_to_int64_do("4711", 0, G_MININT64, G_MAXINT64, -1, 0, 4711);
    test_nm_utils_ascii_str_to_int64_do("04711", 0, G_MININT64, G_MAXINT64, -1, 0, 04711);
    test_nm_utils_ascii_str_to_int64_do("0x4711", 0, G_MININT64, G_MAXINT64, -1, 0, 0x4711);
    test_nm_utils_ascii_str_to_int64_do("080", 0, G_MININT64, G_MAXINT64, -1, EINVAL, -1);
    test_nm_utils_ascii_str_to_int64_do("070", 0, G_MININT64, G_MAXINT64, -1, 0, 7 * 8);
    test_nm_utils_ascii_str_to_int64_do("0x70", 0, G_MININT64, G_MAXINT64, -1, 0, 0x70);

    g_assert_cmpint(21, ==, _nm_utils_ascii_str_to_int64("025", 0, 0, 1000, -1));
    g_assert_cmpint(21, ==, _nm_utils_ascii_str_to_int64("0025", 0, 0, 1000, -1));
    g_assert_cmpint(25, ==, _nm_utils_ascii_str_to_int64("025", 10, 0, 1000, -1));
    g_assert_cmpint(25, ==, _nm_utils_ascii_str_to_int64("0025", 10, 0, 1000, -1));
}

/*****************************************************************************/

static void
test_nm_utils_strstrdictkey(void)
{
#define _VALUES_STATIC(_v1, _v2)                                                    \
    {                                                                               \
        .v1 = _v1, .v2 = _v2, .v_static = _nm_utils_strstrdictkey_static(_v1, _v2), \
    }
    const struct {
        const char *          v1;
        const char *          v2;
        NMUtilsStrStrDictKey *v_static;
    } * val1, *val2,
        values[] = {
            {NULL, NULL},
            {"", NULL},
            {NULL, ""},
            {"a", NULL},
            {NULL, "a"},
            _VALUES_STATIC("", ""),
            _VALUES_STATIC("a", ""),
            _VALUES_STATIC("", "a"),
            _VALUES_STATIC("a", "b"),
        };
    guint i, j;

    for (i = 0; i < G_N_ELEMENTS(values); i++) {
        gs_free NMUtilsStrStrDictKey *key1 = NULL;

        val1 = &values[i];

        key1 = _nm_utils_strstrdictkey_create(val1->v1, val1->v2);
        if (val1->v_static) {
            g_assert(_nm_utils_strstrdictkey_equal(key1, val1->v_static));
            g_assert(_nm_utils_strstrdictkey_equal(val1->v_static, key1));
            g_assert_cmpint(_nm_utils_strstrdictkey_hash(key1),
                            ==,
                            _nm_utils_strstrdictkey_hash(val1->v_static));
        }

        for (j = 0; j < G_N_ELEMENTS(values); j++) {
            gs_free NMUtilsStrStrDictKey *key2 = NULL;

            val2 = &values[j];
            key2 = _nm_utils_strstrdictkey_create(val2->v1, val2->v2);
            if (i != j) {
                g_assert(!_nm_utils_strstrdictkey_equal(key1, key2));
                g_assert(!_nm_utils_strstrdictkey_equal(key2, key1));
            }
        }
    }
}

/*****************************************************************************/

static guint
_g_strv_length(gconstpointer arr)
{
    return arr ? g_strv_length((char **) arr) : 0;
}

static void
test_nm_ptrarray_len(void)
{
#define _PTRARRAY_cmp(len, arr)                         \
    G_STMT_START                                        \
    {                                                   \
        g_assert_cmpint(len, ==, NM_PTRARRAY_LEN(arr)); \
        g_assert_cmpint(len, ==, _g_strv_length(arr));  \
    }                                                   \
    G_STMT_END
#define _PTRARRAY_LEN0(T)                \
    G_STMT_START                         \
    {                                    \
        T **            vnull  = NULL;   \
        T *const *      vnull1 = NULL;   \
        T *const *const vnull2 = NULL;   \
        T *             v0[]   = {NULL}; \
        T *const *      v01    = v0;     \
        T *const *const v02    = v0;     \
        T **const       v03    = v0;     \
                                         \
        _PTRARRAY_cmp(0, vnull);         \
        _PTRARRAY_cmp(0, vnull1);        \
        _PTRARRAY_cmp(0, vnull2);        \
        _PTRARRAY_cmp(0, v0);            \
        _PTRARRAY_cmp(0, v01);           \
        _PTRARRAY_cmp(0, v02);           \
        _PTRARRAY_cmp(0, v03);           \
    }                                    \
    G_STMT_END

    _PTRARRAY_LEN0(char);
    _PTRARRAY_LEN0(const char);
    _PTRARRAY_LEN0(int);
    _PTRARRAY_LEN0(const int);
    _PTRARRAY_LEN0(void *);
    _PTRARRAY_LEN0(void);
    _PTRARRAY_LEN0(const void);

#define _PTRARRAY_LENn(T)                            \
    G_STMT_START                                     \
    {                                                \
        T x[5] = {0};                                \
                                                     \
        T *             v1[] = {&x[0], NULL};        \
        T *const *      v11  = v1;                   \
        T *const *const v12  = v1;                   \
        T **const       v13  = v1;                   \
                                                     \
        T *             v2[] = {&x[0], &x[1], NULL}; \
        T *const *      v21  = v2;                   \
        T *const *const v22  = v2;                   \
        T **const       v23  = v2;                   \
                                                     \
        _PTRARRAY_cmp(1, v1);                        \
        _PTRARRAY_cmp(1, v11);                       \
        _PTRARRAY_cmp(1, v12);                       \
        _PTRARRAY_cmp(1, v13);                       \
                                                     \
        _PTRARRAY_cmp(2, v2);                        \
        _PTRARRAY_cmp(2, v21);                       \
        _PTRARRAY_cmp(2, v22);                       \
        _PTRARRAY_cmp(2, v23);                       \
    }                                                \
    G_STMT_END

    _PTRARRAY_LENn(char);
    _PTRARRAY_LENn(const char);
    _PTRARRAY_LENn(int);
    _PTRARRAY_LENn(const int);
    _PTRARRAY_LENn(void *);
}

/*****************************************************************************/

static void
test_nm_utils_dns_option_validate_do(char *                      option,
                                     gboolean                    ipv6,
                                     const NMUtilsDNSOptionDesc *descs,
                                     gboolean                    exp_result,
                                     char *                      exp_name,
                                     gboolean                    exp_value)
{
    char *   name;
    long     value = 0;
    gboolean result;

    result = _nm_utils_dns_option_validate(option, &name, &value, ipv6, descs);

    g_assert(result == exp_result);
    g_assert_cmpstr(name, ==, exp_name);
    g_assert(value == exp_value);

    g_free(name);
}

static const NMUtilsDNSOptionDesc opt_descs[] = {
    /* name                   num      ipv6 */
    {"opt1", FALSE, FALSE},
    {"opt2", TRUE, FALSE},
    {"opt3", FALSE, TRUE},
    {"opt4", TRUE, TRUE},
    {NULL, FALSE, FALSE}};

static void
test_nm_utils_dns_option_validate(void)
{
    /*                                    opt            ipv6    descs        result name       value */
    test_nm_utils_dns_option_validate_do("", FALSE, NULL, FALSE, NULL, -1);
    test_nm_utils_dns_option_validate_do(":", FALSE, NULL, FALSE, NULL, -1);
    test_nm_utils_dns_option_validate_do(":1", FALSE, NULL, FALSE, NULL, -1);
    test_nm_utils_dns_option_validate_do(":val", FALSE, NULL, FALSE, NULL, -1);
    test_nm_utils_dns_option_validate_do("opt", FALSE, NULL, TRUE, "opt", -1);
    test_nm_utils_dns_option_validate_do("opt:", FALSE, NULL, FALSE, NULL, -1);
    test_nm_utils_dns_option_validate_do("opt:12", FALSE, NULL, TRUE, "opt", 12);
    test_nm_utils_dns_option_validate_do("opt:12 ", FALSE, NULL, FALSE, NULL, -1);
    test_nm_utils_dns_option_validate_do("opt:val", FALSE, NULL, FALSE, NULL, -1);
    test_nm_utils_dns_option_validate_do("opt:2val", FALSE, NULL, FALSE, NULL, -1);
    test_nm_utils_dns_option_validate_do("opt:2:3", FALSE, NULL, FALSE, NULL, -1);
    test_nm_utils_dns_option_validate_do("opt-6", FALSE, NULL, TRUE, "opt-6", -1);

    test_nm_utils_dns_option_validate_do("opt1", FALSE, opt_descs, TRUE, "opt1", -1);
    test_nm_utils_dns_option_validate_do("opt1", TRUE, opt_descs, TRUE, "opt1", -1);
    test_nm_utils_dns_option_validate_do("opt1:3", FALSE, opt_descs, FALSE, NULL, -1);

    test_nm_utils_dns_option_validate_do("opt2", FALSE, opt_descs, FALSE, NULL, -1);
    test_nm_utils_dns_option_validate_do("opt2:5", FALSE, opt_descs, TRUE, "opt2", 5);

    test_nm_utils_dns_option_validate_do("opt3", FALSE, opt_descs, FALSE, NULL, -1);
    test_nm_utils_dns_option_validate_do("opt3", TRUE, opt_descs, TRUE, "opt3", -1);

    test_nm_utils_dns_option_validate_do("opt4", FALSE, opt_descs, FALSE, NULL, -1);
    test_nm_utils_dns_option_validate_do("opt4", TRUE, opt_descs, FALSE, NULL, -1);
    test_nm_utils_dns_option_validate_do("opt4:40", FALSE, opt_descs, FALSE, NULL, -1);
    test_nm_utils_dns_option_validate_do("opt4:40", TRUE, opt_descs, TRUE, "opt4", 40);
}

static void
test_nm_utils_dns_option_find_idx(void)
{
    GPtrArray *options;

    options = g_ptr_array_new();

    g_ptr_array_add(options, "debug");
    g_ptr_array_add(options, "timeout:5");
    g_ptr_array_add(options, "edns0");

    g_assert_cmpint(_nm_utils_dns_option_find_idx(options, "debug"), ==, 0);
    g_assert_cmpint(_nm_utils_dns_option_find_idx(options, "debug:1"), ==, 0);
    g_assert_cmpint(_nm_utils_dns_option_find_idx(options, "timeout"), ==, 1);
    g_assert_cmpint(_nm_utils_dns_option_find_idx(options, "timeout:5"), ==, 1);
    g_assert_cmpint(_nm_utils_dns_option_find_idx(options, "timeout:2"), ==, 1);
    g_assert_cmpint(_nm_utils_dns_option_find_idx(options, "edns0"), ==, 2);
    g_assert_cmpint(_nm_utils_dns_option_find_idx(options, "rotate"), ==, -1);
    g_assert_cmpint(_nm_utils_dns_option_find_idx(options, ""), ==, -1);

    g_ptr_array_free(options, TRUE);
}

/*****************************************************************************/

static void
_json_config_check_valid(const char *conf, gboolean expected)
{
    gs_free_error GError *error = NULL;
    gboolean              res;

    res = nm_utils_is_json_object(conf, &error);
    g_assert_cmpint(res, ==, expected);
    g_assert(res || error);
}

static void
test_nm_utils_check_valid_json(void)
{
    _json_config_check_valid(NULL, FALSE);
    _json_config_check_valid("", FALSE);

    /* Without JSON library everything except empty string is considered valid */
    nmtst_json_vt_reset(FALSE);
    _json_config_check_valid("{ }", TRUE);
    _json_config_check_valid("{'%!-a1} ", TRUE);
    _json_config_check_valid(" {'%!-a1}", TRUE);
    _json_config_check_valid("{'%!-a1", FALSE);

    if (nmtst_json_vt_reset(TRUE)) {
        _json_config_check_valid("{ }", TRUE);
        _json_config_check_valid("{ \"a\" : 1 }", TRUE);
        _json_config_check_valid("{ \"a\" : }", FALSE);
    }
}

static void
_team_config_equal_check(const char *conf1,
                         const char *conf2,
                         gboolean    port_config,
                         gboolean    expected)
{
    nm_auto_free_team_setting NMTeamSetting *team_a = NULL;
    nm_auto_free_team_setting NMTeamSetting *team_b = NULL;
    gboolean                                 is_same;

    if (nmtst_get_rand_bool())
        NM_SWAP(&conf1, &conf2);

    if (!nm_streq0(conf1, conf2)) {
        _team_config_equal_check(conf1, conf1, port_config, TRUE);
        _team_config_equal_check(conf2, conf2, port_config, TRUE);
    }

    team_a = nm_team_setting_new(port_config, conf1);
    team_b = nm_team_setting_new(port_config, conf2);

    is_same = (nm_team_setting_cmp(team_a, team_b, TRUE) == 0);
    g_assert_cmpint(is_same, ==, expected);

    if (nm_streq0(conf1, conf2)) {
        g_assert_cmpint(nm_team_setting_cmp(team_a, team_b, FALSE), ==, 0);
        g_assert(expected);
    } else
        g_assert_cmpint(nm_team_setting_cmp(team_a, team_b, FALSE), !=, 0);
}

static void
test_nm_utils_team_config_equal(void)
{
    int with_json_vt;

    for (with_json_vt = 0; with_json_vt < 2; with_json_vt++) {
        const NMJsonVt *vt;

        vt = nmtst_json_vt_reset(!!with_json_vt);

        _team_config_equal_check("", "", TRUE, TRUE);
        _team_config_equal_check("", " ", TRUE, TRUE);
        _team_config_equal_check("{}", "{ }", TRUE, TRUE);
        _team_config_equal_check("{}", "{", TRUE, TRUE);
        _team_config_equal_check("{ \"a\": 1 }", "{ \"a\": 1 }", TRUE, TRUE);
        _team_config_equal_check("{ \"a\": 1 }", "{ \"a\":   1 }", TRUE, TRUE);

        /* team config */
        _team_config_equal_check("{ }", "{ \"runner\" :  { \"name\" : \"random\"} }", FALSE, !vt);
        _team_config_equal_check("{ \"runner\" :  { \"name\" : \"roundrobin\"} }",
                                 "{ \"runner\" :  { \"name\" : \"random\"} }",
                                 FALSE,
                                 !vt);
        _team_config_equal_check("{ \"runner\" :  { \"name\" : \"random\"} }",
                                 "{ \"runner\" :  { \"name\" : \"random\"} }",
                                 FALSE,
                                 TRUE);
        _team_config_equal_check("{ \"runner\" :  { \"name\" : \"loadbalance\"} }",
                                 "{ \"runner\" :  { \"name\" : \"loadbalance\"} }",
                                 FALSE,
                                 TRUE);
        _team_config_equal_check(
            "{ \"runner\" :  { \"name\" : \"random\"}, \"ports\" : { \"eth0\" : {} } }",
            "{ \"runner\" :  { \"name\" : \"random\"}, \"ports\" : { \"eth1\" : {} } }",
            FALSE,
            TRUE);
        _team_config_equal_check("{ \"runner\" :  { \"name\" : \"lacp\"} }",
                                 "{ \"runner\" :  { \"name\" : \"lacp\", \"tx_hash\" : [ \"eth\", "
                                 "\"ipv4\", \"ipv6\" ] } }",
                                 FALSE,
                                 !vt);
        _team_config_equal_check("{ \"runner\" :  { \"name\" : \"roundrobin\"} }",
                                 "{ \"runner\" :  { \"name\" : \"roundrobin\", \"tx_hash\" : [ "
                                 "\"eth\", \"ipv4\", \"ipv6\" ] } }",
                                 FALSE,
                                 !vt);
        _team_config_equal_check(
            "{ \"runner\" :  { \"name\" : \"lacp\"} }",
            "{ \"runner\" :  { \"name\" : \"lacp\", \"tx_hash\" : [ \"eth\" ] } }",
            FALSE,
            !vt);

        /* team port config */
        _team_config_equal_check("{ }",
                                 "{ \"link_watch\" :  { \"name\" : \"ethtool\"} }",
                                 TRUE,
                                 !vt);
        _team_config_equal_check("{ }",
                                 "{ \"link_watch\" :  { \"name\" : \"arp_ping\"} }",
                                 TRUE,
                                 TRUE);
        _team_config_equal_check("{ \"link_watch\" :  { \"name\" : \"ethtool\"} }",
                                 "{ \"link_watch\" :  { \"name\" : \"arp_ping\"} }",
                                 TRUE,
                                 !vt);
        _team_config_equal_check("{ \"link_watch\" :  { \"name\" : \"arp_ping\"} }",
                                 "{ \"link_watch\" :  { \"name\" : \"arp_ping\"} }",
                                 TRUE,
                                 TRUE);
        _team_config_equal_check(
            "{ \"link_watch\" :  { \"name\" : \"arp_ping\"}, \"ports\" : { \"eth0\" : {} } }",
            "{ \"link_watch\" :  { \"name\" : \"arp_ping\"}, \"ports\" : { \"eth1\" : {} } }",
            TRUE,
            TRUE);
    }

    nmtst_json_vt_reset(TRUE);
}

/*****************************************************************************/

enum TEST_IS_POWER_OF_TWP_ENUM_SIGNED {
    _DUMMY_1 = -1,
};

enum TEST_IS_POWER_OF_TWP_ENUM_UNSIGNED {
    _DUMMY_2,
};

enum TEST_IS_POWER_OF_TWP_ENUM_SIGNED_64 {
    _DUMMY_3 = (1LL << 40),
};

enum TEST_IS_POWER_OF_TWP_ENUM_UNSIGNED_64 {
    _DUMMY_4a = -1,
    _DUMMY_4b = (1LL << 40),
};

#define test_nm_utils_is_power_of_two_do(type, x, expect)                   \
    G_STMT_START                                                            \
    {                                                                       \
        typeof(x) x1 = (x);                                                 \
        type      x2 = (type) x1;                                           \
        gboolean  val;                                                      \
                                                                            \
        val = nm_utils_is_power_of_two(x1);                                 \
        g_assert_cmpint(expect, ==, val);                                   \
        if (x1 != 0)                                                        \
            g_assert_cmpint(val, ==, nm_utils_is_power_of_two_or_zero(x1)); \
        else {                                                              \
            g_assert(nm_utils_is_power_of_two_or_zero(x1));                 \
            g_assert(!val);                                                 \
        }                                                                   \
        if (((typeof(x1)) x2) == x1 && ((typeof(x2)) x1) == x2 && x2 > 0) { \
            /* x2 equals @x, and is positive. Compare to @expect */         \
            g_assert_cmpint(expect, ==, nm_utils_is_power_of_two(x2));      \
        } else if (!(x2 > 0)) {                                             \
            /* a non positive value is always FALSE. */                     \
            g_assert_cmpint(FALSE, ==, nm_utils_is_power_of_two(x2));       \
        }                                                                   \
        if (x2) {                                                           \
            x2 = -x2;                                                       \
            if (!(x2 > 0)) {                                                \
                /* for negative values, we return FALSE. */                 \
                g_assert_cmpint(FALSE, ==, nm_utils_is_power_of_two(x2));   \
            }                                                               \
        }                                                                   \
    }                                                                       \
    G_STMT_END

static void
test_nm_utils_is_power_of_two(void)
{
    guint64 xyes, xno;
    int     i, j;
    GRand * rand = nmtst_get_rand();
    int     numbits;

    g_assert(!nm_utils_is_power_of_two(0));
    g_assert(nm_utils_is_power_of_two_or_zero(0));

    for (i = -1; i < 64; i++) {
        /* find a (positive) x which is a power of two. */
        if (i == -1)
            xyes = 0;
        else {
            xyes = (((guint64) 1) << i);
            g_assert(xyes != 0);
        }

        xno = xyes;
        if (xyes != 0) {
again:
            /* Find another @xno, that is not a power of two. Do that,
             * by randomly setting bits. */
            numbits = g_rand_int_range(rand, 1, 65);
            while (xno != ~((guint64) 0) && numbits > 0) {
                guint64 v = (((guint64) 1) << g_rand_int_range(rand, 0, 64));

                if ((xno | v) != xno) {
                    xno |= v;
                    --numbits;
                }
            }
            if (xno == xyes)
                goto again;
        }

        for (j = 0; j < 2; j++) {
            gboolean expect = j == 0;
            guint64  x      = expect ? xyes : xno;

            if (expect && xyes == 0)
                continue;

            /* check if @x is as @expect, when casted to a certain data type. */
            test_nm_utils_is_power_of_two_do(gint8, x, expect);
            test_nm_utils_is_power_of_two_do(guint8, x, expect);
            test_nm_utils_is_power_of_two_do(gint16, x, expect);
            test_nm_utils_is_power_of_two_do(guint16, x, expect);
            test_nm_utils_is_power_of_two_do(gint32, x, expect);
            test_nm_utils_is_power_of_two_do(guint32, x, expect);
            test_nm_utils_is_power_of_two_do(gint64, x, expect);
            test_nm_utils_is_power_of_two_do(guint64, x, expect);
            test_nm_utils_is_power_of_two_do(char, x, expect);
            test_nm_utils_is_power_of_two_do(unsigned char, x, expect);
            test_nm_utils_is_power_of_two_do(signed char, x, expect);
            test_nm_utils_is_power_of_two_do(enum TEST_IS_POWER_OF_TWP_ENUM_SIGNED, x, expect);
            test_nm_utils_is_power_of_two_do(enum TEST_IS_POWER_OF_TWP_ENUM_UNSIGNED, x, expect);
            test_nm_utils_is_power_of_two_do(enum TEST_IS_POWER_OF_TWP_ENUM_SIGNED_64, x, expect);
            test_nm_utils_is_power_of_two_do(enum TEST_IS_POWER_OF_TWP_ENUM_UNSIGNED_64, x, expect);
        }
    }
}

/*****************************************************************************/

static int
_test_find_binary_search_cmp(gconstpointer a, gconstpointer b, gpointer dummy)
{
    int ia, ib;

    ia = GPOINTER_TO_INT(a);
    ib = GPOINTER_TO_INT(b);

    if (ia == ib)
        return 0;
    if (ia < ib)
        return -1;
    return 1;
}

static void
_test_find_binary_search_do(const int *array, gsize len)
{
    gsize   i;
    gssize  idx, idx2, idx_first, idx_last;
    gs_free gconstpointer *parray  = g_new(gconstpointer, len);
    const int              NEEDLE  = 0;
    gconstpointer          pneedle = GINT_TO_POINTER(NEEDLE);
    gssize                 expected_result;

    for (i = 0; i < len; i++)
        parray[i] = GINT_TO_POINTER(array[i]);

    expected_result = nm_utils_ptrarray_find_first(parray, len, pneedle);

    idx = nm_utils_ptrarray_find_binary_search_range(parray,
                                                     len,
                                                     pneedle,
                                                     _test_find_binary_search_cmp,
                                                     NULL,
                                                     &idx_first,
                                                     &idx_last);

    idx2 = nm_utils_ptrarray_find_binary_search(parray,
                                                len,
                                                pneedle,
                                                _test_find_binary_search_cmp,
                                                NULL);
    g_assert_cmpint(idx, ==, idx2);

    if (expected_result >= 0) {
        g_assert_cmpint(expected_result, ==, idx);
    } else {
        idx2 = ~idx;

        g_assert_cmpint(idx, <, 0);

        g_assert(idx2 >= 0);
        g_assert(idx2 <= len);
        g_assert(idx2 - 1 < 0 || _test_find_binary_search_cmp(parray[idx2 - 1], pneedle, NULL) < 0);
        g_assert(idx2 >= len || _test_find_binary_search_cmp(parray[idx2], pneedle, NULL) > 0);
    }
    g_assert_cmpint(idx, ==, idx_first);
    g_assert_cmpint(idx, ==, idx_last);
    for (i = 0; i < len; i++) {
        int cmp;

        cmp = _test_find_binary_search_cmp(parray[i], pneedle, NULL);
        if (cmp == 0) {
            g_assert(pneedle == parray[i]);
            g_assert(idx >= 0);
            g_assert(i == idx);
        } else {
            g_assert(pneedle != parray[i]);
            if (cmp < 0) {
                if (idx < 0)
                    g_assert(i < ~idx);
                else
                    g_assert(i < idx);
            } else {
                if (idx < 0)
                    g_assert(i >= ~idx);
                else
                    g_assert(i >= idx);
            }
        }
    }
}

static void
_test_find_binary_search_do_uint32(const int *int_array, gsize len)
{
    gssize    idx;
    const int OFFSET          = 100;
    const int NEEDLE          = 0 + OFFSET;
    gssize    expected_result = -1;
    guint32   array[30];

    g_assert(len <= G_N_ELEMENTS(array));

    /* the test data has negative values. Shift them... */
    for (idx = 0; idx < len; idx++) {
        int v = int_array[idx];

        g_assert(v > -OFFSET);
        g_assert(v < OFFSET);
        g_assert(idx == 0 || v > int_array[idx - 1]);
        array[idx] = (guint32) (int_array[idx] + OFFSET);
        if (array[idx] == NEEDLE)
            expected_result = idx;
    }

    idx = nm_utils_array_find_binary_search(array,
                                            sizeof(guint32),
                                            len,
                                            &NEEDLE,
                                            nm_cmp_uint32_p_with_data,
                                            NULL);
    if (expected_result >= 0)
        g_assert_cmpint(expected_result, ==, idx);
    else {
        gssize idx2 = ~idx;
        g_assert_cmpint(idx, <, 0);

        g_assert(idx2 >= 0);
        g_assert(idx2 <= len);
        g_assert(idx2 - 1 < 0 || array[idx2 - 1] < NEEDLE);
        g_assert(idx2 >= len || array[idx2] > NEEDLE);
    }
}
#define test_find_binary_search_do(...)                                   \
    G_STMT_START                                                          \
    {                                                                     \
        const int _array[] = {__VA_ARGS__};                               \
        _test_find_binary_search_do(_array, G_N_ELEMENTS(_array));        \
        _test_find_binary_search_do_uint32(_array, G_N_ELEMENTS(_array)); \
    }                                                                     \
    G_STMT_END

static void
test_nm_utils_ptrarray_find_binary_search(void)
{
    test_find_binary_search_do(0);
    test_find_binary_search_do(-1, 0);
    test_find_binary_search_do(-2, -1, 0);
    test_find_binary_search_do(-3, -2, -1, 0);
    test_find_binary_search_do(0, 1);
    test_find_binary_search_do(0, 1, 2);
    test_find_binary_search_do(-1, 0, 1, 2);
    test_find_binary_search_do(-2, -1, 0, 1, 2);
    test_find_binary_search_do(-3, -2, -1, 0, 1, 2);
    test_find_binary_search_do(-3, -2, -1, 0, 1, 2);
    test_find_binary_search_do(-3, -2, -1, 0, 1, 2, 3);
    test_find_binary_search_do(-3, -2, -1, 0, 1, 2, 3, 4);

    test_find_binary_search_do(-1);
    test_find_binary_search_do(-2, -1);
    test_find_binary_search_do(-3, -2, -1);
    test_find_binary_search_do(1);
    test_find_binary_search_do(1, 2);
    test_find_binary_search_do(-1, 1, 2);
    test_find_binary_search_do(-2, -1, 1, 2);
    test_find_binary_search_do(-3, -2, -1, 1, 2);
    test_find_binary_search_do(-3, -2, -1, 1, 2);
    test_find_binary_search_do(-3, -2, -1, 1, 2, 3);
    test_find_binary_search_do(-3, -2, -1, 1, 2, 3, 4);
}

/*****************************************************************************/

#define BIN_SEARCH_W_DUPS_LEN    100
#define BIN_SEARCH_W_DUPS_JITTER 10

static int
_test_bin_search2_cmp(gconstpointer pa, gconstpointer pb, gpointer user_data)
{
    int a = GPOINTER_TO_INT(pa);
    int b = GPOINTER_TO_INT(pb);

    g_assert(a >= 0 && a <= BIN_SEARCH_W_DUPS_LEN + BIN_SEARCH_W_DUPS_JITTER);
    g_assert(b >= 0 && b <= BIN_SEARCH_W_DUPS_LEN + BIN_SEARCH_W_DUPS_JITTER);
    NM_CMP_DIRECT(a, b);
    return 0;
}

static int
_test_bin_search2_cmp_p(gconstpointer pa, gconstpointer pb, gpointer user_data)
{
    return _test_bin_search2_cmp(*((gpointer *) pa), *((gpointer *) pb), NULL);
}

static void
test_nm_utils_ptrarray_find_binary_search_with_duplicates(void)
{
    gssize        idx, idx2, idx_first2, idx_first, idx_last;
    int           i_test, i_len, i;
    gssize        j;
    gconstpointer arr[BIN_SEARCH_W_DUPS_LEN];
    const int     N_TEST = 10;

    for (i_test = 0; i_test < N_TEST; i_test++) {
        for (i_len = 0; i_len < BIN_SEARCH_W_DUPS_LEN; i_len++) {
            /* fill with random numbers... surely there are some duplicates
             * there... or maybe even there are none... */
            for (i = 0; i < i_len; i++)
                arr[i] =
                    GINT_TO_POINTER(nmtst_get_rand_uint32() % (i_len + BIN_SEARCH_W_DUPS_JITTER));
            g_qsort_with_data(arr, i_len, sizeof(gpointer), _test_bin_search2_cmp_p, NULL);
            for (i = 0; i < i_len + BIN_SEARCH_W_DUPS_JITTER; i++) {
                gconstpointer p = GINT_TO_POINTER(i);

                idx = nm_utils_ptrarray_find_binary_search_range(arr,
                                                                 i_len,
                                                                 p,
                                                                 _test_bin_search2_cmp,
                                                                 NULL,
                                                                 &idx_first,
                                                                 &idx_last);

                idx_first2 = nm_utils_ptrarray_find_first(arr, i_len, p);

                idx2 = nm_utils_array_find_binary_search(arr,
                                                         sizeof(gpointer),
                                                         i_len,
                                                         &p,
                                                         _test_bin_search2_cmp_p,
                                                         NULL);
                g_assert_cmpint(idx, ==, idx2);

                idx2 = nm_utils_ptrarray_find_binary_search(arr,
                                                            i_len,
                                                            p,
                                                            _test_bin_search2_cmp,
                                                            NULL);
                g_assert_cmpint(idx, ==, idx2);

                if (idx_first2 < 0) {
                    g_assert_cmpint(idx, <, 0);
                    g_assert_cmpint(idx, ==, idx_first);
                    g_assert_cmpint(idx, ==, idx_last);
                    idx = ~idx;
                    g_assert_cmpint(idx, >=, 0);
                    g_assert_cmpint(idx, <=, i_len);
                    if (i_len == 0)
                        g_assert_cmpint(idx, ==, 0);
                    else {
                        g_assert(idx == i_len || GPOINTER_TO_INT(arr[idx]) > i);
                        g_assert(idx == 0 || GPOINTER_TO_INT(arr[idx - 1]) < i);
                    }
                } else {
                    g_assert_cmpint(idx_first, ==, idx_first2);
                    g_assert_cmpint(idx_first, >=, 0);
                    g_assert_cmpint(idx_last, <, i_len);
                    g_assert_cmpint(idx_first, <=, idx_last);
                    g_assert_cmpint(idx, >=, idx_first);
                    g_assert_cmpint(idx, <=, idx_last);
                    for (j = idx_first; j < idx_last; j++)
                        g_assert(GPOINTER_TO_INT(arr[j]) == i);
                    g_assert(idx_first == 0 || GPOINTER_TO_INT(arr[idx_first - 1]) < i);
                    g_assert(idx_last == i_len - 1 || GPOINTER_TO_INT(arr[idx_last + 1]) > i);
                }
            }
        }
    }
}

/*****************************************************************************/

static void
_test_nm_utils_enum_to_str_do_full(GType                       type,
                                   int                         flags,
                                   const char *                exp_str,
                                   const NMUtilsEnumValueInfo *value_infos)
{
    gs_free char *str = NULL;
    int           flags2;
    gs_free char *err_token = NULL;
    gboolean      result;

    g_assert(exp_str);

    str = _nm_utils_enum_to_str_full(type, flags, ", ", value_infos);
    g_assert_cmpstr(str, ==, exp_str);

    if (!value_infos) {
        gs_free char *str2 = NULL;

        str2 = nm_utils_enum_to_str(type, flags);
        g_assert_cmpstr(str2, ==, exp_str);
    }

    result = _nm_utils_enum_from_str_full(type, str, &flags2, &err_token, value_infos);
    g_assert(result == TRUE);
    g_assert_cmpint(flags2, ==, flags);
    g_assert_cmpstr(err_token, ==, NULL);
}

#define _test_nm_utils_enum_to_str_do(...) _test_nm_utils_enum_to_str_do_full(__VA_ARGS__, NULL)

static void
_test_nm_utils_enum_from_str_do_full(GType                       type,
                                     const char *                str,
                                     gboolean                    exp_result,
                                     int                         exp_flags,
                                     const char *                exp_err_token,
                                     const NMUtilsEnumValueInfo *value_infos)
{
    int           flags;
    gs_free char *err_token = NULL;
    gboolean      result;

    result = _nm_utils_enum_from_str_full(type, str, &flags, &err_token, value_infos);

    g_assert(result == exp_result);
    g_assert_cmpint(flags, ==, exp_flags);
    g_assert_cmpstr(err_token, ==, exp_err_token);

    if (!value_infos) {
        int           flags2;
        gs_free char *err_token2 = NULL;
        gboolean      result2;

        result2 = nm_utils_enum_from_str(type, str, &flags2, &err_token2);
        g_assert(result2 == exp_result);
        g_assert_cmpint(flags2, ==, exp_flags);
        g_assert_cmpstr(err_token2, ==, exp_err_token);
    }

    if (result) {
        int           flags2;
        gs_free char *str2       = NULL;
        gs_free char *err_token2 = NULL;

        str2 = _nm_utils_enum_to_str_full(type, flags, ", ", value_infos);
        g_assert(str2);

        result = _nm_utils_enum_from_str_full(type, str2, &flags2, &err_token2, value_infos);
        g_assert(result == TRUE);
        g_assert_cmpint(flags2, ==, flags);
        g_assert_cmpstr(err_token, ==, NULL);
    }
}

#define _test_nm_utils_enum_from_str_do(...) _test_nm_utils_enum_from_str_do_full(__VA_ARGS__, NULL)

static void
_test_nm_utils_enum_get_values_do(GType type, int from, int to, const char *exp_str)
{
    gs_free const char **strv = NULL;
    gs_free char *       str  = NULL;

    g_assert(exp_str);

    strv = nm_utils_enum_get_values(type, from, to);
    g_assert(strv);
    str = g_strjoinv(",", (char **) strv);
    g_assert_cmpstr(str, ==, exp_str);
}

static void
test_nm_utils_enum(void)
{
    GType                             bool_enum           = nm_test_general_bool_enum_get_type();
    GType                             meta_flags          = nm_test_general_meta_flags_get_type();
    GType                             color_flags         = nm_test_general_color_flags_get_type();
    static const NMUtilsEnumValueInfo color_value_infos[] = {
        {
            .nick  = "nick-4d",
            .value = 0x4D,
        },
        {
            .nick  = "nick-5",
            .value = 5,
        },
        {
            .nick  = "nick-red",
            .value = NM_TEST_GENERAL_COLOR_FLAGS_RED,
        },
        {0},
    };

    _test_nm_utils_enum_to_str_do(bool_enum, NM_TEST_GENERAL_BOOL_ENUM_YES, "yes");
    _test_nm_utils_enum_to_str_do(bool_enum, NM_TEST_GENERAL_BOOL_ENUM_UNKNOWN, "unknown");
    _test_nm_utils_enum_to_str_do(bool_enum, NM_TEST_GENERAL_BOOL_ENUM_INVALID, "4");
    _test_nm_utils_enum_to_str_do(bool_enum, NM_TEST_GENERAL_BOOL_ENUM_67, "67");
    _test_nm_utils_enum_to_str_do(bool_enum, NM_TEST_GENERAL_BOOL_ENUM_46, "64");

    _test_nm_utils_enum_to_str_do(meta_flags, NM_TEST_GENERAL_META_FLAGS_NONE, "none");
    _test_nm_utils_enum_to_str_do(meta_flags, NM_TEST_GENERAL_META_FLAGS_BAZ, "baz");
    _test_nm_utils_enum_to_str_do(meta_flags,
                                  NM_TEST_GENERAL_META_FLAGS_FOO | NM_TEST_GENERAL_META_FLAGS_BAR
                                      | NM_TEST_GENERAL_META_FLAGS_BAZ,
                                  "foo, bar, baz");
    _test_nm_utils_enum_to_str_do(meta_flags, 0xFF, "foo, bar, baz, 0xf8");
    _test_nm_utils_enum_to_str_do(meta_flags, NM_TEST_GENERAL_META_FLAGS_0x8, "0x8");
    _test_nm_utils_enum_to_str_do(meta_flags, NM_TEST_GENERAL_META_FLAGS_0x4, "0x10");

    _test_nm_utils_enum_to_str_do(color_flags, NM_TEST_GENERAL_COLOR_FLAGS_RED, "red");
    _test_nm_utils_enum_to_str_do(color_flags, NM_TEST_GENERAL_COLOR_FLAGS_WHITE, "0x1");
    _test_nm_utils_enum_to_str_do(color_flags,
                                  NM_TEST_GENERAL_COLOR_FLAGS_RED
                                      | NM_TEST_GENERAL_COLOR_FLAGS_GREEN,
                                  "red, green");

    _test_nm_utils_enum_to_str_do_full(color_flags,
                                       NM_TEST_GENERAL_COLOR_FLAGS_RED
                                           | NM_TEST_GENERAL_COLOR_FLAGS_GREEN,
                                       "nick-red, green",
                                       color_value_infos);

    _test_nm_utils_enum_to_str_do_full(color_flags,
                                       0x4D | NM_TEST_GENERAL_COLOR_FLAGS_RED
                                           | NM_TEST_GENERAL_COLOR_FLAGS_GREEN,
                                       "nick-4d",
                                       color_value_infos);

    _test_nm_utils_enum_to_str_do_full(color_flags,
                                       5 | NM_TEST_GENERAL_COLOR_FLAGS_GREEN,
                                       "nick-5, green",
                                       color_value_infos);

    _test_nm_utils_enum_from_str_do(bool_enum, "", FALSE, 0, NULL);
    _test_nm_utils_enum_from_str_do(bool_enum, " ", FALSE, 0, NULL);
    _test_nm_utils_enum_from_str_do(bool_enum, "invalid", FALSE, 0, "invalid");
    _test_nm_utils_enum_from_str_do(bool_enum, "yes", TRUE, NM_TEST_GENERAL_BOOL_ENUM_YES, NULL);
    _test_nm_utils_enum_from_str_do(bool_enum, "no", TRUE, NM_TEST_GENERAL_BOOL_ENUM_NO, NULL);
    _test_nm_utils_enum_from_str_do(bool_enum, "yes,no", FALSE, 0, "yes,no");

    _test_nm_utils_enum_from_str_do(meta_flags, "", TRUE, 0, NULL);
    _test_nm_utils_enum_from_str_do(meta_flags, " ", TRUE, 0, NULL);
    _test_nm_utils_enum_from_str_do(meta_flags, "foo", TRUE, NM_TEST_GENERAL_META_FLAGS_FOO, NULL);
    _test_nm_utils_enum_from_str_do(meta_flags,
                                    "foo,baz",
                                    TRUE,
                                    NM_TEST_GENERAL_META_FLAGS_FOO | NM_TEST_GENERAL_META_FLAGS_BAZ,
                                    NULL);
    _test_nm_utils_enum_from_str_do(meta_flags,
                                    "foo, baz",
                                    TRUE,
                                    NM_TEST_GENERAL_META_FLAGS_FOO | NM_TEST_GENERAL_META_FLAGS_BAZ,
                                    NULL);
    _test_nm_utils_enum_from_str_do(meta_flags,
                                    "foo,,bar",
                                    TRUE,
                                    NM_TEST_GENERAL_META_FLAGS_FOO | NM_TEST_GENERAL_META_FLAGS_BAR,
                                    NULL);
    _test_nm_utils_enum_from_str_do(meta_flags, "foo,baz,quux,bar", FALSE, 0, "quux");
    _test_nm_utils_enum_from_str_do(meta_flags,
                                    "foo,0x6",
                                    TRUE,
                                    NM_TEST_GENERAL_META_FLAGS_FOO | 0x6,
                                    NULL);
    _test_nm_utils_enum_from_str_do(meta_flags, "0x30,0x08,foo", TRUE, 0x39, NULL);

    _test_nm_utils_enum_from_str_do(color_flags,
                                    "green",
                                    TRUE,
                                    NM_TEST_GENERAL_COLOR_FLAGS_GREEN,
                                    NULL);
    _test_nm_utils_enum_from_str_do(color_flags,
                                    "blue,red",
                                    TRUE,
                                    NM_TEST_GENERAL_COLOR_FLAGS_BLUE
                                        | NM_TEST_GENERAL_COLOR_FLAGS_RED,
                                    NULL);
    _test_nm_utils_enum_from_str_do(color_flags, "blue,white", FALSE, 0, "white");

    _test_nm_utils_enum_from_str_do_full(color_flags,
                                         "nick-red",
                                         TRUE,
                                         NM_TEST_GENERAL_COLOR_FLAGS_RED,
                                         NULL,
                                         color_value_infos);

    _test_nm_utils_enum_from_str_do_full(color_flags, "0x4D", TRUE, 0x4D, NULL, color_value_infos);

    _test_nm_utils_enum_from_str_do_full(color_flags,
                                         "green,nick-4d",
                                         TRUE,
                                         0x4D | NM_TEST_GENERAL_COLOR_FLAGS_GREEN,
                                         NULL,
                                         color_value_infos);

    _test_nm_utils_enum_from_str_do_full(color_flags,
                                         "nick-4d,nick-red,nick-5,green,nick-red",
                                         TRUE,
                                         0x4D | NM_TEST_GENERAL_COLOR_FLAGS_GREEN,
                                         NULL,
                                         color_value_infos);

    _test_nm_utils_enum_from_str_do_full(NM_TYPE_SETTING_CONNECTION_LLMNR,
                                         "-1",
                                         TRUE,
                                         -1,
                                         NULL,
                                         NULL);

    _test_nm_utils_enum_from_str_do_full(NM_TYPE_SETTING_CONNECTION_LLMNR,
                                         "-0x1",
                                         TRUE,
                                         -1,
                                         NULL,
                                         NULL);

    _test_nm_utils_enum_get_values_do(bool_enum, 0, G_MAXINT, "no,yes,maybe,unknown,67,64");
    _test_nm_utils_enum_get_values_do(bool_enum,
                                      NM_TEST_GENERAL_BOOL_ENUM_YES,
                                      NM_TEST_GENERAL_BOOL_ENUM_MAYBE,
                                      "yes,maybe");
    _test_nm_utils_enum_get_values_do(meta_flags, 0, G_MAXINT, "none,foo,bar,baz,0x8,0x10");
    _test_nm_utils_enum_get_values_do(color_flags, 0, G_MAXINT, "blue,red,green");
}

/*****************************************************************************/

static void
_do_test_utils_str_utf8safe_unescape(const char *str, const char *expected, gsize expected_len)
{
    gsize            l;
    const char *     s;
    gs_free gpointer buf_free_1 = NULL;
    gs_free char *   str_free_1 = NULL;

    s = nm_utils_buf_utf8safe_unescape(str, NM_UTILS_STR_UTF8_SAFE_FLAG_NONE, &l, &buf_free_1);
    g_assert_cmpint(expected_len, ==, l);
    g_assert_cmpstr(s, ==, expected);

    if (str == NULL) {
        g_assert(!s);
        g_assert(!buf_free_1);
        g_assert_cmpint(l, ==, 0);
    } else {
        g_assert(s);
        if (!strchr(str, '\\')) {
            g_assert(!buf_free_1);
            g_assert(s == str);
            g_assert_cmpint(l, ==, strlen(str));
        } else {
            g_assert(buf_free_1);
            g_assert(s == buf_free_1);
            g_assert(memcmp(s, expected, expected_len) == 0);
        }
    }

    if (expected && l == strlen(expected)) {
        /* there are no embedded NULs. Check that nm_utils_str_utf8safe_unescape() yields the same result. */
        s = nm_utils_str_utf8safe_unescape(str, NM_UTILS_STR_UTF8_SAFE_FLAG_NONE, &str_free_1);
        g_assert_cmpstr(s, ==, expected);
        g_assert(str);
        if (strchr(str, '\\')) {
            g_assert(str_free_1 != str);
            g_assert(s == str_free_1);
        } else
            g_assert(s == str);
    }
}

#define do_test_utils_str_utf8safe_unescape(str, expected) \
    _do_test_utils_str_utf8safe_unescape("" str "", expected, NM_STRLEN(expected))

static void
_do_test_utils_str_utf8safe(const char *            str,
                            gsize                   str_len,
                            const char *            expected,
                            NMUtilsStrUtf8SafeFlags flags)
{
    const char *  str_safe;
    const char *  buf_safe;
    const char *  s;
    gs_free char *str_free_1  = NULL;
    gs_free char *str_free_2  = NULL;
    gs_free char *str_free_3  = NULL;
    gs_free char *str_free_4  = NULL;
    gs_free char *str_free_5  = NULL;
    gs_free char *str_free_6  = NULL;
    gs_free char *str_free_7  = NULL;
    gs_free char *str_free_8  = NULL;
    gboolean      str_has_nul = FALSE;
#define RND_FLAG                                                \
    ((nmtst_get_rand_bool()) ? NM_UTILS_STR_UTF8_SAFE_FLAG_NONE \
                             : NM_UTILS_STR_UTF8_SAFE_FLAG_SECRET)

    if (expected && strlen(expected) == str_len && memcmp(str, expected, str_len) == 0) {
        g_error("Test error: pass expected as NULL (instead of \"%s\", if the escaping will "
                "produce no difference.",
                expected);
    }

    buf_safe = nm_utils_buf_utf8safe_escape(str, str_len, flags | RND_FLAG, &str_free_1);

    str_safe = nm_utils_str_utf8safe_escape(str, flags | RND_FLAG, &str_free_2);

    if (str_len == 0) {
        g_assert(buf_safe == NULL);
        g_assert(str_free_1 == NULL);
        g_assert(str_safe == str);
        g_assert(str == NULL || str[0] == '\0');
        g_assert(str_free_2 == NULL);
    } else if (str_len == strlen(str)) {
        g_assert(buf_safe);
        g_assert_cmpstr(buf_safe, ==, str_safe);

        /* nm_utils_buf_utf8safe_escape() can only return a pointer equal to the input string,
         * if and only if str_len is negative. Otherwise, the input str won't be NUL terminated
         * and cannot be returned. */
        g_assert(buf_safe != str);
        g_assert(buf_safe == str_free_1);
    } else
        str_has_nul = TRUE;

    str_free_3 = nm_utils_str_utf8safe_escape_cp(str, flags | RND_FLAG);
    g_assert_cmpstr(str_free_3, ==, str_safe);
    g_assert((!str && !str_free_3) || (str != str_free_3));

    if (str_len > 0)
        _do_test_utils_str_utf8safe_unescape(buf_safe, str, str_len);

    if (expected == NULL) {
        g_assert(!str_has_nul);

        g_assert(str_safe == str);
        g_assert(!str_free_2);
        if (str) {
            g_assert(!strchr(str, '\\'));
            g_assert(g_utf8_validate(str, -1, NULL));
        }

        g_assert(str
                 == nm_utils_str_utf8safe_unescape(str_safe,
                                                   NM_UTILS_STR_UTF8_SAFE_FLAG_NONE,
                                                   &str_free_4));
        g_assert(!str_free_4);

        str_free_5 = nm_utils_str_utf8safe_unescape_cp(str_safe, NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
        if (str) {
            g_assert(str_free_5 != str);
            g_assert_cmpstr(str_free_5, ==, str);
        } else
            g_assert(!str_free_5);
        return;
    }

    if (!str_has_nul) {
        g_assert(str);
        g_assert(str_safe != str);
        g_assert(str_safe == str_free_2);
        g_assert(strchr(str, '\\') || !g_utf8_validate(str, -1, NULL)
                 || (NM_FLAGS_HAS(flags, NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_NON_ASCII)
                     && NM_STRCHAR_ANY(str, ch, (guchar) ch >= 127))
                 || (NM_FLAGS_HAS(flags, NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL)
                     && NM_STRCHAR_ANY(str, ch, (guchar) ch < ' ')));
        g_assert(g_utf8_validate(str_safe, -1, NULL));

        str_free_6 = g_strcompress(str_safe);
        g_assert_cmpstr(str, ==, str_free_6);

        str_free_7 = nm_utils_str_utf8safe_unescape_cp(str_safe, NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
        g_assert(str_free_7 != str);
        g_assert_cmpstr(str_free_7, ==, str);

        s = nm_utils_str_utf8safe_unescape(str_safe, NM_UTILS_STR_UTF8_SAFE_FLAG_NONE, &str_free_8);
        g_assert(str_free_8 != str);
        g_assert(s == str_free_8);
        g_assert_cmpstr(str_free_8, ==, str);

        g_assert_cmpstr(str_safe, ==, expected);

        return;
    }

    g_assert_cmpstr(buf_safe, ==, expected);
}
#define do_test_utils_str_utf8safe(str, expected, flags) \
    _do_test_utils_str_utf8safe("" str "", NM_STRLEN(str), expected, flags)

static void
test_utils_str_utf8safe(void)
{
    _do_test_utils_str_utf8safe(NULL, 0, NULL, NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);

    do_test_utils_str_utf8safe("", NULL, NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
    do_test_utils_str_utf8safe("\\", "\\\\", NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
    do_test_utils_str_utf8safe("\\a", "\\\\a", NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
    do_test_utils_str_utf8safe("\314", "\\314", NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
    do_test_utils_str_utf8safe("\314\315x\315\315x",
                               "\\314\\315x\\315\\315x",
                               NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
    do_test_utils_str_utf8safe("\314\315xx", "\\314\\315xx", NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
    do_test_utils_str_utf8safe("\314xx", "\\314xx", NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
    do_test_utils_str_utf8safe("\xa0", "\\240", NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
    do_test_utils_str_utf8safe("\xe2\x91\xa0", NULL, NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
    do_test_utils_str_utf8safe("\xe2\xe2\x91\xa0",
                               "\\342\xe2\x91\xa0",
                               NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
    do_test_utils_str_utf8safe("\xe2\xe2\x91\xa0\xa0",
                               "\\342\xe2\x91\xa0\\240",
                               NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
    do_test_utils_str_utf8safe("a", NULL, NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
    do_test_utils_str_utf8safe("ab", NULL, NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
    do_test_utils_str_utf8safe("ab\314", "ab\\314", NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
    do_test_utils_str_utf8safe("ab\314adsf", "ab\\314adsf", NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
    do_test_utils_str_utf8safe("abadsf", NULL, NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
    do_test_utils_str_utf8safe("abäb", NULL, NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
    do_test_utils_str_utf8safe("x\xa0", "x\\240", NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
    do_test_utils_str_utf8safe("Ä\304ab\\äb", "Ä\\304ab\\\\äb", NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
    do_test_utils_str_utf8safe("Äab\\äb", "Äab\\\\äb", NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
    do_test_utils_str_utf8safe("ÄÄab\\äb", "ÄÄab\\\\äb", NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
    do_test_utils_str_utf8safe("㈞abä㈞b", NULL, NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
    do_test_utils_str_utf8safe("abäb",
                               "ab\\303\\244b",
                               NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_NON_ASCII);
    do_test_utils_str_utf8safe("ab\ab", "ab\\007b", NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL);

    do_test_utils_str_utf8safe("\0", "\\000", NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
    do_test_utils_str_utf8safe("\0a\0", "\\000a\\000", NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
    do_test_utils_str_utf8safe("\\\0", "\\\\\\000", NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
    do_test_utils_str_utf8safe("\n\0", "\n\\000", NM_UTILS_STR_UTF8_SAFE_FLAG_NONE);
    do_test_utils_str_utf8safe("\n\0", "\\012\\000", NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL);

    do_test_utils_str_utf8safe_unescape("\n\\0", "\n\0");
    do_test_utils_str_utf8safe_unescape("\n\\01", "\n\01");
    do_test_utils_str_utf8safe_unescape("\n\\012", "\n\012");
    do_test_utils_str_utf8safe_unescape("\n\\.", "\n.");
    do_test_utils_str_utf8safe_unescape("\\n\\.3\\r", "\n.3\r");

    do_test_utils_str_utf8safe("ab∞c", NULL, NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL);
    do_test_utils_str_utf8safe("ab\ab∞c", "ab\\007b∞c", NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL);
    do_test_utils_str_utf8safe("ab\ab∞c",
                               "ab\\007b\\342\\210\\236c",
                               NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL
                                   | NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_NON_ASCII);
}

/*****************************************************************************/

static int
_test_nm_in_set_get(int *call_counter, gboolean allow_called, int value)
{
    g_assert(call_counter);
    *call_counter += 1;
    if (!allow_called)
        g_assert_not_reached();
    return value;
}

static void
_test_nm_in_set_assert(int *call_counter, int expected)
{
    g_assert(call_counter);
    g_assert_cmpint(expected, ==, *call_counter);
    *call_counter = 0;
}

static void
test_nm_in_set(void)
{
    int call_counter = 0;

#define G(x) _test_nm_in_set_get(&call_counter, TRUE, x)
#define N(x) _test_nm_in_set_get(&call_counter, FALSE, x)
#define _ASSERT(expected, expr)                            \
    G_STMT_START                                           \
    {                                                      \
        _test_nm_in_set_assert(&call_counter, 0);          \
        g_assert(expr);                                    \
        _test_nm_in_set_assert(&call_counter, (expected)); \
    }                                                      \
    G_STMT_END
    _ASSERT(1, !NM_IN_SET(-1, G(1)));
    _ASSERT(1, NM_IN_SET(-1, G(-1)));

    _ASSERT(2, !NM_IN_SET(-1, G(1), G(2)));
    _ASSERT(1, NM_IN_SET(-1, G(-1), N(2)));
    _ASSERT(2, NM_IN_SET(-1, G(1), G(-1)));
    _ASSERT(1, NM_IN_SET(-1, G(-1), N(-1)));

    _ASSERT(3, !NM_IN_SET(-1, G(1), G(2), G(3)));
    _ASSERT(1, NM_IN_SET(-1, G(-1), N(2), N(3)));
    _ASSERT(2, NM_IN_SET(-1, G(1), G(-1), N(3)));
    _ASSERT(3, NM_IN_SET(-1, G(1), G(2), G(-1)));
    _ASSERT(2, NM_IN_SET(-1, G(1), G(-1), N(-1)));
    _ASSERT(1, NM_IN_SET(-1, G(-1), N(2), N(-1)));
    _ASSERT(1, NM_IN_SET(-1, G(-1), N(-1), N(3)));
    _ASSERT(1, NM_IN_SET(-1, G(-1), N(-1), N(-1)));

    _ASSERT(4, !NM_IN_SET(-1, G(1), G(2), G(3), G(4)));
    _ASSERT(1, NM_IN_SET(-1, G(-1), N(2), N(3), N(4)));
    _ASSERT(2, NM_IN_SET(-1, G(1), G(-1), N(3), N(4)));
    _ASSERT(3, NM_IN_SET(-1, G(1), G(2), G(-1), N(4)));
    _ASSERT(4, NM_IN_SET(-1, G(1), G(2), G(3), G(-1)));

    _ASSERT(4, NM_IN_SET(-1, G(1), G(2), G(3), G(-1), G(5)));
    _ASSERT(5, NM_IN_SET(-1, G(1), G(2), G(3), G(4), G(-1)));
    _ASSERT(6, NM_IN_SET(-1, G(1), G(2), G(3), G(4), G(5), G(-1)));

    _ASSERT(1, !NM_IN_SET_SE(-1, G(1)));
    _ASSERT(1, NM_IN_SET_SE(-1, G(-1)));

    _ASSERT(2, !NM_IN_SET_SE(-1, G(1), G(2)));
    _ASSERT(2, NM_IN_SET_SE(-1, G(-1), G(2)));
    _ASSERT(2, NM_IN_SET_SE(-1, G(1), G(-1)));
    _ASSERT(2, NM_IN_SET_SE(-1, G(-1), G(-1)));

    _ASSERT(3, !NM_IN_SET_SE(-1, G(1), G(2), G(3)));
    _ASSERT(3, NM_IN_SET_SE(-1, G(-1), G(2), G(3)));
    _ASSERT(3, NM_IN_SET_SE(-1, G(1), G(-1), G(3)));
    _ASSERT(3, NM_IN_SET_SE(-1, G(1), G(2), G(-1)));
    _ASSERT(3, NM_IN_SET_SE(-1, G(1), G(-1), G(-1)));
    _ASSERT(3, NM_IN_SET_SE(-1, G(-1), G(2), G(-1)));
    _ASSERT(3, NM_IN_SET_SE(-1, G(-1), G(-1), G(3)));
    _ASSERT(3, NM_IN_SET_SE(-1, G(-1), G(-1), G(-1)));

    _ASSERT(4, !NM_IN_SET_SE(-1, G(1), G(2), G(3), G(4)));
    _ASSERT(4, NM_IN_SET_SE(-1, G(-1), G(2), G(3), G(4)));
    _ASSERT(4, NM_IN_SET_SE(-1, G(1), G(-1), G(3), G(4)));
    _ASSERT(4, NM_IN_SET_SE(-1, G(1), G(2), G(-1), G(4)));
    _ASSERT(4, NM_IN_SET_SE(-1, G(1), G(2), G(3), G(-1)));

    _ASSERT(5, NM_IN_SET_SE(-1, G(1), G(2), G(3), G(-1), G(5)));
    _ASSERT(6, NM_IN_SET_SE(-1, G(1), G(2), G(3), G(4), G(5), G(-1)));

    g_assert(!NM_IN_SET(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16));
#undef G
#undef N
#undef _ASSERT
}

/*****************************************************************************/

static const char *
_test_nm_in_set_getstr(int *call_counter, gboolean allow_called, const char *value)
{
    g_assert(call_counter);
    *call_counter += 1;
    if (!allow_called)
        g_assert_not_reached();
    return value;
}

static void
test_nm_in_strset(void)
{
    int call_counter = 0;

#define G(x) _test_nm_in_set_getstr(&call_counter, TRUE, x)
#define N(x) _test_nm_in_set_getstr(&call_counter, FALSE, x)
#define _ASSERT(expected, expr)                            \
    G_STMT_START                                           \
    {                                                      \
        _test_nm_in_set_assert(&call_counter, 0);          \
        g_assert(expr);                                    \
        _test_nm_in_set_assert(&call_counter, (expected)); \
    }                                                      \
    G_STMT_END
    _ASSERT(1, NM_IN_STRSET(NULL, G(NULL)));
    _ASSERT(1, !NM_IN_STRSET("a", G(NULL)));
    _ASSERT(1, !NM_IN_STRSET(NULL, G("a")));

    _ASSERT(1, NM_IN_STRSET_SE(NULL, G(NULL)));
    _ASSERT(1, !NM_IN_STRSET_SE("a", G(NULL)));
    _ASSERT(1, !NM_IN_STRSET_SE(NULL, G("a")));

    _ASSERT(1, NM_IN_STRSET(NULL, G(NULL), N(NULL)));
    _ASSERT(2, !NM_IN_STRSET("a", G(NULL), G(NULL)));
    _ASSERT(2, NM_IN_STRSET(NULL, G("a"), G(NULL)));
    _ASSERT(1, NM_IN_STRSET(NULL, G(NULL), N("a")));
    _ASSERT(2, NM_IN_STRSET("a", G(NULL), G("a")));
    _ASSERT(2, !NM_IN_STRSET(NULL, G("a"), G("a")));
    _ASSERT(1, NM_IN_STRSET(NULL, G(NULL), N("b")));
    _ASSERT(2, !NM_IN_STRSET("a", G(NULL), G("b")));
    _ASSERT(2, !NM_IN_STRSET(NULL, G("a"), G("b")));

    _ASSERT(2, NM_IN_STRSET_SE(NULL, G(NULL), G(NULL)));
    _ASSERT(2, !NM_IN_STRSET_SE("a", G(NULL), G(NULL)));
    _ASSERT(2, NM_IN_STRSET_SE(NULL, G("a"), G(NULL)));
    _ASSERT(2, NM_IN_STRSET_SE(NULL, G(NULL), G("a")));
    _ASSERT(2, NM_IN_STRSET_SE("a", G(NULL), G("a")));
    _ASSERT(2, !NM_IN_STRSET_SE(NULL, G("a"), G("a")));
    _ASSERT(2, NM_IN_STRSET_SE(NULL, G(NULL), G("b")));
    _ASSERT(2, !NM_IN_STRSET_SE("a", G(NULL), G("b")));
    _ASSERT(2, !NM_IN_STRSET_SE(NULL, G("a"), G("b")));

    _ASSERT(1, NM_IN_STRSET(NULL, G(NULL), N(NULL), N(NULL)));
    _ASSERT(3, !NM_IN_STRSET("a", G(NULL), G(NULL), G(NULL)));
    _ASSERT(2, NM_IN_STRSET(NULL, G("a"), G(NULL), N(NULL)));
    _ASSERT(1, NM_IN_STRSET(NULL, G(NULL), N("a"), N(NULL)));
    _ASSERT(2, NM_IN_STRSET("a", G(NULL), G("a"), N(NULL)));
    _ASSERT(3, NM_IN_STRSET(NULL, G("a"), G("a"), G(NULL)));
    _ASSERT(1, NM_IN_STRSET(NULL, G(NULL), N("b"), N(NULL)));
    _ASSERT(3, !NM_IN_STRSET("a", G(NULL), G("b"), G(NULL)));
    _ASSERT(3, NM_IN_STRSET(NULL, G("a"), G("b"), G(NULL)));
    _ASSERT(1, NM_IN_STRSET(NULL, G(NULL), N(NULL), N("a")));
    _ASSERT(3, NM_IN_STRSET("a", G(NULL), G(NULL), G("a")));
    _ASSERT(2, NM_IN_STRSET(NULL, G("a"), G(NULL), N("a")));
    _ASSERT(1, NM_IN_STRSET(NULL, G(NULL), N("a"), N("a")));
    _ASSERT(2, NM_IN_STRSET("a", G(NULL), G("a"), N("a")));
    _ASSERT(3, !NM_IN_STRSET(NULL, G("a"), G("a"), G("a")));
    _ASSERT(1, NM_IN_STRSET(NULL, G(NULL), N("b"), N("a")));
    _ASSERT(3, NM_IN_STRSET("a", G(NULL), G("b"), G("a")));
    _ASSERT(3, !NM_IN_STRSET(NULL, G("a"), G("b"), G("a")));
    _ASSERT(1, NM_IN_STRSET(NULL, G(NULL), N(NULL), N("b")));
    _ASSERT(3, !NM_IN_STRSET("a", G(NULL), G(NULL), G("b")));
    _ASSERT(2, NM_IN_STRSET(NULL, G("a"), G(NULL), N("b")));
    _ASSERT(1, NM_IN_STRSET(NULL, G(NULL), N("a"), N("b")));
    _ASSERT(2, NM_IN_STRSET("a", G(NULL), G("a"), N("b")));
    _ASSERT(3, !NM_IN_STRSET(NULL, G("a"), G("a"), G("b")));
    _ASSERT(1, NM_IN_STRSET(NULL, G(NULL), N("b"), N("b")));
    _ASSERT(3, !NM_IN_STRSET("a", G(NULL), G("b"), G("b")));
    _ASSERT(3, !NM_IN_STRSET(NULL, G("a"), G("b"), G("b")));

    _ASSERT(3, NM_IN_STRSET_SE(NULL, G(NULL), G(NULL), G(NULL)));
    _ASSERT(3, !NM_IN_STRSET_SE("a", G(NULL), G(NULL), G(NULL)));
    _ASSERT(3, NM_IN_STRSET_SE(NULL, G("a"), G(NULL), G(NULL)));
    _ASSERT(3, NM_IN_STRSET_SE(NULL, G(NULL), G("a"), G(NULL)));
    _ASSERT(3, NM_IN_STRSET_SE("a", G(NULL), G("a"), G(NULL)));
    _ASSERT(3, NM_IN_STRSET_SE(NULL, G("a"), G("a"), G(NULL)));
    _ASSERT(3, NM_IN_STRSET_SE(NULL, G(NULL), G("b"), G(NULL)));
    _ASSERT(3, !NM_IN_STRSET_SE("a", G(NULL), G("b"), G(NULL)));
    _ASSERT(3, NM_IN_STRSET_SE(NULL, G("a"), G("b"), G(NULL)));
    _ASSERT(3, NM_IN_STRSET_SE(NULL, G(NULL), G(NULL), G("a")));
    _ASSERT(3, NM_IN_STRSET_SE("a", G(NULL), G(NULL), G("a")));
    _ASSERT(3, NM_IN_STRSET_SE(NULL, G("a"), G(NULL), G("a")));
    _ASSERT(3, NM_IN_STRSET_SE(NULL, G(NULL), G("a"), G("a")));
    _ASSERT(3, NM_IN_STRSET_SE("a", G(NULL), G("a"), G("a")));
    _ASSERT(3, !NM_IN_STRSET_SE(NULL, G("a"), G("a"), G("a")));
    _ASSERT(3, NM_IN_STRSET_SE(NULL, G(NULL), G("b"), G("a")));
    _ASSERT(3, NM_IN_STRSET_SE("a", G(NULL), G("b"), G("a")));
    _ASSERT(3, !NM_IN_STRSET_SE(NULL, G("a"), G("b"), G("a")));
    _ASSERT(3, NM_IN_STRSET_SE(NULL, G(NULL), G(NULL), G("b")));
    _ASSERT(3, !NM_IN_STRSET_SE("a", G(NULL), G(NULL), G("b")));
    _ASSERT(3, NM_IN_STRSET_SE(NULL, G("a"), G(NULL), G("b")));
    _ASSERT(3, NM_IN_STRSET_SE(NULL, G(NULL), G("a"), G("b")));
    _ASSERT(3, NM_IN_STRSET_SE("a", G(NULL), G("a"), G("b")));
    _ASSERT(3, !NM_IN_STRSET_SE(NULL, G("a"), G("a"), G("b")));
    _ASSERT(3, NM_IN_STRSET_SE(NULL, G(NULL), G("b"), G("b")));
    _ASSERT(3, !NM_IN_STRSET_SE("a", G(NULL), G("b"), G("b")));
    _ASSERT(3, !NM_IN_STRSET_SE(NULL, G("a"), G("b"), G("b")));

    _ASSERT(3, NM_IN_STRSET("a", G(NULL), G("b"), G("a"), N("a")));
    _ASSERT(4, NM_IN_STRSET("a", G(NULL), G("b"), G("c"), G("a")));
    _ASSERT(4, !NM_IN_STRSET("a", G(NULL), G("b"), G("c"), G("d")));

    _ASSERT(4, NM_IN_STRSET("a", G(NULL), G("b"), G("c"), G("a"), N("a")));
    _ASSERT(5, NM_IN_STRSET("a", G(NULL), G("b"), G("c"), G("d"), G("a")));
    _ASSERT(5, !NM_IN_STRSET("a", G(NULL), G("b"), G("c"), G("d"), G("e")));

    _ASSERT(5, NM_IN_STRSET("a", G(NULL), G("b"), G("c"), G("d"), G("a"), N("a")));
    _ASSERT(6, NM_IN_STRSET("a", G(NULL), G("b"), G("c"), G("d"), G("e"), G("a")));
    _ASSERT(6, !NM_IN_STRSET("a", G(NULL), G("b"), G("c"), G("d"), G("e"), G("f")));

    g_assert(!NM_IN_STRSET(NULL,
                           "1",
                           "2",
                           "3",
                           "4",
                           "5",
                           "6",
                           "7",
                           "8",
                           "9",
                           "10",
                           "11",
                           "12",
                           "13",
                           "14",
                           "15",
                           "16"));
    g_assert(!NM_IN_STRSET("_",
                           "1",
                           "2",
                           "3",
                           "4",
                           "5",
                           "6",
                           "7",
                           "8",
                           "9",
                           "10",
                           "11",
                           "12",
                           "13",
                           "14",
                           "15",
                           "16"));
    g_assert(NM_IN_STRSET("10",
                          "1",
                          "2",
                          "3",
                          "4",
                          "5",
                          "6",
                          "7",
                          "8",
                          "9",
                          "10",
                          "11",
                          "12",
                          "13",
                          "14",
                          "15",
                          "16"));
#undef G
#undef N
#undef _ASSERT
}

static void
test_route_attributes_parse(void)
{
    GHashTable *ht;
    GError *    error = NULL;
    GVariant *  variant;

    ht = nm_utils_parse_variant_attributes("mtu=1400  src=1.2.3.4 cwnd=14",
                                           ' ',
                                           '=',
                                           FALSE,
                                           nm_ip_route_get_variant_attribute_spec(),
                                           &error);
    g_assert_no_error(error);
    g_assert(ht);
    g_hash_table_unref(ht);

    ht = nm_utils_parse_variant_attributes("mtu=1400 src=1.2.3.4 cwnd=14 \\",
                                           ' ',
                                           '=',
                                           FALSE,
                                           nm_ip_route_get_variant_attribute_spec(),
                                           &error);
    g_assert_error(error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED);
    g_assert(!ht);
    g_clear_error(&error);

    ht = nm_utils_parse_variant_attributes("mtu.1400 src.1\\.2\\.3\\.4 ",
                                           ' ',
                                           '.',
                                           FALSE,
                                           nm_ip_route_get_variant_attribute_spec(),
                                           &error);
    g_assert(ht);
    g_assert_no_error(error);
    variant = g_hash_table_lookup(ht, NM_IP_ROUTE_ATTRIBUTE_MTU);
    g_assert(variant);
    g_assert(g_variant_is_of_type(variant, G_VARIANT_TYPE_UINT32));
    g_assert_cmpuint(g_variant_get_uint32(variant), ==, 1400);

    variant = g_hash_table_lookup(ht, NM_IP_ROUTE_ATTRIBUTE_SRC);
    g_assert(variant);
    g_assert(g_variant_is_of_type(variant, G_VARIANT_TYPE_STRING));
    g_assert_cmpstr(g_variant_get_string(variant, NULL), ==, "1.2.3.4");
    g_hash_table_unref(ht);

    ht = nm_utils_parse_variant_attributes("from:fd01\\:\\:42\\/64/initrwnd:21",
                                           '/',
                                           ':',
                                           FALSE,
                                           nm_ip_route_get_variant_attribute_spec(),
                                           &error);
    g_assert(ht);
    g_assert_no_error(error);
    variant = g_hash_table_lookup(ht, NM_IP_ROUTE_ATTRIBUTE_INITRWND);
    g_assert(variant);
    g_assert(g_variant_is_of_type(variant, G_VARIANT_TYPE_UINT32));
    g_assert_cmpuint(g_variant_get_uint32(variant), ==, 21);

    variant = g_hash_table_lookup(ht, NM_IP_ROUTE_ATTRIBUTE_FROM);
    g_assert(variant);
    g_assert(g_variant_is_of_type(variant, G_VARIANT_TYPE_STRING));
    g_assert_cmpstr(g_variant_get_string(variant, NULL), ==, "fd01::42/64");
    g_hash_table_unref(ht);
}

static void
test_route_attributes_format(void)
{
    gs_unref_hashtable GHashTable *ht = NULL;
    char *                         str;

    ht = g_hash_table_new_full(nm_str_hash, g_str_equal, NULL, (GDestroyNotify) g_variant_unref);

    str = nm_utils_format_variant_attributes(NULL, ' ', '=');
    g_assert_cmpstr(str, ==, NULL);

    str = nm_utils_format_variant_attributes(ht, ' ', '=');
    g_assert_cmpstr(str, ==, NULL);

    g_hash_table_insert(ht, NM_IP_ROUTE_ATTRIBUTE_MTU, g_variant_new_uint32(5000));
    g_hash_table_insert(ht, NM_IP_ROUTE_ATTRIBUTE_INITRWND, g_variant_new_uint32(20));
    g_hash_table_insert(ht, NM_IP_ROUTE_ATTRIBUTE_LOCK_MTU, g_variant_new_boolean(TRUE));
    g_hash_table_insert(ht, NM_IP_ROUTE_ATTRIBUTE_SRC, g_variant_new_string("aaaa:bbbb::1"));
    str = nm_utils_format_variant_attributes(ht, ' ', '=');
    g_assert_cmpstr(str, ==, "initrwnd=20 lock-mtu=true mtu=5000 src=aaaa:bbbb::1");
    g_hash_table_remove_all(ht);
    g_free(str);

    g_hash_table_insert(ht, NM_IP_ROUTE_ATTRIBUTE_WINDOW, g_variant_new_uint32(30000));
    g_hash_table_insert(ht, NM_IP_ROUTE_ATTRIBUTE_INITCWND, g_variant_new_uint32(21));
    g_hash_table_insert(ht,
                        NM_IP_ROUTE_ATTRIBUTE_FROM,
                        g_variant_new_string("aaaa:bbbb:cccc:dddd::/64"));
    str = nm_utils_format_variant_attributes(ht, '/', ':');
    g_assert_cmpstr(str, ==, "from:aaaa\\:bbbb\\:cccc\\:dddd\\:\\:\\/64/initcwnd:21/window:30000");
    g_hash_table_remove_all(ht);
    g_free(str);
}

/*****************************************************************************/

static void
test_variant_attribute_spec(void)
{
    const NMVariantAttributeSpec *const *const specs_list[] = {
        nm_ip_route_get_variant_attribute_spec(),
    };
    int i_specs;

    for (i_specs = 0; i_specs < G_N_ELEMENTS(specs_list); i_specs++) {
        const NMVariantAttributeSpec *const *const specs = specs_list[i_specs];
        gsize                                      len;
        gsize                                      i;

        g_assert(specs);

        len = NM_PTRARRAY_LEN(specs);
        g_assert_cmpint(len, >, 0u);

        _nmtst_variant_attribute_spec_assert_sorted(specs, len);
        for (i = 0; i < len; i++)
            g_assert(specs[i]
                     == _nm_variant_attribute_spec_find_binary_search(specs, len, specs[i]->name));
        g_assert(!_nm_variant_attribute_spec_find_binary_search(specs, len, "bogus"));
    }
}

/*****************************************************************************/

static gboolean
do_test_nm_set_out_called(int *call_count)
{
    (*call_count)++;
    return TRUE;
}

static void
test_nm_set_out(void)
{
    gboolean  val;
    gboolean *p_val;
    int       call_count;

    /* NM_SET_OUT() has an unexpected non-function like behavior
     * wrt. side-effects of the value argument. Test it */

    p_val      = &val;
    call_count = 0;
    NM_SET_OUT(p_val, do_test_nm_set_out_called(&call_count));
    g_assert_cmpint(call_count, ==, 1);

    p_val      = NULL;
    call_count = 0;
    NM_SET_OUT(p_val, do_test_nm_set_out_called(&call_count));
    g_assert_cmpint(call_count, ==, 0);

    /* test that we successfully re-defined _G_BOOLEAN_EXPR() */
#define _T1(a)           \
    ({                   \
        g_assert(a > 2); \
        a;               \
    })
    g_assert(_T1(3) > 1);
#undef _T1
}

/*****************************************************************************/

static void
test_get_start_time_for_pid(void)
{
    guint64 x_start_time;
    char    x_state;
    pid_t   x_ppid;

    x_start_time = nm_utils_get_start_time_for_pid(getpid(), &x_state, &x_ppid);

    g_assert(x_start_time > 0);
    g_assert(x_ppid == getppid());
    g_assert(!NM_IN_SET(x_state, '\0', ' '));
}

/*****************************************************************************/

static void
test_nm_va_args_macros(void)
{
#define GET_NARG_1(...) NM_NARG(__VA_ARGS__)

    g_assert_cmpint(0, ==, GET_NARG_1());
    g_assert_cmpint(1, ==, GET_NARG_1(x));
    g_assert_cmpint(2, ==, GET_NARG_1(, ));
    g_assert_cmpint(2, ==, GET_NARG_1(, x));
    g_assert_cmpint(2, ==, GET_NARG_1(x, ));
    g_assert_cmpint(2, ==, GET_NARG_1(x, x));
    g_assert_cmpint(3, ==, GET_NARG_1(, , ));
    g_assert_cmpint(3, ==, GET_NARG_1(, , x));
    g_assert_cmpint(3, ==, GET_NARG_1(, x, ));
    g_assert_cmpint(3, ==, GET_NARG_1(, x, x));
    g_assert_cmpint(3, ==, GET_NARG_1(x, , ));
    g_assert_cmpint(3, ==, GET_NARG_1(x, , x));
    g_assert_cmpint(3, ==, GET_NARG_1(x, x, ));
    g_assert_cmpint(3, ==, GET_NARG_1(x, x, x));
    g_assert_cmpint(4, ==, GET_NARG_1(, , , ));
    g_assert_cmpint(4, ==, GET_NARG_1(, , , x));
    g_assert_cmpint(4, ==, GET_NARG_1(, , x, ));
    g_assert_cmpint(4, ==, GET_NARG_1(, , x, x));
    g_assert_cmpint(4, ==, GET_NARG_1(, x, , ));
    g_assert_cmpint(4, ==, GET_NARG_1(, x, , x));
    g_assert_cmpint(4, ==, GET_NARG_1(, x, x, ));
    g_assert_cmpint(4, ==, GET_NARG_1(, x, x, x));
    g_assert_cmpint(4, ==, GET_NARG_1(x, , , ));
    g_assert_cmpint(4, ==, GET_NARG_1(x, , , x));
    g_assert_cmpint(4, ==, GET_NARG_1(x, , x, ));
    g_assert_cmpint(4, ==, GET_NARG_1(x, , x, x));
    g_assert_cmpint(4, ==, GET_NARG_1(x, x, , ));
    g_assert_cmpint(4, ==, GET_NARG_1(x, x, , x));
    g_assert_cmpint(4, ==, GET_NARG_1(x, x, x, ));
    g_assert_cmpint(4, ==, GET_NARG_1(x, x, x, x));

    g_assert_cmpint(5, ==, GET_NARG_1(x, x, x, x, x));
    g_assert_cmpint(6, ==, GET_NARG_1(x, x, x, x, x, x));
    g_assert_cmpint(7, ==, GET_NARG_1(x, x, x, x, x, x, x));
    g_assert_cmpint(8, ==, GET_NARG_1(x, x, x, x, x, x, x, x));
    g_assert_cmpint(9, ==, GET_NARG_1(x, x, x, x, x, x, x, x, x));
    g_assert_cmpint(10, ==, NM_NARG(x, x, x, x, x, x, x, x, x, x));

    G_STATIC_ASSERT_EXPR(0 == GET_NARG_1());
    G_STATIC_ASSERT_EXPR(1 == GET_NARG_1(x));
    G_STATIC_ASSERT_EXPR(2 == GET_NARG_1(x, x));

    /* clang-format off */
    G_STATIC_ASSERT_EXPR(NM_NARG(
                                 1,2,3,4,5,6,7,8,9,10,
                                 1,2,3,4,5,6,7,8,9,20,
                                 1,2,3,4,5,6,7,8,9,30
                                 ) == 30);
    G_STATIC_ASSERT_EXPR(NM_NARG(
                                 1,2,3,4,5,6,7,8,9,10,
                                 1,2,3,4,5,6,7,8,9,20,
                                 1,2,3,4,5,6,7,8,9,30,
                                 1,2,3,4,5,6,7,8,9,40,
                                 1,2,3,4,5,6,7,8,9,50,
                                 1,2,3,4,5,6,7,8,9,60,
                                 1,2,3,4,5,6,7,8,9,70,
                                 1,2,3,4,5,6,7,8,9,80
                                 ) == 80);
    G_STATIC_ASSERT_EXPR(NM_NARG(
                                 1,2,3,4,5,6,7,8,9,10,
                                 1,2,3,4,5,6,7,8,9,20,
                                 1,2,3,4,5,6,7,8,9,30,
                                 1,2,3,4,5,6,7,8,9,40,
                                 1,2,3,4,5,6,7,8,9,50,
                                 1,2,3,4,5,6,7,8,9,60,
                                 1,2,3,4,5,6,7,8,9,70,
                                 1,2,3,4,5,6,7,8,9,80,
                                 1,2,3,4,5,6,7,8,9,90,
                                 1,2,3,4,5,6,7,8,9,100,
                                 1,2,3,4,5,6,7,8,9,110,
                                 1,2,3,4,5,6,7,8,9,120
                                 ) == 120);
    /* clang-format on */

    G_STATIC_ASSERT_EXPR(NM_NARG_MAX1() == 0);
    G_STATIC_ASSERT_EXPR(NM_NARG_MAX1(1) == 1);
    G_STATIC_ASSERT_EXPR(NM_NARG_MAX1(1, 2) == 1);
    G_STATIC_ASSERT_EXPR(NM_NARG_MAX1(1, 2, 3) == 1);

    G_STATIC_ASSERT_EXPR(NM_NARG_MAX2() == 0);
    G_STATIC_ASSERT_EXPR(NM_NARG_MAX2(1) == 1);
    G_STATIC_ASSERT_EXPR(NM_NARG_MAX2(1, 2) == 2);
    G_STATIC_ASSERT_EXPR(NM_NARG_MAX2(1, 2, 3) == 2);
}

/*****************************************************************************/

static void
test_ethtool_offload(void)
{
    const NMEthtoolData *d;

    g_assert_cmpint(nm_ethtool_id_get_by_name("invalid"), ==, NM_ETHTOOL_ID_UNKNOWN);
    g_assert_cmpint(nm_ethtool_id_get_by_name("feature-rx"), ==, NM_ETHTOOL_ID_FEATURE_RX);

    d = nm_ethtool_data_get_by_optname(NM_ETHTOOL_OPTNAME_FEATURE_RXHASH);
    g_assert(d);
    g_assert_cmpint(d->id, ==, NM_ETHTOOL_ID_FEATURE_RXHASH);
    g_assert_cmpstr(d->optname, ==, NM_ETHTOOL_OPTNAME_FEATURE_RXHASH);

    /* these features are NETIF_F_NEVER_CHANGE: */
    g_assert(!nm_ethtool_data_get_by_optname("feature-netns-local"));
    g_assert(!nm_ethtool_data_get_by_optname("feature-tx-lockless"));
    g_assert(!nm_ethtool_data_get_by_optname("feature-vlan-challenged"));
}

/*****************************************************************************/

typedef struct {
    GMainLoop *   loop1;
    GMainContext *c2;
    GSource *     extra_sources[2];
    bool          got_signal[5];
    int           fd_2;
} IntegData;

static gboolean
_test_integrate_cb_handle(IntegData *d, int signal)
{
    int i;

    g_assert(d);
    g_assert(signal >= 0);
    g_assert(signal < G_N_ELEMENTS(d->got_signal));

    g_assert(!d->got_signal[signal]);
    d->got_signal[signal] = TRUE;

    for (i = 0; i < G_N_ELEMENTS(d->got_signal); i++) {
        if (!d->got_signal[i])
            break;
    }
    if (i == G_N_ELEMENTS(d->got_signal))
        g_main_loop_quit(d->loop1);
    return G_SOURCE_REMOVE;
}

static gboolean
_test_integrate_cb_timeout_1(gpointer user_data)
{
    return _test_integrate_cb_handle(user_data, 0);
}

static gboolean
_test_integrate_cb_fd_2(int fd, GIOCondition condition, gpointer user_data)

{
    IntegData *d = user_data;

    g_assert(d->got_signal[1]);
    g_assert(d->got_signal[2]);
    g_assert(d->got_signal[3]);
    g_assert(d->extra_sources[0]);
    g_assert(d->extra_sources[1]);

    return _test_integrate_cb_handle(d, 4);
}

static gboolean
_test_integrate_cb_idle_2(gpointer user_data)
{
    IntegData *d = user_data;
    GSource *  extra_source;

    g_assert(d->got_signal[1]);
    g_assert(d->got_signal[2]);
    g_assert(d->extra_sources[0]);
    g_assert(!d->extra_sources[1]);

    extra_source = nm_g_unix_fd_source_new(d->fd_2,
                                           G_IO_IN,
                                           G_PRIORITY_DEFAULT,
                                           _test_integrate_cb_fd_2,
                                           d,
                                           NULL);
    g_source_attach(extra_source, d->c2);

    d->extra_sources[1] = extra_source;

    return _test_integrate_cb_handle(d, 3);
}

static gboolean
_test_integrate_cb_idle_1(gpointer user_data)
{
    IntegData *d = user_data;
    GSource *  extra_source;

    g_assert(d->got_signal[2]);
    g_assert(!d->extra_sources[0]);

    extra_source = g_idle_source_new();
    g_source_set_callback(extra_source, _test_integrate_cb_idle_2, d, NULL);
    g_source_attach(extra_source, d->c2);

    d->extra_sources[0] = extra_source;

    return _test_integrate_cb_handle(d, 1);
}

static gboolean
_test_integrate_cb_fd_1(int fd, GIOCondition condition, gpointer user_data)

{
    IntegData *d = user_data;

    g_assert(!d->got_signal[1]);
    return _test_integrate_cb_handle(d, 2);
}

static gboolean
_test_integrate_maincontext_cb_idle1(gpointer user_data)
{
    guint32 *p_count = user_data;

    g_assert(*p_count < 5);
    (*p_count)++;
    return G_SOURCE_CONTINUE;
}

static void
test_integrate_maincontext(gconstpointer test_data)
{
    const guint                TEST_IDX                     = GPOINTER_TO_UINT(test_data);
    GMainContext *             c1                           = g_main_context_default();
    nm_auto_unref_gmaincontext GMainContext *c2             = g_main_context_new();
    nm_auto_destroy_and_unref_gsource GSource *integ_source = NULL;

    integ_source = nm_utils_g_main_context_create_integrate_source(c2);
    g_source_attach(integ_source, c1);

    if (TEST_IDX == 1) {
        nm_auto_destroy_and_unref_gsource GSource *idle_source_1 = NULL;
        guint32                                    count         = 0;

        idle_source_1 = g_idle_source_new();
        g_source_set_callback(idle_source_1, _test_integrate_maincontext_cb_idle1, &count, NULL);
        g_source_attach(idle_source_1, c2);

        nmtst_main_context_iterate_until_assert(c1, 2000, count == 5);
    }

    if (TEST_IDX == 2) {
        nm_auto_destroy_and_unref_gsource GSource *main_timeout_source = NULL;
        nm_auto_destroy_and_unref_gsource GSource *timeout_source_1    = NULL;
        nm_auto_destroy_and_unref_gsource GSource *idle_source_1       = NULL;
        nm_auto_destroy_and_unref_gsource GSource *fd_source_1         = NULL;
        nm_auto_unref_gmainloop GMainLoop *loop1                       = NULL;
        nm_auto_close int                  fd_1                        = -1;
        nm_auto_close int                  fd_2                        = -1;
        IntegData                          d;
        int                                i;

        main_timeout_source = g_timeout_source_new(3000);
        g_source_set_callback(main_timeout_source, nmtst_g_source_assert_not_called, NULL, NULL);
        g_source_attach(main_timeout_source, c1);

        loop1 = g_main_loop_new(c1, FALSE);

        d = (IntegData){
            .loop1 = loop1,
            .c2    = c2,
        };

        fd_1 = open("/dev/null", O_RDONLY | O_CLOEXEC);
        g_assert(fd_1 >= 0);
        fd_source_1 = nm_g_unix_fd_source_new(fd_1,
                                              G_IO_IN,
                                              G_PRIORITY_DEFAULT,
                                              _test_integrate_cb_fd_1,
                                              &d,
                                              NULL);
        g_source_attach(fd_source_1, c2);

        fd_2 = open("/dev/null", O_RDONLY | O_CLOEXEC);
        g_assert(fd_2 >= 0);
        d.fd_2 = fd_2;

        idle_source_1 = g_idle_source_new();
        g_source_set_callback(idle_source_1, _test_integrate_cb_idle_1, &d, NULL);
        g_source_attach(idle_source_1, c2);

        timeout_source_1 = g_timeout_source_new(5);
        g_source_set_callback(timeout_source_1, _test_integrate_cb_timeout_1, &d, NULL);
        g_source_attach(timeout_source_1, c2);

        g_main_loop_run(loop1);

        for (i = 0; i < G_N_ELEMENTS(d.extra_sources); i++) {
            g_assert(d.extra_sources[i]);
            nm_clear_pointer(&d.extra_sources[i], nm_g_source_destroy_and_unref);
        }
    }
}

/*****************************************************************************/

static void
test_nm_ip_addr_zero(void)
{
    in_addr_t       a4 = nmtst_inet4_from_string("0.0.0.0");
    struct in6_addr a6 = *nmtst_inet6_from_string("::");
    char            buf[NM_UTILS_INET_ADDRSTRLEN];
    NMIPAddr        a = NM_IP_ADDR_INIT;

    g_assert(memcmp(&a, &nm_ip_addr_zero, sizeof(a)) == 0);

    g_assert(IN6_IS_ADDR_UNSPECIFIED(&nm_ip_addr_zero.addr6));
    g_assert(memcmp(&nm_ip_addr_zero.addr6, &in6addr_any, sizeof(in6addr_any)) == 0);

    g_assert(memcmp(&nm_ip_addr_zero, &a4, sizeof(a4)) == 0);
    g_assert(memcmp(&nm_ip_addr_zero, &a6, sizeof(a6)) == 0);

    g_assert_cmpstr(_nm_utils_inet4_ntop(nm_ip_addr_zero.addr4, buf), ==, "0.0.0.0");
    g_assert_cmpstr(_nm_utils_inet6_ntop(&nm_ip_addr_zero.addr6, buf), ==, "::");

    g_assert_cmpstr(nm_utils_inet_ntop(AF_INET, &nm_ip_addr_zero, buf), ==, "0.0.0.0");
    g_assert_cmpstr(nm_utils_inet_ntop(AF_INET6, &nm_ip_addr_zero, buf), ==, "::");

    G_STATIC_ASSERT_EXPR(sizeof(a) == sizeof(a.array));
}

static void
test_connection_ovs_ifname(gconstpointer test_data)
{
    const guint     TEST_CASE                    = GPOINTER_TO_UINT(test_data);
    gs_unref_object NMConnection *con            = NULL;
    NMSettingConnection *         s_con          = NULL;
    NMSettingOvsBridge *          s_ovs_bridge   = NULL;
    NMSettingOvsPort *            s_ovs_port     = NULL;
    NMSettingOvsInterface *       s_ovs_iface    = NULL;
    NMSettingOvsPatch *           s_ovs_patch    = NULL;
    const char *                  ovs_iface_type = NULL;

    switch (TEST_CASE) {
    case 1:
        con          = nmtst_create_minimal_connection("test_connection_ovs_ifname_bridge",
                                              NULL,
                                              NM_SETTING_OVS_BRIDGE_SETTING_NAME,
                                              &s_con);
        s_ovs_bridge = nm_connection_get_setting_ovs_bridge(con);
        g_assert(s_ovs_bridge);
        break;
    case 2:
        con = nmtst_create_minimal_connection("test_connection_ovs_ifname_port",
                                              NULL,
                                              NM_SETTING_OVS_PORT_SETTING_NAME,
                                              &s_con);

        g_object_set(s_con,
                     NM_SETTING_CONNECTION_MASTER,
                     "master0",
                     NM_SETTING_CONNECTION_SLAVE_TYPE,
                     NM_SETTING_OVS_BRIDGE_SETTING_NAME,
                     NULL);

        s_ovs_port = nm_connection_get_setting_ovs_port(con);
        g_assert(s_ovs_port);
        break;
    case 3:
        con         = nmtst_create_minimal_connection("test_connection_ovs_ifname_interface_patch",
                                              NULL,
                                              NM_SETTING_OVS_INTERFACE_SETTING_NAME,
                                              &s_con);
        s_ovs_iface = nm_connection_get_setting_ovs_interface(con);
        g_assert(s_ovs_iface);

        g_object_set(s_con,
                     NM_SETTING_CONNECTION_MASTER,
                     "master0",
                     NM_SETTING_CONNECTION_SLAVE_TYPE,
                     NM_SETTING_OVS_PORT_SETTING_NAME,
                     NULL);

        g_object_set(s_ovs_iface, NM_SETTING_OVS_INTERFACE_TYPE, "patch", NULL);

        s_ovs_patch = NM_SETTING_OVS_PATCH(nm_setting_ovs_patch_new());
        g_assert(s_ovs_patch);

        g_object_set(s_ovs_patch, NM_SETTING_OVS_PATCH_PEER, "1.2.3.4", NULL);

        nm_connection_add_setting(con, NM_SETTING(s_ovs_patch));
        s_ovs_patch = nm_connection_get_setting_ovs_patch(con);
        g_assert(s_ovs_patch);
        ovs_iface_type = "patch";
        break;
    case 4:
        con = nmtst_create_minimal_connection("test_connection_ovs_ifname_interface_internal",
                                              NULL,
                                              NM_SETTING_OVS_INTERFACE_SETTING_NAME,
                                              &s_con);
        s_ovs_iface = nm_connection_get_setting_ovs_interface(con);
        g_assert(s_ovs_iface);

        g_object_set(s_con,
                     NM_SETTING_CONNECTION_MASTER,
                     "master0",
                     NM_SETTING_CONNECTION_SLAVE_TYPE,
                     NM_SETTING_OVS_PORT_SETTING_NAME,
                     NULL);

        g_object_set(s_ovs_iface, NM_SETTING_OVS_INTERFACE_TYPE, "internal", NULL);
        ovs_iface_type = "internal";
        break;
    case 5:
        con = nmtst_create_minimal_connection("test_connection_ovs_ifname_interface_system",
                                              NULL,
                                              NM_SETTING_WIRED_SETTING_NAME,
                                              &s_con);

        g_object_set(s_con,
                     NM_SETTING_CONNECTION_MASTER,
                     "master0",
                     NM_SETTING_CONNECTION_SLAVE_TYPE,
                     NM_SETTING_OVS_PORT_SETTING_NAME,
                     NULL);

        s_ovs_iface = NM_SETTING_OVS_INTERFACE(nm_setting_ovs_interface_new());
        g_assert(s_ovs_iface);

        g_object_set(s_ovs_iface, NM_SETTING_OVS_INTERFACE_TYPE, "system", NULL);

        nm_connection_add_setting(con, NM_SETTING(s_ovs_iface));
        s_ovs_iface = nm_connection_get_setting_ovs_interface(con);
        g_assert(s_ovs_iface);

        ovs_iface_type = "system";
        break;
    case 6:
        con         = nmtst_create_minimal_connection("test_connection_ovs_ifname_interface_dpdk",
                                              NULL,
                                              NM_SETTING_OVS_INTERFACE_SETTING_NAME,
                                              &s_con);
        s_ovs_iface = nm_connection_get_setting_ovs_interface(con);
        g_assert(s_ovs_iface);

        g_object_set(s_con,
                     NM_SETTING_CONNECTION_MASTER,
                     "master0",
                     NM_SETTING_CONNECTION_SLAVE_TYPE,
                     NM_SETTING_OVS_PORT_SETTING_NAME,
                     NULL);

        g_object_set(s_ovs_iface, NM_SETTING_OVS_INTERFACE_TYPE, "dpdk", NULL);
        ovs_iface_type = "dpdk";
        break;
    }

    if (!nm_streq0(ovs_iface_type, "system")) {
        /* wrong: contains backward slash */
        g_object_set(s_con, NM_SETTING_CONNECTION_INTERFACE_NAME, "ovs\\0", NULL);
        nmtst_assert_connection_unnormalizable(con,
                                               NM_CONNECTION_ERROR,
                                               NM_CONNECTION_ERROR_INVALID_PROPERTY);

        /* wrong: contains forward slash */
        g_object_set(s_con, NM_SETTING_CONNECTION_INTERFACE_NAME, "ovs/0", NULL);
        nmtst_assert_connection_unnormalizable(con,
                                               NM_CONNECTION_ERROR,
                                               NM_CONNECTION_ERROR_INVALID_PROPERTY);
    }

    /* wrong: contains space */
    g_object_set(s_con, NM_SETTING_CONNECTION_INTERFACE_NAME, "ovs 0", NULL);
    nmtst_assert_connection_unnormalizable(con,
                                           NM_CONNECTION_ERROR,
                                           NM_CONNECTION_ERROR_INVALID_PROPERTY);

    /* good */
    g_object_set(s_con, NM_SETTING_CONNECTION_INTERFACE_NAME, "ovs0", NULL);
    nmtst_assert_connection_verifies(con);

    g_object_set(s_con, NM_SETTING_CONNECTION_INTERFACE_NAME, "ovs-br0", NULL);
    nmtst_assert_connection_verifies(con);

    /* good if bridge, port, or patch interface */
    g_object_set(s_con, NM_SETTING_CONNECTION_INTERFACE_NAME, "ovs123123123123130123123", NULL);

    if (!ovs_iface_type || nm_streq(ovs_iface_type, "patch"))
        nmtst_assert_connection_verifies(con);
    else {
        nmtst_assert_connection_unnormalizable(con,
                                               NM_CONNECTION_ERROR,
                                               NM_CONNECTION_ERROR_INVALID_PROPERTY);
    }
}

/*****************************************************************************/

static gboolean
_strsplit_quoted_char_needs_escaping(char ch)
{
    return NM_IN_SET(ch, '\'', '\"', '\\') || strchr(NM_ASCII_WHITESPACES, ch);
}

static char *
_strsplit_quoted_create_str_rand(gssize len)
{
    NMStrBuf strbuf = NM_STR_BUF_INIT(nmtst_get_rand_uint32() % 200, nmtst_get_rand_bool());

    g_assert(len >= -1);

    if (len == -1)
        len = nmtst_get_rand_word_length(NULL);

    while (len-- > 0) {
        char ch;

        ch = nmtst_rand_select('a', ' ', '\\', '"', '\'', nmtst_get_rand_uint32() % 255 + 1);
        g_assert(ch);
        nm_str_buf_append_c(&strbuf, ch);
    }

    if (!strbuf.allocated)
        nm_str_buf_maybe_expand(&strbuf, 1, nmtst_get_rand_bool());
    return nm_str_buf_finalize(&strbuf, NULL);
}

static char **
_strsplit_quoted_create_strv_rand(void)
{
    guint  len = nmtst_get_rand_word_length(NULL);
    char **ptr;
    guint  i;

    ptr = g_new(char *, len + 1);
    for (i = 0; i < len; i++)
        ptr[i] = _strsplit_quoted_create_str_rand(-1);
    ptr[i] = NULL;
    return ptr;
}

static char *
_strsplit_quoted_join_strv_rand(const char *const *strv)
{
    NMStrBuf strbuf = NM_STR_BUF_INIT(nmtst_get_rand_uint32() % 200, nmtst_get_rand_bool());
    char *   result;
    gsize    l;
    gsize    l2;
    gsize *  p_l2 = nmtst_get_rand_bool() ? &l2 : NULL;
    gsize    i;

    g_assert(strv);

    nm_str_buf_append_c_repeated(&strbuf, ' ', nmtst_get_rand_word_length(NULL) / 4);
    for (i = 0; strv[i]; i++) {
        const char *s = strv[i];
        gsize       j;
        char        quote;

        nm_str_buf_append_c_repeated(&strbuf, ' ', 1 + nmtst_get_rand_word_length(NULL) / 4);

        j     = 0;
        quote = '\0';
        while (TRUE) {
            char ch = s[j++];

            /* extract_first_word*/
            if (quote != '\0') {
                if (ch == '\0') {
                    nm_str_buf_append_c(&strbuf, quote);
                    break;
                }
                if (ch == quote || ch == '\\' || nmtst_get_rand_uint32() % 5 == 0)
                    nm_str_buf_append_c(&strbuf, '\\');
                nm_str_buf_append_c(&strbuf, ch);
                if (nmtst_get_rand_uint32() % 3 == 0) {
                    nm_str_buf_append_c(&strbuf, quote);
                    quote = '\0';
                    goto next_maybe_quote;
                }
                continue;
            }

            if (ch == '\0') {
                if (s == strv[i]) {
                    quote = nmtst_rand_select('\'', '"');
                    nm_str_buf_append_c_repeated(&strbuf, quote, 2);
                }
                break;
            }

            if (_strsplit_quoted_char_needs_escaping(ch) || nmtst_get_rand_uint32() % 5 == 0)
                nm_str_buf_append_c(&strbuf, '\\');

            nm_str_buf_append_c(&strbuf, ch);

next_maybe_quote:
            if (nmtst_get_rand_uint32() % 5 == 0) {
                quote = nmtst_rand_select('\'', '\"');
                nm_str_buf_append_c(&strbuf, quote);
                if (nmtst_get_rand_uint32() % 5 == 0) {
                    nm_str_buf_append_c(&strbuf, quote);
                    quote = '\0';
                }
            }
        }
    }
    nm_str_buf_append_c_repeated(&strbuf, ' ', nmtst_get_rand_word_length(NULL) / 4);

    nm_str_buf_maybe_expand(&strbuf, 1, nmtst_get_rand_bool());

    l      = strbuf.len;
    result = nm_str_buf_finalize(&strbuf, p_l2);
    g_assert(!p_l2 || l == *p_l2);
    g_assert(strlen(result) == l);
    return result;
}

static void
_strsplit_quoted_assert_strv(const char *       topic,
                             const char *       str,
                             const char *const *strv1,
                             const char *const *strv2)
{
    nm_auto_str_buf NMStrBuf s1          = {};
    nm_auto_str_buf NMStrBuf s2          = {};
    gs_free char *           str_escaped = NULL;
    int                      i;

    g_assert(str);
    g_assert(strv1);
    g_assert(strv2);

    if (nm_utils_strv_equal(strv1, strv2))
        return;

    for (i = 0; strv1[i]; i++) {
        gs_free char *s = g_strescape(strv1[i], NULL);

        g_print(">>> [%s] strv1[%d] = \"%s\"\n", topic, i, s);
        if (i > 0)
            nm_str_buf_append_c(&s1, ' ');
        nm_str_buf_append_printf(&s1, "\"%s\"", s);
    }

    for (i = 0; strv2[i]; i++) {
        gs_free char *s = g_strescape(strv2[i], NULL);

        g_print(">>> [%s] strv2[%d] = \"%s\"\n", topic, i, s);
        if (i > 0)
            nm_str_buf_append_c(&s2, ' ');
        nm_str_buf_append_printf(&s2, "\"%s\"", s);
    }

    nm_str_buf_maybe_expand(&s1, 1, FALSE);
    nm_str_buf_maybe_expand(&s2, 1, FALSE);

    str_escaped = g_strescape(str, NULL);
    g_error("compared words differs: [%s] str=\"%s\"; strv1=%s; strv2=%s",
            topic,
            str_escaped,
            nm_str_buf_get_str(&s1),
            nm_str_buf_get_str(&s2));
}

static void
_strsplit_quoted_test(const char *str, const char *const *strv_expected)
{
    gs_strfreev char **strv_systemd = NULL;
    gs_strfreev char **strv_nm      = NULL;
    int                r;

    g_assert(str);

    r = nmtst_systemd_extract_first_word_all(str, &strv_systemd);
    g_assert_cmpint(r, ==, 1);
    g_assert(strv_systemd);

    if (!strv_expected)
        strv_expected = (const char *const *) strv_systemd;

    _strsplit_quoted_assert_strv("systemd", str, strv_expected, (const char *const *) strv_systemd);

    strv_nm = nm_utils_strsplit_quoted(str);
    g_assert(strv_nm);
    _strsplit_quoted_assert_strv("nm", str, strv_expected, (const char *const *) strv_nm);
}

static void
test_strsplit_quoted(void)
{
    int i_run;

    _strsplit_quoted_test("", NM_MAKE_STRV());
    _strsplit_quoted_test(" ", NM_MAKE_STRV());
    _strsplit_quoted_test("  ", NM_MAKE_STRV());
    _strsplit_quoted_test("  \t", NM_MAKE_STRV());
    _strsplit_quoted_test("a b", NM_MAKE_STRV("a", "b"));
    _strsplit_quoted_test("a\\ b", NM_MAKE_STRV("a b"));
    _strsplit_quoted_test(" a\\ \"b\"", NM_MAKE_STRV("a b"));
    _strsplit_quoted_test(" a\\ \"b\" c \n", NM_MAKE_STRV("a b", "c"));

    for (i_run = 0; i_run < 1000; i_run++) {
        gs_strfreev char **strv = NULL;
        gs_free char *     str  = NULL;

        /* create random strv array and join them carefully so that splitting
         * them will yield the original value. */
        strv = _strsplit_quoted_create_strv_rand();
        str  = _strsplit_quoted_join_strv_rand((const char *const *) strv);
        _strsplit_quoted_test(str, (const char *const *) strv);
    }

    /* Create random words and assert that systemd and our implementation can
     * both split them (and in the exact same way). */
    for (i_run = 0; i_run < 1000; i_run++) {
        gs_free char *s = _strsplit_quoted_create_str_rand(nmtst_get_rand_uint32() % 150);

        _strsplit_quoted_test(s, NULL);
    }
}

/*****************************************************************************/

static void
test_nm_property_variant_to_gvalue(void)
{
#define _test_variant_to_gvalue_bad(variant, gtype)                                     \
    G_STMT_START                                                                        \
    {                                                                                   \
        gs_unref_variant GVariant * _variant = (variant);                               \
        GType                       _gtype   = (gtype);                                 \
        nm_auto_unset_gvalue GValue _gvalue  = G_VALUE_INIT;                            \
                                                                                        \
        g_value_init(&_gvalue, _gtype);                                                 \
        g_assert_cmpint(_nm_property_variant_to_gvalue(_variant, &_gvalue), ==, FALSE); \
    }                                                                                   \
    G_STMT_END

#define _test_variant_to_gvalue(variant, gtype, check)                                 \
    G_STMT_START                                                                       \
    {                                                                                  \
        gs_unref_variant GVariant * _variant = (variant);                              \
        GType                       _gtype   = (gtype);                                \
        nm_auto_unset_gvalue GValue _gvalue  = G_VALUE_INIT;                           \
        _nm_unused GValue *const gg          = &_gvalue;                               \
                                                                                       \
        g_value_init(&_gvalue, _gtype);                                                \
        g_assert_cmpint(_nm_property_variant_to_gvalue(_variant, &_gvalue), ==, TRUE); \
        check;                                                                         \
    }                                                                                  \
    G_STMT_END

#define _test_variant_to_gvalue_int(variant, gtype, gvalue_get, expected) \
    _test_variant_to_gvalue((variant), (gtype), g_assert_cmpint(gvalue_get(gg), ==, (expected)))

    _test_variant_to_gvalue_bad(g_variant_new_string(""), G_TYPE_BOOLEAN);
    _test_variant_to_gvalue(g_variant_new_string(""),
                            G_TYPE_STRING,
                            g_assert_cmpstr(g_value_get_string(gg), ==, ""));
    _test_variant_to_gvalue_int(g_variant_new_boolean(FALSE),
                                G_TYPE_BOOLEAN,
                                g_value_get_boolean,
                                FALSE);
    _test_variant_to_gvalue_int(g_variant_new_boolean(TRUE),
                                G_TYPE_BOOLEAN,
                                g_value_get_boolean,
                                TRUE);
    _test_variant_to_gvalue_int(g_variant_new_int32(0), G_TYPE_BOOLEAN, g_value_get_boolean, FALSE);
    _test_variant_to_gvalue_int(g_variant_new_int32(1), G_TYPE_BOOLEAN, g_value_get_boolean, 1);
    _test_variant_to_gvalue_int(g_variant_new_int32(2), G_TYPE_BOOLEAN, g_value_get_boolean, 1);
    _test_variant_to_gvalue_int(g_variant_new_byte(0), G_TYPE_BOOLEAN, g_value_get_boolean, 0);
    _test_variant_to_gvalue_int(g_variant_new_byte(1), G_TYPE_BOOLEAN, g_value_get_boolean, 1);
    _test_variant_to_gvalue_int(g_variant_new_byte(2), G_TYPE_BOOLEAN, g_value_get_boolean, 1);
}

/*****************************************************************************/

static void
_do_wifi_ghz_freqs(const guint *freqs, const char *band)
{
    int len;
    int j;
    int i;

    g_assert(NM_IN_STRSET(band, "a", "bg"));
    g_assert(freqs);
    g_assert(freqs[0] != 0);

    for (i = 0; freqs[i]; i++) {
        for (j = 0; j < i; j++)
            g_assert(freqs[i] != freqs[j]);
    }
    len = i;

    g_assert(nm_utils_wifi_freq_to_channel(0) == 0);
    g_assert(nm_utils_wifi_channel_to_freq(0, "bg") == -1);
    g_assert(nm_utils_wifi_channel_to_freq(0, "foo") == 0);
    g_assert(!nm_utils_wifi_is_channel_valid(0, "bg"));
    g_assert(!nm_utils_wifi_is_channel_valid(0, "foo"));

    for (i = 0; i < len; i++) {
        guint   freq = freqs[i];
        guint32 chan;
        guint32 freq2;

        chan = nm_utils_wifi_freq_to_channel(freq);
        g_assert(chan != 0);

        freq2 = nm_utils_wifi_channel_to_freq(chan, band);
        g_assert(freq2 == freq);

        g_assert(nm_utils_wifi_is_channel_valid(chan, band));
    }

    g_assert(freqs[len] == 0);
}

static void
test_nm_utils_wifi_ghz_freqs(void)
{
    _do_wifi_ghz_freqs(nm_utils_wifi_2ghz_freqs(), "bg");
    _do_wifi_ghz_freqs(nm_utils_wifi_5ghz_freqs(), "a");
}

/*****************************************************************************/

static void
test_vpn_connection_state_reason(void)
{
#define ASSERT(v1, v2)                                                 \
    G_STMT_START                                                       \
    {                                                                  \
        G_STATIC_ASSERT((gint64) (v1) == v2);                          \
        G_STATIC_ASSERT((gint64) (v2) == v1);                          \
                                                                       \
        nm_assert(((NMActiveConnectionStateReason) (int) (v1)) == v2); \
        nm_assert(((NMVpnConnectionStateReason) (int) (v2)) == v1);    \
    }                                                                  \
    G_STMT_END

    ASSERT(NM_VPN_CONNECTION_STATE_REASON_UNKNOWN, NM_ACTIVE_CONNECTION_STATE_REASON_UNKNOWN);
    ASSERT(NM_VPN_CONNECTION_STATE_REASON_NONE, NM_ACTIVE_CONNECTION_STATE_REASON_NONE);
    ASSERT(NM_VPN_CONNECTION_STATE_REASON_USER_DISCONNECTED,
           NM_ACTIVE_CONNECTION_STATE_REASON_USER_DISCONNECTED);
    ASSERT(NM_VPN_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED,
           NM_ACTIVE_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED);
    ASSERT(NM_VPN_CONNECTION_STATE_REASON_SERVICE_STOPPED,
           NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_STOPPED);
    ASSERT(NM_VPN_CONNECTION_STATE_REASON_IP_CONFIG_INVALID,
           NM_ACTIVE_CONNECTION_STATE_REASON_IP_CONFIG_INVALID);
    ASSERT(NM_VPN_CONNECTION_STATE_REASON_CONNECT_TIMEOUT,
           NM_ACTIVE_CONNECTION_STATE_REASON_CONNECT_TIMEOUT);
    ASSERT(NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_TIMEOUT,
           NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_START_TIMEOUT);
    ASSERT(NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_FAILED,
           NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_START_FAILED);
    ASSERT(NM_VPN_CONNECTION_STATE_REASON_NO_SECRETS, NM_ACTIVE_CONNECTION_STATE_REASON_NO_SECRETS);
    ASSERT(NM_VPN_CONNECTION_STATE_REASON_LOGIN_FAILED,
           NM_ACTIVE_CONNECTION_STATE_REASON_LOGIN_FAILED);
    ASSERT(NM_VPN_CONNECTION_STATE_REASON_CONNECTION_REMOVED,
           NM_ACTIVE_CONNECTION_STATE_REASON_CONNECTION_REMOVED);
}

/*****************************************************************************/

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init(&argc, &argv, TRUE);

    g_test_add_func("/core/general/test_nm_ascii_spaces", test_nm_ascii_spaces);
    g_test_add_func("/core/general/test_wired_wake_on_lan_enum", test_wired_wake_on_lan_enum);
    g_test_add_func("/core/general/test_wireless_wake_on_wlan_enum",
                    test_wireless_wake_on_wlan_enum);
    g_test_add_func("/core/general/test_device_wifi_capabilities", test_device_wifi_capabilities);
    g_test_add_func("/core/general/test_80211_mode", test_80211_mode);
    g_test_add_func("/core/general/test_vlan_flags", test_vlan_flags);
    g_test_add_func("/core/general/test_nm_hash", test_nm_hash);
    g_test_add_func("/core/general/test_nm_g_slice_free_fcn", test_nm_g_slice_free_fcn);
    g_test_add_func("/core/general/test_c_list_sort", test_c_list_sort);
    g_test_add_func("/core/general/test_dedup_multi", test_dedup_multi);
    g_test_add_func("/core/general/test_utils_str_utf8safe", test_utils_str_utf8safe);
    g_test_add_func("/core/general/test_nm_utils_strsplit_set", test_nm_utils_strsplit_set);
    g_test_add_func("/core/general/test_nm_utils_escaped_tokens", test_nm_utils_escaped_tokens);
    g_test_add_func("/core/general/test_nm_in_set", test_nm_in_set);
    g_test_add_func("/core/general/test_nm_in_strset", test_nm_in_strset);
    g_test_add_func("/core/general/test_setting_vpn_items", test_setting_vpn_items);
    g_test_add_func("/core/general/test_setting_vpn_update_secrets",
                    test_setting_vpn_update_secrets);
    g_test_add_func("/core/general/test_setting_vpn_modify_during_foreach",
                    test_setting_vpn_modify_during_foreach);
    g_test_add_func("/core/general/test_setting_ip4_config_labels", test_setting_ip4_config_labels);
    g_test_add_func("/core/general/test_setting_ip4_config_address_data",
                    test_setting_ip4_config_address_data);
    g_test_add_func("/core/general/test_setting_ip_route_attributes",
                    test_setting_ip_route_attributes);
    g_test_add_func("/core/general/test_setting_gsm_apn_spaces", test_setting_gsm_apn_spaces);
    g_test_add_func("/core/general/test_setting_gsm_apn_bad_chars", test_setting_gsm_apn_bad_chars);
    g_test_add_func("/core/general/test_setting_gsm_apn_underscore",
                    test_setting_gsm_apn_underscore);
    g_test_add_func("/core/general/test_setting_gsm_without_number",
                    test_setting_gsm_without_number);
    g_test_add_func("/core/general/test_setting_gsm_sim_operator_id",
                    test_setting_gsm_sim_operator_id);
    g_test_add_func("/core/general/test_setting_to_dbus_all", test_setting_to_dbus_all);
    g_test_add_func("/core/general/test_setting_to_dbus_no_secrets",
                    test_setting_to_dbus_no_secrets);
    g_test_add_func("/core/general/test_setting_to_dbus_only_secrets",
                    test_setting_to_dbus_only_secrets);
    g_test_add_func("/core/general/test_setting_to_dbus_transform", test_setting_to_dbus_transform);
    g_test_add_func("/core/general/test_setting_to_dbus_enum", test_setting_to_dbus_enum);
    g_test_add_func("/core/general/test_setting_compare_id", test_setting_compare_id);
    g_test_add_func("/core/general/test_setting_compare_addresses", test_setting_compare_addresses);
    g_test_add_func("/core/general/test_setting_compare_routes", test_setting_compare_routes);
    g_test_add_func("/core/general/test_setting_compare_wired_cloned_mac_address",
                    test_setting_compare_wired_cloned_mac_address);
    g_test_add_func("/core/general/test_setting_compare_wirless_cloned_mac_address",
                    test_setting_compare_wireless_cloned_mac_address);
    g_test_add_func("/core/general/test_setting_compare_timestamp", test_setting_compare_timestamp);
#define ADD_FUNC(name, func, secret_flags, comp_flags, remove_secret)           \
    g_test_add_data_func_full(                                                  \
        "/core/general/" G_STRINGIFY(func) "_" name,                            \
        test_data_compare_secrets_new(secret_flags, comp_flags, remove_secret), \
        func,                                                                   \
        g_free)
    ADD_FUNC("agent_owned",
             test_setting_compare_secrets,
             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
             NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS,
             TRUE);
    ADD_FUNC("not_saved",
             test_setting_compare_secrets,
             NM_SETTING_SECRET_FLAG_NOT_SAVED,
             NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS,
             TRUE);
    ADD_FUNC("secrets",
             test_setting_compare_secrets,
             NM_SETTING_SECRET_FLAG_NONE,
             NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS,
             TRUE);
    ADD_FUNC("exact",
             test_setting_compare_secrets,
             NM_SETTING_SECRET_FLAG_NONE,
             NM_SETTING_COMPARE_FLAG_EXACT,
             FALSE);
    ADD_FUNC("agent_owned",
             test_setting_compare_vpn_secrets,
             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
             NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS,
             TRUE);
    ADD_FUNC("not_saved",
             test_setting_compare_vpn_secrets,
             NM_SETTING_SECRET_FLAG_NOT_SAVED,
             NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS,
             TRUE);
    ADD_FUNC("secrets",
             test_setting_compare_vpn_secrets,
             NM_SETTING_SECRET_FLAG_NONE,
             NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS,
             TRUE);
    ADD_FUNC("exact",
             test_setting_compare_vpn_secrets,
             NM_SETTING_SECRET_FLAG_NONE,
             NM_SETTING_COMPARE_FLAG_EXACT,
             FALSE);
    g_test_add_func("/core/general/test_setting_old_uuid", test_setting_old_uuid);

    g_test_add_func("/core/general/test_connection_to_dbus_setting_name",
                    test_connection_to_dbus_setting_name);
    g_test_add_func("/core/general/test_connection_to_dbus_deprecated_props",
                    test_connection_to_dbus_deprecated_props);
    g_test_add_func("/core/general/test_setting_new_from_dbus", test_setting_new_from_dbus);
    g_test_add_func("/core/general/test_setting_new_from_dbus_transform",
                    test_setting_new_from_dbus_transform);
    g_test_add_func("/core/general/test_setting_new_from_dbus_enum",
                    test_setting_new_from_dbus_enum);
    g_test_add_func("/core/general/test_setting_new_from_dbus_bad", test_setting_new_from_dbus_bad);
    g_test_add_func("/core/general/test_connection_replace_settings",
                    test_connection_replace_settings);
    g_test_add_func("/core/general/test_connection_replace_settings_from_connection",
                    test_connection_replace_settings_from_connection);
    g_test_add_func("/core/general/test_connection_replace_settings_bad",
                    test_connection_replace_settings_bad);
    g_test_add_func("/core/general/test_connection_new_from_dbus", test_connection_new_from_dbus);
    g_test_add_func("/core/general/test_connection_normalize_virtual_iface_name",
                    test_connection_normalize_virtual_iface_name);
    g_test_add_func("/core/general/test_connection_normalize_uuid", test_connection_normalize_uuid);
    g_test_add_func("/core/general/test_connection_normalize_type", test_connection_normalize_type);
    g_test_add_func("/core/general/test_connection_normalize_slave_type_1",
                    test_connection_normalize_slave_type_1);
    g_test_add_func("/core/general/test_connection_normalize_slave_type_2",
                    test_connection_normalize_slave_type_2);
    g_test_add_func("/core/general/test_connection_normalize_infiniband_mtu",
                    test_connection_normalize_infiniband_mtu);
    g_test_add_func("/core/general/test_connection_normalize_gateway_never_default",
                    test_connection_normalize_gateway_never_default);
    g_test_add_func("/core/general/test_connection_normalize_may_fail",
                    test_connection_normalize_may_fail);
    g_test_add_func("/core/general/test_connection_normalize_shared_addresses",
                    test_connection_normalize_shared_addresses);
    g_test_add_data_func("/core/general/test_connection_normalize_ovs_interface_type_system/1",
                         GUINT_TO_POINTER(1),
                         test_connection_normalize_ovs_interface_type_system);
    g_test_add_data_func("/core/general/test_connection_normalize_ovs_interface_type_system/2",
                         GUINT_TO_POINTER(2),
                         test_connection_normalize_ovs_interface_type_system);
    g_test_add_data_func("/core/general/test_connection_normalize_ovs_interface_type_system/3",
                         GUINT_TO_POINTER(3),
                         test_connection_normalize_ovs_interface_type_system);
    g_test_add_data_func("/core/general/test_connection_normalize_ovs_interface_type_system/4",
                         GUINT_TO_POINTER(4),
                         test_connection_normalize_ovs_interface_type_system);
    g_test_add_data_func("/core/general/test_connection_normalize_ovs_interface_type_system/5",
                         GUINT_TO_POINTER(5),
                         test_connection_normalize_ovs_interface_type_system);
    g_test_add_data_func("/core/general/test_connection_normalize_ovs_interface_type_system/6",
                         GUINT_TO_POINTER(6),
                         test_connection_normalize_ovs_interface_type_system);
    g_test_add_data_func("/core/general/test_connection_normalize_ovs_interface_type_system/7",
                         GUINT_TO_POINTER(7),
                         test_connection_normalize_ovs_interface_type_system);
    g_test_add_data_func(
        "/core/general/test_connection_normalize_ovs_interface_type_ovs_interface/1",
        GUINT_TO_POINTER(1),
        test_connection_normalize_ovs_interface_type_ovs_interface);
    g_test_add_data_func(
        "/core/general/test_connection_normalize_ovs_interface_type_ovs_interface/2",
        GUINT_TO_POINTER(2),
        test_connection_normalize_ovs_interface_type_ovs_interface);
    g_test_add_data_func(
        "/core/general/test_connection_normalize_ovs_interface_type_ovs_interface/3",
        GUINT_TO_POINTER(3),
        test_connection_normalize_ovs_interface_type_ovs_interface);
    g_test_add_data_func(
        "/core/general/test_connection_normalize_ovs_interface_type_ovs_interface/4",
        GUINT_TO_POINTER(4),
        test_connection_normalize_ovs_interface_type_ovs_interface);
    g_test_add_data_func(
        "/core/general/test_connection_normalize_ovs_interface_type_ovs_interface/5",
        GUINT_TO_POINTER(5),
        test_connection_normalize_ovs_interface_type_ovs_interface);
    g_test_add_data_func(
        "/core/general/test_connection_normalize_ovs_interface_type_ovs_interface/6",
        GUINT_TO_POINTER(6),
        test_connection_normalize_ovs_interface_type_ovs_interface);
    g_test_add_data_func(
        "/core/general/test_connection_normalize_ovs_interface_type_ovs_interface/7",
        GUINT_TO_POINTER(7),
        test_connection_normalize_ovs_interface_type_ovs_interface);
    g_test_add_data_func(
        "/core/general/test_connection_normalize_ovs_interface_type_ovs_interface/8",
        GUINT_TO_POINTER(8),
        test_connection_normalize_ovs_interface_type_ovs_interface);
    g_test_add_data_func(
        "/core/general/test_connection_normalize_ovs_interface_type_ovs_interface/9",
        GUINT_TO_POINTER(9),
        test_connection_normalize_ovs_interface_type_ovs_interface);
    g_test_add_data_func(
        "/core/general/test_connection_normalize_ovs_interface_type_ovs_interface/10",
        GUINT_TO_POINTER(10),
        test_connection_normalize_ovs_interface_type_ovs_interface);
    g_test_add_data_func(
        "/core/general/test_connection_normalize_ovs_interface_type_ovs_interface/11",
        GUINT_TO_POINTER(11),
        test_connection_normalize_ovs_interface_type_ovs_interface);
    g_test_add_data_func(
        "/core/general/test_connection_normalize_ovs_interface_type_ovs_interface/12",
        GUINT_TO_POINTER(12),
        test_connection_normalize_ovs_interface_type_ovs_interface);

    g_test_add_data_func("/core/general/test_connection_ovs_ifname/1",
                         GUINT_TO_POINTER(1),
                         test_connection_ovs_ifname);
    g_test_add_data_func("/core/general/test_connection_ovs_ifname/2",
                         GUINT_TO_POINTER(2),
                         test_connection_ovs_ifname);
    g_test_add_data_func("/core/general/test_connection_ovs_ifname/3",
                         GUINT_TO_POINTER(3),
                         test_connection_ovs_ifname);
    g_test_add_data_func("/core/general/test_connection_ovs_ifname/4",
                         GUINT_TO_POINTER(4),
                         test_connection_ovs_ifname);
    g_test_add_data_func("/core/general/test_connection_ovs_ifname/5",
                         GUINT_TO_POINTER(5),
                         test_connection_ovs_ifname);
    g_test_add_data_func("/core/general/test_connection_ovs_ifname/6",
                         GUINT_TO_POINTER(6),
                         test_connection_ovs_ifname);

    g_test_add_func("/core/general/test_setting_connection_permissions_helpers",
                    test_setting_connection_permissions_helpers);
    g_test_add_func("/core/general/test_setting_connection_permissions_property",
                    test_setting_connection_permissions_property);

    g_test_add_func("/core/general/test_nm_property_variant_to_gvalue",
                    test_nm_property_variant_to_gvalue);

    g_test_add_func("/core/general/test_connection_compare_same", test_connection_compare_same);
    g_test_add_func("/core/general/test_connection_compare_key_only_in_a",
                    test_connection_compare_key_only_in_a);
    g_test_add_func("/core/general/test_connection_compare_setting_only_in_a",
                    test_connection_compare_setting_only_in_a);
    g_test_add_func("/core/general/test_connection_compare_key_only_in_b",
                    test_connection_compare_key_only_in_b);
    g_test_add_func("/core/general/test_connection_compare_setting_only_in_b",
                    test_connection_compare_setting_only_in_b);

    g_test_add_func("/core/general/test_connection_diff_a_only", test_connection_diff_a_only);
    g_test_add_func("/core/general/test_connection_diff_same", test_connection_diff_same);
    g_test_add_func("/core/general/test_connection_diff_different", test_connection_diff_different);
    g_test_add_func("/core/general/test_connection_diff_no_secrets",
                    test_connection_diff_no_secrets);
    g_test_add_func("/core/general/test_connection_diff_inferrable",
                    test_connection_diff_inferrable);
    g_test_add_func("/core/general/test_connection_good_base_types",
                    test_connection_good_base_types);
    g_test_add_func("/core/general/test_connection_bad_base_types", test_connection_bad_base_types);

    g_test_add_func("/core/general/test_hwaddr_aton_ether_normal", test_hwaddr_aton_ether_normal);
    g_test_add_func("/core/general/test_hwaddr_aton_ib_normal", test_hwaddr_aton_ib_normal);
    g_test_add_func("/core/general/test_hwaddr_aton_no_leading_zeros",
                    test_hwaddr_aton_no_leading_zeros);
    g_test_add_func("/core/general/test_hwaddr_aton_malformed", test_hwaddr_aton_malformed);
    g_test_add_func("/core/general/test_hwaddr_equal", test_hwaddr_equal);
    g_test_add_func("/core/general/test_hwaddr_canonical", test_hwaddr_canonical);

    g_test_add_func("/core/general/test_ip4_prefix_to_netmask", test_ip4_prefix_to_netmask);
    g_test_add_func("/core/general/test_ip4_netmask_to_prefix", test_ip4_netmask_to_prefix);

    g_test_add_func("/core/general/test_connection_changed_signal", test_connection_changed_signal);
    g_test_add_func("/core/general/test_setting_connection_changed_signal",
                    test_setting_connection_changed_signal);
    g_test_add_func("/core/general/test_setting_bond_changed_signal",
                    test_setting_bond_changed_signal);
    g_test_add_func("/core/general/test_setting_ip4_changed_signal",
                    test_setting_ip4_changed_signal);
    g_test_add_func("/core/general/test_setting_ip6_changed_signal",
                    test_setting_ip6_changed_signal);
    g_test_add_func("/core/general/test_setting_vlan_changed_signal",
                    test_setting_vlan_changed_signal);
    g_test_add_func("/core/general/test_setting_vpn_changed_signal",
                    test_setting_vpn_changed_signal);
    g_test_add_func("/core/general/test_setting_wired_changed_signal",
                    test_setting_wired_changed_signal);
    g_test_add_func("/core/general/test_setting_wireless_changed_signal",
                    test_setting_wireless_changed_signal);
    g_test_add_func("/core/general/test_setting_wireless_security_changed_signal",
                    test_setting_wireless_security_changed_signal);
    g_test_add_func("/core/general/test_setting_802_1x_changed_signal",
                    test_setting_802_1x_changed_signal);
    g_test_add_func("/core/general/test_setting_ip4_gateway", test_setting_ip4_gateway);
    g_test_add_func("/core/general/test_setting_ip6_gateway", test_setting_ip6_gateway);
    g_test_add_func("/core/general/test_setting_compare_default_strv",
                    test_setting_compare_default_strv);
    g_test_add_func("/core/general/test_setting_user_data", test_setting_user_data);

    g_test_add_func("/core/general/test_sock_addr_endpoint", test_sock_addr_endpoint);

    g_test_add_func("/core/general/hexstr2bin", test_hexstr2bin);
    g_test_add_func("/core/general/nm_strquote", test_nm_strquote);
    g_test_add_func("/core/general/test_nm_utils_uuid_generate_from_string",
                    test_nm_utils_uuid_generate_from_string);
    g_test_add_func("/core/general/nm_uuid_generate_from_strings",
                    test_nm_utils_uuid_generate_from_strings);
    g_test_add_func("/core/general/test_nm_uuid_init", test_nm_uuid_init);

    g_test_add_func("/core/general/_nm_utils_ascii_str_to_int64", test_nm_utils_ascii_str_to_int64);
    g_test_add_func("/core/general/nm_utils_is_power_of_two", test_nm_utils_is_power_of_two);
    g_test_add_func("/core/general/nm_utils_ptrarray_find_binary_search_range",
                    test_nm_utils_ptrarray_find_binary_search);
    g_test_add_func("/core/general/nm_utils_ptrarray_find_binary_search_with_duplicates",
                    test_nm_utils_ptrarray_find_binary_search_with_duplicates);
    g_test_add_func("/core/general/_nm_utils_strstrdictkey", test_nm_utils_strstrdictkey);
    g_test_add_func("/core/general/nm_ptrarray_len", test_nm_ptrarray_len);

    g_test_add_func("/core/general/_nm_utils_dns_option_validate",
                    test_nm_utils_dns_option_validate);
    g_test_add_func("/core/general/_nm_utils_dns_option_find_idx",
                    test_nm_utils_dns_option_find_idx);
    g_test_add_func("/core/general/_nm_utils_validate_json", test_nm_utils_check_valid_json);
    g_test_add_func("/core/general/_nm_utils_team_config_equal", test_nm_utils_team_config_equal);
    g_test_add_func("/core/general/test_nm_utils_enum", test_nm_utils_enum);
    g_test_add_func("/core/general/nm-set-out", test_nm_set_out);
    g_test_add_func("/core/general/route_attributes/parse", test_route_attributes_parse);
    g_test_add_func("/core/general/route_attributes/format", test_route_attributes_format);
    g_test_add_func("/core/general/test_variant_attribute_spec", test_variant_attribute_spec);

    g_test_add_func("/core/general/get_start_time_for_pid", test_get_start_time_for_pid);
    g_test_add_func("/core/general/test_nm_va_args_macros", test_nm_va_args_macros);
    g_test_add_func("/core/general/test_ethtool_offload", test_ethtool_offload);

    g_test_add_data_func("/core/general/test_integrate_maincontext/1",
                         GUINT_TO_POINTER(1),
                         test_integrate_maincontext);
    g_test_add_data_func("/core/general/test_integrate_maincontext/2",
                         GUINT_TO_POINTER(2),
                         test_integrate_maincontext);

    g_test_add_func("/core/general/test_nm_ip_addr_zero", test_nm_ip_addr_zero);
    g_test_add_func("/core/general/test_nm_utils_wifi_ghz_freqs", test_nm_utils_wifi_ghz_freqs);

    g_test_add_func("/core/general/test_strsplit_quoted", test_strsplit_quoted);
    g_test_add_func("/core/general/test_vpn_connection_state_reason",
                    test_vpn_connection_state_reason);

    return g_test_run();
}
