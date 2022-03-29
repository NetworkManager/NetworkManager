/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2009 - 2013 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-rfkill-manager.h"

#include <libudev.h>

#include "c-list/src/c-list.h"
#include "libnm-udev-aux/nm-udev-utils.h"

/*****************************************************************************/

enum {
    RFKILL_CHANGED,
    LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = {0};

typedef struct {
    NMUdevClient *udev_client;

    /* Authoritative rfkill state (RFKILL_* enum) */
    NMRfkillState rfkill_states[NM_RFKILL_TYPE_MAX];

    CList killswitch_lst_head;
} NMRfkillManagerPrivate;

struct _NMRfkillManager {
    GObject                parent;
    NMRfkillManagerPrivate _priv;
};

struct _NMRfkillManagerClass {
    GObjectClass parent;
};

G_DEFINE_TYPE(NMRfkillManager, nm_rfkill_manager, G_TYPE_OBJECT)

#define NM_RFKILL_MANAGER_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMRfkillManager, NM_IS_RFKILL_MANAGER)

/*****************************************************************************/

typedef struct {
    CList        killswitch_lst;
    char        *name;
    char        *path;
    char        *driver;
    guint64      seqnum;
    NMRfkillType rtype;
    int          state;
    bool         platform : 1;
} Killswitch;

NMRfkillState
nm_rfkill_manager_get_rfkill_state(NMRfkillManager *self, NMRfkillType rtype)
{
    g_return_val_if_fail(self != NULL, NM_RFKILL_STATE_UNBLOCKED);
    g_return_val_if_fail(rtype < NM_RFKILL_TYPE_MAX, NM_RFKILL_STATE_UNBLOCKED);

    return NM_RFKILL_MANAGER_GET_PRIVATE(self)->rfkill_states[rtype];
}

NMRadioFlags
nm_rfkill_type_to_radio_available_flag(NMRfkillType type)
{
    switch (type) {
    case NM_RFKILL_TYPE_WLAN:
        return NM_RADIO_FLAG_WLAN_AVAILABLE;
    case NM_RFKILL_TYPE_WWAN:
        return NM_RADIO_FLAG_WWAN_AVAILABLE;
    case NM_RFKILL_TYPE_UNKNOWN:
        break;
    }
    return nm_assert_unreachable_val(NM_RADIO_FLAG_NONE);
}

const char *
nm_rfkill_type_to_string(NMRfkillType type)
{
    switch (type) {
    case NM_RFKILL_TYPE_WLAN:
        return "Wi-Fi";
    case NM_RFKILL_TYPE_WWAN:
        return "WWAN";
    case NM_RFKILL_TYPE_UNKNOWN:
        break;
    }
    return nm_assert_unreachable_val("unknown");
}

static const char *
nm_rfkill_state_to_string(NMRfkillState state)
{
    switch (state) {
    case NM_RFKILL_STATE_UNAVAILABLE:
        return "unavailable";
    case NM_RFKILL_STATE_UNBLOCKED:
        return "unblocked";
    case NM_RFKILL_STATE_SOFT_BLOCKED:
        return "soft-blocked";
    case NM_RFKILL_STATE_HARD_BLOCKED:
        return "hard-blocked";
    case NM_RFKILL_STATE_HARD_BLOCKED_OS_NOT_OWNER:
        return "hard-blocked-os-not-owner";
    }
    return nm_assert_unreachable_val("unknown");
}

static Killswitch *
killswitch_new(struct udev_device *device, NMRfkillType rtype)
{
    Killswitch         *ks;
    struct udev_device *parent      = NULL;
    struct udev_device *grandparent = NULL;
    const char         *driver;
    const char         *subsys;
    const char         *parent_subsys = NULL;
    gboolean            platform;

    driver = udev_device_get_property_value(device, "DRIVER");
    subsys = udev_device_get_subsystem(device);

    /* Check parent for various attributes */
    parent = udev_device_get_parent(device);
    if (parent) {
        parent_subsys = udev_device_get_subsystem(parent);
        if (!driver)
            driver = udev_device_get_property_value(parent, "DRIVER");
        if (!driver) {
            /* Sigh; try the grandparent */
            grandparent = udev_device_get_parent(parent);
            if (grandparent)
                driver = udev_device_get_property_value(grandparent, "DRIVER");
        }
    }
    if (!driver)
        driver = "(unknown)";

    platform = FALSE;
    if (nm_streq0(subsys, "platform") || nm_streq0(parent_subsys, "platform")
        || nm_streq0(subsys, "acpi") || nm_streq0(parent_subsys, "acpi"))
        platform = TRUE;

    ks  = g_slice_new(Killswitch);
    *ks = (Killswitch){
        .name     = g_strdup(udev_device_get_sysname(device)),
        .seqnum   = udev_device_get_seqnum(device),
        .path     = g_strdup(udev_device_get_syspath(device)),
        .rtype    = rtype,
        .driver   = g_strdup(driver),
        .platform = platform,
    };

    return ks;
}

static void
killswitch_destroy(Killswitch *ks)
{
    c_list_unlink_stale(&ks->killswitch_lst);
    g_free(ks->name);
    g_free(ks->path);
    g_free(ks->driver);
    nm_g_slice_free(ks);
}

static NMRfkillState
sysfs_state_to_nm_state(int sysfs_state, int sysfs_reason)
{
    switch (sysfs_state) {
    case 0:
        return NM_RFKILL_STATE_SOFT_BLOCKED;
    case 1:
        return NM_RFKILL_STATE_UNBLOCKED;
    case 2:
        /* sysfs reason is a bitmap, in case we have both reasons (SIGNAL and NOT_OWNER), we want
         * to consider the device as not owned.
         */
        if (sysfs_reason & 2)
            return NM_RFKILL_STATE_HARD_BLOCKED_OS_NOT_OWNER;
        return NM_RFKILL_STATE_HARD_BLOCKED;
    default:
        nm_log_warn(LOGD_RFKILL, "unhandled rfkill state %d", sysfs_state);
        break;
    }
    return NM_RFKILL_STATE_UNBLOCKED;
}

static void
recheck_killswitches(NMRfkillManager *self)
{
    NMRfkillManagerPrivate *priv = NM_RFKILL_MANAGER_GET_PRIVATE(self);
    Killswitch             *ks;
    NMRfkillState           poll_states[NM_RFKILL_TYPE_MAX];
    NMRfkillState           platform_states[NM_RFKILL_TYPE_MAX];
    gboolean                platform_checked[NM_RFKILL_TYPE_MAX];
    int                     i;

    /* Default state is unblocked */
    for (i = 0; i < NM_RFKILL_TYPE_MAX; i++) {
        poll_states[i]      = NM_RFKILL_STATE_UNAVAILABLE;
        platform_states[i]  = NM_RFKILL_STATE_UNAVAILABLE;
        platform_checked[i] = FALSE;
    }

    /* Poll the states of all killswitches */
    c_list_for_each_entry (ks, &priv->killswitch_lst_head, killswitch_lst) {
        struct udev_device *device;
        NMRfkillState       dev_state;
        int                 sysfs_state;
        int                 sysfs_reason;

        device = udev_device_new_from_subsystem_sysname(nm_udev_client_get_udev(priv->udev_client),
                                                        "rfkill",
                                                        ks->name);
        if (!device)
            continue;
        sysfs_state =
            _nm_utils_ascii_str_to_int64(udev_device_get_property_value(device, "RFKILL_STATE"),
                                         10,
                                         G_MININT,
                                         G_MAXINT,
                                         -1);

        sysfs_reason = _nm_utils_ascii_str_to_int64(
            udev_device_get_property_value(device, "RFKILL_HW_BLOCK_REASON"),
            16,
            G_MININT,
            G_MAXINT,
            1); /* defaults to SIGNAL in case the kernel does not support this */

        dev_state = sysfs_state_to_nm_state(sysfs_state, sysfs_reason);

        nm_log_dbg(LOGD_RFKILL,
                   "%s rfkill%s switch %s state now %d/%s reason: 0x%x",
                   nm_rfkill_type_to_string(ks->rtype),
                   ks->platform ? " platform" : "",
                   ks->name,
                   sysfs_state,
                   nm_rfkill_state_to_string(dev_state),
                   sysfs_reason);

        if (ks->platform == FALSE) {
            if (dev_state > poll_states[ks->rtype])
                poll_states[ks->rtype] = dev_state;
        } else {
            platform_checked[ks->rtype] = TRUE;
            if (dev_state > platform_states[ks->rtype])
                platform_states[ks->rtype] = dev_state;
        }

        udev_device_unref(device);
    }

    /* Log and emit change signal for final rfkill states */
    for (i = 0; i < NM_RFKILL_TYPE_MAX; i++) {
        if (platform_checked[i] == TRUE) {
            /* blocked platform switch state overrides device state, otherwise
             * let the device state stand. (bgo #655773)
             */
            if (platform_states[i] > NM_RFKILL_STATE_UNBLOCKED)
                poll_states[i] = platform_states[i];
        }

        if (poll_states[i] != priv->rfkill_states[i]) {
            nm_log_dbg(LOGD_RFKILL,
                       "%s rfkill state now '%s'",
                       nm_rfkill_type_to_string(i),
                       nm_rfkill_state_to_string(poll_states[i]));

            priv->rfkill_states[i] = poll_states[i];
            g_signal_emit(self,
                          signals[RFKILL_CHANGED],
                          0,
                          (guint) i,
                          (guint) priv->rfkill_states[i]);
        }
    }
}

static Killswitch *
killswitch_find_by_name(NMRfkillManager *self, const char *name)
{
    NMRfkillManagerPrivate *priv = NM_RFKILL_MANAGER_GET_PRIVATE(self);
    Killswitch             *ks;

    nm_assert(name);

    c_list_for_each_entry (ks, &priv->killswitch_lst_head, killswitch_lst) {
        if (nm_streq(name, ks->name))
            return ks;
    }
    return NULL;
}

static NMRfkillType
rfkill_type_to_enum(const char *str)
{
    if (str) {
        if (nm_streq(str, "wlan"))
            return NM_RFKILL_TYPE_WLAN;
        if (nm_streq(str, "wwan"))
            return NM_RFKILL_TYPE_WWAN;
    }

    return NM_RFKILL_TYPE_UNKNOWN;
}

static void
add_one_killswitch(NMRfkillManager *self, struct udev_device *device)
{
    NMRfkillManagerPrivate *priv = NM_RFKILL_MANAGER_GET_PRIVATE(self);
    NMRfkillType            rtype;
    Killswitch             *ks;

    rtype = rfkill_type_to_enum(udev_device_get_property_value(device, "RFKILL_TYPE"));
    if (rtype == NM_RFKILL_TYPE_UNKNOWN)
        return;

    ks = killswitch_new(device, rtype);
    c_list_link_front(&priv->killswitch_lst_head, &ks->killswitch_lst);

    nm_log_info(LOGD_RFKILL,
                "%s: found %s radio killswitch (at %s) (%sdriver %s)",
                ks->name,
                nm_rfkill_type_to_string(rtype),
                ks->path,
                ks->platform ? "platform " : "",
                ks->driver ?: "<unknown>");
}

static void
rfkill_add(NMRfkillManager *self, struct udev_device *device)
{
    const char *name;

    g_return_if_fail(device != NULL);
    name = udev_device_get_sysname(device);

    g_return_if_fail(name != NULL);

    if (!killswitch_find_by_name(self, name))
        add_one_killswitch(self, device);
}

static void
rfkill_remove(NMRfkillManager *self, struct udev_device *device)
{
    NMRfkillManagerPrivate *priv = NM_RFKILL_MANAGER_GET_PRIVATE(self);
    Killswitch             *ks;
    const char             *name;

    g_return_if_fail(device != NULL);

    name = udev_device_get_sysname(device);

    g_return_if_fail(name != NULL);

    c_list_for_each_entry (ks, &priv->killswitch_lst_head, killswitch_lst) {
        if (nm_streq(ks->name, name)) {
            nm_log_info(LOGD_RFKILL, "radio killswitch %s disappeared", ks->path);
            killswitch_destroy(ks);
            return;
        }
    }
}

static void
handle_uevent(NMUdevClient *client, struct udev_device *device, gpointer user_data)
{
    NMRfkillManager *self = NM_RFKILL_MANAGER(user_data);
    const char      *subsys;
    const char      *action;

    action = udev_device_get_action(device);

    g_return_if_fail(action != NULL);

    /* A bit paranoid */
    subsys = udev_device_get_subsystem(device);
    g_return_if_fail(nm_streq0(subsys, "rfkill"));

    nm_log_dbg(LOGD_PLATFORM,
               "udev rfkill event: action '%s' device '%s'",
               action,
               udev_device_get_sysname(device));

    if (nm_streq(action, "add"))
        rfkill_add(self, device);
    else if (nm_streq(action, "remove"))
        rfkill_remove(self, device);

    recheck_killswitches(self);
}

/*****************************************************************************/

static void
nm_rfkill_manager_init(NMRfkillManager *self)
{
    NMRfkillManagerPrivate *priv = NM_RFKILL_MANAGER_GET_PRIVATE(self);
    struct udev_enumerate  *enumerate;
    struct udev_list_entry *iter;
    guint                   i;

    c_list_init(&priv->killswitch_lst_head);

    for (i = 0; i < NM_RFKILL_TYPE_MAX; i++)
        priv->rfkill_states[i] = NM_RFKILL_STATE_UNAVAILABLE;

    priv->udev_client = nm_udev_client_new(NM_MAKE_STRV("rfkill"), handle_uevent, self);

    enumerate = nm_udev_client_enumerate_new(priv->udev_client);
    udev_enumerate_scan_devices(enumerate);
    iter = udev_enumerate_get_list_entry(enumerate);
    for (; iter; iter = udev_list_entry_get_next(iter)) {
        struct udev_device *udevice;

        udevice = udev_device_new_from_syspath(udev_enumerate_get_udev(enumerate),
                                               udev_list_entry_get_name(iter));
        if (!udevice)
            continue;

        add_one_killswitch(self, udevice);
        udev_device_unref(udevice);
    }
    udev_enumerate_unref(enumerate);

    recheck_killswitches(self);
}

NMRfkillManager *
nm_rfkill_manager_new(void)
{
    return g_object_new(NM_TYPE_RFKILL_MANAGER, NULL);
}

static void
dispose(GObject *object)
{
    NMRfkillManager        *self = NM_RFKILL_MANAGER(object);
    NMRfkillManagerPrivate *priv = NM_RFKILL_MANAGER_GET_PRIVATE(self);
    Killswitch             *ks;

    while ((ks = c_list_first_entry(&priv->killswitch_lst_head, Killswitch, killswitch_lst)))
        killswitch_destroy(ks);

    priv->udev_client = nm_udev_client_destroy(priv->udev_client);

    G_OBJECT_CLASS(nm_rfkill_manager_parent_class)->dispose(object);
}

static void
nm_rfkill_manager_class_init(NMRfkillManagerClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);

    object_class->dispose = dispose;

    signals[RFKILL_CHANGED] = g_signal_new(NM_RFKILL_MANAGER_SIGNAL_RFKILL_CHANGED,
                                           G_OBJECT_CLASS_TYPE(object_class),
                                           G_SIGNAL_RUN_FIRST,
                                           0,
                                           NULL,
                                           NULL,
                                           NULL,
                                           G_TYPE_NONE,
                                           2,
                                           G_TYPE_UINT /* NMRfkillType */,
                                           G_TYPE_UINT /* NMRfkillState */);
}
