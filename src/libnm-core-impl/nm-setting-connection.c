/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2013 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-connection.h"

#include "libnm-glib-aux/nm-uuid.h"
#include "libnm-core-aux-intern/nm-common-macros.h"
#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-core-enum-types.h"
#include "nm-connection-private.h"
#include "nm-setting-bond.h"
#include "nm-setting-bridge.h"
#include "nm-setting-team.h"
#include "nm-setting-vlan.h"
#include "libnm-systemd-shared/nm-sd-utils-shared.h"

/**
 * SECTION:nm-setting-connection
 * @short_description: Describes general connection properties
 *
 * The #NMSettingConnection object is a #NMSetting subclass that describes
 * properties that apply to all #NMConnection objects, regardless of what type
 * of network connection they describe.  Each #NMConnection object must contain
 * a #NMSettingConnection setting.
 **/

/*****************************************************************************/

typedef enum _nm_packed {
    PERM_TYPE_INVALID,
    PERM_TYPE_USER,
} PermType;

typedef struct {
    PermType ptype;
    char    *item;
} Permission;

NM_GOBJECT_PROPERTIES_DEFINE(NMSettingConnection,
                             PROP_ID,
                             PROP_UUID,
                             PROP_INTERFACE_NAME,
                             PROP_TYPE,
                             PROP_PERMISSIONS,
                             PROP_AUTOCONNECT,
                             PROP_AUTOCONNECT_PRIORITY,
                             PROP_AUTOCONNECT_RETRIES,
                             PROP_MULTI_CONNECT,
                             PROP_TIMESTAMP,
                             PROP_READ_ONLY,
                             PROP_ZONE,
                             PROP_MASTER,
                             PROP_CONTROLLER,
                             PROP_SLAVE_TYPE,
                             PROP_PORT_TYPE,
                             PROP_AUTOCONNECT_SLAVES,
                             PROP_AUTOCONNECT_PORTS,
                             PROP_SECONDARIES,
                             PROP_GATEWAY_PING_TIMEOUT,
                             PROP_METERED,
                             PROP_LLDP,
                             PROP_MDNS,
                             PROP_LLMNR,
                             PROP_DNS_OVER_TLS,
                             PROP_MPTCP_FLAGS,
                             PROP_STABLE_ID,
                             PROP_AUTH_RETRIES,
                             PROP_WAIT_DEVICE_TIMEOUT,
                             PROP_MUD_URL,
                             PROP_WAIT_ACTIVATION_DELAY,
                             PROP_DOWN_ON_POWEROFF, );

typedef struct {
    GArray     *permissions;
    NMValueStrv secondaries;
    char       *id;
    char       *uuid;
    char       *stable_id;
    char       *interface_name;
    char       *type;
    char       *controller;
    char       *port_type;
    char       *zone;
    char       *mud_url;
    guint64     timestamp;
    int         autoconnect_ports;
    int         down_on_poweroff;
    int         metered;
    gint32      autoconnect_priority;
    gint32      autoconnect_retries;
    gint32      multi_connect;
    gint32      auth_retries;
    gint32      mdns;
    gint32      llmnr;
    gint32      dns_over_tls;
    gint32      wait_device_timeout;
    gint32      lldp;
    gint32      wait_activation_delay;
    guint32     mptcp_flags;
    guint32     gateway_ping_timeout;
    bool        autoconnect;
    bool        read_only;
} NMSettingConnectionPrivate;

/**
 * NMSettingConnection:
 *
 * General Connection Profile Settings
 */
struct _NMSettingConnection {
    NMSetting                  parent;
    NMSettingConnectionPrivate _priv;
};

struct _NMSettingConnectionClass {
    NMSettingClass parent;
};

G_DEFINE_TYPE(NMSettingConnection, nm_setting_connection, NM_TYPE_SETTING)

#define NM_SETTING_CONNECTION_GET_PRIVATE(o) \
    _NM_GET_PRIVATE(o, NMSettingConnection, NM_IS_SETTING_CONNECTION, NMSetting)

/*****************************************************************************/

static void
_permission_set_stale(Permission *permission, PermType ptype, char *item_take)
{
    nm_assert(permission);
    nm_assert(NM_IN_SET(ptype, PERM_TYPE_INVALID, PERM_TYPE_USER));
    nm_assert(ptype != PERM_TYPE_USER
              || nm_settings_connection_validate_permission_user(item_take, -1));

    /* we don't inspect (clear) permission before setting. It takes a
     * stale instance. */
    *permission = (Permission){
        .ptype = ptype,
        .item  = item_take,
    };
}

static void
_permission_clear_stale(Permission *permission)
{
    g_free(permission->item);
    /* We leave the permission instance with dangling pointers.
     * It is "stale". */
}

static gboolean
_permission_set_stale_parse(Permission *permission, const char *str)
{
    const char *str0 = str;
    const char *last_colon;
    gsize       ulen;

    nm_assert(str);

    if (!str)
        goto invalid;

    if (!NM_STR_HAS_PREFIX(str, NM_SETTINGS_CONNECTION_PERMISSION_USER_PREFIX))
        goto invalid;

    str += NM_STRLEN(NM_SETTINGS_CONNECTION_PERMISSION_USER_PREFIX);

    last_colon = strrchr(str, ':');
    if (last_colon) {
        /* Reject :[detail] for now */
        if (last_colon[1] != '\0')
            goto invalid;
        ulen = last_colon - str;
    } else
        ulen = strlen(str);

    if (!nm_settings_connection_validate_permission_user(str, ulen))
        goto invalid;

    /* Yay, valid... create the new permission */
    if (permission)
        _permission_set_stale(permission, PERM_TYPE_USER, g_strndup(str, ulen));
    return TRUE;

invalid:
    if (permission)
        _permission_set_stale(permission, PERM_TYPE_INVALID, g_strdup(str0));
    return FALSE;
}

static char *
_permission_to_string(Permission *permission)
{
    nm_assert(permission);

    switch (permission->ptype) {
    case PERM_TYPE_USER:
        return g_strdup_printf(NM_SETTINGS_CONNECTION_PERMISSION_USER_PREFIX "%s:",
                               permission->item);
    case PERM_TYPE_INVALID:
        nm_assert(permission->item);
        return g_strdup(permission->item);
    }
    nm_assert_not_reached();
    return g_strdup(permission->item ?: "");
}

/*****************************************************************************/

/**
 * nm_setting_connection_get_id:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:id property of the connection.
 *
 * Returns: the connection ID
 **/
const char *
nm_setting_connection_get_id(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), NULL);

    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->id;
}

/**
 * nm_setting_connection_get_uuid:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:uuid property of the connection.
 *
 * Returns: the connection UUID
 **/
const char *
nm_setting_connection_get_uuid(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), NULL);

    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->uuid;
}

/**
 * nm_setting_connection_get_stable_id:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:stable_id property of the connection.
 *
 * Returns: the stable-id for the connection
 *
 * Since: 1.4
 **/
const char *
nm_setting_connection_get_stable_id(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), NULL);

    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->stable_id;
}

/**
 * nm_setting_connection_get_interface_name:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:interface-name property of the connection.
 *
 * Returns: the connection's interface name
 **/
const char *
nm_setting_connection_get_interface_name(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), NULL);

    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->interface_name;
}

/**
 * nm_setting_connection_get_connection_type:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:type property of the connection.
 *
 * Returns: the connection type
 **/
const char *
nm_setting_connection_get_connection_type(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), NULL);

    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->type;
}

/**
 * nm_setting_connection_get_num_permissions:
 * @setting: the #NMSettingConnection
 *
 * Returns the number of entries in the #NMSettingConnection:permissions
 * property of this setting.
 *
 * Returns: the number of permissions entries
 */
guint32
nm_setting_connection_get_num_permissions(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), 0);

    return nm_g_array_len(NM_SETTING_CONNECTION_GET_PRIVATE(setting)->permissions);
}

/**
 * nm_setting_connection_get_permission:
 * @setting: the #NMSettingConnection
 * @idx: the zero-based index of the permissions entry
 * @out_ptype: on return, the permission type. This is currently always "user",
 *   unless the entry is invalid, in which case it returns "invalid".
 * @out_pitem: on return, the permission item (formatted according to @ptype, see
 * #NMSettingConnection:permissions for more detail
 * @out_detail: on return, the permission detail (at this time, always %NULL)
 *
 * Retrieve one of the entries of the #NMSettingConnection:permissions property
 * of this setting.
 *
 * Returns: %TRUE if a permission was returned, %FALSE if @idx was invalid
 */
gboolean
nm_setting_connection_get_permission(NMSettingConnection *setting,
                                     guint32              idx,
                                     const char         **out_ptype,
                                     const char         **out_pitem,
                                     const char         **out_detail)
{
    NMSettingConnectionPrivate *priv;
    Permission                 *permission;

    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), FALSE);

    priv = NM_SETTING_CONNECTION_GET_PRIVATE(setting);

    g_return_val_if_fail(idx < nm_g_array_len(priv->permissions), FALSE);

    permission = &nm_g_array_index(priv->permissions, Permission, idx);
    switch (permission->ptype) {
    case PERM_TYPE_USER:
        NM_SET_OUT(out_ptype, NM_SETTINGS_CONNECTION_PERMISSION_USER);
        NM_SET_OUT(out_pitem, permission->item);
        NM_SET_OUT(out_detail, NULL);
        return TRUE;
    case PERM_TYPE_INVALID:
        goto invalid;
    }
    nm_assert_not_reached();
invalid:
    NM_SET_OUT(out_ptype, "invalid");
    NM_SET_OUT(out_pitem, permission->item);
    NM_SET_OUT(out_detail, NULL);
    return TRUE;
}

static gboolean
_permissions_user_allowed(NMSettingConnection *setting, const char *uname, gulong uid)
{
    gs_free struct passwd      *pw = NULL;
    NMSettingConnectionPrivate *priv;
    guint                       i;

    nm_assert(NM_IS_SETTING_CONNECTION(setting));

    priv = NM_SETTING_CONNECTION_GET_PRIVATE(setting);

    if (nm_g_array_len(priv->permissions) == 0) {
        /* If no permissions, visible to all */
        return TRUE;
    }

    for (i = 0; i < priv->permissions->len; i++) {
        const Permission *permission = &nm_g_array_index(priv->permissions, Permission, i);

        if (permission->ptype != PERM_TYPE_USER)
            continue;

        if (!uname) {
            if (uid != G_MAXULONG) {
                pw    = nm_getpwuid(uid);
                uname = nm_passwd_name(pw);
            }
            if (!uname)
                return FALSE;
        }

        if (nm_streq(permission->item, uname))
            return TRUE;
    }

    return FALSE;
}

/**
 * nm_setting_connection_permissions_user_allowed:
 * @setting: the #NMSettingConnection
 * @uname: the user name to check permissions for
 *
 * Checks whether the given username is allowed to view/access this connection.
 *
 * Returns: %TRUE if the requested user is allowed to view this connection,
 * %FALSE if the given user is not allowed to view this connection
 */
gboolean
nm_setting_connection_permissions_user_allowed(NMSettingConnection *setting, const char *uname)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), FALSE);
    g_return_val_if_fail(uname != NULL, FALSE);

    return _permissions_user_allowed(setting, uname, G_MAXULONG);
}

gboolean
nm_setting_connection_permissions_user_allowed_by_uid(NMSettingConnection *setting, gulong uid)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), FALSE);

    return _permissions_user_allowed(setting, NULL, uid);
}

/**
 * nm_setting_connection_add_permission:
 * @setting: the #NMSettingConnection
 * @ptype: the permission type; at this time only "user" is supported
 * @pitem: the permission item formatted as required for @ptype
 * @detail: (nullable): unused at this time; must be %NULL
 *
 * Adds a permission to the connection's permission list.  At this time, only
 * the "user" permission type is supported, and @pitem must be a username. See
 * #NMSettingConnection:permissions: for more details.
 *
 * Returns: %TRUE if the permission was unique and was successfully added to the
 * list, %FALSE if @ptype or @pitem was invalid.
 * If the permission was already present in the list, it will not be added
 * a second time but %TRUE will be returned. Note that before 1.28, in this
 * case %FALSE would be returned.
 */
gboolean
nm_setting_connection_add_permission(NMSettingConnection *setting,
                                     const char          *ptype,
                                     const char          *pitem,
                                     const char          *detail)
{
    NMSettingConnectionPrivate *priv;
    guint                       i;

    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), FALSE);
    g_return_val_if_fail(ptype, FALSE);
    g_return_val_if_fail(pitem, FALSE);

    if (!nm_streq0(ptype, NM_SETTINGS_CONNECTION_PERMISSION_USER))
        return FALSE;

    if (!nm_settings_connection_validate_permission_user(pitem, -1))
        return FALSE;

    if (detail)
        return FALSE;

    priv = NM_SETTING_CONNECTION_GET_PRIVATE(setting);

    if (!priv->permissions) {
        priv->permissions = g_array_sized_new(FALSE, FALSE, sizeof(Permission), 1);
        g_array_set_clear_func(priv->permissions, (GDestroyNotify) _permission_clear_stale);
    }

    for (i = 0; i < priv->permissions->len; i++) {
        const Permission *permission = &nm_g_array_index(priv->permissions, Permission, i);

        if (permission->ptype == PERM_TYPE_USER && nm_streq(permission->item, pitem))
            return TRUE;
    }

    _permission_set_stale(nm_g_array_append_new(priv->permissions, Permission),
                          PERM_TYPE_USER,
                          g_strdup(pitem));
    _notify(setting, PROP_PERMISSIONS);
    return TRUE;
}

/**
 * nm_setting_connection_remove_permission:
 * @setting: the #NMSettingConnection
 * @idx: the zero-based index of the permission to remove
 *
 * Removes the permission at index @idx from the connection.
 */
void
nm_setting_connection_remove_permission(NMSettingConnection *setting, guint32 idx)
{
    NMSettingConnectionPrivate *priv;

    g_return_if_fail(NM_IS_SETTING_CONNECTION(setting));

    priv = NM_SETTING_CONNECTION_GET_PRIVATE(setting);

    g_return_if_fail(idx < nm_g_array_len(priv->permissions));

    g_array_remove_index(priv->permissions, idx);

    _notify(setting, PROP_PERMISSIONS);
}

/**
 * nm_setting_connection_remove_permission_by_value:
 * @setting: the #NMSettingConnection
 * @ptype: the permission type; at this time only "user" is supported
 * @pitem: the permission item formatted as required for @ptype
 * @detail: (nullable): unused at this time; must be %NULL
 *
 * Removes the permission from the connection.
 * At this time, only the "user" permission type is supported, and @pitem must
 * be a username. See #NMSettingConnection:permissions: for more details.
 *
 * Returns: %TRUE if the permission was found and removed; %FALSE if it was not.
 */
gboolean
nm_setting_connection_remove_permission_by_value(NMSettingConnection *setting,
                                                 const char          *ptype,
                                                 const char          *pitem,
                                                 const char          *detail)
{
    NMSettingConnectionPrivate *priv;
    guint                       i;

    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), FALSE);
    g_return_val_if_fail(ptype, FALSE);
    g_return_val_if_fail(pitem, FALSE);

    if (!nm_streq0(ptype, NM_SETTINGS_CONNECTION_PERMISSION_USER))
        return FALSE;

    if (detail)
        return FALSE;

    priv = NM_SETTING_CONNECTION_GET_PRIVATE(setting);
    if (priv->permissions) {
        for (i = 0; i < priv->permissions->len; i++) {
            const Permission *permission = &nm_g_array_index(priv->permissions, Permission, i);

            if (permission->ptype == PERM_TYPE_USER && nm_streq(permission->item, pitem)) {
                g_array_remove_index(priv->permissions, i);
                _notify(setting, PROP_PERMISSIONS);
                return TRUE;
            }
        }
    }
    return FALSE;
}

/**
 * nm_setting_connection_get_autoconnect:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:autoconnect property of the connection.
 *
 * Returns: the connection's autoconnect behavior
 **/
gboolean
nm_setting_connection_get_autoconnect(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), FALSE);

    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->autoconnect;
}

/**
 * nm_setting_connection_get_autoconnect_priority:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:autoconnect-priority property of the connection.
 * The higher number, the higher priority.
 *
 * Returns: the connection's autoconnect priority
 **/
int
nm_setting_connection_get_autoconnect_priority(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), 0);

    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->autoconnect_priority;
}

/**
 * nm_setting_connection_get_autoconnect_retries:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:autoconnect-retries property of the connection.
 * Zero means infinite, -1 means the global default value.
 *
 * Returns: the connection's autoconnect retries
 *
 * Since: 1.6
 **/
int
nm_setting_connection_get_autoconnect_retries(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), -1);

    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->autoconnect_retries;
}

/**
 * nm_setting_connection_get_multi_connect:
 * @setting: the #NMSettingConnection
 *
 * Returns: the #NMSettingConnection:multi-connect property of the connection.
 *
 * Since: 1.14
 **/
NMConnectionMultiConnect
nm_setting_connection_get_multi_connect(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), -1);

    return (NMConnectionMultiConnect) NM_SETTING_CONNECTION_GET_PRIVATE(setting)->multi_connect;
}

/**
 * nm_setting_connection_get_auth_retries:
 * @setting: the #NMSettingConnection
 *
 * Returns the value contained in the #NMSettingConnection:auth-retries property.
 *
 * Returns: the configured authentication retries. Zero means
 * infinity and -1 means a global default value.
 *
 * Since: 1.10
 **/
int
nm_setting_connection_get_auth_retries(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), -1);

    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->auth_retries;
}

/**
 * nm_setting_connection_get_timestamp:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:timestamp property of the connection.
 *
 * Returns: the connection's timestamp
 **/
guint64
nm_setting_connection_get_timestamp(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), 0);

    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->timestamp;
}

static GVariant *
_to_dbus_fcn_timestamp(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil)
{
    guint64 v;

    v = options && options->timestamp.has ? options->timestamp.val
                                          : NM_SETTING_CONNECTION_GET_PRIVATE(setting)->timestamp;

    if (v == 0u)
        return NULL;

    return g_variant_new_uint64(v);
}

/**
 * nm_setting_connection_get_read_only:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:read-only property of the connection.
 *
 * Returns: %TRUE if the connection is read-only, %FALSE if it is not
 *
 * Deprecated: 1.44: This property is deprecated and has no meaning.
 **/
gboolean
nm_setting_connection_get_read_only(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), TRUE);

    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->read_only;
}

/**
 * nm_setting_connection_get_zone:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:zone property of the connection.
 *
 * Returns: the trust level of a connection
 **/
const char *
nm_setting_connection_get_zone(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), NULL);

    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->zone;
}

/**
 * nm_setting_connection_get_master:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:master property of the connection.
 *
 * Returns: interface name of the master device or UUID of the master
 * connection.
 *
 * Deprecated: 1.46. Use nm_setting_connection_get_master() instead which
 * is just an alias.
 */
const char *
nm_setting_connection_get_master(NMSettingConnection *setting)
{
    return nm_setting_connection_get_controller(setting);
}

/**
 * nm_setting_connection_get_controller:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:controller property of the connection.
 *
 * Returns: interface name of the controller device or UUID of the controller
 * connection.
 *
 * Since: 1.46
 */
const char *
nm_setting_connection_get_controller(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), NULL);

    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->controller;
}

/**
 * nm_setting_connection_get_port_type:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:port-type property of the connection.
 *
 * Returns: the type of port this connection is, if any.
 *
 * Since: 1.46
 */
const char *
nm_setting_connection_get_port_type(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), NULL);

    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->port_type;
}

/**
 * nm_setting_connection_get_slave_type:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:slave-type property of the connection.
 *
 * Returns: the type of slave this connection is, if any
 *
 * Deprecated: 1.46. Use nm_setting_connection_get_port_type() instead which
 * is just an alias.
 */
const char *
nm_setting_connection_get_slave_type(NMSettingConnection *setting)
{
    return nm_setting_connection_get_port_type(setting);
}

/**
 * nm_setting_connection_is_slave_type:
 * @setting: the #NMSettingConnection
 * @type: the setting name (ie #NM_SETTING_BOND_SETTING_NAME) to be matched
 * against @setting's slave type
 *
 * Returns: %TRUE if connection is of the given slave @type
 *
 * Deprecated: 1.46.
 */
gboolean
nm_setting_connection_is_slave_type(NMSettingConnection *setting, const char *type)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), FALSE);

    return nm_streq0(NM_SETTING_CONNECTION_GET_PRIVATE(setting)->port_type, type);
}

/**
 * nm_setting_connection_get_wait_device_timeout:
 * @setting: the #NMSettingConnection
 *
 * Returns: the %NM_SETTING_CONNECTION_WAIT_DEVICE_TIMEOUT property with
 *   the timeout in milliseconds. -1 is the default.
 *
 * Since: 1.20
 */
gint32
nm_setting_connection_get_wait_device_timeout(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), -1);

    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->wait_device_timeout;
}

/**
 * nm_setting_connection_get_wait_activation_delay:
 * @setting: the #NMSettingConnection
 *
 * Returns: the %NM_SETTING_CONNECTION_WAIT_ACTIVATION_DELAY property with
 *   the delay in milliseconds. -1 is the default.
 *
 * Since: 1.40
 */
gint32
nm_setting_connection_get_wait_activation_delay(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), -1);

    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->wait_activation_delay;
}

/**
 * nm_setting_connection_get_down_on_poweroff:
 * @setting: the #NMSettingConnection
 *
 * Returns the %NM_SETTING_CONNECTION_DOWN_ON_POWEROFF property.
 *
 * Returns: whether the connection will be brought down before the system
 * is powered off.
 *
 * Since: 1.48
 */
NMSettingConnectionDownOnPoweroff
nm_setting_connection_get_down_on_poweroff(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting),
                         NM_SETTING_CONNECTION_DOWN_ON_POWEROFF_DEFAULT);

    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->down_on_poweroff;
}

/**
 * nm_setting_connection_get_autoconnect_ports:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:autoconnect-ports property of the connection.
 *
 * Returns: whether ports of the connection should be activated together
 *          with the connection.
 *
 * Since: 1.46
 **/
NMTernary
nm_setting_connection_get_autoconnect_ports(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), NM_TERNARY_DEFAULT);

    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->autoconnect_ports;
}

/**
 * nm_setting_connection_get_autoconnect_slaves:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:autoconnect-slaves property of the connection.
 *
 * Returns: whether slaves of the connection should be activated together
 *          with the connection.
 *
 * Since: 1.2
 *
 * Deprecated: 1.46. Use nm_setting_connection_get_autoconnect_ports() instead, this
 * is just an alias.
 **/
NMSettingConnectionAutoconnectSlaves
nm_setting_connection_get_autoconnect_slaves(NMSettingConnection *setting)
{
    return (NMSettingConnectionAutoconnectSlaves) nm_setting_connection_get_autoconnect_ports(
        setting);
}

GArray *
_nm_setting_connection_get_secondaries(NMSettingConnection *setting)
{
    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->secondaries.arr;
}

/**
 * nm_setting_connection_get_num_secondaries:
 * @setting: the #NMSettingConnection
 *
 * Returns: the number of configured secondary connection UUIDs
 **/
guint32
nm_setting_connection_get_num_secondaries(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), 0);

    return nm_g_array_len(NM_SETTING_CONNECTION_GET_PRIVATE(setting)->secondaries.arr);
}

/**
 * nm_setting_connection_get_secondary:
 * @setting: the #NMSettingConnection
 * @idx: the zero-based index of the secondary connection UUID entry.
 *   Access one past the length of secondaries is ok and will return
 *   %NULL. Otherwise, it is a user error.
 *
 * Returns: the secondary connection UUID at index @idx or
 *   %NULL if @idx is the number of secondaries.
 **/
const char *
nm_setting_connection_get_secondary(NMSettingConnection *setting, guint32 idx)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), NULL);

    return nm_strvarray_get_idxnull_or_greturn(
        NM_SETTING_CONNECTION_GET_PRIVATE(setting)->secondaries.arr,
        idx);
}

/**
 * nm_setting_connection_get_mud_url:
 * @setting: the #NMSettingConnection
 *
 * Returns the value contained in the #NMSettingConnection:mud-url
 * property.
 *
 * Since: 1.26
 **/
const char *
nm_setting_connection_get_mud_url(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), NULL);

    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->mud_url;
}

/**
 * nm_setting_connection_add_secondary:
 * @setting: the #NMSettingConnection
 * @sec_uuid: the secondary connection UUID to add
 *
 * Adds a new secondary connection UUID to the setting.
 *
 * Returns: %TRUE if the secondary connection UUID was added; %FALSE if the UUID
 * was already present
 **/
gboolean
nm_setting_connection_add_secondary(NMSettingConnection *setting, const char *sec_uuid)
{
    NMSettingConnectionPrivate *priv;

    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), FALSE);
    g_return_val_if_fail(sec_uuid, FALSE);

    priv = NM_SETTING_CONNECTION_GET_PRIVATE(setting);

    if (!nm_strvarray_ensure_and_add_unique(&priv->secondaries.arr, sec_uuid))
        return FALSE;

    _notify(setting, PROP_SECONDARIES);
    return TRUE;
}

/**
 * nm_setting_connection_remove_secondary:
 * @setting: the #NMSettingConnection
 * @idx: index number of the secondary connection UUID
 *
 * Removes the secondary connection UUID at index @idx.
 **/
void
nm_setting_connection_remove_secondary(NMSettingConnection *setting, guint32 idx)
{
    NMSettingConnectionPrivate *priv;

    g_return_if_fail(NM_IS_SETTING_CONNECTION(setting));

    priv = NM_SETTING_CONNECTION_GET_PRIVATE(setting);

    g_return_if_fail(idx < nm_g_array_len(priv->secondaries.arr));

    nm_strvarray_remove_index(priv->secondaries.arr, idx);
    _notify(setting, PROP_SECONDARIES);
}

/**
 * nm_setting_connection_remove_secondary_by_value:
 * @setting: the #NMSettingConnection
 * @sec_uuid: the secondary connection UUID to remove
 *
 * Removes the secondary connection UUID @sec_uuid.
 *
 * Returns: %TRUE if the secondary connection UUID was found and removed; %FALSE if it was not.
 **/
gboolean
nm_setting_connection_remove_secondary_by_value(NMSettingConnection *setting, const char *sec_uuid)
{
    NMSettingConnectionPrivate *priv;

    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), FALSE);
    g_return_val_if_fail(sec_uuid, FALSE);

    priv = NM_SETTING_CONNECTION_GET_PRIVATE(setting);

    if (!nm_strvarray_remove_first(priv->secondaries.arr, sec_uuid))
        return FALSE;

    _notify(setting, PROP_SECONDARIES);
    return TRUE;
}

/**
 * nm_setting_connection_get_gateway_ping_timeout:
 * @setting: the #NMSettingConnection
 *
 * Returns: the value contained in the #NMSettingConnection:gateway-ping-timeout
 * property.
 **/
guint32
nm_setting_connection_get_gateway_ping_timeout(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), 0);

    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->gateway_ping_timeout;
}

/**
 * nm_setting_connection_get_metered:
 * @setting: the #NMSettingConnection
 *
 * Returns: the #NMSettingConnection:metered property of the setting.
 *
 * Since: 1.2
 **/
NMMetered
nm_setting_connection_get_metered(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), NM_METERED_UNKNOWN);

    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->metered;
}

/**
 * nm_setting_connection_get_lldp:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:lldp property of the connection.
 *
 * Returns: a %NMSettingConnectionLldp which indicates whether LLDP must be
 * enabled for the connection.
 *
 * Since: 1.2
 **/
NMSettingConnectionLldp
nm_setting_connection_get_lldp(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), NM_SETTING_CONNECTION_LLDP_DEFAULT);

    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->lldp;
}

/**
 * nm_setting_connection_get_mdns:
 * @setting: the #NMSettingConnection
 *
 * Returns: the #NMSettingConnection:mdns property of the setting.
 *
 * Since: 1.12
 **/
NMSettingConnectionMdns
nm_setting_connection_get_mdns(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), NM_SETTING_CONNECTION_MDNS_DEFAULT);

    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->mdns;
}

/**
 * nm_setting_connection_get_llmnr:
 * @setting: the #NMSettingConnection
 *
 * Returns: the #NMSettingConnection:llmnr property of the setting.
 *
 * Since: 1.14
 **/
NMSettingConnectionLlmnr
nm_setting_connection_get_llmnr(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), NM_SETTING_CONNECTION_LLMNR_DEFAULT);

    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->llmnr;
}

/**
 * nm_setting_connection_get_dns_over_tls:
 * @setting: the #NMSettingConnection
 *
 * Returns: the #NMSettingConnection:dns-over-tls property of the setting.
 *
 * Since: 1.34
 **/
NMSettingConnectionDnsOverTls
nm_setting_connection_get_dns_over_tls(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting),
                         NM_SETTING_CONNECTION_DNS_OVER_TLS_DEFAULT);

    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->dns_over_tls;
}

/**
 * nm_setting_connection_get_mptcp_flags:
 * @setting: the #NMSettingConnection
 *
 * Returns: the #NMSettingConnection:mptcp-flags property of the setting.
 *
 * Since: 1.42
 **/
NMMptcpFlags
nm_setting_connection_get_mptcp_flags(NMSettingConnection *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CONNECTION(setting), NM_MPTCP_FLAGS_NONE);

    return NM_SETTING_CONNECTION_GET_PRIVATE(setting)->mptcp_flags;
}

static void
_set_error_missing_base_setting(GError **error, const char *type)
{
    g_set_error(error,
                NM_CONNECTION_ERROR,
                NM_CONNECTION_ERROR_MISSING_SETTING,
                _("setting required for connection of type '%s'"),
                type);
    g_prefix_error(error, "%s: ", type);
}

gboolean
_nm_connection_detect_slave_type_full(NMSettingConnection *s_con,
                                      NMConnection        *connection,
                                      const char         **out_slave_type,
                                      const char         **out_normerr_slave_setting_type,
                                      const char         **out_normerr_missing_slave_type,
                                      const char         **out_normerr_missing_slave_type_port,
                                      GError             **error)
{
    NMSettingConnectionPrivate *priv = NM_SETTING_CONNECTION_GET_PRIVATE(s_con);
    gboolean                    is_slave;
    const char                 *slave_setting_type;
    const char                 *slave_type;
    const char                 *normerr_slave_setting_type      = NULL;
    const char                 *normerr_missing_slave_type      = NULL;
    const char                 *normerr_missing_slave_type_port = NULL;

    is_slave           = FALSE;
    slave_setting_type = NULL;
    slave_type         = priv->port_type;
    if (slave_type) {
        is_slave = _nm_setting_slave_type_is_valid(slave_type, &slave_setting_type);
        if (!is_slave) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("Unknown slave type '%s'"),
                        slave_type);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_CONNECTION_SETTING_NAME,
                           NM_SETTING_CONNECTION_PORT_TYPE);
            return FALSE;
        }
    }

    if (is_slave) {
        if (!priv->controller) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_MISSING_PROPERTY,
                        _("Slave connections need a valid '%s' property"),
                        NM_SETTING_CONNECTION_CONTROLLER);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_CONNECTION_SETTING_NAME,
                           NM_SETTING_CONNECTION_CONTROLLER);
            return FALSE;
        }
        if (slave_setting_type && connection
            && !nm_connection_get_setting_by_name(connection, slave_setting_type))
            normerr_slave_setting_type = slave_setting_type;
    } else {
        nm_assert(!slave_type);
        if (priv->controller) {
            NMSetting *s_port;

            if (connection
                && (slave_type = _nm_connection_detect_slave_type(connection, &s_port))) {
                normerr_missing_slave_type      = slave_type;
                normerr_missing_slave_type_port = nm_setting_get_name(s_port);
            } else {
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_MISSING_PROPERTY,
                            _("Cannot set '%s' without '%s'"),
                            NM_SETTING_CONNECTION_CONTROLLER,
                            NM_SETTING_CONNECTION_PORT_TYPE);
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_CONNECTION_SETTING_NAME,
                               NM_SETTING_CONNECTION_PORT_TYPE);
                return FALSE;
            }
        }
    }

    NM_SET_OUT(out_slave_type, slave_type);
    NM_SET_OUT(out_normerr_slave_setting_type, normerr_slave_setting_type);
    NM_SET_OUT(out_normerr_missing_slave_type, normerr_missing_slave_type);
    NM_SET_OUT(out_normerr_missing_slave_type_port, normerr_missing_slave_type_port);
    return TRUE;
}

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingConnection        *self              = NM_SETTING_CONNECTION(setting);
    NMSettingConnectionPrivate *priv              = NM_SETTING_CONNECTION_GET_PRIVATE(self);
    NMSetting                  *normerr_base_type = NULL;
    const char                 *type;
    const char                 *slave_type;
    const char                 *normerr_slave_setting_type      = NULL;
    const char                 *normerr_missing_slave_type      = NULL;
    const char                 *normerr_missing_slave_type_port = NULL;
    gboolean                    normerr_base_setting            = FALSE;
    gboolean                    uuid_was_normalized             = FALSE;

    if (!priv->id) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_MISSING_PROPERTY,
                            _("property is missing"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_CONNECTION_SETTING_NAME,
                       NM_SETTING_CONNECTION_ID);
        return FALSE;
    } else if (!priv->id[0]) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property is empty"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_CONNECTION_SETTING_NAME,
                       NM_SETTING_CONNECTION_ID);
        return FALSE;
    }

    if (priv->uuid && !nm_uuid_is_valid_nm(priv->uuid, &uuid_was_normalized, NULL)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is not a valid UUID"),
                    priv->uuid);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_CONNECTION_SETTING_NAME,
                       NM_SETTING_CONNECTION_UUID);
        return FALSE;
    }

    type = priv->type;
    if (!type) {
        if (!connection
            || !(normerr_base_type = _nm_connection_find_base_type_setting(connection))) {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_MISSING_PROPERTY,
                                _("property is missing"));
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_CONNECTION_SETTING_NAME,
                           NM_SETTING_CONNECTION_TYPE);
            return FALSE;
        }
        type = nm_setting_get_name(normerr_base_type);
    } else {
        GType base_type;

        if (!type[0]) {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                _("property is empty"));
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_CONNECTION_SETTING_NAME,
                           NM_SETTING_CONNECTION_TYPE);
            return FALSE;
        }

        base_type = nm_setting_lookup_type(type);
        if (base_type == G_TYPE_INVALID
            || _nm_setting_type_get_base_type_priority(base_type) == NM_SETTING_PRIORITY_INVALID) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("connection type '%s' is not valid"),
                        type);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_CONNECTION_SETTING_NAME,
                           NM_SETTING_CONNECTION_TYPE);
            return FALSE;
        }

        /* Make sure the corresponding 'type' item is present */
        if (connection && !nm_connection_get_setting_by_name(connection, type)) {
            NMSetting    *s_base;
            NMConnection *connection2;

            s_base      = g_object_new(base_type, NULL);
            connection2 = nm_simple_connection_new_clone(connection);
            nm_connection_add_setting(connection2, s_base);

            normerr_base_setting = nm_setting_verify(s_base, connection2, NULL);

            g_object_unref(connection2);

            if (!normerr_base_setting) {
                _set_error_missing_base_setting(error, type);
                return FALSE;
            }
        }
    }

    if (priv->interface_name) {
        GError          *tmp_error = NULL;
        NMUtilsIfaceType iface_type;

        if (NM_IN_STRSET(type,
                         NM_SETTING_OVS_BRIDGE_SETTING_NAME,
                         NM_SETTING_OVS_PORT_SETTING_NAME))
            iface_type = NMU_IFACE_OVS;
        else if (nm_streq(type, NM_SETTING_OVS_INTERFACE_SETTING_NAME)) {
            NMSettingOvsInterface *s_ovs_iface = NULL;
            const char            *ovs_iface_type;

            if (connection)
                s_ovs_iface = nm_connection_get_setting_ovs_interface(connection);
            _nm_setting_ovs_interface_verify_interface_type(
                s_ovs_iface,
                s_ovs_iface ? nm_setting_ovs_interface_get_interface_type(s_ovs_iface) : NULL,
                connection,
                FALSE,
                NULL,
                &ovs_iface_type,
                NULL);
            if (!ovs_iface_type) {
                /* We cannot determine to OVS interface type. Consequently, we cannot
                 * fully validate the interface name.
                 *
                 * If we have a connection (and we do a full validation anyway), skip the
                 * check. The connection will fail validation when we validate the OVS setting.
                 *
                 * Otherwise, do the most basic validation.
                 */
                if (connection)
                    goto after_interface_name;
                iface_type = NMU_IFACE_ANY;
            } else if (NM_IN_STRSET(ovs_iface_type, "patch")) {
                /* this interface type is internal to OVS. */
                iface_type = NMU_IFACE_OVS;
            } else {
                /* This interface type also requires a netdev. We need to validate
                 * for both OVS and KERNEL. */
                nm_assert(NM_IN_STRSET(ovs_iface_type, "internal", "system", "dpdk"));
                iface_type = NMU_IFACE_OVS_AND_KERNEL;
            }
        } else
            iface_type = NMU_IFACE_KERNEL;

        if (!nm_utils_ifname_valid(priv->interface_name, iface_type, &tmp_error)) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        "'%s': %s",
                        priv->interface_name,
                        tmp_error->message);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_CONNECTION_SETTING_NAME,
                           NM_SETTING_CONNECTION_INTERFACE_NAME);
            g_error_free(tmp_error);
            return FALSE;
        }
    }
after_interface_name:

    if (!_nm_connection_detect_slave_type_full(self,
                                               connection,
                                               &slave_type,
                                               &normerr_slave_setting_type,
                                               &normerr_missing_slave_type,
                                               &normerr_missing_slave_type_port,
                                               error))
        return FALSE;

    if (nm_streq(type, NM_SETTING_OVS_PORT_SETTING_NAME) && slave_type
        && !nm_streq(slave_type, NM_SETTING_OVS_BRIDGE_SETTING_NAME)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_MISSING_PROPERTY,
                    _("'%s' connections must be enslaved to '%s', not '%s'"),
                    NM_SETTING_OVS_PORT_SETTING_NAME,
                    NM_SETTING_OVS_BRIDGE_SETTING_NAME,
                    slave_type);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_CONNECTION_SETTING_NAME,
                       NM_SETTING_CONNECTION_PORT_TYPE);
        return FALSE;
    }

    if (!NM_IN_SET(priv->metered, NM_METERED_UNKNOWN, NM_METERED_NO, NM_METERED_YES)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("metered value %d is not valid"),
                    priv->metered);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_CONNECTION_SETTING_NAME,
                       NM_SETTING_CONNECTION_METERED);
        return FALSE;
    }

    if (priv->mdns < (int) NM_SETTING_CONNECTION_MDNS_DEFAULT
        || priv->mdns > (int) NM_SETTING_CONNECTION_MDNS_YES) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("value %d is not valid"),
                    priv->mdns);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_CONNECTION_SETTING_NAME,
                       NM_SETTING_CONNECTION_MDNS);
        return FALSE;
    }

    if (priv->llmnr < (int) NM_SETTING_CONNECTION_LLMNR_DEFAULT
        || priv->llmnr > (int) NM_SETTING_CONNECTION_LLMNR_YES) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("value %d is not valid"),
                    priv->llmnr);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_CONNECTION_SETTING_NAME,
                       NM_SETTING_CONNECTION_LLMNR);
        return FALSE;
    }

    if (priv->dns_over_tls < (int) NM_SETTING_CONNECTION_DNS_OVER_TLS_DEFAULT
        || priv->dns_over_tls > (int) NM_SETTING_CONNECTION_DNS_OVER_TLS_YES) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("value %d is not valid"),
                    priv->dns_over_tls);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_CONNECTION_SETTING_NAME,
                       NM_SETTING_CONNECTION_DNS_OVER_TLS);
        return FALSE;
    }

    if (priv->mptcp_flags != 0) {
        if (NM_FLAGS_HAS(priv->mptcp_flags, NM_MPTCP_FLAGS_DISABLED)) {
            if (priv->mptcp_flags != NM_MPTCP_FLAGS_DISABLED) {
                g_set_error_literal(
                    error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("\"disabled\" flag cannot be combined with other MPTCP flags"));
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_CONNECTION_SETTING_NAME,
                               NM_SETTING_CONNECTION_MPTCP_FLAGS);
                return FALSE;
            }
        } else {
            guint32 f;

            if (NM_FLAGS_ALL(priv->mptcp_flags, NM_MPTCP_FLAGS_SIGNAL | NM_MPTCP_FLAGS_FULLMESH)) {
                g_set_error_literal(error,
                                    NM_CONNECTION_ERROR,
                                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                    _("cannot set both \"signal\" and \"fullmesh\" MPTCP flags"));
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_CONNECTION_SETTING_NAME,
                               NM_SETTING_CONNECTION_MPTCP_FLAGS);
                return FALSE;
            }
            f = priv->mptcp_flags | ((guint32) NM_MPTCP_FLAGS_ENABLED);
            if (f != nm_mptcp_flags_normalize(f)) {
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("value %u is not a valid combination of MPTCP flags"),
                            priv->mptcp_flags);
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_CONNECTION_SETTING_NAME,
                               NM_SETTING_CONNECTION_MPTCP_FLAGS);
                return FALSE;
            }
        }
    }

    if (!NM_IN_SET(priv->multi_connect,
                   (int) NM_CONNECTION_MULTI_CONNECT_DEFAULT,
                   (int) NM_CONNECTION_MULTI_CONNECT_SINGLE,
                   (int) NM_CONNECTION_MULTI_CONNECT_MANUAL_MULTIPLE,
                   (int) NM_CONNECTION_MULTI_CONNECT_MULTIPLE)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("value %d is not valid"),
                    priv->multi_connect);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_CONNECTION_SETTING_NAME,
                       NM_SETTING_CONNECTION_MULTI_CONNECT);
        return FALSE;
    }

    if (priv->mud_url) {
        if (!priv->mud_url[0]) {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                _("property is empty"));
            g_prefix_error(error,
                           "%s.%s: ",
                           nm_setting_get_name(setting),
                           NM_SETTING_CONNECTION_MUD_URL);
            return FALSE;
        }
        if (nm_streq(priv->mud_url, NM_CONNECTION_MUD_URL_NONE)) {
            /* pass */
        } else {
            if (strlen(priv->mud_url) > 255) {
                g_set_error_literal(error,
                                    NM_CONNECTION_ERROR,
                                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                    _("DHCP option cannot be longer than 255 characters"));
                g_prefix_error(error,
                               "%s.%s: ",
                               nm_setting_get_name(setting),
                               NM_SETTING_CONNECTION_MUD_URL);
                return FALSE;
            }
            if (!nm_sd_http_url_is_valid_https(priv->mud_url)) {
                g_set_error_literal(error,
                                    NM_CONNECTION_ERROR,
                                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                    _("MUD URL is not a valid URL"));
                g_prefix_error(error,
                               "%s.%s: ",
                               nm_setting_get_name(setting),
                               NM_SETTING_CONNECTION_MUD_URL);
                return FALSE;
            }
        }
    }

    if (priv->permissions) {
        guint i;

        for (i = 0; i < priv->permissions->len; i++) {
            const Permission *permissions = &nm_g_array_index(priv->permissions, Permission, i);

            if (permissions->ptype != PERM_TYPE_USER) {
                g_set_error_literal(error,
                                    NM_CONNECTION_ERROR,
                                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                    _("invalid permissions not in format \"user:$UNAME[:]\""));
                g_prefix_error(error,
                               "%s.%s: ",
                               nm_setting_get_name(setting),
                               NM_SETTING_CONNECTION_PERMISSIONS);
                return FALSE;
            }
            nm_assert(nm_settings_connection_validate_permission_user(permissions->item, -1));
        }
    }

    /* *** errors above here should be always fatal, below NORMALIZABLE_ERROR *** */

    if (!priv->uuid) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_MISSING_PROPERTY,
                            _("property is missing"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_CONNECTION_SETTING_NAME,
                       NM_SETTING_CONNECTION_UUID);
        return NM_SETTING_VERIFY_NORMALIZABLE_ERROR;
    }

    if (normerr_base_type) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_MISSING_PROPERTY,
                    _("property type should be set to '%s'"),
                    nm_setting_get_name(normerr_base_type));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_CONNECTION_SETTING_NAME,
                       NM_SETTING_CONNECTION_TYPE);
        return NM_SETTING_VERIFY_NORMALIZABLE_ERROR;
    }

    if (normerr_base_setting) {
        _set_error_missing_base_setting(error, priv->type);
        return NM_SETTING_VERIFY_NORMALIZABLE_ERROR;
    }

    if (normerr_slave_setting_type) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_MISSING_SETTING,
                    _("port-type '%s' requires a '%s' setting in the connection"),
                    priv->port_type,
                    normerr_slave_setting_type);
        g_prefix_error(error, "%s: ", normerr_slave_setting_type);
        return NM_SETTING_VERIFY_NORMALIZABLE_ERROR;
    }

    if (normerr_missing_slave_type) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_MISSING_PROPERTY,
                    _("Detect a slave connection with '%s' set and a port type '%s'. '%s' should "
                      "be set to '%s'"),
                    NM_SETTING_CONNECTION_CONTROLLER,
                    normerr_missing_slave_type_port,
                    NM_SETTING_CONNECTION_PORT_TYPE,
                    normerr_missing_slave_type);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_CONNECTION_SETTING_NAME,
                       NM_SETTING_CONNECTION_PORT_TYPE);
        return NM_SETTING_VERIFY_NORMALIZABLE_ERROR;
    }

    if (connection) {
        gboolean has_bridge_port = FALSE;

        if ((!nm_streq0(priv->port_type, NM_SETTING_BRIDGE_SETTING_NAME)
             && (has_bridge_port =
                     !!nm_connection_get_setting_by_name(connection,
                                                         NM_SETTING_BRIDGE_PORT_SETTING_NAME)))
            || (!nm_streq0(priv->port_type, NM_SETTING_TEAM_SETTING_NAME)
                && nm_connection_get_setting_by_name(connection,
                                                     NM_SETTING_TEAM_PORT_SETTING_NAME))) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_SETTING,
                        _("A slave connection with '%s' set to '%s' cannot have a '%s' setting"),
                        NM_SETTING_CONNECTION_PORT_TYPE,
                        priv->port_type ?: "",
                        has_bridge_port ? NM_SETTING_BRIDGE_PORT_SETTING_NAME
                                        : NM_SETTING_TEAM_PORT_SETTING_NAME);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_CONNECTION_SETTING_NAME,
                           NM_SETTING_CONNECTION_PORT_TYPE);
            return NM_SETTING_VERIFY_NORMALIZABLE_ERROR;
        }
    }

    if (uuid_was_normalized) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_MISSING_PROPERTY,
                            _("UUID needs normalization"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_CONNECTION_SETTING_NAME,
                       NM_SETTING_CONNECTION_UUID);
        return NM_SETTING_VERIFY_NORMALIZABLE;
    }

    if (!_nm_setting_connection_verify_secondaries(priv->secondaries.arr, error))
        return NM_SETTING_VERIFY_NORMALIZABLE;

    if (priv->read_only) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_MISSING_PROPERTY,
                            _("read-only is deprecated and not settable for the user"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_CONNECTION_SETTING_NAME,
                       NM_SETTING_CONNECTION_READ_ONLY);
        return NM_SETTING_VERIFY_NORMALIZABLE;
    }

    return TRUE;
}

static const char *
find_virtual_interface_name(GVariant *connection_dict, GVariant **variant_to_free)
{
    GVariant   *setting_dict;
    const char *interface_name;

    nm_assert(variant_to_free && !*variant_to_free);

    setting_dict = g_variant_lookup_value(connection_dict,
                                          NM_SETTING_BOND_SETTING_NAME,
                                          NM_VARIANT_TYPE_SETTING);
    if (!setting_dict)
        setting_dict = g_variant_lookup_value(connection_dict,
                                              NM_SETTING_BRIDGE_SETTING_NAME,
                                              NM_VARIANT_TYPE_SETTING);
    if (!setting_dict)
        setting_dict = g_variant_lookup_value(connection_dict,
                                              NM_SETTING_TEAM_SETTING_NAME,
                                              NM_VARIANT_TYPE_SETTING);
    if (!setting_dict)
        setting_dict = g_variant_lookup_value(connection_dict,
                                              NM_SETTING_VLAN_SETTING_NAME,
                                              NM_VARIANT_TYPE_SETTING);

    if (!setting_dict)
        return NULL;

    *variant_to_free = setting_dict;

    /* All of the deprecated virtual interface name properties were named "interface-name". */
    if (!g_variant_lookup(setting_dict, "interface-name", "&s", &interface_name))
        interface_name = NULL;

    return interface_name;
}

static gboolean
nm_setting_connection_no_interface_name(_NM_SETT_INFO_PROP_MISSING_FROM_DBUS_FCN_ARGS _nm_nil)
{
    const char                *virtual_interface_name;
    gs_unref_variant GVariant *variant_to_free = NULL;

    virtual_interface_name = find_virtual_interface_name(connection_dict, &variant_to_free);
    g_object_set(G_OBJECT(setting),
                 NM_SETTING_CONNECTION_INTERFACE_NAME,
                 virtual_interface_name,
                 NULL);
    return TRUE;
}

static NMTernary
compare_fcn_id(_NM_SETT_INFO_PROP_COMPARE_FCN_ARGS _nm_nil)
{
    if (NM_FLAGS_HAS(flags, NM_SETTING_COMPARE_FLAG_IGNORE_ID))
        return NM_TERNARY_DEFAULT;

    return _nm_setting_property_compare_fcn_direct(sett_info,
                                                   property_info,
                                                   con_a,
                                                   set_a,
                                                   con_b,
                                                   set_b,
                                                   flags);
}

static NMTernary
compare_fcn_timestamp(_NM_SETT_INFO_PROP_COMPARE_FCN_ARGS _nm_nil)
{
    if (NM_FLAGS_HAS(flags, NM_SETTING_COMPARE_FLAG_IGNORE_TIMESTAMP))
        return NM_TERNARY_DEFAULT;

    return _nm_setting_property_compare_fcn_default(sett_info,
                                                    property_info,
                                                    con_a,
                                                    set_a,
                                                    con_b,
                                                    set_b,
                                                    flags);
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMSettingConnection        *setting = NM_SETTING_CONNECTION(object);
    NMSettingConnectionPrivate *priv    = NM_SETTING_CONNECTION_GET_PRIVATE(setting);

    switch (prop_id) {
    case PROP_PERMISSIONS:
    {
        char **strv;
        gsize  i, l;

        l    = nm_g_array_len(priv->permissions);
        strv = g_new(char *, l + 1u);

        for (i = 0; i < l; i++)
            strv[i] = _permission_to_string(&nm_g_array_index(priv->permissions, Permission, i));
        strv[i] = NULL;

        g_value_take_boxed(value, strv);
        break;
    }
    case PROP_TIMESTAMP:
        g_value_set_uint64(value, nm_setting_connection_get_timestamp(setting));
        break;
    default:
        _nm_setting_property_get_property_direct(object, prop_id, value, pspec);
        break;
    }
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMSettingConnectionPrivate *priv = NM_SETTING_CONNECTION_GET_PRIVATE(object);

    switch (prop_id) {
    case PROP_PERMISSIONS:
    {
        const char *const *strv;
        guint              i;

        nm_clear_pointer(&priv->permissions, g_array_unref);
        strv = g_value_get_boxed(value);
        if (strv && strv[0]) {
            priv->permissions =
                g_array_sized_new(FALSE, FALSE, sizeof(Permission), NM_PTRARRAY_LEN(strv));
            g_array_set_clear_func(priv->permissions, (GDestroyNotify) _permission_clear_stale);

            for (i = 0; strv[i]; i++) {
                Permission *permission = nm_g_array_append_new(priv->permissions, Permission);

                _permission_set_stale_parse(permission, strv[i]);
            }
        }
        break;
    }
    case PROP_TIMESTAMP:
        priv->timestamp = g_value_get_uint64(value);
        break;
    default:
        _nm_setting_property_set_property_direct(object, prop_id, value, pspec);
        break;
    }
}

/*****************************************************************************/

gboolean
_nm_setting_connection_master_from_dbus(_NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil)
{
    const char *str;

    if (!_nm_setting_use_legacy_property(setting,
                                         connection_dict,
                                         NM_SETTING_CONNECTION_MASTER,
                                         NM_SETTING_CONNECTION_CONTROLLER)) {
        *out_is_modified = FALSE;
        return TRUE;
    }
    str = g_variant_get_string(value, NULL);

    g_object_set(setting, NM_SETTING_CONNECTION_MASTER, str, NULL);
    return TRUE;
}

GVariant *
_nm_setting_connection_controller_to_dbus(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil)
{
    const char *controller;

    /* FIXME: `controller` is an alias of `master` property. Serializing the
     * property to the clients would break them as they won't be able to drop
     * it if they are not aware of the existance of `controller`. In order to
     * give them time to adapt their code, NetworkManager is not serializing
     * `controller` on DBus.
     */
    if (_nm_utils_is_manager_process) {
        return NULL;
    }

    controller = nm_setting_connection_get_controller(NM_SETTING_CONNECTION(setting));
    if (!controller)
        return NULL;

    return g_variant_new_string(controller);
}

gboolean
_nm_setting_connection_controller_from_dbus(_NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil)
{
    const char *str;

    /* Ignore 'controller' if we're going to process 'master' */
    if (_nm_setting_use_legacy_property(setting,
                                        connection_dict,
                                        NM_SETTING_CONNECTION_MASTER,
                                        NM_SETTING_CONNECTION_CONTROLLER)) {
        *out_is_modified = FALSE;
        return TRUE;
    }
    str = g_variant_get_string(value, NULL);

    g_object_set(setting, NM_SETTING_CONNECTION_CONTROLLER, str, NULL);
    return TRUE;
}

gboolean
_nm_setting_connection_slave_type_from_dbus(_NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil)
{
    const char *str;

    if (!_nm_setting_use_legacy_property(setting,
                                         connection_dict,
                                         NM_SETTING_CONNECTION_SLAVE_TYPE,
                                         NM_SETTING_CONNECTION_PORT_TYPE)) {
        *out_is_modified = FALSE;
        return TRUE;
    }
    str = g_variant_get_string(value, NULL);

    g_object_set(setting, NM_SETTING_CONNECTION_SLAVE_TYPE, str, NULL);
    return TRUE;
}

gboolean
_nm_setting_connection_autoconnect_slaves_from_dbus(_NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil)
{
    gint32 autoconnect;

    if (!_nm_setting_use_legacy_property(setting,
                                         connection_dict,
                                         NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES,
                                         NM_SETTING_CONNECTION_AUTOCONNECT_PORTS)) {
        *out_is_modified = FALSE;
        return TRUE;
    }
    autoconnect = g_variant_get_int32(value);

    g_object_set(setting, NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES, autoconnect, NULL);
    return TRUE;
}

GVariant *
_nm_setting_connection_port_type_to_dbus(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil)
{
    const char *port_type;

    /* FIXME: `port-type` is an alias of `slave-type` property. Serializing the
     * property to the clients would break them as they won't be able to drop
     * it if they are not aware of the existance of `port-type`. In order to
     * give them time to adapt their code, NetworkManager is not serializing
     * `port-type` on DBus.
     */
    if (_nm_utils_is_manager_process) {
        return NULL;
    }

    port_type = nm_setting_connection_get_port_type(NM_SETTING_CONNECTION(setting));
    if (!port_type)
        return NULL;

    return g_variant_new_string(port_type);
}

gboolean
_nm_setting_connection_port_type_from_dbus(_NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil)
{
    const char *str;

    /* Ignore 'port-type' if we're going to process 'slave-type' */
    if (_nm_setting_use_legacy_property(setting,
                                        connection_dict,
                                        NM_SETTING_CONNECTION_SLAVE_TYPE,
                                        NM_SETTING_CONNECTION_PORT_TYPE)) {
        *out_is_modified = FALSE;
        return TRUE;
    }
    str = g_variant_get_string(value, NULL);

    g_object_set(setting, NM_SETTING_CONNECTION_PORT_TYPE, str, NULL);
    return TRUE;
}

GVariant *
_nm_setting_connection_autoconnect_ports_to_dbus(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil)
{
    NMTernary autoconnect;

    /* FIXME: `autoconnect-ports` is an alias of `autoconnect-slaves` property.
     * Serializing the property to the clients would break them as they won't
     * be able to drop it if they are not aware of the existance of
     * `autoconnect-ports`. In order to give them time to adapt their code,
     * NetworkManager is not serializing `autoconnect-ports` on DBus.
     */
    if (_nm_utils_is_manager_process) {
        return NULL;
    }

    autoconnect = nm_setting_connection_get_autoconnect_ports(NM_SETTING_CONNECTION(setting));

    return g_variant_new_int32(autoconnect);
}

gboolean
_nm_setting_connection_autoconnect_ports_from_dbus(_NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil)
{
    NMTernary autoconnect;

    /* Ignore 'autoconnect-ports' if we're going to process 'autoconnect-slaves' */
    if (_nm_setting_use_legacy_property(setting,
                                        connection_dict,
                                        NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES,
                                        NM_SETTING_CONNECTION_AUTOCONNECT_PORTS)) {
        *out_is_modified = FALSE;
        return TRUE;
    }
    autoconnect = g_variant_get_int32(value);

    g_object_set(setting, NM_SETTING_CONNECTION_AUTOCONNECT_PORTS, autoconnect, NULL);
    return TRUE;
}

/*****************************************************************************/

static void
nm_setting_connection_init(NMSettingConnection *setting)
{}

/**
 * nm_setting_connection_new:
 *
 * Creates a new #NMSettingConnection object with default values.
 *
 * Returns: the new empty #NMSettingConnection object
 **/
NMSetting *
nm_setting_connection_new(void)
{
    return g_object_new(NM_TYPE_SETTING_CONNECTION, NULL);
}

static void
finalize(GObject *object)
{
    NMSettingConnectionPrivate *priv = NM_SETTING_CONNECTION_GET_PRIVATE(object);

    nm_clear_pointer(&priv->permissions, g_array_unref);

    G_OBJECT_CLASS(nm_setting_connection_parent_class)->finalize(object);
}

static void
nm_setting_connection_class_init(NMSettingConnectionClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array_sized(35);
    guint           prop_idx;

    object_class->get_property = get_property;
    object_class->set_property = set_property;
    object_class->finalize     = finalize;

    setting_class->verify = verify;

    /**
     * NMSettingConnection:id:
     *
     * A human readable unique identifier for the connection, like "Work Wi-Fi"
     * or "T-Mobile 3G".
     **/
    /* ---ifcfg-rh---
     * property: id
     * variable: NAME(+)
     * description: User friendly name for the connection profile.
     * ---end---
     */
    _nm_setting_property_define_direct_string_full(
        properties_override,
        obj_properties,
        NM_SETTING_CONNECTION_ID,
        PROP_ID,
        NM_SETTING_PARAM_FUZZY_IGNORE,
        NM_SETT_INFO_PROPERT_TYPE_DBUS(G_VARIANT_TYPE_STRING,
                                       .direct_type   = NM_VALUE_TYPE_STRING,
                                       .compare_fcn   = compare_fcn_id,
                                       .to_dbus_fcn   = _nm_setting_property_to_dbus_fcn_direct,
                                       .from_dbus_fcn = _nm_setting_property_from_dbus_fcn_direct,
                                       .from_dbus_is_full                = TRUE,
                                       .from_dbus_direct_allow_transform = TRUE),
        NMSettingConnectionPrivate,
        id);

    /**
     * NMSettingConnection:uuid:
     *
     * A universally unique identifier for the connection, for example generated
     * with libuuid.  It should be assigned when the connection is created, and
     * never changed as long as the connection still applies to the same
     * network.  For example, it should not be changed when the
     * #NMSettingConnection:id property or #NMSettingIP4Config changes, but
     * might need to be re-created when the Wi-Fi SSID, mobile broadband network
     * provider, or #NMSettingConnection:type property changes.
     *
     * The UUID must be in the format "2815492f-7e56-435e-b2e9-246bd7cdc664"
     * (ie, contains only hexadecimal characters and "-").  A suitable UUID may
     * be generated by nm_utils_uuid_generate() or
     * nm_uuid_generate_from_string_str().
     **/
    /* ---nmcli---
     * property: uuid
     * format: a valid RFC4122 universally unique identifier (UUID).
     * description: The connection.uuid is the real identifier of a profile.
     *   It cannot change and it must be unique. It is therefore often best
     *   to refer to a profile by UUID, for example with `nmcli connection up uuid $UUID`.
     *
     *   The UUID cannot be changed, except in offline mode. In that case,
     *   the special values "new", "generate" and "" are allowed to generate
     *   a new random UUID.
     * ---end---
     */
    /* ---ifcfg-rh---
     * property: uuid
     * variable: UUID(+)
     * description: UUID for the connection profile. When missing, NetworkManager
     *   creates the UUID itself (by hashing the filename).
     * ---end---
     */
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_CONNECTION_UUID,
                                              PROP_UUID,
                                              NM_SETTING_PARAM_FUZZY_IGNORE,
                                              NMSettingConnectionPrivate,
                                              uuid);

    /**
     * NMSettingConnection:stable-id:
     *
     * This represents the identity of the connection used for various purposes.
     * It allows to configure multiple profiles to share the identity. Also,
     * the stable-id can contain placeholders that are substituted dynamically and
     * deterministically depending on the context.
     *
     * The stable-id is used for generating IPv6 stable private addresses with
     * ipv6.addr-gen-mode=stable-privacy. It is also used to seed the generated
     * cloned MAC address for ethernet.cloned-mac-address=stable and
     * wifi.cloned-mac-address=stable. It is also used to derive the DHCP
     * client identifier with ipv4.dhcp-client-id=stable, the DHCPv6 DUID with
     * ipv6.dhcp-duid=stable-[llt,ll,uuid] and the DHCP IAID with
     * ipv4.iaid=stable and ipv6.iaid=stable.
     *
     * Note that depending on the context where it is used, other parameters are
     * also seeded into the generation algorithm. For example, a per-host key
     * is commonly also included, so that different systems end up generating
     * different IDs. Or with ipv6.addr-gen-mode=stable-privacy, also the device's
     * name is included, so that different interfaces yield different addresses.
     * The per-host key is the identity of your machine and stored in /var/lib/NetworkManager/secret_key.
     * See NetworkManager(8) manual about the secret-key and the host identity.
     *
     * The '$' character is treated special to perform dynamic substitutions at
     * activation time. Currently, supported are "${CONNECTION}", "${DEVICE}",
     * "${MAC}", "${NETWORK_SSID}", "${BOOT}", "${RANDOM}".  These effectively
     * create unique IDs per-connection, per-device, per-SSID, per-boot, or
     * every time.  The "${CONNECTION}" uses the profile's connection.uuid, the
     * "${DEVICE}" uses the interface name of the device and "${MAC}" the
     * permanent MAC address of the device. "${NETWORK_SSID}" uses the SSID for
     * Wi-Fi networks and falls back to "${CONNECTION}" on other networks. Any
     * unrecognized patterns following '$' are treated verbatim, however are
     * reserved for future use. You are thus advised to avoid '$' or escape it
     * as "$$".  For example, set it to "${CONNECTION}-${BOOT}-${DEVICE}" to
     * create a unique id for this connection that changes with every reboot
     * and differs depending on the interface where the profile activates.
     *
     * If the value is unset, a global connection default is consulted. If the
     * value is still unset, the default is "default${CONNECTION}" go generate
     * an ID unique per connection profile.
     *
     * Since: 1.4
     **/
    /* ---ifcfg-rh---
     * property: stable-id
     * variable: STABLE_ID(+)
     * description: Token to generate stable IDs.
     * ---end---
     */
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_CONNECTION_STABLE_ID,
                                              PROP_STABLE_ID,
                                              NM_SETTING_PARAM_FUZZY_IGNORE,
                                              NMSettingConnectionPrivate,
                                              stable_id,
                                              .direct_string_allow_empty = TRUE);

    /**
     * NMSettingConnection:interface-name:
     *
     * The name of the network interface this connection is bound to. If not
     * set, then the connection can be attached to any interface of the
     * appropriate type (subject to restrictions imposed by other settings).
     *
     * For software devices this specifies the name of the created device.
     *
     * For connection types where interface names cannot easily be made
     * persistent (e.g. mobile broadband or USB Ethernet), this property should
     * not be used. Setting this property restricts the interfaces a connection
     * can be used with, and if interface names change or are reordered the
     * connection may be applied to the wrong interface.
     **/
    /* ---ifcfg-rh---
     * property: interface-name
     * variable: DEVICE
     * description: Interface name of the device this profile is bound to. The variable
     *   can be left out when the profile should apply for more devices. Note that DEVICE
     *   can be required for some connection types.
     * ---end---
     */
    _nm_setting_property_define_direct_string_full(
        properties_override,
        obj_properties,
        NM_SETTING_CONNECTION_INTERFACE_NAME,
        PROP_INTERFACE_NAME,
        NM_SETTING_PARAM_INFERRABLE,
        NM_SETT_INFO_PROPERT_TYPE_DBUS(G_VARIANT_TYPE_STRING,
                                       .direct_type = NM_VALUE_TYPE_STRING,
                                       .compare_fcn = _nm_setting_property_compare_fcn_direct,
                                       .to_dbus_fcn = _nm_setting_property_to_dbus_fcn_direct,
                                       .missing_from_dbus_fcn =
                                           nm_setting_connection_no_interface_name,
                                       .from_dbus_fcn = _nm_setting_property_from_dbus_fcn_direct,
                                       .from_dbus_is_full                = TRUE,
                                       .from_dbus_direct_allow_transform = TRUE),
        NMSettingConnectionPrivate,
        interface_name,
        .direct_string_allow_empty = TRUE);

    /**
     * NMSettingConnection:type:
     *
     * Base type of the connection. For hardware-dependent connections, should
     * contain the setting name of the hardware-type specific setting (ie,
     * "802-3-ethernet" or "802-11-wireless" or "bluetooth", etc), and for
     * non-hardware dependent connections like VPN or otherwise, should contain
     * the setting name of that setting type (ie, "vpn" or "bridge", etc).
     **/
    /* ---ifcfg-rh---
     * property: type
     * variable: TYPE (DEVICETYPE, DEVICE)
     * values: Ethernet, Wireless, InfiniBand, Bridge, Bond, Vlan, Team, TeamPort
     * description: Base type of the connection. DEVICETYPE is used for teaming
     *   connections.
     * example: TYPE=Ethernet; TYPE=Bond; TYPE=Bridge; DEVICETYPE=TeamPort
     * ---end---
     */
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_CONNECTION_TYPE,
                                              PROP_TYPE,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingConnectionPrivate,
                                              type,
                                              .direct_string_is_refstr   = TRUE,
                                              .direct_string_allow_empty = TRUE);

    /**
     * NMSettingConnection:permissions:
     *
     * An array of strings defining what access a given user has to this
     * connection.  If this is %NULL or empty, all users are allowed to access
     * this connection; otherwise users are allowed if and only if they are in
     * this list.  When this is not empty, the connection can be active only when
     * one of the specified users is logged into an active session.  Each entry
     * is of the form "[type]:[id]:[reserved]"; for example, "user:dcbw:blah".
     *
     * At this time only the "user" [type] is allowed.  Any other values are
     * ignored and reserved for future use.  [id] is the username that this
     * permission refers to, which may not contain the ":" character. Any
     * [reserved] information present must be ignored and is reserved for future
     * use.  All of [type], [id], and [reserved] must be valid UTF-8.
     */
    /* ---ifcfg-rh---
     * property: permissions
     * variable: USERS(+)
     * description: Restrict to certain users the access to this connection, and
     *     allow the connection to be active only when at least one of the
     *     specified users is logged into an active session.
     * example: USERS="joe bob"
     * ---end---
     */
    _nm_setting_property_define_gprop_strv_oldstyle(properties_override,
                                                    obj_properties,
                                                    NM_SETTING_CONNECTION_PERMISSIONS,
                                                    PROP_PERMISSIONS,
                                                    NM_SETTING_PARAM_NONE);

    /**
     * NMSettingConnection:autoconnect:
     *
     * Whether or not the connection should be automatically connected by
     * NetworkManager when the resources for the connection are available.
     * %TRUE to automatically activate the connection, %FALSE to require manual
     * intervention to activate the connection.
     *
     * Autoconnect happens when the circumstances are suitable. That means for
     * example that the device is currently managed and not active. Autoconnect
     * thus never replaces or competes with an already active profile.
     *
     * Note that autoconnect is not implemented for VPN profiles. See
     * #NMSettingConnection:secondaries as an alternative to automatically
     * connect VPN profiles.
     *
     * If multiple profiles are ready to autoconnect on the same device,
     * the one with the better "connection.autoconnect-priority" is chosen. If
     * the priorities are equal, then the most recently connected profile is activated.
     * If the profiles were not connected earlier or their
     * "connection.timestamp" is identical, the choice is undefined.
     *
     * Depending on "connection.multi-connect", a profile can (auto)connect only
     * once at a time or multiple times.
     **/
    /* ---ifcfg-rh---
     * property: autoconnect
     * variable: ONBOOT
     * default: yes
     * description: Whether the connection should be autoconnected (not only while booting).
     * ---end---
     */
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_CONNECTION_AUTOCONNECT,
                                               PROP_AUTOCONNECT,
                                               TRUE,
                                               NM_SETTING_PARAM_FUZZY_IGNORE,
                                               NMSettingConnectionPrivate,
                                               autoconnect);

    /**
     * NMSettingConnection:autoconnect-priority:
     *
     * The autoconnect priority in range -999 to 999. If the connection is set
     * to autoconnect, connections with higher priority will be preferred.
     * The higher number means higher priority. Defaults to 0.
     * Note that this property only matters if there are more than one candidate
     * profile to select for autoconnect. In case of equal priority, the profile
     * used most recently is chosen.
     **/
    /* ---ifcfg-rh---
     * property: autoconnect-priority
     * variable: AUTOCONNECT_PRIORITY(+)
     * values: -999 to 999
     * default: 0
     * description: Connection priority for automatic activation. Connections with
     *  higher numbers are preferred when selecting profiles for automatic activation.
     * example: AUTOCONNECT_PRIORITY=20
     * ---end---
     */
    _nm_setting_property_define_direct_int32(properties_override,
                                             obj_properties,
                                             NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY,
                                             PROP_AUTOCONNECT_PRIORITY,
                                             NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY_MIN,
                                             NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY_MAX,
                                             NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY_DEFAULT,
                                             NM_SETTING_PARAM_FUZZY_IGNORE,
                                             NMSettingConnectionPrivate,
                                             autoconnect_priority);

    /**
     * NMSettingConnection:autoconnect-retries:
     *
     * The number of times a connection should be tried when autoactivating before
     * giving up. Zero means forever, -1 means the global default (4 times if not
     * overridden). Setting this to 1 means to try activation only once before
     * blocking autoconnect. Note that after a timeout, NetworkManager will try
     * to autoconnect again.
     */
    /* ---ifcfg-rh---
     * property: autoconnect-retries
     * variable: AUTOCONNECT_RETRIES(+)
     * description: The number of times a connection should be autoactivated
     * before giving up and switching to the next one.
     * values: -1 (use global default), 0 (forever) or a positive value
     * example: AUTOCONNECT_RETRIES=1
     * ---end---
     */
    _nm_setting_property_define_direct_int32(properties_override,
                                             obj_properties,
                                             NM_SETTING_CONNECTION_AUTOCONNECT_RETRIES,
                                             PROP_AUTOCONNECT_RETRIES,
                                             -1,
                                             G_MAXINT32,
                                             -1,
                                             NM_SETTING_PARAM_FUZZY_IGNORE,
                                             NMSettingConnectionPrivate,
                                             autoconnect_retries);

    /**
     * NMSettingConnection:multi-connect:
     *
     * Specifies whether the profile can be active multiple times at a particular
     * moment. The value is of type #NMConnectionMultiConnect.
     *
     * Since: 1.14
     */
    /* ---ifcfg-rh---
     * property: multi-connect
     * variable: MULTI_CONNECT(+)
     * description: whether the profile can be active on multiple devices at a given
     *   moment. The values are numbers corresponding to #NMConnectionMultiConnect enum.
     * example: MULTI_CONNECT=3
     * ---end---
     */
    _nm_setting_property_define_direct_int32(properties_override,
                                             obj_properties,
                                             NM_SETTING_CONNECTION_MULTI_CONNECT,
                                             PROP_MULTI_CONNECT,
                                             G_MININT32,
                                             G_MAXINT32,
                                             NM_CONNECTION_MULTI_CONNECT_DEFAULT,
                                             NM_SETTING_PARAM_FUZZY_IGNORE,
                                             NMSettingConnectionPrivate,
                                             multi_connect);

    /**
     * NMSettingConnection:timestamp:
     *
     * The time, in seconds since the Unix Epoch, that the connection was last
     * _successfully_ fully activated.
     *
     * NetworkManager updates the connection timestamp periodically when the
     * connection is active to ensure that an active connection has the latest
     * timestamp. The property is only meant for reading (changes to this
     * property will not be preserved).
     **/
    obj_properties[PROP_TIMESTAMP] = g_param_spec_uint64(
        NM_SETTING_CONNECTION_TIMESTAMP,
        "",
        "",
        0,
        G_MAXUINT64,
        0,
        G_PARAM_READWRITE | NM_SETTING_PARAM_FUZZY_IGNORE | G_PARAM_STATIC_STRINGS);
    _nm_properties_override_gobj(
        properties_override,
        obj_properties[PROP_TIMESTAMP],
        NM_SETT_INFO_PROPERT_TYPE_DBUS(G_VARIANT_TYPE_UINT64,
                                       .compare_fcn   = compare_fcn_timestamp,
                                       .to_dbus_fcn   = _to_dbus_fcn_timestamp,
                                       .from_dbus_fcn = _nm_setting_property_from_dbus_fcn_gprop,
                                       .from_dbus_is_full = TRUE));

    /**
     * NMSettingConnection:read-only:
     *
     * This property is deprecated and has no meaning.
     *
     * Deprecated: 1.44: This property is deprecated and has no meaning.
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_CONNECTION_READ_ONLY,
                                               PROP_READ_ONLY,
                                               FALSE,
                                               NM_SETTING_PARAM_FUZZY_IGNORE,
                                               NMSettingConnectionPrivate,
                                               read_only,
                                               .is_deprecated = TRUE, );

    /**
     * NMSettingConnection:zone:
     *
     * The trust level of a the connection.  Free form case-insensitive string
     * (for example "Home", "Work", "Public").  %NULL or unspecified zone means
     * the connection will be placed in the default zone as defined by the
     * firewall.
     *
     * When updating this property on a currently activated connection,
     * the change takes effect immediately.
     **/
    /* ---ifcfg-rh---
     * property: zone
     * variable: ZONE(+)
     * description: Trust level of this connection. The string is usually used
     *   for a firewall.
     * example: ZONE=Work
     * ---end---
     */
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_CONNECTION_ZONE,
                                              PROP_ZONE,
                                              NM_SETTING_PARAM_FUZZY_IGNORE
                                                  | NM_SETTING_PARAM_REAPPLY_IMMEDIATELY,
                                              NMSettingConnectionPrivate,
                                              zone,
                                              .direct_string_allow_empty = TRUE);

    /**
     * NMSettingConnection:master:
     *
     * Interface name of the master device or UUID of the master connection.
     *
     * Deprecated 1.46. Use #NMSettingConnection:controller instead, this is just an alias.
     **/
    /* ---ifcfg-rh---
     * property: master
     * variable: MASTER, MASTER_UUID, TEAM_MASTER, TEAM_MASTER_UUID, BRIDGE, BRIDGE_UUID
     * description: Reference to master connection. The variable used depends on
     *   the connection type and the value. In general, if the *_UUID variant is present,
     *   the variant without *_UUID is ignored. NetworkManager attempts to write both
     *   for compatibility with legacy tooling.
     * ---end---
     */
    prop_idx = _nm_setting_property_define_direct_string_full(
        properties_override,
        obj_properties,
        NM_SETTING_CONNECTION_MASTER,
        PROP_MASTER,
        NM_SETTING_PARAM_INFERRABLE | NM_SETTING_PARAM_FUZZY_IGNORE,
        NM_SETT_INFO_PROPERT_TYPE_DBUS(G_VARIANT_TYPE_STRING,
                                       .direct_type   = NM_VALUE_TYPE_STRING,
                                       .compare_fcn   = _nm_setting_property_compare_fcn_direct,
                                       .to_dbus_fcn   = _nm_setting_property_to_dbus_fcn_direct,
                                       .from_dbus_fcn = _nm_setting_connection_master_from_dbus, ),
        NMSettingConnectionPrivate,
        controller,
        .direct_string_allow_empty = TRUE,
        .is_deprecated             = TRUE,
        .direct_is_aliased_field   = TRUE, );

    /**
     * NMSettingConnection:controller:
     *
     * Interface name of the controller device or UUID of the controller connection.
     **/
    _nm_setting_property_define_direct_string_full(
        properties_override,
        obj_properties,
        NM_SETTING_CONNECTION_CONTROLLER,
        PROP_CONTROLLER,
        NM_SETTING_PARAM_INFERRABLE | NM_SETTING_PARAM_FUZZY_IGNORE,
        NM_SETT_INFO_PROPERT_TYPE_DBUS(G_VARIANT_TYPE_STRING,
                                       .direct_type = NM_VALUE_TYPE_STRING,
                                       .compare_fcn = _nm_setting_property_compare_fcn_direct,
                                       .to_dbus_fcn = _nm_setting_connection_controller_to_dbus,
                                       .from_dbus_fcn =
                                           _nm_setting_connection_controller_from_dbus),
        NMSettingConnectionPrivate,
        controller,
        .direct_string_allow_empty = TRUE,
        .direct_also_notify        = obj_properties[PROP_MASTER]);

    nm_g_array_index(properties_override, NMSettInfoProperty, prop_idx).direct_also_notify =
        obj_properties[PROP_CONTROLLER];

    /**
     * NMSettingConnection:slave-type:
     *
     * Setting name of the device type of this slave's master connection (eg,
     * %NM_SETTING_BOND_SETTING_NAME), or %NULL if this connection is not a
     * slave.
     *
     * Deprecated 1.46. Use #NMSettingConnection:port-type instead, this is just an alias.
     **/
    /* ---ifcfg-rh---
     * property: slave-type
     * variable: MASTER, MASTER_UUID, TEAM_MASTER, TEAM_MASTER_UUID, DEVICETYPE,
     *   BRIDGE, BRIDGE_UUID
     * description: Slave type doesn't map directly to a variable, but it is
     *   recognized using different variables.  MASTER and MASTER_UUID for bonding,
     *   TEAM_MASTER, TEAM_MASTER_UUID and DEVICETYPE for teaming, BRIDGE
     *   and BRIDGE_UUID for bridging.
     * ---end---
     */
    prop_idx = _nm_setting_property_define_direct_string_full(
        properties_override,
        obj_properties,
        NM_SETTING_CONNECTION_SLAVE_TYPE,
        PROP_SLAVE_TYPE,
        NM_SETTING_PARAM_FUZZY_IGNORE | NM_SETTING_PARAM_INFERRABLE,
        NM_SETT_INFO_PROPERT_TYPE_DBUS(G_VARIANT_TYPE_STRING,
                                       .direct_type = NM_VALUE_TYPE_STRING,
                                       .compare_fcn = _nm_setting_property_compare_fcn_direct,
                                       .to_dbus_fcn = _nm_setting_property_to_dbus_fcn_direct,
                                       .from_dbus_fcn =
                                           _nm_setting_connection_slave_type_from_dbus, ),
        NMSettingConnectionPrivate,
        port_type,
        .is_deprecated             = TRUE,
        .direct_string_allow_empty = TRUE,
        .direct_is_aliased_field   = TRUE, );

    /**
     * NMSettingConnection:port-type:
     *
     * Setting name of the device type of this port's controller connection (eg,
     * %NM_SETTING_BOND_SETTING_NAME), or %NULL if this connection is not a
     * port.
     *
     * Since: 1.46
     **/
    _nm_setting_property_define_direct_string_full(
        properties_override,
        obj_properties,
        NM_SETTING_CONNECTION_PORT_TYPE,
        PROP_PORT_TYPE,
        NM_SETTING_PARAM_FUZZY_IGNORE | NM_SETTING_PARAM_INFERRABLE,
        NM_SETT_INFO_PROPERT_TYPE_DBUS(G_VARIANT_TYPE_STRING,
                                       .direct_type = NM_VALUE_TYPE_STRING,
                                       .compare_fcn = _nm_setting_property_compare_fcn_direct,
                                       .to_dbus_fcn = _nm_setting_connection_port_type_to_dbus,
                                       .from_dbus_fcn =
                                           _nm_setting_connection_port_type_from_dbus, ),
        NMSettingConnectionPrivate,
        port_type,
        .direct_string_allow_empty = TRUE,
        .direct_also_notify        = obj_properties[PROP_SLAVE_TYPE]);

    nm_g_array_index(properties_override, NMSettInfoProperty, prop_idx).direct_also_notify =
        obj_properties[PROP_PORT_TYPE];

    /**
     * NMSettingConnection:autoconnect-slaves:
     *
     * Whether or not slaves of this connection should be automatically brought up
     * when NetworkManager activates this connection. This only has a real effect
     * for master connections. The properties #NMSettingConnection:autoconnect,
     * #NMSettingConnection:autoconnect-priority and #NMSettingConnection:autoconnect-retries
     * are unrelated to this setting.
     * The permitted values are: 0: leave slave connections untouched,
     * 1: activate all the slave connections with this connection, -1: default.
     * If -1 (default) is set, global connection.autoconnect-slaves is read to
     * determine the real value. If it is default as well, this fallbacks to 0.
     *
     * Deprecated 1.46. Use #NMSettingConnection:autoconnect-ports instead, this is just an alias.
     *
     * Since: 1.2
     **/
    /* ---ifcfg-rh---
     * property: autoconnect-slaves
     * variable: AUTOCONNECT_SLAVES(+)
     * default: missing variable means global default
     * description: Whether slaves of this connection should be auto-connected
     *   when this connection is activated.
     * ---end---
     */
    prop_idx = _nm_setting_property_define_direct_real_enum(
        properties_override,
        obj_properties,
        NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES,
        PROP_AUTOCONNECT_SLAVES,
        NM_TYPE_SETTING_CONNECTION_AUTOCONNECT_SLAVES,
        NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_DEFAULT,
        NM_SETTING_PARAM_FUZZY_IGNORE,
        NM_SETT_INFO_PROPERT_TYPE_DBUS(G_VARIANT_TYPE_INT32,
                                       .direct_type = NM_VALUE_TYPE_ENUM,
                                       .compare_fcn = _nm_setting_property_compare_fcn_direct,
                                       .to_dbus_fcn = _nm_setting_property_to_dbus_fcn_direct,
                                       .from_dbus_fcn =
                                           _nm_setting_connection_autoconnect_slaves_from_dbus, ),
        NMSettingConnectionPrivate,
        autoconnect_ports,
        .is_deprecated           = 1,
        .direct_is_aliased_field = TRUE, );

    /**
     * NMSettingConnection:autoconnect-ports:
     *
     * Whether or not ports of this connection should be automatically brought up
     * when NetworkManager activates this connection. This only has a real effect
     * for controller connections. The properties #NMSettingConnection:autoconnect,
     * #NMSettingConnection:autoconnect-priority and #NMSettingConnection:autoconnect-retries
     * are unrelated to this setting.
     * The permitted values are: 0: leave port connections untouched,
     * 1: activate all the port connections with this connection, -1: default.
     * If -1 (default) is set, global connection.autoconnect-ports is read to
     * determine the real value. If it is default as well, this fallbacks to 0.
     *
     * Since: 1.46
     **/
    _nm_setting_property_define_direct_enum(
        properties_override,
        obj_properties,
        NM_SETTING_CONNECTION_AUTOCONNECT_PORTS,
        PROP_AUTOCONNECT_PORTS,
        NM_TYPE_TERNARY,
        NM_TERNARY_DEFAULT,
        NM_SETTING_PARAM_FUZZY_IGNORE,
        NM_SETT_INFO_PROPERT_TYPE_DBUS(
            G_VARIANT_TYPE_INT32,
            .direct_type   = NM_VALUE_TYPE_ENUM,
            .compare_fcn   = _nm_setting_property_compare_fcn_direct,
            .to_dbus_fcn   = _nm_setting_connection_autoconnect_ports_to_dbus,
            .from_dbus_fcn = _nm_setting_connection_autoconnect_ports_from_dbus, ),
        NMSettingConnectionPrivate,
        autoconnect_ports,
        .direct_also_notify = obj_properties[PROP_AUTOCONNECT_SLAVES]);

    nm_g_array_index(properties_override, NMSettInfoProperty, prop_idx).direct_also_notify =
        obj_properties[PROP_AUTOCONNECT_PORTS];

    /**
     * NMSettingConnection:secondaries:
     *
     * List of connection UUIDs that should be activated when the base
     * connection itself is activated. Currently, only VPN connections are
     * supported.
     **/
    /* ---ifcfg-rh---
     * property: secondaries
     * variable: SECONDARY_UUIDS(+)
     * description: UUID of VPN connections that should be activated
     *   together with this connection.
     * ---end---
     */
    _nm_setting_property_define_direct_strv(properties_override,
                                            obj_properties,
                                            NM_SETTING_CONNECTION_SECONDARIES,
                                            PROP_SECONDARIES,
                                            NM_SETTING_PARAM_FUZZY_IGNORE,
                                            NULL,
                                            NMSettingConnectionPrivate,
                                            secondaries);

    /**
     * NMSettingConnection:gateway-ping-timeout:
     *
     * If greater than zero, delay success of IP addressing until either the
     * timeout is reached, or an IP gateway replies to a ping.
     **/
    /* ---ifcfg-rh---
     * property: gateway-ping-timeout
     * variable: GATEWAY_PING_TIMEOUT(+)
     * default: 0
     * description: If greater than zero, the IP connectivity will be checked by
     *   pinging the gateway and waiting for the specified timeout (in seconds).
     * example: GATEWAY_PING_TIMEOUT=5
     * ---end---
     */
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_CONNECTION_GATEWAY_PING_TIMEOUT,
                                              PROP_GATEWAY_PING_TIMEOUT,
                                              0,
                                              600,
                                              0,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingConnectionPrivate,
                                              gateway_ping_timeout);

    /**
     * NMSettingConnection:metered:
     *
     * Whether the connection is metered.
     *
     * When updating this property on a currently activated connection,
     * the change takes effect immediately.
     *
     * Since: 1.2
     **/
    /* ---ifcfg-rh---
     * property: metered
     * variable: CONNECTION_METERED(+)
     * values: yes,no,unknown
     * description: Whether the device is metered
     * example: CONNECTION_METERED=yes
     * ---end---
     */
    _nm_setting_property_define_direct_real_enum(properties_override,
                                                 obj_properties,
                                                 NM_SETTING_CONNECTION_METERED,
                                                 PROP_METERED,
                                                 NM_TYPE_METERED,
                                                 NM_METERED_UNKNOWN,
                                                 NM_SETTING_PARAM_REAPPLY_IMMEDIATELY,
                                                 NULL,
                                                 NMSettingConnectionPrivate,
                                                 metered);

    /**
     * NMSettingConnection:lldp:
     *
     * Whether LLDP is enabled for the connection.
     *
     * Since: 1.2
     **/
    /* ---ifcfg-rh---
     * property: lldp
     * variable: LLDP(+)
     * values: boolean value or 'rx'
     * default: missing variable means global default
     * description: whether LLDP is enabled for the connection
     * example: LLDP=no
     * ---end---
     */
    _nm_setting_property_define_direct_int32(properties_override,
                                             obj_properties,
                                             NM_SETTING_CONNECTION_LLDP,
                                             PROP_LLDP,
                                             G_MININT32,
                                             G_MAXINT32,
                                             NM_SETTING_CONNECTION_LLDP_DEFAULT,
                                             NM_SETTING_PARAM_FUZZY_IGNORE,
                                             NMSettingConnectionPrivate,
                                             lldp);

    /**
     * NMSettingConnection:auth-retries:
     *
     * The number of retries for the authentication. Zero means to try indefinitely; -1 means
     * to use a global default. If the global default is not set, the authentication
     * retries for 3 times before failing the connection.
     *
     * Currently, this only applies to 802-1x authentication.
     *
     * Since: 1.10
     **/
    /* ---ifcfg-rh---
     * property: auth-retries
     * variable: AUTH_RETRIES(+)
     * default: 0
     * description: Number of retries for authentication.
     * ---end---
     */
    _nm_setting_property_define_direct_int32(properties_override,
                                             obj_properties,
                                             NM_SETTING_CONNECTION_AUTH_RETRIES,
                                             PROP_AUTH_RETRIES,
                                             -1,
                                             G_MAXINT32,
                                             -1,
                                             NM_SETTING_PARAM_FUZZY_IGNORE,
                                             NMSettingConnectionPrivate,
                                             auth_retries);

    /**
     * NMSettingConnection:mdns:
     *
     * Whether mDNS is enabled for the connection.
     *
     * The permitted values are: "yes" (2) register hostname and resolving
     * for the connection, "no" (0) disable mDNS for the interface, "resolve"
     * (1) do not register hostname but allow resolving of mDNS host names
     * and "default" (-1) to allow lookup of a global default in NetworkManager.conf.
     * If unspecified, "default" ultimately depends on the DNS plugin.
     *
     * This feature requires a plugin which supports mDNS. Otherwise, the
     * setting has no effect. Currently the only supported DNS plugin is
     * systemd-resolved. For systemd-resolved, the default is configurable via
     * MulticastDNS= setting in resolved.conf.
     *
     * Since: 1.12
     **/
    /* ---ifcfg-rh---
     * property: mdns
     * variable: MDNS(+)
     * values: yes,no,resolve
     * default: missing variable means global default
     * description: Whether or not mDNS is enabled for the connection
     * example: MDNS=yes
     * ---end---
     */
    _nm_setting_property_define_direct_int32(properties_override,
                                             obj_properties,
                                             NM_SETTING_CONNECTION_MDNS,
                                             PROP_MDNS,
                                             G_MININT32,
                                             G_MAXINT32,
                                             NM_SETTING_CONNECTION_MDNS_DEFAULT,
                                             NM_SETTING_PARAM_NONE,
                                             NMSettingConnectionPrivate,
                                             mdns);

    /**
     * NMSettingConnection:llmnr:
     *
     * Whether Link-Local Multicast Name Resolution (LLMNR) is enabled
     * for the connection. LLMNR is a protocol based on the Domain Name
     * System (DNS) packet format that allows both IPv4 and IPv6 hosts
     * to perform name resolution for hosts on the same local link.
     *
     * The permitted values are: "yes" (2) register hostname and resolving
     * for the connection, "no" (0) disable LLMNR for the interface, "resolve"
     * (1) do not register hostname but allow resolving of LLMNR host names
     * If unspecified, "default" ultimately depends on the DNS plugin (which
     * for systemd-resolved currently means "yes").
     *
     * This feature requires a plugin which supports LLMNR. Otherwise, the
     * setting has no effect. One such plugin is dns-systemd-resolved.
     *
     * Since: 1.14
     **/
    /* ---ifcfg-rh---
     * property: llmnr
     * variable: LLMNR(+)
     * values: yes,no,resolve
     * default: missing variable means global default
     * description: Whether or not LLMNR is enabled for the connection
     * example: LLMNR=yes
     * ---end---
     */
    _nm_setting_property_define_direct_int32(properties_override,
                                             obj_properties,
                                             NM_SETTING_CONNECTION_LLMNR,
                                             PROP_LLMNR,
                                             G_MININT32,
                                             G_MAXINT32,
                                             NM_SETTING_CONNECTION_LLMNR_DEFAULT,
                                             NM_SETTING_PARAM_NONE,
                                             NMSettingConnectionPrivate,
                                             llmnr);

    /**
     * NMSettingConnection:dns-over-tls:
     *
     * Whether DNSOverTls (dns-over-tls) is enabled for the connection.
     * DNSOverTls is a technology which uses TLS to encrypt dns traffic.
     *
     * The permitted values are: "yes" (2) use DNSOverTls and disabled fallback,
     * "opportunistic" (1) use DNSOverTls but allow fallback to unencrypted resolution,
     * "no" (0) don't ever use DNSOverTls.
     * If unspecified "default" depends on the plugin used. Systemd-resolved
     * uses global setting.
     *
     * This feature requires a plugin which supports DNSOverTls. Otherwise, the
     * setting has no effect. One such plugin is dns-systemd-resolved.
     *
     * Since: 1.34
     **/
    /* ---ifcfg-rh---
     * property: dns-over-tls
     * variable: DNS_OVER_TLS(+)
     * values: yes,no,opportunistic
     * default: missing variable means global default
     * description: Whether or not DNSOverTls is enabled for the connection
     * ---end---
     */
    _nm_setting_property_define_direct_int32(properties_override,
                                             obj_properties,
                                             NM_SETTING_CONNECTION_DNS_OVER_TLS,
                                             PROP_DNS_OVER_TLS,
                                             G_MININT32,
                                             G_MAXINT32,
                                             NM_SETTING_CONNECTION_DNS_OVER_TLS_DEFAULT,
                                             NM_SETTING_PARAM_NONE,
                                             NMSettingConnectionPrivate,
                                             dns_over_tls);

    /* Notes about "mptcp-flags":
     *
     * It is a bit odd that NMMptcpFlags mixes flags with different purposes:
     *
     * - "disabled", "disabled-on-local-iface", "enable": whether MPTCP handling
     *   is enabled. The flag "disabled-on-local-iface" enables it based on whether
     *   the interface has a default route.
     * - "signal", "subflow", "backup", "fullmesh": the endpoint flags
     *   that are used.
     *
     * The reason is, that it is useful to have one "connection.mptcp-flags"
     * property, that can express various aspects at once. The alternatives
     * would be multiple properties like "connection.mptcp-enabled",
     * "connection.mptcp-addr-flags" and "connection.mptcp-notify-flags".
     * More properties does not necessarily make the API simpler. In particular
     * for something like MPTCP, which should just work by default and only
     * in special cases require special configuration.
     *
     * The entire idea is to only have one "connection.mptcp-flags" property (for now).
     * That one can encode multiple aspects about MPTCP, whether it's enabled at all,
     * which address flags to use when configuring endpoints, and opt-in addresses
     * that otherwise would not be configured as endpoints.
     *
     * "connection.mptcp-flags" applies to all addresses on the interface (minus the ones
     * that are not included by default). The idea is that in the future we could have
     * more properties like "ipv4.dhcp-mptcp-flags=subflow", "ipv6.link-local-mptcp-flags=disabled",
     * "ipv4.addresses='192.168.1.5/24 mptcp-flags=signal,backup'", which can overwrite the
     * flags on a per-address basis.
     *
     * But for that future extension, we now need a global "connection.mptcp-flags" property
     * in the API that is the basis and applies to all addresses.
     */

    /**
     * NMSettingConnection:mptcp-flags:
     *
     * Whether to configure MPTCP endpoints and the address flags.
     * If MPTCP is enabled in NetworkManager, it will configure the
     * addresses of the interface as MPTCP endpoints. Note that
     * IPv4 loopback addresses (127.0.0.0/8), IPv4 link local
     * addresses (169.254.0.0/16), the IPv6 loopback address (::1),
     * IPv6 link local addresses (fe80::/10), IPv6 unique
     * local addresses (ULA, fc00::/7) and IPv6 privacy extension addresses
     * (rfc3041, ipv6.ip6-privacy) will be excluded from being
     * configured as endpoints.
     *
     * If "disabled" (0x1), MPTCP handling for the interface is disabled and
     * no endpoints are registered.
     *
     * The "enabled" (0x2) flag means that MPTCP handling is enabled.
     * This flag can also be implied from the presence of other flags.
     *
     * Even when enabled, MPTCP handling will by default still be disabled
     * unless "/proc/sys/net/mptcp/enabled" sysctl is on. NetworkManager
     * does not change the sysctl and this is up to the administrator
     * or distribution. To configure endpoints even if the sysctl is
     * disabled, "also-without-sysctl" (0x4) flag can be used. In that case,
     * NetworkManager doesn't look at the sysctl and configures endpoints
     * regardless.
     *
     * Even when enabled, NetworkManager will only configure MPTCP endpoints
     * for a certain address family, if there is a unicast default route (0.0.0.0/0
     * or ::/0) in the main routing table. The flag "also-without-default-route"
     * (0x8) can override that.
     *
     * When MPTCP handling is enabled then endpoints are configured with
     * the specified address flags "signal" (0x10), "subflow" (0x20), "backup" (0x40),
     * "fullmesh" (0x80). See ip-mptcp(8) manual for additional information about the flags.
     *
     * If the flags are zero (0x0), the global connection default from NetworkManager.conf is
     * honored. If still unspecified, the fallback is "enabled,subflow".
     * Note that this means that MPTCP is by default done depending on the
     * "/proc/sys/net/mptcp/enabled" sysctl.
     *
     * NetworkManager does not change the MPTCP limits nor enable MPTCP via
     * "/proc/sys/net/mptcp/enabled". That is a host configuration which the
     * admin can change via sysctl and ip-mptcp.
     *
     * Strict reverse path filtering (rp_filter) breaks many MPTCP use cases, so when
     * MPTCP handling for IPv4 addresses on the interface is enabled, NetworkManager would
     * loosen the strict reverse path filtering (1) to the loose setting (2).
     *
     * Since: 1.40
     **/
    /* ---ifcfg-rh---
     * property: mptcp-flags
     * variable: MPTCP_FLAGS(+)
     * default: missing variable means global default
     * description: The MPTCP flags that indicate whether MPTCP is enabled
     *   and which flags to use for the address endpoints.
     * example: MPTCP_FLAGS="signal,subflow"
     * ---end---
     */
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_CONNECTION_MPTCP_FLAGS,
                                              PROP_MPTCP_FLAGS,
                                              0,
                                              G_MAXUINT32,
                                              NM_MPTCP_FLAGS_NONE,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingConnectionPrivate,
                                              mptcp_flags);

    /**
     * NMSettingConnection:wait-device-timeout:
     *
     * Timeout in milliseconds to wait for device at startup.
     * During boot, devices may take a while to be detected by the driver.
     * This property will cause to delay NetworkManager-wait-online.service
     * and nm-online to give the device a chance to appear. This works by
     * waiting for the given timeout until a compatible device for the
     * profile is available and managed.
     *
     * The value 0 means no wait time. The default value is -1, which
     * currently has the same meaning as no wait time.
     *
     * Since: 1.20
     **/
    /* ---ifcfg-rh---
     * property: wait-device-timeout
     * variable: DEVTIMEOUT(+)
     * values: timeout in seconds.
     * description: for initscripts compatibility, this variable must be
     *   a whole integer. If necessary, NetworkManager stores also a fractional
     *   component for the milliseconds.
     * example: DEVTIMEOUT=5
     * ---end---
     */
    _nm_setting_property_define_direct_int32(properties_override,
                                             obj_properties,
                                             NM_SETTING_CONNECTION_WAIT_DEVICE_TIMEOUT,
                                             PROP_WAIT_DEVICE_TIMEOUT,
                                             -1,
                                             G_MAXINT32,
                                             -1,
                                             NM_SETTING_PARAM_NONE,
                                             NMSettingConnectionPrivate,
                                             wait_device_timeout);

    /**
     * NMSettingConnection:mud-url:
     *
     * If configured, set to a Manufacturer Usage Description (MUD) URL that points
     * to manufacturer-recommended network policies for IoT devices. It is transmitted
     * as a DHCPv4 or DHCPv6 option. The value must be a valid URL starting with "https://".
     *
     * The special value "none" is allowed to indicate that no MUD URL is used.
     *
     * If the per-profile value is unspecified (the default), a global connection default gets
     * consulted. If still unspecified, the ultimate default is "none".
     *
     * Since: 1.26
     **/
    /* ---ifcfg-rh---
     * property: mud-url
     * variable: MUD_URL
     * values: a valid URL that points to recommended policy for this device
     * description: MUD_URL to be sent by device (See RFC 8520).
     * example: https://yourdevice.example.com/model.json
     * ---end---
     */
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_CONNECTION_MUD_URL,
                                              PROP_MUD_URL,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingConnectionPrivate,
                                              mud_url,
                                              .direct_string_allow_empty = TRUE);

    /**
     * NMSettingConnection:wait-activation-delay:
     *
     * Time in milliseconds to wait for connection to be considered activated.
     * The wait will start after the pre-up dispatcher event.
     *
     * The value 0 means no wait time. The default value is -1, which
     * currently has the same meaning as no wait time.
     *
     * Since: 1.40
     **/
    /* ---ifcfg-rh---
     * property: wait-activation-delay
     * variable: WAIT_ACTIVATION_DELAY(+)
     * values: delay in milliseconds.
     * description: Time in milliseconds to wait for connection to be considered activated.
     * The wait will start after the pre-up dispatcher event.
     * example: WAIT_ACTIVATION_DELAY=5000
     * ---end---
     */
    _nm_setting_property_define_direct_int32(properties_override,
                                             obj_properties,
                                             NM_SETTING_CONNECTION_WAIT_ACTIVATION_DELAY,
                                             PROP_WAIT_ACTIVATION_DELAY,
                                             -1,
                                             G_MAXINT32,
                                             -1,
                                             NM_SETTING_PARAM_NONE,
                                             NMSettingConnectionPrivate,
                                             wait_activation_delay);

    /**
     * NMSettingConnection:down-on-poweroff:
     *
     *
     * Whether the connection will be brought down before the system is powered
     * off.  The default value is %NM_SETTING_CONNECTION_DOWN_ON_POWEROFF_DEFAULT. When
     * the default value is specified, then the global value from
     * NetworkManager configuration is looked up, if not set, it is considered
     * as %NM_SETTING_CONNECTION_DOWN_ON_POWEROFF_NO.
     *
     * Since: 1.48
     **/
    _nm_setting_property_define_direct_enum(properties_override,
                                            obj_properties,
                                            NM_SETTING_CONNECTION_DOWN_ON_POWEROFF,
                                            PROP_DOWN_ON_POWEROFF,
                                            NM_TYPE_SETTING_CONNECTION_DOWN_ON_POWEROFF,
                                            NM_SETTING_CONNECTION_DOWN_ON_POWEROFF_DEFAULT,
                                            NM_SETTING_PARAM_NONE,
                                            NULL,
                                            NMSettingConnectionPrivate,
                                            down_on_poweroff);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_CONNECTION,
                             NULL,
                             properties_override,
                             G_STRUCT_OFFSET(NMSettingConnection, _priv));
}
