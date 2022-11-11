/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Lubomir Rintel <lkundrak@v3.sk>
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-wpan.h"

#include "nm-connection-private.h"
#include "nm-setting-connection.h"
#include "nm-setting-private.h"
#include "nm-utils-private.h"

/**
 * SECTION:nm-setting-wpan
 * @short_description: Describes connection properties for IEEE 802.15.4 (WPAN) MAC
 *
 * The #NMSettingWpan object is a #NMSetting subclass that describes properties
 * necessary for configuring IEEE 802.15.4 (WPAN) MAC layer devices.
 **/

/* Ideally we'll be able to get these from a public header. */
#ifndef IEEE802154_ADDR_LEN
#define IEEE802154_ADDR_LEN 8
#endif

#ifndef IEEE802154_MAX_PAGE
#define IEEE802154_MAX_PAGE 31
#endif

#ifndef IEEE802154_MAX_CHANNEL
#define IEEE802154_MAX_CHANNEL 26
#endif

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_MAC_ADDRESS,
                                  PROP_PAN_ID,
                                  PROP_SHORT_ADDRESS,
                                  PROP_PAGE,
                                  PROP_CHANNEL, );

typedef struct {
    char   *mac_address;
    guint32 pan_id;
    guint32 short_address;
    gint32  page;
    gint32  channel;
} NMSettingWpanPrivate;

/**
 * NMSettingWpan:
 *
 * IEEE 802.15.4 (WPAN) MAC Settings
 *
 * Since: 1.14
 */
struct _NMSettingWpan {
    NMSetting parent;
};

struct _NMSettingWpanClass {
    NMSettingClass parent;
};

G_DEFINE_TYPE(NMSettingWpan, nm_setting_wpan, NM_TYPE_SETTING)

#define NM_SETTING_WPAN_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), NM_TYPE_SETTING_WPAN, NMSettingWpanPrivate))

/*****************************************************************************/

/**
 * nm_setting_wpan_get_mac_address:
 * @setting: the #NMSettingWpan
 *
 * Returns: the #NMSettingWpan:mac-address property of the setting
 *
 * Since: 1.42
 **/
const char *
nm_setting_wpan_get_mac_address(NMSettingWpan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WPAN(setting), NULL);

    return NM_SETTING_WPAN_GET_PRIVATE(setting)->mac_address;
}

/**
 * nm_setting_wpan_get_pan_id:
 * @setting: the #NMSettingWpan
 *
 * Returns: the #NMSettingWpan:pan-id property of the setting
 *
 * Since: 1.42
 **/
guint16
nm_setting_wpan_get_pan_id(NMSettingWpan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WPAN(setting), G_MAXUINT16);

    return NM_SETTING_WPAN_GET_PRIVATE(setting)->pan_id;
}

/**
 * nm_setting_wpan_get_short_address:
 * @setting: the #NMSettingWpan
 *
 * Returns: the #NMSettingWpan:short-address property of the setting
 *
 * Since: 1.42
 **/
guint16
nm_setting_wpan_get_short_address(NMSettingWpan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WPAN(setting), G_MAXUINT16);

    return NM_SETTING_WPAN_GET_PRIVATE(setting)->short_address;
}

/**
 * nm_setting_wpan_get_page:
 * @setting: the #NMSettingWpan
 *
 * Returns: the #NMSettingWpan:page property of the setting
 *
 * Since: 1.42
 **/
gint16
nm_setting_wpan_get_page(NMSettingWpan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WPAN(setting), NM_SETTING_WPAN_PAGE_DEFAULT);

    return NM_SETTING_WPAN_GET_PRIVATE(setting)->page;
}

/**
 * nm_setting_wpan_get_channel:
 * @setting: the #NMSettingWpan
 *
 * Returns: the #NMSettingWpan:channel property of the setting
 *
 * Since: 1.42
 **/
gint16
nm_setting_wpan_get_channel(NMSettingWpan *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_WPAN(setting), NM_SETTING_WPAN_CHANNEL_DEFAULT);

    return NM_SETTING_WPAN_GET_PRIVATE(setting)->channel;
}

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingWpanPrivate *priv = NM_SETTING_WPAN_GET_PRIVATE(setting);

    if (priv->mac_address && !nm_utils_hwaddr_valid(priv->mac_address, IEEE802154_ADDR_LEN)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property is invalid"));
        g_prefix_error(error, "%s.%s: ", NM_SETTING_WPAN_SETTING_NAME, NM_SETTING_WPAN_MAC_ADDRESS);
        return FALSE;
    }

    if ((priv->page == NM_SETTING_WPAN_PAGE_DEFAULT)
        != (priv->channel == NM_SETTING_WPAN_CHANNEL_DEFAULT)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("page must be defined along with a channel"));
        g_prefix_error(error, "%s.%s: ", NM_SETTING_WPAN_SETTING_NAME, NM_SETTING_WPAN_PAGE);
        return FALSE;
    }

    if (priv->page < NM_SETTING_WPAN_PAGE_DEFAULT || priv->page > IEEE802154_MAX_PAGE) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("page must be between %d and %d"),
                    NM_SETTING_WPAN_PAGE_DEFAULT,
                    IEEE802154_MAX_PAGE);
        g_prefix_error(error, "%s.%s: ", NM_SETTING_WPAN_SETTING_NAME, NM_SETTING_WPAN_PAGE);
        return FALSE;
    }

    if (priv->channel < NM_SETTING_WPAN_CHANNEL_DEFAULT || priv->channel > IEEE802154_MAX_CHANNEL) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("channel must not be between %d and %d"),
                    NM_SETTING_WPAN_CHANNEL_DEFAULT,
                    IEEE802154_MAX_CHANNEL);
        g_prefix_error(error, "%s.%s: ", NM_SETTING_WPAN_SETTING_NAME, NM_SETTING_WPAN_CHANNEL);
        return FALSE;
    }

    return TRUE;
}

/*****************************************************************************/

static void
nm_setting_wpan_init(NMSettingWpan *setting)
{}

/**
 * nm_setting_wpan_new:
 *
 * Creates a new #NMSettingWpan object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingWpan object
 *
 * Since: 1.42
 **/
NMSetting *
nm_setting_wpan_new(void)
{
    return g_object_new(NM_TYPE_SETTING_WPAN, NULL);
}

static void
nm_setting_wpan_class_init(NMSettingWpanClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    g_type_class_add_private(setting_class, sizeof(NMSettingWpanPrivate));

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify = verify;

    /**
     * NMSettingWpan:mac-address:
     *
     * If specified, this connection will only apply to the IEEE 802.15.4 (WPAN)
     * MAC layer device whose permanent MAC address matches.
     **/
    /* ---keyfile---
     * property: mac-address
     * format: usual hex-digits-and-colons notation
     * description: MAC address in hex-digits-and-colons notation
     *   (e.g. 76:d8:9b:87:66:60:84:ee).
     * ---end---
     */
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_WPAN_MAC_ADDRESS,
                                              PROP_MAC_ADDRESS,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingWpanPrivate,
                                              mac_address,
                                              .direct_set_string_mac_address_len =
                                                  IEEE802154_ADDR_LEN);

    /**
     * NMSettingWpan:pan-id:
     *
     * IEEE 802.15.4 Personal Area Network (PAN) identifier.
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_WPAN_PAN_ID,
                                              PROP_PAN_ID,
                                              0,
                                              G_MAXUINT16,
                                              G_MAXUINT16,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingWpanPrivate,
                                              pan_id);

    /**
     * NMSettingWpan:short-address:
     *
     * Short IEEE 802.15.4 address to be used within a restricted environment.
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_WPAN_SHORT_ADDRESS,
                                              PROP_SHORT_ADDRESS,
                                              0,
                                              G_MAXUINT16,
                                              G_MAXUINT16,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingWpanPrivate,
                                              short_address);

    /**
     * NMSettingWpan:page:
     *
     * IEEE 802.15.4 channel page. A positive integer or -1, meaning "do not
     * set, use whatever the device is already set to".
     *
     * Since: 1.16
     **/
    _nm_setting_property_define_direct_int32(properties_override,
                                             obj_properties,
                                             NM_SETTING_WPAN_PAGE,
                                             PROP_PAGE,
                                             G_MININT16,
                                             G_MAXINT16,
                                             NM_SETTING_WPAN_PAGE_DEFAULT,
                                             NM_SETTING_PARAM_NONE,
                                             NMSettingWpanPrivate,
                                             page);

    /**
     * NMSettingWpan:channel:
     *
     * IEEE 802.15.4 channel. A positive integer or -1, meaning "do not
     * set, use whatever the device is already set to".
     *
     * Since: 1.16
     **/
    _nm_setting_property_define_direct_int32(properties_override,
                                             obj_properties,
                                             NM_SETTING_WPAN_CHANNEL,
                                             PROP_CHANNEL,
                                             G_MININT16,
                                             G_MAXINT16,
                                             NM_SETTING_WPAN_CHANNEL_DEFAULT,
                                             NM_SETTING_PARAM_NONE,
                                             NMSettingWpanPrivate,
                                             channel);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_WPAN,
                             NULL,
                             properties_override,
                             NM_SETT_INFO_PRIVATE_OFFSET_FROM_CLASS);
}
