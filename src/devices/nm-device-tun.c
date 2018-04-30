/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright 2013 - 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-tun.h"

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <linux/if_tun.h>

#include "nm-act-request.h"
#include "nm-device-private.h"
#include "nm-ip4-config.h"
#include "platform/nm-platform.h"
#include "nm-device-factory.h"
#include "nm-setting-tun.h"
#include "nm-core-internal.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceTun);

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMDeviceTun,
	PROP_OWNER,
	PROP_GROUP,
	PROP_MODE,
	PROP_NO_PI,
	PROP_VNET_HDR,
	PROP_MULTI_QUEUE,
);

typedef struct {
	NMPlatformLnkTun props;
} NMDeviceTunPrivate;

struct _NMDeviceTun {
	NMDevice parent;
	NMDeviceTunPrivate _priv;
};

struct _NMDeviceTunClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceTun, nm_device_tun, NM_TYPE_DEVICE)

#define NM_DEVICE_TUN_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDeviceTun, NM_IS_DEVICE_TUN)

/*****************************************************************************/

static void
update_properties_from_struct (NMDeviceTun *self,
                               const NMPlatformLnkTun *props)
{
	NMDeviceTunPrivate *priv = NM_DEVICE_TUN_GET_PRIVATE (self);
	const NMPlatformLnkTun props0 = { };

	if (!props) {
		/* allow passing %NULL to reset all properties. */
		props = &props0;
	}

	g_object_freeze_notify (G_OBJECT (self));

#define CHECK_PROPERTY_CHANGED_VALID(field, prop) \
	G_STMT_START { \
		if (   priv->props.field != props->field \
		    || priv->props.field##_valid != props->field##_valid) { \
			priv->props.field##_valid = props->field##_valid; \
			priv->props.field = props->field; \
			_notify (self, prop); \
		} \
	} G_STMT_END

#define CHECK_PROPERTY_CHANGED(field, prop) \
	G_STMT_START { \
		if (priv->props.field != props->field) { \
			priv->props.field = props->field; \
			_notify (self, prop); \
		} \
	} G_STMT_END

	CHECK_PROPERTY_CHANGED_VALID (owner, PROP_OWNER);
	CHECK_PROPERTY_CHANGED_VALID (group, PROP_GROUP);
	CHECK_PROPERTY_CHANGED (type, PROP_MODE);
	CHECK_PROPERTY_CHANGED (pi, PROP_NO_PI);
	CHECK_PROPERTY_CHANGED (vnet_hdr, PROP_VNET_HDR);
	CHECK_PROPERTY_CHANGED (multi_queue, PROP_MULTI_QUEUE);

	g_object_thaw_notify (G_OBJECT (self));
}

static void
update_properties (NMDeviceTun *self)
{
	NMPlatformLnkTun props_storage;
	const NMPlatformLnkTun *props = NULL;
	int ifindex;

	ifindex = nm_device_get_ifindex (NM_DEVICE (self));
	if (   ifindex > 0
	    && nm_platform_link_tun_get_properties (nm_device_get_platform (NM_DEVICE (self)),
	                                            ifindex,
	                                            &props_storage))
		props = &props_storage;

	update_properties_from_struct (self, props);
}

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *dev)
{
	return NM_DEVICE_CAP_IS_SOFTWARE;
}

static void
link_changed (NMDevice *device,
              const NMPlatformLink *pllink)
{
	NM_DEVICE_CLASS (nm_device_tun_parent_class)->link_changed (device, pllink);
	update_properties (NM_DEVICE_TUN (device));
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     NMConnection *const*existing_connections,
                     GError **error)
{
	NMSettingTun *s_tun;

	nm_utils_complete_generic (nm_device_get_platform (device),
	                           connection,
	                           NM_SETTING_TUN_SETTING_NAME,
	                           existing_connections,
	                           NULL,
	                           _("TUN connection"),
	                           NULL,
	                           TRUE);

	s_tun = nm_connection_get_setting_tun (connection);
	if (!s_tun) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INVALID_CONNECTION,
		                     "A 'tun' setting is required.");
		return FALSE;
	}

	return TRUE;
}

static void
update_connection (NMDevice *device, NMConnection *connection)
{
	NMDeviceTun *self = NM_DEVICE_TUN (device);
	NMDeviceTunPrivate *priv = NM_DEVICE_TUN_GET_PRIVATE (self);
	NMSettingTun *s_tun;
	NMSettingTunMode mode;
	char s_buf[100];
	const char *str;

	/* Note: since we read tun properties from sysctl for older kernels,
	 *       we don't get proper change notifications. Make sure that all our
	 *       tun properties are up to date at this point. We should not do this,
	 *       if we would entirely rely on netlink events. */
	update_properties (NM_DEVICE_TUN (device));

	switch (priv->props.type) {
	case IFF_TUN: mode = NM_SETTING_TUN_MODE_TUN; break;
	case IFF_TAP: mode = NM_SETTING_TUN_MODE_TAP; break;
	default:
		/* Huh? */
		return;
	}

	s_tun = nm_connection_get_setting_tun (connection);
	if (!s_tun) {
		s_tun = (NMSettingTun *) nm_setting_tun_new ();
		nm_connection_add_setting (connection, (NMSetting *) s_tun);
	}

	if (mode != nm_setting_tun_get_mode (s_tun))
		g_object_set (G_OBJECT (s_tun), NM_SETTING_TUN_MODE, (guint) mode, NULL);

	str = priv->props.owner_valid
	      ? nm_sprintf_buf (s_buf, "%" G_GINT32_FORMAT, priv->props.owner)
	      : NULL;
	if (!nm_streq0 (str, nm_setting_tun_get_owner (s_tun)))
		g_object_set (G_OBJECT (s_tun), NM_SETTING_TUN_OWNER, str, NULL);

	str = priv->props.group_valid
	      ? nm_sprintf_buf (s_buf, "%" G_GINT32_FORMAT, priv->props.group)
	      : NULL;
	if (!nm_streq0 (str, nm_setting_tun_get_group (s_tun)))
		g_object_set (G_OBJECT (s_tun), NM_SETTING_TUN_GROUP, str, NULL);

	if (priv->props.pi != nm_setting_tun_get_pi (s_tun))
		g_object_set (G_OBJECT (s_tun), NM_SETTING_TUN_PI, (gboolean) priv->props.pi, NULL);
	if (priv->props.vnet_hdr != nm_setting_tun_get_vnet_hdr (s_tun))
		g_object_set (G_OBJECT (s_tun), NM_SETTING_TUN_VNET_HDR, (gboolean) priv->props.vnet_hdr, NULL);
	if (priv->props.multi_queue != nm_setting_tun_get_multi_queue (s_tun))
		g_object_set (G_OBJECT (s_tun), NM_SETTING_TUN_MULTI_QUEUE, (gboolean) priv->props.multi_queue, NULL);
}

static gboolean
create_and_realize (NMDevice *device,
                    NMConnection *connection,
                    NMDevice *parent,
                    const NMPlatformLink **out_plink,
                    GError **error)
{
	const char *iface = nm_device_get_iface (device);
	NMPlatformLnkTun props = { };
	NMPlatformError plerr;
	NMSettingTun *s_tun;
	gint64 owner, group;

	s_tun = nm_connection_get_setting_tun (connection);
	g_return_val_if_fail (s_tun, FALSE);

	switch (nm_setting_tun_get_mode (s_tun)) {
	case NM_SETTING_TUN_MODE_TAP: props.type = IFF_TAP; break;
	case NM_SETTING_TUN_MODE_TUN: props.type = IFF_TUN; break;
	default:
		g_return_val_if_reached (FALSE);
	}

	owner = _nm_utils_ascii_str_to_int64 (nm_setting_tun_get_owner (s_tun), 10, 0, G_MAXINT32, -1);
	if (owner != -1) {
		props.owner_valid = TRUE;
		props.owner = owner;
	}
	group = _nm_utils_ascii_str_to_int64 (nm_setting_tun_get_group (s_tun), 10, 0, G_MAXINT32, -1);
	if (group != -1) {
		props.group_valid = TRUE;
		props.group = group;
	}

	props.pi = nm_setting_tun_get_pi (s_tun);
	props.vnet_hdr = nm_setting_tun_get_vnet_hdr (s_tun);
	props.multi_queue = nm_setting_tun_get_multi_queue (s_tun);
	props.persist = TRUE;

	plerr = nm_platform_link_tun_add (nm_device_get_platform (device),
	                                  iface,
	                                  &props,
	                                  out_plink,
	                                  NULL);
	if (plerr != NM_PLATFORM_ERROR_SUCCESS) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
		             "Failed to create TUN/TAP interface '%s' for '%s': %s",
		             iface,
		             nm_connection_get_id (connection),
		             nm_platform_error_to_string_a (plerr));
		return FALSE;
	}

	return TRUE;
}

static gboolean
_same_og (const char *str, gboolean og_valid, guint32 og_num)
{
	gint64 v;

	v = _nm_utils_ascii_str_to_int64 (str, 10, 0, G_MAXINT32, -1);
	return    (!og_valid && (           v  == (gint64) -1))
	       || ( og_valid && (((guint32) v) == og_num     ));
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection)
{
	NMDeviceTun *self = NM_DEVICE_TUN (device);
	NMDeviceTunPrivate *priv = NM_DEVICE_TUN_GET_PRIVATE (self);
	NMSettingTunMode mode;
	NMSettingTun *s_tun;

	if (!NM_DEVICE_CLASS (nm_device_tun_parent_class)->check_connection_compatible (device, connection))
		return FALSE;

	s_tun = nm_connection_get_setting_tun (connection);
	if (!s_tun)
		return FALSE;

	if (nm_device_is_real (device)) {
		switch (priv->props.type) {
		case IFF_TUN: mode = NM_SETTING_TUN_MODE_TUN; break;
		case IFF_TAP: mode = NM_SETTING_TUN_MODE_TAP; break;
		default:
			/* Huh? */
			return FALSE;
		}

		if (mode != nm_setting_tun_get_mode (s_tun))
			return FALSE;
		if (!_same_og (nm_setting_tun_get_owner (s_tun), priv->props.owner_valid, priv->props.owner))
			return FALSE;
		if (!_same_og (nm_setting_tun_get_group (s_tun), priv->props.group_valid, priv->props.group))
			return FALSE;
		if (nm_setting_tun_get_pi (s_tun) != priv->props.pi)
			return FALSE;
		if (nm_setting_tun_get_vnet_hdr (s_tun) != priv->props.vnet_hdr)
			return FALSE;
		if (nm_setting_tun_get_multi_queue (s_tun) != priv->props.multi_queue)
			return FALSE;
	}

	return TRUE;
}

static NMActStageReturn
act_stage1_prepare (NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
	NMDeviceTun *self = NM_DEVICE_TUN (device);
	NMDeviceTunPrivate *priv = NM_DEVICE_TUN_GET_PRIVATE (self);
	NMActStageReturn ret;

	ret = NM_DEVICE_CLASS (nm_device_tun_parent_class)->act_stage1_prepare (device, out_failure_reason);
	if (ret != NM_ACT_STAGE_RETURN_SUCCESS)
		return ret;

	/* Nothing to do for TUN devices */
	if (priv->props.type == IFF_TUN)
		return NM_ACT_STAGE_RETURN_SUCCESS;

	if (!nm_device_hw_addr_set_cloned (device, nm_device_get_applied_connection (device), FALSE))
		return NM_ACT_STAGE_RETURN_FAILURE;

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static void
unrealize_notify (NMDevice *device)
{
	NM_DEVICE_CLASS (nm_device_tun_parent_class)->unrealize_notify (device);
	update_properties_from_struct (NM_DEVICE_TUN (device), NULL);
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceTun *self = NM_DEVICE_TUN (object);
	NMDeviceTunPrivate *priv = NM_DEVICE_TUN_GET_PRIVATE (self);
	const char *s;

	switch (prop_id) {
	case PROP_OWNER:
		g_value_set_int64 (value, priv->props.owner_valid ? (gint64) priv->props.owner : (gint64) -1);
		break;
	case PROP_GROUP:
		g_value_set_int64 (value, priv->props.group_valid ? (gint64) priv->props.group : (gint64) -1);
		break;
	case PROP_MODE:
		switch (priv->props.type) {
		case IFF_TUN: s = "tun"; break;
		case IFF_TAP: s = "tap"; break;
		default:      s = NULL;  break;
		}
		g_value_set_static_string (value, s);
		break;
	case PROP_NO_PI:
		g_value_set_boolean (value, !priv->props.pi);
		break;
	case PROP_VNET_HDR:
		g_value_set_boolean (value, priv->props.vnet_hdr);
		break;
	case PROP_MULTI_QUEUE:
		g_value_set_boolean (value, priv->props.multi_queue);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_device_tun_init (NMDeviceTun *self)
{
}

static const NMDBusInterfaceInfoExtended interface_info_device_tun = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_DEVICE_TUN,
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&nm_signal_info_property_changed_legacy,
		),
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Owner",      "x",  NM_DEVICE_TUN_OWNER),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Group",      "x",  NM_DEVICE_TUN_GROUP),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Mode",       "s",  NM_DEVICE_TUN_MODE),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("NoPi",       "b",  NM_DEVICE_TUN_NO_PI),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("VnetHdr",    "b",  NM_DEVICE_TUN_VNET_HDR),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("MultiQueue", "b",  NM_DEVICE_TUN_MULTI_QUEUE),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("HwAddress",  "s",  NM_DEVICE_HW_ADDRESS),
		),
	),
	.legacy_property_changed = TRUE,
};

static void
nm_device_tun_class_init (NMDeviceTunClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	NM_DEVICE_CLASS_DECLARE_TYPES (klass, NULL, NM_LINK_TYPE_TUN)

	object_class->get_property = get_property;

	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_device_tun);

	device_class->connection_type = NM_SETTING_TUN_SETTING_NAME;
	device_class->link_changed = link_changed;
	device_class->complete_connection = complete_connection;
	device_class->check_connection_compatible = check_connection_compatible;
	device_class->create_and_realize = create_and_realize;
	device_class->get_generic_capabilities = get_generic_capabilities;
	device_class->unrealize_notify = unrealize_notify;
	device_class->update_connection = update_connection;
	device_class->act_stage1_prepare = act_stage1_prepare;
	device_class->get_configured_mtu = nm_device_get_configured_mtu_for_wired;

	obj_properties[PROP_OWNER] =
	     g_param_spec_int64 (NM_DEVICE_TUN_OWNER, "", "",
	                         -1, G_MAXUINT32, -1,
	                         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_GROUP] =
	     g_param_spec_int64 (NM_DEVICE_TUN_GROUP, "", "",
	                         -1, G_MAXUINT32, -1,
	                         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_MODE] =
	     g_param_spec_string (NM_DEVICE_TUN_MODE, "", "",
	                          NULL,
	                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_NO_PI] =
	     g_param_spec_boolean (NM_DEVICE_TUN_NO_PI, "", "",
	                           FALSE,
	                           G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_VNET_HDR] =
	     g_param_spec_boolean (NM_DEVICE_TUN_VNET_HDR, "", "",
	                           FALSE,
	                           G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_MULTI_QUEUE] =
	     g_param_spec_boolean (NM_DEVICE_TUN_MULTI_QUEUE, "", "",
	                           FALSE,
	                           G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}

/*****************************************************************************/

#define NM_TYPE_TUN_DEVICE_FACTORY (nm_tun_device_factory_get_type ())
#define NM_TUN_DEVICE_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_TUN_DEVICE_FACTORY, NMTunDeviceFactory))

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               const NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	g_return_val_if_fail (!plink || plink->type == NM_LINK_TYPE_TUN, NULL);
	g_return_val_if_fail (!connection || nm_streq0 (nm_connection_get_connection_type (connection), NM_SETTING_TUN_SETTING_NAME), NULL);

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_TUN,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_TYPE_DESC, "Tun",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_TUN,
	                                  NM_DEVICE_LINK_TYPE, (guint) NM_LINK_TYPE_TUN,
	                                  NULL);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL (TUN, Tun, tun,
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES (NM_LINK_TYPE_TUN)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_TUN_SETTING_NAME),
	factory_class->create_device = create_device;
);
