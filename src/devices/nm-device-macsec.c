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
 * Copyright 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-macsec.h"

#include "nm-device-private.h"
#include "platform/nm-platform.h"
#include "nm-device-factory.h"
#include "nm-manager.h"
#include "nm-core-internal.h"

#include "introspection/org.freedesktop.NetworkManager.Device.Macsec.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceMacsec);

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMDeviceMacsec,
	PROP_SCI,
	PROP_CIPHER_SUITE,
	PROP_ICV_LENGTH,
	PROP_WINDOW,
	PROP_ENCODING_SA,
	PROP_ENCRYPT,
	PROP_PROTECT,
	PROP_INCLUDE_SCI,
	PROP_ES,
	PROP_SCB,
	PROP_REPLAY_PROTECT,
	PROP_VALIDATION,
);

typedef struct {
	NMPlatformLnkMacsec props;
	gulong parent_state_id;
} NMDeviceMacsecPrivate;

struct _NMDeviceMacsec {
	NMDevice parent;
	NMDeviceMacsecPrivate _priv;
};

struct _NMDeviceMacsecClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceMacsec, nm_device_macsec, NM_TYPE_DEVICE)

#define NM_DEVICE_MACSEC_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDeviceMacsec, NM_IS_DEVICE_MACSEC)

/******************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (validation_mode_to_string, guint8,
	NM_UTILS_LOOKUP_DEFAULT_WARN ("<unknown>"),
	NM_UTILS_LOOKUP_STR_ITEM (0, "disable"),
	NM_UTILS_LOOKUP_STR_ITEM (1, "check"),
	NM_UTILS_LOOKUP_STR_ITEM (2, "strict"),
);

static void
parent_state_changed (NMDevice *parent,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMDeviceMacsec *self = NM_DEVICE_MACSEC (user_data);

	/* We'll react to our own carrier state notifications. Ignore the parent's. */
	if (reason == NM_DEVICE_STATE_REASON_CARRIER)
		return;

	nm_device_set_unmanaged_by_flags (NM_DEVICE (self), NM_UNMANAGED_PARENT, !nm_device_get_managed (parent, FALSE), reason);
}

static void
parent_changed_notify (NMDevice *device,
                       int old_ifindex,
                       NMDevice *old_parent,
                       int new_ifindex,
                       NMDevice *new_parent)
{
	NMDeviceMacsec *self = NM_DEVICE_MACSEC (device);
	NMDeviceMacsecPrivate *priv = NM_DEVICE_MACSEC_GET_PRIVATE (self);

	NM_DEVICE_CLASS (nm_device_macsec_parent_class)->parent_changed_notify (device,
	                                                                        old_ifindex,
	                                                                        old_parent,
	                                                                        new_ifindex,
	                                                                        new_parent);

	/*  note that @self doesn't have to clear @parent_state_id on dispose,
	 *  because NMDevice's dispose() will unset the parent, which in turn calls
	 *  parent_changed_notify(). */
	nm_clear_g_signal_handler (old_parent, &priv->parent_state_id);

	if (new_parent) {
		priv->parent_state_id = g_signal_connect (new_parent,
		                                          NM_DEVICE_STATE_CHANGED,
		                                          G_CALLBACK (parent_state_changed),
		                                          device);

		/* Set parent-dependent unmanaged flag */
		nm_device_set_unmanaged_by_flags (device,
		                                  NM_UNMANAGED_PARENT,
		                                  !nm_device_get_managed (new_parent, FALSE),
		                                  NM_DEVICE_STATE_REASON_PARENT_MANAGED_CHANGED);
	}

	/* Recheck availability now that the parent has changed */
	if (new_ifindex > 0) {
		nm_device_queue_recheck_available (device,
		                                   NM_DEVICE_STATE_REASON_PARENT_CHANGED,
		                                   NM_DEVICE_STATE_REASON_PARENT_CHANGED);
	}
}

static void
update_properties (NMDevice *device)
{
	NMDeviceMacsec *self;
	NMDeviceMacsecPrivate *priv;
	const NMPlatformLink *plink = NULL;
	const NMPlatformLnkMacsec *props = NULL;
	int ifindex;

	g_return_if_fail (NM_IS_DEVICE_MACSEC (device));
	self = NM_DEVICE_MACSEC (device);
	priv = NM_DEVICE_MACSEC_GET_PRIVATE (self);

	ifindex = nm_device_get_ifindex (device);
	g_return_if_fail (ifindex > 0);
	props = nm_platform_link_get_lnk_macsec (NM_PLATFORM_GET, ifindex, &plink);

	if (!props) {
		_LOGW (LOGD_PLATFORM, "could not get macsec properties");
		return;
	}

	g_object_freeze_notify ((GObject *) device);

	if (priv->props.parent_ifindex != props->parent_ifindex)
		nm_device_parent_set_ifindex (device, props->parent_ifindex);

#define CHECK_PROPERTY_CHANGED(field, prop) \
	if (props->field != priv->props.field) \
		_notify (self, prop)

	CHECK_PROPERTY_CHANGED (sci, PROP_SCI);
	CHECK_PROPERTY_CHANGED (cipher_suite, PROP_CIPHER_SUITE);
	CHECK_PROPERTY_CHANGED (window, PROP_WINDOW);
	CHECK_PROPERTY_CHANGED (icv_length, PROP_ICV_LENGTH);
	CHECK_PROPERTY_CHANGED (encoding_sa, PROP_ENCODING_SA);
	CHECK_PROPERTY_CHANGED (validation, PROP_VALIDATION);
	CHECK_PROPERTY_CHANGED (encrypt, PROP_ENCRYPT);
	CHECK_PROPERTY_CHANGED (protect, PROP_PROTECT);
	CHECK_PROPERTY_CHANGED (include_sci, PROP_INCLUDE_SCI);
	CHECK_PROPERTY_CHANGED (es, PROP_ES);
	CHECK_PROPERTY_CHANGED (scb, PROP_SCB);
	CHECK_PROPERTY_CHANGED (replay_protect, PROP_REPLAY_PROTECT);

	priv->props = *props;
	g_object_thaw_notify ((GObject *) device);
}

/******************************************************************/

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *dev)
{
	/* We assume MACsec interfaces always support carrier detect */
	return NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_IS_SOFTWARE;
}

/******************************************************************/

static gboolean
is_available (NMDevice *device, NMDeviceCheckDevAvailableFlags flags)
{
	if (!nm_device_parent_get_device (device))
		return FALSE;
	return NM_DEVICE_CLASS (nm_device_macsec_parent_class)->is_available (device, flags);
}

static void
link_changed (NMDevice *device,
              const NMPlatformLink *pllink)
{
	NM_DEVICE_CLASS (nm_device_macsec_parent_class)->link_changed (device, pllink);
	update_properties (device);
}

/******************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceMacsec *self = NM_DEVICE_MACSEC (object);
	NMDeviceMacsecPrivate *priv = NM_DEVICE_MACSEC_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_SCI:
		g_value_set_uint64 (value, priv->props.sci);
		break;
	case PROP_CIPHER_SUITE:
		g_value_set_uint64 (value, priv->props.cipher_suite);
		break;
	case PROP_ICV_LENGTH:
		g_value_set_uchar (value, priv->props.icv_length);
		break;
	case PROP_WINDOW:
		g_value_set_uint (value, priv->props.window);
		break;
	case PROP_ENCODING_SA:
		g_value_set_uchar (value, priv->props.encoding_sa);
		break;
	case PROP_ENCRYPT:
		g_value_set_boolean (value, priv->props.encrypt);
		break;
	case PROP_PROTECT:
		g_value_set_boolean (value, priv->props.protect);
		break;
	case PROP_INCLUDE_SCI:
		g_value_set_boolean (value, priv->props.include_sci);
		break;
	case PROP_ES:
		g_value_set_boolean (value, priv->props.es);
		break;
	case PROP_SCB:
		g_value_set_boolean (value, priv->props.scb);
		break;
	case PROP_REPLAY_PROTECT:
		g_value_set_boolean (value, priv->props.replay_protect);
		break;
	case PROP_VALIDATION:
		g_value_set_string (value,
		                    validation_mode_to_string (priv->props.validation));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_macsec_init (NMDeviceMacsec * self)
{
}

static void
nm_device_macsec_class_init (NMDeviceMacsecClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	NM_DEVICE_CLASS_DECLARE_TYPES (klass, NULL, NM_LINK_TYPE_MACSEC)

	object_class->get_property = get_property;

	parent_class->get_generic_capabilities = get_generic_capabilities;
	parent_class->is_available = is_available;
	parent_class->link_changed = link_changed;
	parent_class->parent_changed_notify = parent_changed_notify;

	obj_properties[PROP_SCI] =
	    g_param_spec_uint64 (NM_DEVICE_MACSEC_SCI, "", "",
	                         0, G_MAXUINT64, 0,
	                         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_CIPHER_SUITE] =
	    g_param_spec_uint64 (NM_DEVICE_MACSEC_CIPHER_SUITE, "", "",
	                         0, G_MAXUINT64, 0,
	                         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ICV_LENGTH] =
	    g_param_spec_uchar (NM_DEVICE_MACSEC_ICV_LENGTH, "", "",
	                        0, G_MAXUINT8, 0,
	                        G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_WINDOW] =
	    g_param_spec_uint (NM_DEVICE_MACSEC_WINDOW, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ENCODING_SA] =
	    g_param_spec_uchar (NM_DEVICE_MACSEC_ENCODING_SA, "", "",
	                        0, 3, 0,
	                        G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_VALIDATION] =
	    g_param_spec_string (NM_DEVICE_MACSEC_VALIDATION, "", "",
	                         NULL,
	                         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ENCRYPT] =
	    g_param_spec_boolean (NM_DEVICE_MACSEC_ENCRYPT, "", "",
	                          FALSE,
	                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_PROTECT] =
	    g_param_spec_boolean (NM_DEVICE_MACSEC_PROTECT, "", "",
	                          FALSE,
	                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_INCLUDE_SCI] =
	    g_param_spec_boolean (NM_DEVICE_MACSEC_INCLUDE_SCI, "", "",
	                          FALSE,
	                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ES] =
	    g_param_spec_boolean (NM_DEVICE_MACSEC_ES, "", "",
	                          FALSE,
	                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_SCB] =
	    g_param_spec_boolean (NM_DEVICE_MACSEC_SCB, "", "",
	                          FALSE,
	                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_REPLAY_PROTECT] =
	    g_param_spec_boolean (NM_DEVICE_MACSEC_REPLAY_PROTECT, "", "",
	                          FALSE,
	                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
	                                        NMDBUS_TYPE_DEVICE_MACSEC_SKELETON,
	                                        NULL);
}

/*************************************************************/

#define NM_TYPE_MACSEC_DEVICE_FACTORY (nm_macsec_device_factory_get_type ())
#define NM_MACSEC_DEVICE_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_MACSEC_DEVICE_FACTORY, NMMacsecDeviceFactory))

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               const NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_MACSEC,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_TYPE_DESC, "Macsec",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_MACSEC,
	                                  NM_DEVICE_LINK_TYPE, NM_LINK_TYPE_MACSEC,
	                                  NULL);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL (MACSEC, Macsec, macsec,
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES (NM_LINK_TYPE_MACSEC),
	factory_class->create_device = create_device;
)
