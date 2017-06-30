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
 * Copyright (C) 2007 - 2014 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_FACTORY_H__
#define __NETWORKMANAGER_DEVICE_FACTORY_H__

#include "nm-dbus-interface.h"
#include "nm-device.h"

/* WARNING: this file is private API between NetworkManager and its internal
 * device plugins.  Its API can change at any time and is not guaranteed to be
 * stable.  NM and device plugins are distributed together and this API is
 * not meant to enable third-party plugins.
 */

#define NM_TYPE_DEVICE_FACTORY            (nm_device_factory_get_type ())
#define NM_DEVICE_FACTORY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_FACTORY, NMDeviceFactory))
#define NM_DEVICE_FACTORY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_FACTORY, NMDeviceFactoryClass))
#define NM_IS_DEVICE_FACTORY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_FACTORY))
#define NM_IS_DEVICE_FACTORY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DEVICE_FACTORY))
#define NM_DEVICE_FACTORY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_FACTORY, NMDeviceFactoryClass))

#define NM_DEVICE_FACTORY_COMPONENT_ADDED "component-added"
#define NM_DEVICE_FACTORY_DEVICE_ADDED    "device-added"

typedef struct {
	GObject parent;
} NMDeviceFactory;

typedef struct {
	GObjectClass parent;

	/**
	 * get_supported_types:
	 * @factory: the #NMDeviceFactory
	 * @out_link_types: on return, a %NM_LINK_TYPE_NONE terminated
	 *  list of #NMLinkType that the plugin supports
	 * @out_setting_types: on return, a %NULL terminated list of
	 *  base-type #NMSetting names that the plugin can create devices for
	 *
	 * Returns the #NMLinkType and #NMSetting names that this plugin
	 * supports.  This function MUST be implemented.
	 */
	void (*get_supported_types) (NMDeviceFactory *factory,
	                             const NMLinkType **out_link_types,
	                             const char *const**out_setting_types);

	/**
	 * start:
	 * @factory: the #NMDeviceFactory
	 *
	 * Start the factory and discover any existing devices that the factory
	 * can manage.
	 */
	void (*start)                 (NMDeviceFactory *factory);

	/**
	 * match_connection:
	 * @connection: the #NMConnection
	 *
	 * Check if the factory supports the given connection.
	 */
	gboolean (*match_connection)  (NMDeviceFactory *factory, NMConnection *connection);

	/**
	 * get_connection_parent:
	 * @factory: the #NMDeviceFactory
	 * @connection: the #NMConnection to return the parent name for, if supported
	 *
	 * Given a connection, returns the parent interface name, parent connection
	 * UUID, or parent device permanent hardware address for @connection.
	 *
	 * Returns: the parent interface name, parent connection UUID, parent
	 *   device permenent hardware address, or %NULL
	 */
	const char * (*get_connection_parent) (NMDeviceFactory *factory,
	                                       NMConnection *connection);

	/**
	 * get_connection_iface:
	 * @factory: the #NMDeviceFactory
	 * @connection: the #NMConnection to return the interface name for
	 * @parent_iface: optional parent interface name for virtual devices
	 *
	 * Given a connection, returns the interface name that a device activating
	 * that connection would have.
	 *
	 * Returns: the interface name, or %NULL
	 */
	char * (*get_connection_iface) (NMDeviceFactory *factory,
	                                NMConnection *connection,
	                                const char *parent_iface);

	/**
	 * create_device:
	 * @factory: the #NMDeviceFactory
	 * @iface: the interface name of the device
	 * @plink: the #NMPlatformLink if backed by a kernel device
	 * @connection: the #NMConnection if not backed by a kernel device
	 * @out_ignore: on return, %TRUE if the link should be ignored
	 *
	 * The plugin should create a new unrealized device using the details given
	 * by @iface and @plink or @connection.  If both @iface and @plink are given,
	 * they are guaranteed to match.  If both @iface and @connection are given,
	 * @iface is guaranteed to be the interface name that @connection specifies.
	 *
	 * If the plugin cannot create a #NMDevice for the link and wants the
	 * core to ignore it, set @out_ignore to %TRUE and return %NULL.
	 *
	 * Returns: the new unrealized #NMDevice, or %NULL
	 */
	NMDevice * (*create_device)   (NMDeviceFactory *factory,
	                               const char *iface,
	                               const NMPlatformLink *plink,
	                               NMConnection *connection,
	                               gboolean *out_ignore);

	/* Signals */

	/**
	 * device_added:
	 * @factory: the #NMDeviceFactory
	 * @device: the new #NMDevice subclass
	 *
	 * The factory emits this signal if it finds a new device by itself.
	 */
	void       (*device_added)    (NMDeviceFactory *factory, NMDevice *device);

	/**
	 * component_added:
	 * @factory: the #NMDeviceFactory
	 * @component: a new component which existing devices may wish to claim
	 *
	 * The factory emits this signal when an appearance of some component
	 * native to it could be interesting to some of the already existing devices.
	 * The devices then indicate if they took interest in claiming the component.
	 *
	 * For example, the WWAN factory may indicate that a new modem is available,
	 * which an existing Bluetooth device may wish to claim. It emits a signal
	 * passing the modem instance around to see if any device claims it.
	 * If no device claims the component, the plugin is allowed to create a new
	 * #NMDevice instance for that component and emit the "device-added" signal.
	 *
	 * Returns: %TRUE if the component was claimed by a device, %FALSE if not
	 */
	gboolean   (*component_added) (NMDeviceFactory *factory, GObject *component);

} NMDeviceFactoryClass;

GType      nm_device_factory_get_type    (void);

/*****************************************************************************/

/**
 * nm_device_factory_create:
 * @error: an error if creation of the factory failed, or %NULL
 *
 * Creates a #GObject that implements the #NMDeviceFactory interface. This
 * function must not emit any signals or perform any actions that would cause
 * devices or components to be created immediately.  Instead these should be
 * deferred to the "start" interface method.
 *
 * Returns: the #GObject implementing #NMDeviceFactory or %NULL
 */
NMDeviceFactory *nm_device_factory_create (GError **error);

/* Should match nm_device_factory_create() */
typedef NMDeviceFactory * (*NMDeviceFactoryCreateFunc) (GError **error);

/*****************************************************************************/

const char *nm_device_factory_get_connection_parent (NMDeviceFactory *factory,
                                                     NMConnection *connection);

char *     nm_device_factory_get_connection_iface (NMDeviceFactory *factory,
                                                   NMConnection *connection,
                                                   const char *parent_iface,
                                                   GError **error);

void       nm_device_factory_start (NMDeviceFactory *factory);

NMDevice * nm_device_factory_create_device (NMDeviceFactory *factory,
                                            const char *iface,
                                            const NMPlatformLink *plink,
                                            NMConnection *connection,
                                            gboolean *out_ignore,
                                            GError **error);

/* For use by implementations */
gboolean   nm_device_factory_emit_component_added (NMDeviceFactory *factory,
                                                   GObject *component);

#define NM_DEVICE_FACTORY_DECLARE_LINK_TYPES(...) \
	{ static NMLinkType const _link_types_declared[] = { __VA_ARGS__, NM_LINK_TYPE_NONE }; _link_types = _link_types_declared; }
#define NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES(...) \
	{ static const char *const _setting_types_declared[] = { __VA_ARGS__, NULL }; _setting_types = _setting_types_declared; }

#define NM_DEVICE_FACTORY_DECLARE_TYPES(...) \
	static void \
	get_supported_types (NMDeviceFactory *factory, \
	                     const NMLinkType **out_link_types, \
	                     const char *const**out_setting_types) \
	{ \
		static NMLinkType const _link_types_null[1] = { NM_LINK_TYPE_NONE }; \
		static const char *const _setting_types_null[1] = { NULL }; \
		\
		const NMLinkType *_link_types = _link_types_null; \
		const char *const*_setting_types = _setting_types_null; \
		\
		{ __VA_ARGS__; } \
		\
		NM_SET_OUT (out_link_types, _link_types); \
		NM_SET_OUT (out_setting_types, _setting_types); \
	}

/**************************************************************************
 * INTERNAL DEVICE FACTORY FUNCTIONS - devices provided by plugins should
 * not use these functions.
 **************************************************************************/

#define NM_DEVICE_FACTORY_DEFINE_INTERNAL(upper, mixed, lower, st_code, dfi_code) \
	typedef struct { \
		NMDeviceFactory parent; \
	} NM##mixed##DeviceFactory; \
	typedef struct { \
		NMDeviceFactoryClass parent; \
	} NM##mixed##DeviceFactoryClass; \
 \
	GType nm_##lower##_device_factory_get_type (void); \
 \
	G_DEFINE_TYPE (NM##mixed##DeviceFactory, nm_##lower##_device_factory, NM_TYPE_DEVICE_FACTORY) \
 \
	NM_DEVICE_FACTORY_DECLARE_TYPES(st_code) \
 \
	static void \
	nm_##lower##_device_factory_init (NM##mixed##DeviceFactory *self) \
	{ \
	} \
 \
	static void \
	nm_##lower##_device_factory_class_init (NM##mixed##DeviceFactoryClass *klass) \
	{ \
		NMDeviceFactoryClass *factory_class = NM_DEVICE_FACTORY_CLASS (klass); \
		\
		factory_class->get_supported_types = get_supported_types; \
		dfi_code \
	}

/**************************************************************************
 * PRIVATE FACTORY FUNCTIONS - for factory consumers (eg, NMManager).
 **************************************************************************/

typedef void (*NMDeviceFactoryManagerFactoryFunc)    (NMDeviceFactory *factory,
                                                      gpointer user_data);

void              nm_device_factory_manager_load_factories (NMDeviceFactoryManagerFactoryFunc callback,
                                                            gpointer user_data);

NMDeviceFactory * nm_device_factory_manager_find_factory_for_link_type  (NMLinkType link_type);

NMDeviceFactory * nm_device_factory_manager_find_factory_for_connection (NMConnection *connection);

void              nm_device_factory_manager_for_each_factory (NMDeviceFactoryManagerFactoryFunc callback,
                                                              gpointer user_data);

#endif /* __NETWORKMANAGER_DEVICE_FACTORY_H__ */
