/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * Dan Williams <dcbw@redhat.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2012 Red Hat, Inc.
 */

#ifndef NM_SETTING_BRIDGE_PORT_H
#define NM_SETTING_BRIDGE_PORT_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_BRIDGE_PORT            (nm_setting_bridge_port_get_type ())
#define NM_SETTING_BRIDGE_PORT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_BRIDGE_PORT, NMSettingBridgePort))
#define NM_SETTING_BRIDGE_PORT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_BRIDGE_PORT, NMSettingBridgePortClass))
#define NM_IS_SETTING_BRIDGE_PORT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_BRIDGE_PORT))
#define NM_IS_SETTING_BRIDGE_PORT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_BRIDGE_PORT))
#define NM_SETTING_BRIDGE_PORT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_BRIDGE_PORT, NMSettingBridgePortClass))

#define NM_SETTING_BRIDGE_PORT_SETTING_NAME "bridge-port"

/**
 * NMSettingBridgePortError:
 * @NM_SETTING_BRIDGE_PORT_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_SETTING_BRIDGE_PORT_ERROR_INVALID_PROPERTY: the property was invalid
 * @NM_SETTING_BRIDGE_PORT_ERROR_MISSING_PROPERTY: the property was missing and
 * is required
 *
 * Since: 0.9.8
 */
typedef enum {
	NM_SETTING_BRIDGE_PORT_ERROR_UNKNOWN = 0,      /*< nick=UnknownError >*/
	NM_SETTING_BRIDGE_PORT_ERROR_INVALID_PROPERTY, /*< nick=InvalidProperty >*/
	NM_SETTING_BRIDGE_PORT_ERROR_MISSING_PROPERTY, /*< nick=MissingProperty >*/
} NMSettingBridgePortError;

#define NM_SETTING_BRIDGE_PORT_ERROR nm_setting_bridge_port_error_quark ()
GQuark nm_setting_bridge_port_error_quark (void);

#define NM_SETTING_BRIDGE_PORT_PRIORITY     "priority"
#define NM_SETTING_BRIDGE_PORT_PATH_COST    "path-cost"
#define NM_SETTING_BRIDGE_PORT_HAIRPIN_MODE "hairpin-mode"

typedef struct {
	NMSetting parent;
} NMSettingBridgePort;

typedef struct {
	NMSettingClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
} NMSettingBridgePortClass;

GType nm_setting_bridge_port_get_type (void);

NMSetting * nm_setting_bridge_port_new              (void);

guint16     nm_setting_bridge_port_get_priority     (NMSettingBridgePort *setting);

guint16     nm_setting_bridge_port_get_path_cost    (NMSettingBridgePort *setting);

gboolean    nm_setting_bridge_port_get_hairpin_mode (NMSettingBridgePort *setting);

G_END_DECLS

#endif /* NM_SETTING_BRIDGE_PORT_H */
