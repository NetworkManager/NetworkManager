/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * Thomas Graf <tgraf@redhat.com>
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
 * (C) Copyright 2011 Red Hat, Inc.
 */

#ifndef NM_SETTING_BOND_H
#define NM_SETTING_BOND_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_BOND            (nm_setting_bond_get_type ())
#define NM_SETTING_BOND(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_BOND, NMSettingBond))
#define NM_SETTING_BOND_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_BOND, NMSettingBondClass))
#define NM_IS_SETTING_BOND(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_BOND))
#define NM_IS_SETTING_BOND_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTING_BOND))
#define NM_SETTING_BOND_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_BOND, NMSettingBondClass))

#define NM_SETTING_BOND_SETTING_NAME "bond"

/**
 * NMSettingBondError:
 * @NM_SETTING_BOND_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_SETTING_BOND_ERROR_INVALID_PROPERTY: the property was invalid
 * @NM_SETTING_BOND_ERROR_MISSING_PROPERTY: the property was missing and is
 * required
 */
typedef enum {
	NM_SETTING_BOND_ERROR_UNKNOWN = 0,
	NM_SETTING_BOND_ERROR_INVALID_PROPERTY,
	NM_SETTING_BOND_ERROR_MISSING_PROPERTY,
} NMSettingBondError;

#define NM_TYPE_SETTING_BOND_ERROR (nm_setting_bond_error_get_type ()) 
GType nm_setting_bond_error_get_type (void);

#define NM_SETTING_BOND_ERROR nm_setting_bond_error_quark ()
GQuark nm_setting_bond_error_quark (void);

#define NM_SETTING_BOND_INTERFACE_NAME "interface-name"
#define NM_SETTING_BOND_MODE "mode"
#define NM_SETTING_BOND_MIIMON "miimon"
#define NM_SETTING_BOND_DOWNDELAY "down-delay"
#define NM_SETTING_BOND_UPDELAY "up-delay"
#define NM_SETTING_BOND_ARP_INTERVAL "arp-interval"
#define NM_SETTING_BOND_ARP_IP_TARGET "arp-ip-target"

typedef struct {
	NMSetting parent;
} NMSettingBond;

typedef struct {
	NMSettingClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
} NMSettingBondClass;

GType nm_setting_bond_get_type (void);

NMSetting *  nm_setting_bond_new                (void);
const char * nm_setting_bond_get_interface_name (NMSettingBond *setting);
const char * nm_setting_bond_get_mode           (NMSettingBond *setting);
guint32      nm_setting_bond_get_miimon         (NMSettingBond *setting);
guint32      nm_setting_bond_get_downdelay      (NMSettingBond *setting);
guint32      nm_setting_bond_get_updelay        (NMSettingBond *setting);
guint32      nm_setting_bond_get_arp_interval   (NMSettingBond *setting);
const char * nm_setting_bond_get_arp_ip_target  (NMSettingBond *setting);

G_END_DECLS

#endif /* NM_SETTING_BOND_H */
