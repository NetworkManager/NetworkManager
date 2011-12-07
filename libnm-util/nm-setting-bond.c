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

#include <string.h>
#include <ctype.h>
#include <dbus/dbus-glib.h>

#include "nm-setting-bond.h"
#include "nm-param-spec-specialized.h"
#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-dbus-glib-types.h"

/**
 * SECTION:nm-setting-bond
 * @short_description: Describes connection properties for bonds
 * @include: nm-setting-bond.h
 *
 * The #NMSettingBond object is a #NMSetting subclass that describes properties
 * necessary for bond connections.
 **/

/**
 * nm_setting_bond_error_quark:
 *
 * Registers an error quark for #NMSettingBond if necessary.
 *
 * Returns: the error quark used for #NMSettingBond errors.
 **/
GQuark
nm_setting_bond_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-bond-error-quark");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_setting_bond_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (NM_SETTING_BOND_ERROR_UNKNOWN, "UnknownError"),
			/* The specified property was invalid. */
			ENUM_ENTRY (NM_SETTING_BOND_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (NM_SETTING_BOND_ERROR_MISSING_PROPERTY, "MissingProperty"),
			{ 0, 0, 0 }
		};

		etype = g_enum_register_static ("NMSettingBondError", values);
	}

	return etype;
}


G_DEFINE_TYPE (NMSettingBond, nm_setting_bond, NM_TYPE_SETTING)

#define NM_SETTING_BOND_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_BOND, NMSettingBondPrivate))

typedef struct {
	char *	interface_name;
	char *	mode;
	guint32	miimon;
	guint32	downdelay;
	guint32	updelay;
	guint32	arp_interval;
	char *	arp_ip_target;
} NMSettingBondPrivate;

enum {
	PROP_0,
	PROP_INTERFACE_NAME,
	PROP_MODE,
	PROP_MIIMON,
	PROP_DOWNDELAY,
	PROP_UPDELAY,
	PROP_ARP_INTERVAL,
	PROP_ARP_IP_TARGET,
	LAST_PROP
};

/**
 * nm_setting_bond_new:
 *
 * Creates a new #NMSettingBond object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingBond object
 **/
NMSetting *
nm_setting_bond_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_BOND, NULL);
}

/**
 * nm_setting_bond_get_interface_name
 * @setting: the #NMSettingBond
 *
 * Returns: the #NMSettingBond:interface-name property of the setting
 **/
const char *
nm_setting_bond_get_interface_name (NMSettingBond *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), 0);

	return NM_SETTING_BOND_GET_PRIVATE (setting)->interface_name;
}

/**
 * nm_setting_bond_get_mode:
 * @setting: the #NMSettingBond
 *
 * Returns: the #NMSettingBond:mode property of the setting
 **/
const char *
nm_setting_bond_get_mode (NMSettingBond *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), 0);

	return NM_SETTING_BOND_GET_PRIVATE (setting)->mode;
}

/**
 * nm_setting_bond_get_miimon:
 * @setting: the #NMSettingBond
 *
 * Returns: the #NMSettingBond:miimon property of the setting
 **/
guint32
nm_setting_bond_get_miimon (NMSettingBond *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), 0);

	return NM_SETTING_BOND_GET_PRIVATE (setting)->miimon;
}

/**
 * nm_setting_bond_get_downdelay:
 * @setting: the #NMSettingBond
 *
 * Returns: the #NMSettingBond:downdelay property of the setting
 **/
guint32
nm_setting_bond_get_downdelay (NMSettingBond *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), 0);

	return NM_SETTING_BOND_GET_PRIVATE (setting)->downdelay;
}

/**
 * nm_setting_bond_get_updelay:
 * @setting: the #NMSettingBond
 *
 * Returns: the #NMSettingBond:updelay property of the setting
 **/
guint32
nm_setting_bond_get_updelay (NMSettingBond *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), 0);

	return NM_SETTING_BOND_GET_PRIVATE (setting)->updelay;
}

/**
 * nm_setting_bond_get_arp_interval:
 * @setting: the #NMSettingBond
 *
 * Returns: the #NMSettingBond:arp_interval property of the setting
 **/
guint32
nm_setting_bond_get_arp_interval (NMSettingBond *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), 0);

	return NM_SETTING_BOND_GET_PRIVATE (setting)->arp_interval;
}

/**
 * nm_setting_bond_get_arp_ip_target:
 * @setting: the #NMSettingBond
 *
 * Returns: the #NMSettingBond:arp_ip_target property of the setting
 **/
const char *
nm_setting_bond_get_arp_ip_target (NMSettingBond *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), 0);

	return NM_SETTING_BOND_GET_PRIVATE (setting)->arp_ip_target;
}

/*
 * This function is a 1:1 copy of the kernel's
 * dev_valid_name() in net/core/dev.c
 */
static gboolean
dev_valid_name(const char *name)
{
	if (*name == '\0')
		return FALSE;

	if (strlen (name) >= 16)
		return FALSE;

	if (!strcmp (name, ".") || !strcmp (name, ".."))
		return FALSE;

	while (*name) {
		if (*name == '/' || isspace (*name))
			return FALSE;
		name++;
	}

	return TRUE;
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingBondPrivate *priv = NM_SETTING_BOND_GET_PRIVATE (setting);
	const char *valid_modes[] = { "balance-rr",
	                              "active-backup",
	                              "balance-xor",
	                              "broadcast",
	                              "802.3ad",
	                              "balance-tlb",
	                              "balance-alb",
	                              NULL };

	if (!priv->interface_name || !strlen(priv->interface_name)) {
		g_set_error (error,
		             NM_SETTING_BOND_ERROR,
		             NM_SETTING_BOND_ERROR_MISSING_PROPERTY,
		             NM_SETTING_BOND_INTERFACE_NAME);
		return FALSE;
	}

	if (!dev_valid_name (priv->interface_name)) {
		g_set_error (error,
		             NM_SETTING_BOND_ERROR,
		             NM_SETTING_BOND_ERROR_INVALID_PROPERTY,
		             NM_SETTING_BOND_INTERFACE_NAME);
		return FALSE;
	}

	if (priv->mode && !_nm_utils_string_in_list (priv->mode, valid_modes)) {
		g_set_error (error,
		             NM_SETTING_BOND_ERROR,
		             NM_SETTING_BOND_ERROR_INVALID_PROPERTY,
		             NM_SETTING_BOND_MODE);
		return FALSE;
	}

	/* XXX: Validate arp-ip-target */

	return TRUE;
}

static const char *
get_virtual_iface_name (NMSetting *setting)
{
	NMSettingBond *self = NM_SETTING_BOND (setting);

	return nm_setting_bond_get_interface_name (self);
}

static void
nm_setting_bond_init (NMSettingBond *setting)
{
	g_object_set (setting, NM_SETTING_NAME, NM_SETTING_BOND_SETTING_NAME,
	              NM_SETTING_BOND_MIIMON, 100, /* default: miimon=100 */
	              NULL);
}

static void
finalize (GObject *object)
{
	NMSettingBondPrivate *priv = NM_SETTING_BOND_GET_PRIVATE (object);

	g_free (priv->interface_name);
	g_free (priv->mode);
	g_free (priv->arp_ip_target);

	G_OBJECT_CLASS (nm_setting_bond_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingBondPrivate *priv = NM_SETTING_BOND_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_INTERFACE_NAME:
		priv->interface_name = g_value_dup_string (value);
		break;
	case PROP_MODE:
		priv->mode = g_value_dup_string (value);
		break;
	case PROP_MIIMON:
		priv->miimon = g_value_get_uint (value);
		break;
	case PROP_DOWNDELAY:
		priv->downdelay = g_value_get_uint (value);
		break;
	case PROP_UPDELAY:
		priv->updelay = g_value_get_uint (value);
		break;
	case PROP_ARP_INTERVAL:
		priv->arp_interval = g_value_get_uint (value);
		break;
	case PROP_ARP_IP_TARGET:
		g_free (priv->arp_ip_target);
		priv->arp_ip_target = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingBond *setting = NM_SETTING_BOND (object);

	switch (prop_id) {
	case PROP_INTERFACE_NAME:
		g_value_set_string (value, nm_setting_bond_get_interface_name (setting));
		break;
	case PROP_MODE:
		g_value_set_string (value, nm_setting_bond_get_mode (setting));
		break;
	case PROP_MIIMON:
		g_value_set_uint (value, nm_setting_bond_get_miimon (setting));
		break;
	case PROP_DOWNDELAY:
		g_value_set_uint (value, nm_setting_bond_get_downdelay (setting));
		break;
	case PROP_UPDELAY:
		g_value_set_uint (value, nm_setting_bond_get_updelay (setting));
		break;
	case PROP_ARP_INTERVAL:
		g_value_set_uint (value, nm_setting_bond_get_arp_interval (setting));
		break;
	case PROP_ARP_IP_TARGET:
		g_value_set_string (value, nm_setting_bond_get_arp_ip_target (setting));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_bond_class_init (NMSettingBondClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingBondPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;
	parent_class->get_virtual_iface_name = get_virtual_iface_name;

	/* Properties */
	/**
	 * NMSettingBond:interface-name:
	 *
	 * Name of virtual kernel interface
	 **/
	g_object_class_install_property
		(object_class, PROP_INTERFACE_NAME,
		 g_param_spec_string (NM_SETTING_BOND_INTERFACE_NAME,
		                      "InterfaceName",
		                      "The name of the virtual in-kernel bonding nework interface",
		                      NULL,
		                      G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingBond:mode:
	 *
	 * Bonding policy
	 **/
	g_object_class_install_property
		(object_class, PROP_MODE,
		 g_param_spec_string (NM_SETTING_BOND_MODE,
		                      "Mode",
		                      "The bonding policy to use. One of 'balance-rr' (default), "
		                      "'active-backup', 'balance-xor', 'broadcast', '802.3ad', "
		                      "'balance-tlb', 'balance-alb'.",
		                      NULL,
		                      G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingBond:miimon:
	 *
	 * Specifies the MII link monitoring frequency in milliseconds.
	 * This determines how often the link state of each slave is
	 * inspected for link failures.  A value of zero disables MII
	 * link monitoring.  A value of 100 is a good starting point.
	 * The use_carrier option, below, affects how the link state is
	 * determined.
	 **/
	g_object_class_install_property
		(object_class, PROP_MIIMON,
		 g_param_spec_uint (NM_SETTING_BOND_MIIMON,
		                    "MiiMon",
		                    "Specifies the MII link monitoring frequency in milliseconds. "
		                    "This determines how often the link state of each slave is "
		                    "inspected for link failures.  A value of zero disables MII "
		                    "link monitoring.  A value of 100 is a good starting point. "
		                    "The use_carrier option, below, affects how the link state is "
		                    "determined. The default value is 0.",
		                    0, G_MAXUINT32, 100,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingBond:downdelay:
	 *
	 * Specifies the time, in milliseconds, to wait before disabling
	 * a slave after a link failure has been detected.  This option
	 * is only valid for the miimon link monitor.  The downdelay
	 * value should be a multiple of the miimon value; if not, it
	 * will be rounded down to the nearest multiple.  The default
	 * value is 0.
	 **/
	g_object_class_install_property
		(object_class, PROP_DOWNDELAY,
		 g_param_spec_uint (NM_SETTING_BOND_DOWNDELAY,
		                    "DownDelay",
		                    "Specifies the time, in milliseconds, to wait before disabling "
		                    "a slave after a link failure has been detected.  This option "
		                    "is only valid for the miimon link monitor.  The downdelay "
		                    "value should be a multiple of the miimon value; if not, it "
		                    "will be rounded down to the nearest multiple.  The default "
		                    "value is 0.",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingBond:updelay:
	 *
	 * Specifies the time, in milliseconds, to wait before enabling a
	 * slave after a link recovery has been detected.  This option is
	 * only valid for the miimon link monitor.  The updelay value
	 * should be a multiple of the miimon value; if not, it will be
	 * rounded down to the nearest multiple.  The default value is 0.
	 **/
	g_object_class_install_property
		(object_class, PROP_UPDELAY,
		 g_param_spec_uint (NM_SETTING_BOND_UPDELAY,
		                    "UpDelay",
		                    "Specifies the time, in milliseconds, to wait before enabling a "
		                    "slave after a link recovery has been detected.  This option is "
		                    "only valid for the miimon link monitor.  The updelay value "
		                    "should be a multiple of the miimon value; if not, it will be "
		                    "rounded down to the nearest multiple.  The default value is 0.",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingBond:arp_interval:
	 *
	 * Specifies the ARP link monitoring frequency in milliseconds.
	 *
	 * The ARP monitor works by periodically checking the slave
	 * devices to determine whether they have sent or received
	 * traffic recently (the precise criteria depends upon the
	 * bonding mode, and the state of the slave).  Regular traffic is
	 * generated via ARP probes issued for the addresses specified by
	 * the arp-ip-target option.
	 *
	 * This behavior can be modified by the arp-validate option.
	 *
	 * If ARP monitoring is used in an etherchannel compatible mode
	 * (modes 0 and 2), the switch should be configured in a mode
	 * that evenly distributes packets across all links. If the
	 * switch is configured to distribute the packets in an XOR
	 * fashion, all replies from the ARP targets will be received on
	 * the same link which could cause the other team members to
	 * fail.  ARP monitoring should not be used in conjunction with
	 * miimon.  A value of 0 disables ARP monitoring.  The default
	 * value is 0.
	 **/
	g_object_class_install_property
		(object_class, PROP_ARP_INTERVAL,
		 g_param_spec_uint (NM_SETTING_BOND_ARP_INTERVAL,
		                    "ArpInterval",
		                    "Specifies the ARP link monitoring frequency in milliseconds. "
		                    "The ARP monitor works by periodically checking the slave "
		                    "devices to determine whether they have sent or received "
		                    "traffic recently (the precise criteria depends upon the "
		                    "bonding mode, and the state of the slave).  Regular traffic is "
		                    "generated via ARP probes issued for the addresses specified by "
		                    "the arp-ip-target option. "
		                    "This behavior can be modified by the arp-validate option. "
		                    "If ARP monitoring is used in an etherchannel compatible mode "
		                    "(modes 0 and 2), the switch should be configured in a mode "
		                    "that evenly distributes packets across all links. If the "
		                    "switch is configured to distribute the packets in an XOR "
		                    "fashion, all replies from the ARP targets will be received on "
		                    "the same link which could cause the other team members to "
		                    "fail.  ARP monitoring should not be used in conjunction with "
		                    "miimon.  A value of 0 disables ARP monitoring.  The default "
		                    "value is 0.",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingBond:arp_ip_target:
	 *
	 * Specifies the IP addresses to use as ARP monitoring peers when
	 * arp_interval is > 0.  These are the targets of the ARP request
	 * sent to determine the health of the link to the targets.
	 * Specify these values in ddd.ddd.ddd.ddd format.  Multiple IP
	 * addresses must be separated by a comma.  At least one IP
	 * address must be given for ARP monitoring to function.  The
	 * maximum number of targets that can be specified is 16.  The
	 * default value is no IP addresses.
	 **/
	g_object_class_install_property
		(object_class, PROP_ARP_IP_TARGET,
		 g_param_spec_string (NM_SETTING_BOND_ARP_IP_TARGET,
		                      "ArpIpTarget",
		                      "Specifies the IP addresses to use as ARP monitoring peers when "
		                      "arp-interval is > 0.  These are the targets of the ARP request "
		                      "sent to determine the health of the link to the targets. "
		                      "Specify these values in ddd.ddd.ddd.ddd format.  Multiple IP "
		                      "addresses must be separated by a comma.  At least one IP "
		                      "address must be given for ARP monitoring to function.  The "
		                      "maximum number of targets that can be specified is 16.  The "
		                      "default value is no IP addresses.",
		                      NULL,
		                      G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));
}
