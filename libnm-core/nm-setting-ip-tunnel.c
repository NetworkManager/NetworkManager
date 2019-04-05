/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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
 * Copyright 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-setting-ip-tunnel.h"

#include "nm-setting-private.h"
#include "nm-utils.h"

/**
 * SECTION:nm-setting-ip-tunnel
 * @short_description: Describes connection properties for IP tunnel devices
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_PARENT,
	PROP_MODE,
	PROP_LOCAL,
	PROP_REMOTE,
	PROP_TTL,
	PROP_TOS,
	PROP_PATH_MTU_DISCOVERY,
	PROP_INPUT_KEY,
	PROP_OUTPUT_KEY,
	PROP_ENCAPSULATION_LIMIT,
	PROP_FLOW_LABEL,
	PROP_MTU,
	PROP_FLAGS,
);

typedef struct {
	char *parent;
	NMIPTunnelMode mode;
	char *local;
	char *remote;
	guint ttl;
	guint tos;
	gboolean path_mtu_discovery;
	char *input_key;
	char *output_key;
	guint encapsulation_limit;
	guint flow_label;
	guint32 mtu;
	guint32 flags;
} NMSettingIPTunnelPrivate;

G_DEFINE_TYPE (NMSettingIPTunnel, nm_setting_ip_tunnel, NM_TYPE_SETTING)

#define NM_SETTING_IP_TUNNEL_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_IP_TUNNEL, NMSettingIPTunnelPrivate))

/*****************************************************************************/

/**
 * nm_setting_ip_tunnel_get_parent:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:parent property of the setting
 *
 * Returns: the parent device
 *
 * Since: 1.2
 **/
const char *
nm_setting_ip_tunnel_get_parent (NMSettingIPTunnel *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_TUNNEL (setting), NULL);
	return NM_SETTING_IP_TUNNEL_GET_PRIVATE (setting)->parent;
}

/**
 * nm_setting_ip_tunnel_get_mode:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:mode property of the setting.
 *
 * Returns: the tunnel mode
 *
 * Since: 1.2
 **/
NMIPTunnelMode
nm_setting_ip_tunnel_get_mode (NMSettingIPTunnel *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_TUNNEL (setting), 0);

	return NM_SETTING_IP_TUNNEL_GET_PRIVATE (setting)->mode;
}

/**
 * nm_setting_ip_tunnel_get_local:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:local property of the setting.
 *
 * Returns: the local endpoint
 *
 * Since: 1.2
 **/
const char *
nm_setting_ip_tunnel_get_local (NMSettingIPTunnel *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_TUNNEL (setting), NULL);

	return NM_SETTING_IP_TUNNEL_GET_PRIVATE (setting)->local;
}

/**
 * nm_setting_ip_tunnel_get_remote:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:remote property of the setting.
 *
 * Returns: the remote endpoint
 *
 * Since: 1.2
 **/
const char *
nm_setting_ip_tunnel_get_remote (NMSettingIPTunnel *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_TUNNEL (setting), NULL);

	return NM_SETTING_IP_TUNNEL_GET_PRIVATE (setting)->remote;
}

/**
 * nm_setting_ip_tunnel_get_ttl:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:ttl property of the setting.
 *
 * Returns: the Time-to-live value
 *
 * Since: 1.2
 **/

guint
nm_setting_ip_tunnel_get_ttl (NMSettingIPTunnel *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_TUNNEL (setting), 0);

	return NM_SETTING_IP_TUNNEL_GET_PRIVATE (setting)->ttl;
}

/**
 * nm_setting_ip_tunnel_get_tos:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:tos property of the setting.
 *
 * Returns: the TOS value
 *
 * Since: 1.2
 **/
guint
nm_setting_ip_tunnel_get_tos (NMSettingIPTunnel *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_TUNNEL (setting), 0);

	return NM_SETTING_IP_TUNNEL_GET_PRIVATE (setting)->tos;
}

/**
 * nm_setting_ip_tunnel_get_path_mtu_discovery:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:path-mtu-discovery property of the setting.
 *
 * Returns: whether path MTU discovery is enabled
 *
 * Since: 1.2
 **/
gboolean
nm_setting_ip_tunnel_get_path_mtu_discovery (NMSettingIPTunnel *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_TUNNEL (setting), TRUE);

	return NM_SETTING_IP_TUNNEL_GET_PRIVATE (setting)->path_mtu_discovery;
}

/**
 * nm_setting_ip_tunnel_get_input_key:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:input-key property of the setting.
 *
 * Returns: the input key
 *
 * Since: 1.2
 **/
const char *
nm_setting_ip_tunnel_get_input_key (NMSettingIPTunnel *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_TUNNEL (setting), NULL);

	return NM_SETTING_IP_TUNNEL_GET_PRIVATE (setting)->input_key;
}

/**
 * nm_setting_ip_tunnel_get_output_key:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:output-key property of the setting.
 *
 * Returns: the output key
 *
 * Since: 1.2
 **/
const char *
nm_setting_ip_tunnel_get_output_key (NMSettingIPTunnel *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_TUNNEL (setting), NULL);

	return NM_SETTING_IP_TUNNEL_GET_PRIVATE (setting)->output_key;
}

/**
 * nm_setting_ip_tunnel_get_encapsulation_limit:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:encapsulation-limit property of the setting.
 *
 * Returns: the encapsulation limit value
 *
 * Since: 1.2
 **/
guint
nm_setting_ip_tunnel_get_encapsulation_limit (NMSettingIPTunnel *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_TUNNEL (setting), 0);

	return NM_SETTING_IP_TUNNEL_GET_PRIVATE (setting)->encapsulation_limit;
}

/**
 * nm_setting_ip_tunnel_get_flow_label:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:flow-label property of the setting.
 *
 * Returns: the flow label value
 *
 * Since: 1.2
 **/
guint
nm_setting_ip_tunnel_get_flow_label (NMSettingIPTunnel *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_TUNNEL (setting), 0);

	return NM_SETTING_IP_TUNNEL_GET_PRIVATE (setting)->flow_label;
}

/**
 * nm_setting_ip_tunnel_get_mtu:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:mtu property of the setting.
 *
 * Returns: the MTU
 *
 * Since: 1.2
 **/
guint
nm_setting_ip_tunnel_get_mtu (NMSettingIPTunnel *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_TUNNEL (setting), 0);

	return NM_SETTING_IP_TUNNEL_GET_PRIVATE (setting)->mtu;
}

/*
 * nm_setting_ip_tunnel_get_flags:
 * @setting: the #NMSettingIPTunnel
 *
 * Returns the #NMSettingIPTunnel:flags property of the setting.
 *
 * Returns: the tunnel flags
 *
 * Since: 1.12
 **/
NMIPTunnelFlags
nm_setting_ip_tunnel_get_flags (NMSettingIPTunnel *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_TUNNEL (setting), NM_IP_TUNNEL_FLAG_NONE);

	return NM_SETTING_IP_TUNNEL_GET_PRIVATE (setting)->flags;
}

/*****************************************************************************/

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingIPTunnelPrivate *priv = NM_SETTING_IP_TUNNEL_GET_PRIVATE (setting);
	int family = AF_UNSPEC;
	guint32 flags;

	switch (priv->mode) {
	case NM_IP_TUNNEL_MODE_IPIP:
	case NM_IP_TUNNEL_MODE_SIT:
	case NM_IP_TUNNEL_MODE_ISATAP:
	case NM_IP_TUNNEL_MODE_GRE:
	case NM_IP_TUNNEL_MODE_VTI:
	case NM_IP_TUNNEL_MODE_GRETAP:
		family = AF_INET;
		break;
	case NM_IP_TUNNEL_MODE_IP6IP6:
	case NM_IP_TUNNEL_MODE_IPIP6:
	case NM_IP_TUNNEL_MODE_IP6GRE:
	case NM_IP_TUNNEL_MODE_VTI6:
	case NM_IP_TUNNEL_MODE_IP6GRETAP:
		family = AF_INET6;
		break;
	case NM_IP_TUNNEL_MODE_UNKNOWN:
		break;
	}

	if (family == AF_UNSPEC) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%d' is not a valid tunnel mode"),
		             (int) priv->mode);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP_TUNNEL_SETTING_NAME, NM_SETTING_IP_TUNNEL_MODE);
		return FALSE;
	}

	if (   priv->parent
	    && !nm_utils_is_valid_iface_name (priv->parent, NULL)
	    && !nm_utils_is_uuid (priv->parent)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is neither an UUID nor an interface name"),
		             priv->parent);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP_TUNNEL_SETTING_NAME,
		                NM_SETTING_IP_TUNNEL_PARENT);
		return FALSE;
	}

	if (priv->local && !nm_utils_ipaddr_valid (family, priv->local)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid IPv%c address"),
		             priv->local,
		             family == AF_INET ? '4' : '6');
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP_TUNNEL_SETTING_NAME, NM_SETTING_IP_TUNNEL_LOCAL);
		return FALSE;
	}

	if (!priv->remote) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP_TUNNEL_SETTING_NAME, NM_SETTING_IP_TUNNEL_REMOTE);
		return FALSE;
	}

	if (!nm_utils_ipaddr_valid (family, priv->remote)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid IPv%c address"),
		             priv->remote,
		             family == AF_INET ? '4' : '6');
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP_TUNNEL_SETTING_NAME, NM_SETTING_IP_TUNNEL_REMOTE);
		return FALSE;
	}

	if (   (priv->input_key && priv->input_key[0])
	    || (priv->output_key && priv->output_key[0])) {
		if (!NM_IN_SET (priv->mode,
		                NM_IP_TUNNEL_MODE_GRE,
		                NM_IP_TUNNEL_MODE_GRETAP,
		                NM_IP_TUNNEL_MODE_IP6GRE,
		                NM_IP_TUNNEL_MODE_IP6GRETAP)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("tunnel keys can only be specified for GRE tunnels"));
			return FALSE;
		}
	}

	if (priv->input_key && priv->input_key[0]) {
		gint64 val;

		val = _nm_utils_ascii_str_to_int64 (priv->input_key, 10, 0, G_MAXUINT32, -1);
		if (val == -1) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("'%s' is not a valid tunnel key"),
			             priv->input_key);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP_TUNNEL_SETTING_NAME,
			                NM_SETTING_IP_TUNNEL_INPUT_KEY);
			return FALSE;
		}
	}

	if (priv->output_key && priv->output_key[0]) {
		gint64 val;

		val = _nm_utils_ascii_str_to_int64 (priv->output_key, 10, 0, G_MAXUINT32, -1);
		if (val == -1) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("'%s' is not a valid tunnel key"),
			             priv->output_key);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP_TUNNEL_SETTING_NAME,
			                NM_SETTING_IP_TUNNEL_OUTPUT_KEY);
			return FALSE;
		}
	}

	if (!priv->path_mtu_discovery && priv->ttl != 0) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("a fixed TTL is allowed only when path MTU discovery is enabled"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP_TUNNEL_SETTING_NAME,
		                NM_SETTING_IP_TUNNEL_TTL);
		return FALSE;
	}

	flags = priv->flags;
	if (NM_IN_SET (priv->mode, NM_IP_TUNNEL_MODE_IPIP6, NM_IP_TUNNEL_MODE_IP6IP6))
		flags &= (guint32) (~_NM_IP_TUNNEL_FLAG_ALL_IP6TNL);
	if (flags) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("some flags are invalid for the select mode: %s"),
		             nm_utils_enum_to_str (nm_ip_tunnel_flags_get_type (), flags));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP_TUNNEL_SETTING_NAME,
		                NM_SETTING_IP_TUNNEL_FLAGS);
		return FALSE;
	}

	if (   nm_connection_get_setting_wired (connection)
	    && !NM_IN_SET (priv->mode,
	                   NM_IP_TUNNEL_MODE_GRETAP,
	                   NM_IP_TUNNEL_MODE_IP6GRETAP)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("wired setting not allowed for mode %s"),
		             nm_utils_enum_to_str (nm_ip_tunnel_mode_get_type (), priv->mode));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_IP_TUNNEL_SETTING_NAME,
		                NM_SETTING_IP_TUNNEL_MODE);
		return NM_SETTING_VERIFY_NORMALIZABLE_ERROR;
	}

	return TRUE;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingIPTunnel *setting = NM_SETTING_IP_TUNNEL (object);
	NMSettingIPTunnelPrivate *priv = NM_SETTING_IP_TUNNEL_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_PARENT:
		g_value_set_string (value, priv->parent);
		break;
	case PROP_MODE:
		g_value_set_uint (value, priv->mode);
		break;
	case PROP_LOCAL:
		g_value_set_string (value, priv->local);
		break;
	case PROP_REMOTE:
		g_value_set_string (value, priv->remote);
		break;
	case PROP_TTL:
		g_value_set_uint (value, priv->ttl);
		break;
	case PROP_TOS:
		g_value_set_uint (value, priv->tos);
		break;
	case PROP_PATH_MTU_DISCOVERY:
		g_value_set_boolean (value, priv->path_mtu_discovery);
		break;
	case PROP_INPUT_KEY:
		g_value_set_string (value, priv->input_key);
		break;
	case PROP_OUTPUT_KEY:
		g_value_set_string (value, priv->output_key);
		break;
	case PROP_ENCAPSULATION_LIMIT:
		g_value_set_uint (value, priv->encapsulation_limit);
		break;
	case PROP_FLOW_LABEL:
		g_value_set_uint (value, priv->flow_label);
		break;
	case PROP_MTU:
		g_value_set_uint (value, priv->mtu);
		break;
	case PROP_FLAGS:
		g_value_set_uint (value, priv->flags);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingIPTunnel *setting = NM_SETTING_IP_TUNNEL (object);
	NMSettingIPTunnelPrivate *priv = NM_SETTING_IP_TUNNEL_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_PARENT:
		g_free (priv->parent);
		priv->parent = g_value_dup_string (value);
		break;
	case PROP_MODE:
		priv->mode = g_value_get_uint (value);
		break;
	case PROP_LOCAL:
		g_free (priv->local);
		priv->local = g_value_dup_string (value);
		break;
	case PROP_REMOTE:
		g_free (priv->remote);
		priv->remote = g_value_dup_string (value);
		break;
	case PROP_TTL:
		priv->ttl = g_value_get_uint (value);
		break;
	case PROP_TOS:
		priv->tos = g_value_get_uint (value);
		break;
	case PROP_PATH_MTU_DISCOVERY:
		priv->path_mtu_discovery = g_value_get_boolean (value);
		break;
	case PROP_INPUT_KEY:
		g_free (priv->input_key);
		priv->input_key = g_value_dup_string (value);
		break;
	case PROP_OUTPUT_KEY:
		g_free (priv->output_key);
		priv->output_key = g_value_dup_string (value);
		break;
	case PROP_ENCAPSULATION_LIMIT:
		priv->encapsulation_limit = g_value_get_uint (value);
		break;
	case PROP_FLOW_LABEL:
		priv->flow_label = g_value_get_uint (value);
		break;
	case PROP_MTU:
		priv->mtu = g_value_get_uint (value);
		break;
	case PROP_FLAGS:
		priv->flags = g_value_get_uint (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_ip_tunnel_init (NMSettingIPTunnel *setting)
{
}

/**
 * nm_setting_ip_tunnel_new:
 *
 * Creates a new #NMSettingIPTunnel object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingIPTunnel object
 *
 * Since: 1.2
 **/
NMSetting *
nm_setting_ip_tunnel_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_IP_TUNNEL, NULL);
}

static void
finalize (GObject *object)
{
	NMSettingIPTunnel *setting = NM_SETTING_IP_TUNNEL (object);
	NMSettingIPTunnelPrivate *priv = NM_SETTING_IP_TUNNEL_GET_PRIVATE (setting);

	g_free (priv->parent);
	g_free (priv->local);
	g_free (priv->remote);
	g_free (priv->input_key);
	g_free (priv->output_key);

	G_OBJECT_CLASS (nm_setting_ip_tunnel_parent_class)->finalize (object);
}

static void
nm_setting_ip_tunnel_class_init (NMSettingIPTunnelClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMSettingIPTunnelPrivate));

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize     = finalize;

	setting_class->verify = verify;

	/**
	 * NMSettingIPTunnel:parent:
	 *
	 * If given, specifies the parent interface name or parent connection UUID
	 * the new device will be bound to so that tunneled packets will only be
	 * routed via that interface.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_PARENT] =
	    g_param_spec_string (NM_SETTING_IP_TUNNEL_PARENT, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_INFERRABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPTunnel:mode:
	 *
	 * The tunneling mode, for example %NM_IP_TUNNEL_MODE_IPIP or
	 * %NM_IP_TUNNEL_MODE_GRE.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_MODE] =
	    g_param_spec_uint (NM_SETTING_IP_TUNNEL_MODE, "", "",
	                       0, G_MAXUINT, 0,
	                       G_PARAM_READWRITE |
	                       NM_SETTING_PARAM_INFERRABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPTunnel:local:
	 *
	 * The local endpoint of the tunnel; the value can be empty, otherwise it
	 * must contain an IPv4 or IPv6 address.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_LOCAL] =
	    g_param_spec_string (NM_SETTING_IP_TUNNEL_LOCAL, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_INFERRABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPTunnel:remote:
	 *
	 * The remote endpoint of the tunnel; the value must contain an IPv4 or IPv6
	 * address.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_REMOTE] =
	    g_param_spec_string (NM_SETTING_IP_TUNNEL_REMOTE, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_INFERRABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPTunnel:ttl
	 *
	 * The TTL to assign to tunneled packets. 0 is a special value meaning that
	 * packets inherit the TTL value.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_TTL] =
	    g_param_spec_uint (NM_SETTING_IP_TUNNEL_TTL, "", "",
	                       0, 255, 0,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       NM_SETTING_PARAM_INFERRABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPTunnel:tos
	 *
	 * The type of service (IPv4) or traffic class (IPv6) field to be set on
	 * tunneled packets.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_TOS] =
	    g_param_spec_uint (NM_SETTING_IP_TUNNEL_TOS, "", "",
	                       0, 255, 0,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       NM_SETTING_PARAM_INFERRABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPTunnel:path-mtu-discovery
	 *
	 * Whether to enable Path MTU Discovery on this tunnel.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_PATH_MTU_DISCOVERY] =
	    g_param_spec_boolean (NM_SETTING_IP_TUNNEL_PATH_MTU_DISCOVERY, "", "",
	                          TRUE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT |
	                          NM_SETTING_PARAM_INFERRABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPTunnel:input-key:
	 *
	 * The key used for tunnel input packets; the property is valid only for
	 * certain tunnel modes (GRE, IP6GRE). If empty, no key is used.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_INPUT_KEY] =
	    g_param_spec_string (NM_SETTING_IP_TUNNEL_INPUT_KEY, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_INFERRABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPTunnel:output-key:
	 *
	 * The key used for tunnel output packets; the property is valid only for
	 * certain tunnel modes (GRE, IP6GRE). If empty, no key is used.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_OUTPUT_KEY] =
	    g_param_spec_string (NM_SETTING_IP_TUNNEL_OUTPUT_KEY, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_INFERRABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPTunnel:encapsulation-limit:
	 *
	 * How many additional levels of encapsulation are permitted to be prepended
	 * to packets. This property applies only to IPv6 tunnels.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_ENCAPSULATION_LIMIT] =
	    g_param_spec_uint (NM_SETTING_IP_TUNNEL_ENCAPSULATION_LIMIT, "", "",
	                       0, 255, 0,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       NM_SETTING_PARAM_INFERRABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPTunnel:flow-label:
	 *
	 * The flow label to assign to tunnel packets. This property applies only to
	 * IPv6 tunnels.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_FLOW_LABEL] =
	    g_param_spec_uint (NM_SETTING_IP_TUNNEL_FLOW_LABEL, "", "",
	                       0, (1 << 20) - 1, 0,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       NM_SETTING_PARAM_INFERRABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPTunnel:mtu:
	 *
	 * If non-zero, only transmit packets of the specified size or smaller,
	 * breaking larger packets up into multiple fragments.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_MTU] =
	    g_param_spec_uint (NM_SETTING_IP_TUNNEL_MTU, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       NM_SETTING_PARAM_FUZZY_IGNORE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPTunnel:flags:
	 *
	 * Tunnel flags. Currently the following values are supported:
	 * %NM_IP_TUNNEL_FLAG_IP6_IGN_ENCAP_LIMIT, %NM_IP_TUNNEL_FLAG_IP6_USE_ORIG_TCLASS,
	 * %NM_IP_TUNNEL_FLAG_IP6_USE_ORIG_FLOWLABEL, %NM_IP_TUNNEL_FLAG_IP6_MIP6_DEV,
	 * %NM_IP_TUNNEL_FLAG_IP6_RCV_DSCP_COPY, %NM_IP_TUNNEL_FLAG_IP6_USE_ORIG_FWMARK.
	 * They are valid only for IPv6 tunnels.
	 *
	 * Since: 1.12
	 **/
	obj_properties[PROP_FLAGS] =
	    g_param_spec_uint (NM_SETTING_IP_TUNNEL_FLAGS, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READWRITE |
	                       NM_SETTING_PARAM_FUZZY_IGNORE |
	                       G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	_nm_setting_class_commit (setting_class, NM_META_SETTING_TYPE_IP_TUNNEL);
}
