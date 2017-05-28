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
 * Copyright 2007 - 2013 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "nm-setting-ppp.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-ppp
 * @short_description: Describes connection properties for devices/networks
 * that require PPP to deliver IP capability
 * @include: nm-setting-ppp.h
 *
 * The #NMSettingPPP object is a #NMSetting subclass that describes properties
 * necessary for connection to networks that require PPP transport, like PPPoE
 * cable and DSL modems and some mobile broadband devices.
 **/

/**
 * nm_setting_ppp_error_quark:
 *
 * Registers an error quark for #NMSettingPPP if necessary.
 *
 * Returns: the error quark used for #NMSettingPPP errors.
 **/
GQuark
nm_setting_ppp_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-ppp-error-quark");
	return quark;
}


G_DEFINE_TYPE_WITH_CODE (NMSettingPPP, nm_setting_ppp, NM_TYPE_SETTING,
                         _nm_register_setting (NM_SETTING_PPP_SETTING_NAME,
                                               g_define_type_id,
                                               3,
                                               NM_SETTING_PPP_ERROR))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_PPP)

#define NM_SETTING_PPP_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_PPP, NMSettingPPPPrivate))

typedef struct {
	gboolean noauth;
	gboolean refuse_eap;
	gboolean refuse_pap;
	gboolean refuse_chap;
	gboolean refuse_mschap;
	gboolean refuse_mschapv2;
	gboolean nobsdcomp;
	gboolean nodeflate;
	gboolean no_vj_comp;
	gboolean require_mppe;
	gboolean require_mppe_128;
	gboolean mppe_stateful;
	gboolean crtscts;
	guint32 baud;
	guint32 mru;
	guint32 mtu;
	guint32 lcp_echo_failure;
	guint32 lcp_echo_interval;
} NMSettingPPPPrivate;

enum {
	PROP_0,
	PROP_NOAUTH,
	PROP_REFUSE_EAP,
	PROP_REFUSE_PAP,
	PROP_REFUSE_CHAP,
	PROP_REFUSE_MSCHAP,
	PROP_REFUSE_MSCHAPV2,
	PROP_NOBSDCOMP,
	PROP_NODEFLATE,
	PROP_NO_VJ_COMP,
	PROP_REQUIRE_MPPE,
	PROP_REQUIRE_MPPE_128,
	PROP_MPPE_STATEFUL,
	PROP_CRTSCTS,
	PROP_BAUD,
	PROP_MRU,
	PROP_MTU,
	PROP_LCP_ECHO_FAILURE,
	PROP_LCP_ECHO_INTERVAL,

	LAST_PROP
};

/**
 * nm_setting_ppp_new:
 *
 * Creates a new #NMSettingPPP object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingPPP object
 **/
NMSetting *
nm_setting_ppp_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_PPP, NULL);
}

/**
 * nm_setting_ppp_get_noauth:
 * @setting: the #NMSettingPPP
 *
 * Returns: the #NMSettingPPP:noauth property of the setting
 **/
gboolean
nm_setting_ppp_get_noauth (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->noauth;
}

/**
 * nm_setting_ppp_get_refuse_eap:
 * @setting: the #NMSettingPPP
 *
 * Returns: the #NMSettingPPP:refuse-eap property of the setting
 **/
gboolean
nm_setting_ppp_get_refuse_eap (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->refuse_eap;
}

/**
 * nm_setting_ppp_get_refuse_pap:
 * @setting: the #NMSettingPPP
 *
 * Returns: the #NMSettingPPP:refuse-pap property of the setting
 **/
gboolean
nm_setting_ppp_get_refuse_pap (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->refuse_pap;
}

/**
 * nm_setting_ppp_get_refuse_chap:
 * @setting: the #NMSettingPPP
 *
 * Returns: the #NMSettingPPP:refuse-chap property of the setting
 **/
gboolean
nm_setting_ppp_get_refuse_chap (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->refuse_chap;
}

/**
 * nm_setting_ppp_get_refuse_mschap:
 * @setting: the #NMSettingPPP
 *
 * Returns: the #NMSettingPPP:refuse-mschap property of the setting
 **/
gboolean
nm_setting_ppp_get_refuse_mschap (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->refuse_mschap;
}

/**
 * nm_setting_ppp_get_refuse_mschapv2:
 * @setting: the #NMSettingPPP
 *
 * Returns: the #NMSettingPPP:refuse-mschapv2 property of the setting
 **/
gboolean
nm_setting_ppp_get_refuse_mschapv2 (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->refuse_mschapv2;
}

/**
 * nm_setting_ppp_get_nobsdcomp:
 * @setting: the #NMSettingPPP
 *
 * Returns: the #NMSettingPPP:nobsdcomp property of the setting
 **/
gboolean
nm_setting_ppp_get_nobsdcomp (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->nobsdcomp;
}

/**
 * nm_setting_ppp_get_nodeflate:
 * @setting: the #NMSettingPPP
 *
 * Returns: the #NMSettingPPP:nodeflate property of the setting
 **/
gboolean
nm_setting_ppp_get_nodeflate (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->nodeflate;
}

/**
 * nm_setting_ppp_get_no_vj_comp:
 * @setting: the #NMSettingPPP
 *
 * Returns: the #NMSettingPPP:no-vj-comp property of the setting
 **/
gboolean
nm_setting_ppp_get_no_vj_comp (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->no_vj_comp;
}

/**
 * nm_setting_ppp_get_require_mppe:
 * @setting: the #NMSettingPPP
 *
 * Returns: the #NMSettingPPP:require-mppe property of the setting
 **/
gboolean
nm_setting_ppp_get_require_mppe (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->require_mppe;
}

/**
 * nm_setting_ppp_get_require_mppe_128:
 * @setting: the #NMSettingPPP
 *
 * Returns: the #NMSettingPPP:require-mppe-128 property of the setting
 **/
gboolean
nm_setting_ppp_get_require_mppe_128 (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->require_mppe_128;
}

/**
 * nm_setting_ppp_get_mppe_stateful:
 * @setting: the #NMSettingPPP
 *
 * Returns: the #NMSettingPPP:mppe-stateful property of the setting
 **/
gboolean
nm_setting_ppp_get_mppe_stateful (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->mppe_stateful;
}

/**
 * nm_setting_ppp_get_crtscts:
 * @setting: the #NMSettingPPP
 *
 * Returns: the #NMSettingPPP:crtscts property of the setting
 **/
gboolean
nm_setting_ppp_get_crtscts (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->crtscts;
}

/**
 * nm_setting_ppp_get_baud:
 * @setting: the #NMSettingPPP
 *
 * Returns: the #NMSettingPPP:baud property of the setting
 **/
guint32
nm_setting_ppp_get_baud (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), 0);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->baud;
}

/**
 * nm_setting_ppp_get_mru:
 * @setting: the #NMSettingPPP
 *
 * Returns: the #NMSettingPPP:mru property of the setting
 **/
guint32
nm_setting_ppp_get_mru (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), 0);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->mru;
}

/**
 * nm_setting_ppp_get_mtu:
 * @setting: the #NMSettingPPP
 *
 * Returns: the #NMSettingPPP:mtu property of the setting
 **/
guint32
nm_setting_ppp_get_mtu (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), 0);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->mtu;
}

/**
 * nm_setting_ppp_get_lcp_echo_failure:
 * @setting: the #NMSettingPPP
 *
 * Returns: the #NMSettingPPP:lcp-echo-failure property of the setting
 **/
guint32
nm_setting_ppp_get_lcp_echo_failure (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), 0);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->lcp_echo_failure;
}

/**
 * nm_setting_ppp_get_lcp_echo_interval:
 * @setting: the #NMSettingPPP
 *
 * Returns: the #NMSettingPPP:lcp-echo-interval property of the setting
 **/
guint32
nm_setting_ppp_get_lcp_echo_interval (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), 0);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->lcp_echo_interval;
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingPPPPrivate *priv = NM_SETTING_PPP_GET_PRIVATE (setting);

	/* FIXME: Do we even want this or can we just let pppd evaluate the options? */
	if (priv->mru > 0) {
		if (priv->mru < 128 || priv->mru > 16384) {
			g_set_error (error,
			             NM_SETTING_PPP_ERROR,
			             NM_SETTING_PPP_ERROR_INVALID_PROPERTY,
			             _("'%d' is out of valid range <128-16384>"),
			             priv->mru);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_PPP_SETTING_NAME, NM_SETTING_PPP_MRU);
			return FALSE;
		}
	}

	if (priv->lcp_echo_failure > 0) {
		/* lcp_echo_interval must also be non-zero */
		if (priv->lcp_echo_interval == 0) {
			g_set_error (error,
			             NM_SETTING_PPP_ERROR,
			             NM_SETTING_PPP_ERROR_INVALID_PROPERTY,
			             _("setting this property requires non-zero '%s' property"),
			             NM_SETTING_PPP_LCP_ECHO_INTERVAL);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_PPP_SETTING_NAME, NM_SETTING_PPP_LCP_ECHO_FAILURE);
			return FALSE;
		}
	}

	return TRUE;
}

static void
nm_setting_ppp_init (NMSettingPPP *setting)
{
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingPPPPrivate *priv = NM_SETTING_PPP_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_NOAUTH:
		priv->noauth = g_value_get_boolean (value);
		break;
	case PROP_REFUSE_EAP:
		priv->refuse_eap = g_value_get_boolean (value);
		break;
	case PROP_REFUSE_PAP:
		priv->refuse_pap = g_value_get_boolean (value);
		break;
	case PROP_REFUSE_CHAP:
		priv->refuse_chap = g_value_get_boolean (value);
		break;
	case PROP_REFUSE_MSCHAP:
		priv->refuse_mschap = g_value_get_boolean (value);
		break;
	case PROP_REFUSE_MSCHAPV2:
		priv->refuse_mschapv2 = g_value_get_boolean (value);
		break;
	case PROP_NOBSDCOMP:
		priv->nobsdcomp = g_value_get_boolean (value);
		break;
	case PROP_NODEFLATE:
		priv->nodeflate = g_value_get_boolean (value);
		break;
	case PROP_NO_VJ_COMP:
		priv->no_vj_comp = g_value_get_boolean (value);
		break;
	case PROP_REQUIRE_MPPE:
		priv->require_mppe = g_value_get_boolean (value);
		break;
	case PROP_REQUIRE_MPPE_128:
		priv->require_mppe_128 = g_value_get_boolean (value);
		break;
	case PROP_MPPE_STATEFUL:
		priv->mppe_stateful = g_value_get_boolean (value);
		break;
	case PROP_CRTSCTS:
		priv->crtscts = g_value_get_boolean (value);
		break;
	case PROP_BAUD:
		priv->baud = g_value_get_uint (value);
		break;
	case PROP_MRU:
		priv->mru = g_value_get_uint (value);
		break;
	case PROP_MTU:
		priv->mtu = g_value_get_uint (value);
		break;
	case PROP_LCP_ECHO_FAILURE:
		priv->lcp_echo_failure = g_value_get_uint (value);
		break;
	case PROP_LCP_ECHO_INTERVAL:
		priv->lcp_echo_interval = g_value_get_uint (value);
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
	NMSettingPPP *setting = NM_SETTING_PPP (object);

	switch (prop_id) {
	case PROP_NOAUTH:
		g_value_set_boolean (value, nm_setting_ppp_get_noauth (setting));
		break;
	case PROP_REFUSE_EAP:
		g_value_set_boolean (value, nm_setting_ppp_get_refuse_eap (setting));
		break;
	case PROP_REFUSE_PAP:
		g_value_set_boolean (value, nm_setting_ppp_get_refuse_pap (setting));
		break;
	case PROP_REFUSE_CHAP:
		g_value_set_boolean (value, nm_setting_ppp_get_refuse_chap (setting));
		break;
	case PROP_REFUSE_MSCHAP:
		g_value_set_boolean (value, nm_setting_ppp_get_refuse_mschap (setting));
		break;
	case PROP_REFUSE_MSCHAPV2:
		g_value_set_boolean (value, nm_setting_ppp_get_refuse_mschapv2 (setting));
		break;
	case PROP_NOBSDCOMP:
		g_value_set_boolean (value, nm_setting_ppp_get_nobsdcomp (setting));
		break;
	case PROP_NODEFLATE:
		g_value_set_boolean (value, nm_setting_ppp_get_nodeflate (setting));
		break;
	case PROP_NO_VJ_COMP:
		g_value_set_boolean (value, nm_setting_ppp_get_no_vj_comp (setting));
		break;
	case PROP_REQUIRE_MPPE:
		g_value_set_boolean (value, nm_setting_ppp_get_require_mppe (setting));
		break;
	case PROP_REQUIRE_MPPE_128:
		g_value_set_boolean (value, nm_setting_ppp_get_require_mppe_128 (setting));
		break;
	case PROP_MPPE_STATEFUL:
		g_value_set_boolean (value, nm_setting_ppp_get_mppe_stateful (setting));
		break;
	case PROP_CRTSCTS:
		g_value_set_boolean (value, nm_setting_ppp_get_crtscts (setting));
		break;
	case PROP_BAUD:
		g_value_set_uint (value, nm_setting_ppp_get_baud (setting));
		break;
	case PROP_MRU:
		g_value_set_uint (value, nm_setting_ppp_get_mru (setting));
		break;
	case PROP_MTU:
		g_value_set_uint (value, nm_setting_ppp_get_mtu (setting));
		break;
	case PROP_LCP_ECHO_FAILURE:
		g_value_set_uint (value, nm_setting_ppp_get_lcp_echo_failure (setting));
		break;
	case PROP_LCP_ECHO_INTERVAL:
		g_value_set_uint (value, nm_setting_ppp_get_lcp_echo_interval (setting));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_ppp_class_init (NMSettingPPPClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingPPPPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	parent_class->verify       = verify;

	/* Properties */
	/**
	 * NMSettingPPP:noauth:
	 *
	 * If %TRUE, do not require the other side (usually the PPP server) to
	 * authenticate itself to the client.  If %FALSE, require authentication
	 * from the remote side.  In almost all cases, this should be %TRUE.
	 **/
	g_object_class_install_property
		(object_class, PROP_NOAUTH,
		 g_param_spec_boolean (NM_SETTING_PPP_NOAUTH, "", "",
		                       TRUE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingPPP:refuse-eap:
	 *
	 * If %TRUE, the EAP authentication method will not be used.
	 **/
	g_object_class_install_property
		(object_class, PROP_REFUSE_EAP,
		 g_param_spec_boolean (NM_SETTING_PPP_REFUSE_EAP, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingPPP:refuse-pap:
	 *
	 * If %TRUE, the PAP authentication method will not be used.
	 **/
	g_object_class_install_property
		(object_class, PROP_REFUSE_PAP,
		 g_param_spec_boolean (NM_SETTING_PPP_REFUSE_PAP, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingPPP:refuse-chap:
	 *
	 * If %TRUE, the CHAP authentication method will not be used.
	 **/
	g_object_class_install_property
		(object_class, PROP_REFUSE_CHAP,
		 g_param_spec_boolean (NM_SETTING_PPP_REFUSE_CHAP, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingPPP:refuse-mschap:
	 *
	 * If %TRUE, the MSCHAP authentication method will not be used.
	 **/
	g_object_class_install_property
		(object_class, PROP_REFUSE_MSCHAP,
		 g_param_spec_boolean (NM_SETTING_PPP_REFUSE_MSCHAP, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingPPP:refuse-mschapv2:
	 *
	 * If %TRUE, the MSCHAPv2 authentication method will not be used.
	 **/
	g_object_class_install_property
		(object_class, PROP_REFUSE_MSCHAPV2,
		 g_param_spec_boolean (NM_SETTING_PPP_REFUSE_MSCHAPV2, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingPPP:nobsdcomp:
	 *
	 * If %TRUE, BSD compression will not be requested.
	 **/
	g_object_class_install_property
		(object_class, PROP_NOBSDCOMP,
		 g_param_spec_boolean (NM_SETTING_PPP_NOBSDCOMP, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       NM_SETTING_PARAM_FUZZY_IGNORE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingPPP:nodeflate:
	 *
	 * If %TRUE, "deflate" compression will not be requested.
	 **/
	g_object_class_install_property
		(object_class, PROP_NODEFLATE,
		 g_param_spec_boolean (NM_SETTING_PPP_NODEFLATE, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       NM_SETTING_PARAM_FUZZY_IGNORE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingPPP:no-vj-comp:
	 *
	 * If %TRUE, Van Jacobsen TCP header compression will not be requested.
	 **/
	g_object_class_install_property
		(object_class, PROP_NO_VJ_COMP,
		 g_param_spec_boolean (NM_SETTING_PPP_NO_VJ_COMP, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       NM_SETTING_PARAM_FUZZY_IGNORE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingPPP:require-mppe:
	 *
	 * If %TRUE, MPPE (Microsoft Point-to-Point Encryption) will be required for
	 * the PPP session.  If either 64-bit or 128-bit MPPE is not available the
	 * session will fail.  Note that MPPE is not used on mobile broadband
	 * connections.
	 **/
	g_object_class_install_property
		(object_class, PROP_REQUIRE_MPPE,
		 g_param_spec_boolean (NM_SETTING_PPP_REQUIRE_MPPE, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingPPP:require-mppe-128:
	 *
	 * If %TRUE, 128-bit MPPE (Microsoft Point-to-Point Encryption) will be
	 * required for the PPP session, and the "require-mppe" property must also
	 * be set to %TRUE.  If 128-bit MPPE is not available the session will fail.
	 **/
	g_object_class_install_property
		(object_class, PROP_REQUIRE_MPPE_128,
		 g_param_spec_boolean (NM_SETTING_PPP_REQUIRE_MPPE_128, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE  | G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingPPP:mppe-stateful:
	 *
	 * If %TRUE, stateful MPPE is used.  See pppd documentation for more
	 * information on stateful MPPE.
	 **/
	g_object_class_install_property
		(object_class, PROP_MPPE_STATEFUL,
		 g_param_spec_boolean (NM_SETTING_PPP_MPPE_STATEFUL, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingPPP:crtscts:
	 *
	 * If %TRUE, specify that pppd should set the serial port to use hardware
	 * flow control with RTS and CTS signals.  This value should normally be set
	 * to %FALSE.
	 **/
	g_object_class_install_property
		(object_class, PROP_CRTSCTS,
		 g_param_spec_boolean (NM_SETTING_PPP_CRTSCTS, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingPPP:baud:
	 *
	 * If non-zero, instruct pppd to set the serial port to the specified
	 * baudrate.  This value should normally be left as 0 to automatically
	 * choose the speed.
	 **/
	g_object_class_install_property
		(object_class, PROP_BAUD,
		 g_param_spec_uint (NM_SETTING_PPP_BAUD, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    NM_SETTING_PARAM_FUZZY_IGNORE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingPPP:mru:
	 *
	 * If non-zero, instruct pppd to request that the peer send packets no
	 * larger than the specified size.  If non-zero, the MRU should be between
	 * 128 and 16384.
	 */
	g_object_class_install_property
		(object_class, PROP_MRU,
		 g_param_spec_uint (NM_SETTING_PPP_MRU, "", "",
		                    0, 16384, 0,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingPPP:mtu:
	 *
	 * If non-zero, instruct pppd to send packets no larger than the specified
	 * size.
	 **/
	g_object_class_install_property
		(object_class, PROP_MTU,
		 g_param_spec_uint (NM_SETTING_PPP_MTU, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    NM_SETTING_PARAM_FUZZY_IGNORE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingPPP:lcp-echo-failure:
	 *
	 * If non-zero, instruct pppd to presume the connection to the peer has
	 * failed if the specified number of LCP echo-requests go unanswered by the
	 * peer.  The "lcp-echo-interval" property must also be set to a non-zero
	 * value if this property is used.
	 **/
	g_object_class_install_property
		(object_class, PROP_LCP_ECHO_FAILURE,
		 g_param_spec_uint (NM_SETTING_PPP_LCP_ECHO_FAILURE, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    NM_SETTING_PARAM_FUZZY_IGNORE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingPPP:lcp-echo-interval:
	 *
	 * If non-zero, instruct pppd to send an LCP echo-request frame to the peer
	 * every n seconds (where n is the specified value).  Note that some PPP
	 * peers will respond to echo requests and some will not, and it is not
	 * possible to autodetect this.
	 **/
	g_object_class_install_property
		(object_class, PROP_LCP_ECHO_INTERVAL,
		 g_param_spec_uint (NM_SETTING_PPP_LCP_ECHO_INTERVAL, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    NM_SETTING_PARAM_FUZZY_IGNORE |
		                    G_PARAM_STATIC_STRINGS));
}
