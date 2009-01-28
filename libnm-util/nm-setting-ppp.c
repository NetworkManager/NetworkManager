/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
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
 * (C) Copyright 2007 - 2008 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#include "nm-setting-ppp.h"

GQuark
nm_setting_ppp_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-ppp-error-quark");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_setting_ppp_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (NM_SETTING_PPP_ERROR_UNKNOWN, "UnknownError"),
			/* The specified property was invalid. */
			ENUM_ENTRY (NM_SETTING_PPP_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (NM_SETTING_PPP_ERROR_MISSING_PROPERTY, "MissingProperty"),
			/* The 'require-mppe' option is not allowed in conjunction with the specified authentication. */
			ENUM_ENTRY (NM_SETTING_PPP_ERROR_REQUIRE_MPPE_NOT_ALLOWED, "RequireMPPENotAllowed"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMSettingPPPError", values);
	}
	return etype;
}


G_DEFINE_TYPE (NMSettingPPP, nm_setting_ppp, NM_TYPE_SETTING)

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

NMSetting *
nm_setting_ppp_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_PPP, NULL);
}

gboolean
nm_setting_ppp_get_noauth (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->noauth;
}

gboolean
nm_setting_ppp_get_refuse_eap (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->refuse_eap;
}

gboolean
nm_setting_ppp_get_refuse_pap (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->refuse_pap;
}

gboolean
nm_setting_ppp_get_refuse_chap (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->refuse_chap;
}

gboolean
nm_setting_ppp_get_refuse_mschap (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->refuse_mschap;
}

gboolean
nm_setting_ppp_get_refuse_mschapv2 (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->refuse_mschapv2;
}

gboolean
nm_setting_ppp_get_nobsdcomp (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->nobsdcomp;
}

gboolean
nm_setting_ppp_get_nodeflate (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->nodeflate;
}

gboolean
nm_setting_ppp_get_no_vj_comp (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->no_vj_comp;
}

gboolean
nm_setting_ppp_get_require_mppe (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->require_mppe;
}

gboolean
nm_setting_ppp_get_require_mppe_128 (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->require_mppe_128;
}

gboolean
nm_setting_ppp_get_mppe_stateful (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->mppe_stateful;
}

gboolean
nm_setting_ppp_get_crtscts (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->crtscts;
}

guint32
nm_setting_ppp_get_baud (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), 0);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->baud;
}

guint32
nm_setting_ppp_get_mru (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), 0);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->mru;
}

guint32
nm_setting_ppp_get_mtu (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), 0);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->mtu;
}

guint32
nm_setting_ppp_get_lcp_echo_failure (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), 0);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->lcp_echo_failure;
}

guint32
nm_setting_ppp_get_lcp_echo_interval (NMSettingPPP *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), 0);

	return NM_SETTING_PPP_GET_PRIVATE (setting)->lcp_echo_interval;
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	/* FIXME: Do we even want this or can we just let pppd evaluate the options? */
	return TRUE;
}

static void
nm_setting_ppp_init (NMSettingPPP *setting)
{
	g_object_set (setting, NM_SETTING_NAME, NM_SETTING_PPP_SETTING_NAME, NULL);
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
	g_object_class_install_property
		(object_class, PROP_NOAUTH,
		 g_param_spec_boolean (NM_SETTING_PPP_NOAUTH,
						   "NoAuth",
						   "NoAuth",
						   TRUE,
						   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_REFUSE_EAP,
		 g_param_spec_boolean (NM_SETTING_PPP_REFUSE_EAP,
						   "Refuse EAP",
						   "Refuse EAP",
						   FALSE,
						   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_REFUSE_PAP,
		 g_param_spec_boolean (NM_SETTING_PPP_REFUSE_PAP,
						   "Refuse PAP",
						   "Refuse PAP",
						   FALSE,
						   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_REFUSE_CHAP,
		 g_param_spec_boolean (NM_SETTING_PPP_REFUSE_CHAP,
						   "Refuse CHAP",
						   "Refuse CHAP",
						   FALSE,
						   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_REFUSE_MSCHAP,
		 g_param_spec_boolean (NM_SETTING_PPP_REFUSE_MSCHAP,
						   "Refuse MSCHAP",
						   "Refuse MSCHAP",
						   FALSE,
						   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_REFUSE_MSCHAPV2,
		 g_param_spec_boolean (NM_SETTING_PPP_REFUSE_MSCHAPV2,
						   "Refuse MSCHAPv2",
						   "Refuse MSCHAPv2",
						   FALSE,
						   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_NOBSDCOMP,
		 g_param_spec_boolean (NM_SETTING_PPP_NOBSDCOMP,
						   "No BSD compression",
						   "No BSD compression",
						   FALSE,
						   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_FUZZY_IGNORE));

	g_object_class_install_property
		(object_class, PROP_NODEFLATE,
		 g_param_spec_boolean (NM_SETTING_PPP_NODEFLATE,
						   "No deflate",
						   "No deflate",
						   FALSE,
						   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_FUZZY_IGNORE));

	g_object_class_install_property
		(object_class, PROP_NO_VJ_COMP,
		 g_param_spec_boolean (NM_SETTING_PPP_NO_VJ_COMP,
						   "No VJ compression",
						   "No VJ compression",
						   FALSE,
						   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_FUZZY_IGNORE));

	g_object_class_install_property
		(object_class, PROP_REQUIRE_MPPE,
		 g_param_spec_boolean (NM_SETTING_PPP_REQUIRE_MPPE,
						   "Require MPPE",
						   "Require MPPE",
						   FALSE,
						   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_REQUIRE_MPPE_128,
		 g_param_spec_boolean (NM_SETTING_PPP_REQUIRE_MPPE_128,
						   "Require MPPE 128",
						   "Require MPPE 128",
						   FALSE,
						   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_MPPE_STATEFUL,
		 g_param_spec_boolean (NM_SETTING_PPP_MPPE_STATEFUL,
						   "MPPE stateful",
						   "MPPE stateful",
						   FALSE,
						   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_CRTSCTS,
		 g_param_spec_boolean (NM_SETTING_PPP_CRTSCTS,
						   "CRTSCTS",
						   "CRTSCTS",
						   FALSE,
						   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_BAUD,
		 g_param_spec_uint (NM_SETTING_PPP_BAUD,
						"Baud",
						"Baud",
						0, G_MAXUINT32, 0,
						G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_FUZZY_IGNORE));

	g_object_class_install_property
		(object_class, PROP_MRU,
		 g_param_spec_uint (NM_SETTING_PPP_MRU,
						"MRU",
						"MRU",
						0, G_MAXUINT32, 0,
						G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_MTU,
		 g_param_spec_uint (NM_SETTING_PPP_MTU,
						"MTU",
						"MTU",
						0, G_MAXUINT32, 0,
						G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_FUZZY_IGNORE));

	g_object_class_install_property
		(object_class, PROP_LCP_ECHO_FAILURE,
		 g_param_spec_uint (NM_SETTING_PPP_LCP_ECHO_FAILURE,
						"LCP echo failure",
						"LCP echo failure",
						0, G_MAXUINT32, 0,
						G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_FUZZY_IGNORE));

	g_object_class_install_property
		(object_class, PROP_LCP_ECHO_INTERVAL,
		 g_param_spec_uint (NM_SETTING_PPP_LCP_ECHO_INTERVAL,
						"LCP echo interval",
						"LCP echo interval",
						0, G_MAXUINT32, 0,
						G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_FUZZY_IGNORE));
}
