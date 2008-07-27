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

#ifndef NM_SETTING_PPP_H
#define NM_SETTING_PPP_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_PPP            (nm_setting_ppp_get_type ())
#define NM_SETTING_PPP(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_PPP, NMSettingPPP))
#define NM_SETTING_PPP_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_PPP, NMSettingPPPClass))
#define NM_IS_SETTING_PPP(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_PPP))
#define NM_IS_SETTING_PPP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTING_PPP))
#define NM_SETTING_PPP_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_PPP, NMSettingPPPClass))

#define NM_SETTING_PPP_SETTING_NAME "ppp"

typedef enum
{
	NM_SETTING_PPP_ERROR_UNKNOWN = 0,
	NM_SETTING_PPP_ERROR_INVALID_PROPERTY,
	NM_SETTING_PPP_ERROR_MISSING_PROPERTY,
	NM_SETTING_PPP_ERROR_REQUIRE_MPPE_NOT_ALLOWED
} NMSettingPPPError;

#define NM_TYPE_SETTING_PPP_ERROR (nm_setting_ppp_error_get_type ()) 
GType nm_setting_ppp_error_get_type (void);

#define NM_SETTING_PPP_ERROR nm_setting_ppp_error_quark ()
GQuark nm_setting_ppp_error_quark (void);

#define NM_SETTING_PPP_NOAUTH            "noauth"
#define NM_SETTING_PPP_REFUSE_EAP        "refuse-eap"
#define NM_SETTING_PPP_REFUSE_PAP        "refuse-pap"
#define NM_SETTING_PPP_REFUSE_CHAP       "refuse-chap"
#define NM_SETTING_PPP_REFUSE_MSCHAP     "refuse-mschap"
#define NM_SETTING_PPP_REFUSE_MSCHAPV2   "refuse-mschapv2"
#define NM_SETTING_PPP_NOBSDCOMP         "nobsdcomp"
#define NM_SETTING_PPP_NODEFLATE         "nodeflate"
#define NM_SETTING_PPP_NO_VJ_COMP        "no-vj-comp"
#define NM_SETTING_PPP_REQUIRE_MPPE      "require-mppe"
#define NM_SETTING_PPP_REQUIRE_MPPE_128  "require-mppe-128"
#define NM_SETTING_PPP_MPPE_STATEFUL     "mppe-stateful"
#define NM_SETTING_PPP_CRTSCTS           "crtscts"
#define NM_SETTING_PPP_BAUD              "baud"
#define NM_SETTING_PPP_MRU               "mru"
#define NM_SETTING_PPP_MTU               "mtu"
#define NM_SETTING_PPP_LCP_ECHO_FAILURE  "lcp-echo-failure"
#define NM_SETTING_PPP_LCP_ECHO_INTERVAL "lcp-echo-interval"

typedef struct {
	NMSetting parent;

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
} NMSettingPPP;

typedef struct {
	NMSettingClass parent;
} NMSettingPPPClass;

GType nm_setting_ppp_get_type (void);

NMSetting *nm_setting_ppp_new (void);

G_END_DECLS

#endif /* NM_SETTING_PPP_H */
