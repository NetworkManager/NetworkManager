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
 * Copyright 2007 - 2008 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#ifndef __NM_SETTING_PPP_H__
#define __NM_SETTING_PPP_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_PPP            (nm_setting_ppp_get_type ())
#define NM_SETTING_PPP(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_PPP, NMSettingPpp))
#define NM_SETTING_PPP_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_PPP, NMSettingPppClass))
#define NM_IS_SETTING_PPP(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_PPP))
#define NM_IS_SETTING_PPP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_PPP))
#define NM_SETTING_PPP_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_PPP, NMSettingPppClass))

#define NM_SETTING_PPP_SETTING_NAME "ppp"

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

/**
 * NMSettingPpp:
 */
struct _NMSettingPpp {
	NMSetting parent;
};

typedef struct {
	NMSettingClass parent;

	/*< private >*/
	gpointer padding[4];
} NMSettingPppClass;

GType nm_setting_ppp_get_type (void);

NMSetting *nm_setting_ppp_new                   (void);
gboolean   nm_setting_ppp_get_noauth            (NMSettingPpp *setting);
gboolean   nm_setting_ppp_get_refuse_eap        (NMSettingPpp *setting);
gboolean   nm_setting_ppp_get_refuse_pap        (NMSettingPpp *setting);
gboolean   nm_setting_ppp_get_refuse_chap       (NMSettingPpp *setting);
gboolean   nm_setting_ppp_get_refuse_mschap     (NMSettingPpp *setting);
gboolean   nm_setting_ppp_get_refuse_mschapv2   (NMSettingPpp *setting);
gboolean   nm_setting_ppp_get_nobsdcomp         (NMSettingPpp *setting);
gboolean   nm_setting_ppp_get_nodeflate         (NMSettingPpp *setting);
gboolean   nm_setting_ppp_get_no_vj_comp        (NMSettingPpp *setting);
gboolean   nm_setting_ppp_get_require_mppe      (NMSettingPpp *setting);
gboolean   nm_setting_ppp_get_require_mppe_128  (NMSettingPpp *setting);
gboolean   nm_setting_ppp_get_mppe_stateful     (NMSettingPpp *setting);
gboolean   nm_setting_ppp_get_crtscts           (NMSettingPpp *setting);
guint32    nm_setting_ppp_get_baud              (NMSettingPpp *setting);
guint32    nm_setting_ppp_get_mru               (NMSettingPpp *setting);
guint32    nm_setting_ppp_get_mtu               (NMSettingPpp *setting);
guint32    nm_setting_ppp_get_lcp_echo_failure  (NMSettingPpp *setting);
guint32    nm_setting_ppp_get_lcp_echo_interval (NMSettingPpp *setting);

G_END_DECLS

#endif /* __NM_SETTING_PPP_H__ */
