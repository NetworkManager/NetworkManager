/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

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

#define NM_SETTING_PPP_NOAUTH            "noauth"
#define NM_SETTING_PPP_REFUSE_EAP        "refuse-eap"
#define NM_SETTING_PPP_REFUSE_CHAP       "refuse-chap"
#define NM_SETTING_PPP_REFUSE_MSCHAP     "refuse-mschap"
#define NM_SETTING_PPP_NOBSDCOMP         "nobsdcomp"
#define NM_SETTING_PPP_NODEFLATE         "nodeflate"
#define NM_SETTING_PPP_REQUIRE_MPPE      "require-mppe"
#define NM_SETTING_PPP_REQUIRE_MPPE_128  "require-mppe-128"
#define NM_SETTING_PPP_MPPE_STATEFUL     "mpppe-stateful"
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
	gboolean refuse_chap;
	gboolean refuse_mschap;
	gboolean nobsdcomp;
	gboolean nodeflate;
	gboolean require_mppe;
	gboolean require_mppe_128;
	gboolean mppe_stateful;
	gboolean crtscts;

	gint32 baud;
	gint32 mru;
	gint32 mtu;
	gint32 lcp_echo_failure;
	gint32 lcp_echo_interval;
} NMSettingPPP;

typedef struct {
	NMSettingClass parent;
} NMSettingPPPClass;

GType nm_setting_ppp_get_type (void);

NMSetting *nm_setting_ppp_new (void);

G_END_DECLS

#endif /* NM_SETTING_PPP_H */
