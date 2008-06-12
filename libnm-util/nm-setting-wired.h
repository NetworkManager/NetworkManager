/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_SETTING_WIRED_H
#define NM_SETTING_WIRED_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_WIRED            (nm_setting_wired_get_type ())
#define NM_SETTING_WIRED(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_WIRED, NMSettingWired))
#define NM_SETTING_WIRED_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_WIRED, NMSettingWiredClass))
#define NM_IS_SETTING_WIRED(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_WIRED))
#define NM_IS_SETTING_WIRED_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTING_WIRED))
#define NM_SETTING_WIRED_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_WIRED, NMSettingWiredClass))

#define NM_SETTING_WIRED_SETTING_NAME "802-3-ethernet"

typedef enum
{
	NM_SETTING_WIRED_ERROR_UNKNOWN = 0,
	NM_SETTING_WIRED_ERROR_INVALID_PROPERTY,
	NM_SETTING_WIRED_ERROR_MISSING_PROPERTY
} NMSettingWiredError;

#define NM_TYPE_SETTING_WIRED_ERROR (nm_setting_wired_error_get_type ()) 
GType nm_setting_wired_error_get_type (void);

#define NM_SETTING_WIRED_ERROR nm_setting_wired_error_quark ()
GQuark nm_setting_wired_error_quark (void);

#define NM_SETTING_WIRED_PORT "port"
#define NM_SETTING_WIRED_SPEED "speed"
#define NM_SETTING_WIRED_DUPLEX "duplex"
#define NM_SETTING_WIRED_AUTO_NEGOTIATE "auto-negotiate"
#define NM_SETTING_WIRED_MAC_ADDRESS "mac-address"
#define NM_SETTING_WIRED_MTU "mtu"

typedef struct {
	NMSetting parent;

	char *port;
	guint32 speed;
	char *duplex;
	gboolean auto_negotiate;
	GByteArray *mac_address;
	guint32 mtu;
} NMSettingWired;

typedef struct {
	NMSettingClass parent;
} NMSettingWiredClass;

GType nm_setting_wired_get_type (void);

NMSetting *nm_setting_wired_new (void);

G_END_DECLS

#endif /* NM_SETTING_WIRED_H */
