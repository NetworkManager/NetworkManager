/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_SETTING_VPN_PROPERTIES_H
#define NM_SETTING_VPN_PROPERTIES_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_VPN_PROPERTIES            (nm_setting_vpn_properties_get_type ())
#define NM_SETTING_VPN_PROPERTIES(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_VPN_PROPERTIES, NMSettingVPNProperties))
#define NM_SETTING_VPN_PROPERTIES_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_VPN_PROPERTIES, NMSettingVPNPropertiesClass))
#define NM_IS_SETTING_VPN_PROPERTIES(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_VPN_PROPERTIES))
#define NM_IS_SETTING_VPN_PROPERTIES_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTING_VPN_PROPERTIES))
#define NM_SETTING_VPN_PROPERTIES_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_VPN_PROPERTIES, NMSettingVPNPropertiesClass))

#define NM_SETTING_VPN_PROPERTIES_SETTING_NAME "vpn-properties"
#define NM_SETTING_VPN_PROPERTIES_DATA "data"

typedef struct {
	NMSetting parent;

	/* The hash table is created at setting object
	 * init time and should not be replaced.  It is
	 * a char * -> GValue * mapping, and both the key
	 * and value are owned by the hash table.  GValues
	 * inserted into the hash table must be allocated
	 * with the g_slice_* functions.
	 */
	GHashTable *data;
} NMSettingVPNProperties;

typedef struct {
	NMSettingClass parent;
} NMSettingVPNPropertiesClass;

GType nm_setting_vpn_properties_get_type (void);

NMSetting *nm_setting_vpn_properties_new (void);

G_END_DECLS

#endif /* NM_SETTING_VPN_PROPERTIES_H */
