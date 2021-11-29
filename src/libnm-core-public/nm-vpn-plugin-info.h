/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NM_VPN_PLUGIN_INFO_H__
#define __NM_VPN_PLUGIN_INFO_H__

#include <glib.h>
#include <glib-object.h>

#include "nm-utils.h"
#include "nm-vpn-editor-plugin.h"

G_BEGIN_DECLS

#define NM_TYPE_VPN_PLUGIN_INFO (nm_vpn_plugin_info_get_type())
#define NM_VPN_PLUGIN_INFO(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_VPN_PLUGIN_INFO, NMVpnPluginInfo))
#define NM_VPN_PLUGIN_INFO_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_VPN_PLUGIN_INFO, NMVpnPluginInfoClass))
#define NM_IS_VPN_PLUGIN_INFO(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_VPN_PLUGIN_INFO))
#define NM_IS_VPN_PLUGIN_INFO_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_VPN_PLUGIN_INFO))
#define NM_VPN_PLUGIN_INFO_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_VPN_PLUGIN_INFO, NMVpnPluginInfoClass))

#define NM_VPN_PLUGIN_INFO_NAME     "name"
#define NM_VPN_PLUGIN_INFO_FILENAME "filename"
#define NM_VPN_PLUGIN_INFO_KEYFILE  "keyfile"

#define NM_VPN_PLUGIN_INFO_KF_GROUP_CONNECTION "VPN Connection"
#define NM_VPN_PLUGIN_INFO_KF_GROUP_LIBNM      "libnm"
#define NM_VPN_PLUGIN_INFO_KF_GROUP_GNOME      "GNOME"

typedef struct _NMVpnPluginInfoClass NMVpnPluginInfoClass;

NM_AVAILABLE_IN_1_2
GType nm_vpn_plugin_info_get_type(void);

NM_AVAILABLE_IN_1_2
NMVpnPluginInfo *nm_vpn_plugin_info_new_from_file(const char *filename, GError **error);

NM_AVAILABLE_IN_1_2
NMVpnPluginInfo *
nm_vpn_plugin_info_new_with_data(const char *filename, GKeyFile *keyfile, GError **error);

NM_AVAILABLE_IN_1_4
NMVpnPluginInfo *nm_vpn_plugin_info_new_search_file(const char *name, const char *service);

NM_AVAILABLE_IN_1_2
const char *nm_vpn_plugin_info_get_name(NMVpnPluginInfo *self);
NM_AVAILABLE_IN_1_2
const char *nm_vpn_plugin_info_get_filename(NMVpnPluginInfo *self);
NM_AVAILABLE_IN_1_4
const char *nm_vpn_plugin_info_get_service(NMVpnPluginInfo *self);
NM_AVAILABLE_IN_1_2
const char *nm_vpn_plugin_info_get_plugin(NMVpnPluginInfo *self);
NM_AVAILABLE_IN_1_2
const char *nm_vpn_plugin_info_get_program(NMVpnPluginInfo *self);
NM_AVAILABLE_IN_1_4
const char *nm_vpn_plugin_info_get_auth_dialog(NMVpnPluginInfo *self);
NM_AVAILABLE_IN_1_4
gboolean nm_vpn_plugin_info_supports_hints(NMVpnPluginInfo *self);
NM_AVAILABLE_IN_1_2
gboolean nm_vpn_plugin_info_supports_multiple(NMVpnPluginInfo *self);
NM_AVAILABLE_IN_1_4
const char *const *nm_vpn_plugin_info_get_aliases(NMVpnPluginInfo *self);
NM_AVAILABLE_IN_1_2
const char *
nm_vpn_plugin_info_lookup_property(NMVpnPluginInfo *self, const char *group, const char *key);

NM_AVAILABLE_IN_1_2
gboolean nm_vpn_plugin_info_validate_filename(const char *filename);

NM_AVAILABLE_IN_1_2
GSList *nm_vpn_plugin_info_list_load(void);
NM_AVAILABLE_IN_1_2
gboolean nm_vpn_plugin_info_list_add(GSList **list, NMVpnPluginInfo *plugin_info, GError **error);
NM_AVAILABLE_IN_1_2
gboolean nm_vpn_plugin_info_list_remove(GSList **list, NMVpnPluginInfo *plugin_info);
NM_AVAILABLE_IN_1_2
NMVpnPluginInfo *nm_vpn_plugin_info_list_find_by_name(GSList *list, const char *name);
NM_AVAILABLE_IN_1_2
NMVpnPluginInfo *nm_vpn_plugin_info_list_find_by_filename(GSList *list, const char *filename);
NM_AVAILABLE_IN_1_2
NMVpnPluginInfo *nm_vpn_plugin_info_list_find_by_service(GSList *list, const char *service);

NM_AVAILABLE_IN_1_4
char *nm_vpn_plugin_info_list_find_service_type(GSList *list, const char *name);
NM_AVAILABLE_IN_1_4
char **nm_vpn_plugin_info_list_get_service_types(GSList  *list,
                                                 gboolean only_existing,
                                                 gboolean with_abbreviations);

NM_AVAILABLE_IN_1_2
NMVpnEditorPlugin *nm_vpn_plugin_info_get_editor_plugin(NMVpnPluginInfo *self);
NM_AVAILABLE_IN_1_2
void nm_vpn_plugin_info_set_editor_plugin(NMVpnPluginInfo *self, NMVpnEditorPlugin *plugin);
NM_AVAILABLE_IN_1_2
NMVpnEditorPlugin *nm_vpn_plugin_info_load_editor_plugin(NMVpnPluginInfo *self, GError **error);

G_END_DECLS

#endif /* __NM_VPN_PLUGIN_INFO_H__ */
