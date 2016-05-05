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
 * Copyright 2011 - 2014 Red Hat, Inc.
 */

#ifndef __NM_SETTING_VLAN_H__
#define __NM_SETTING_VLAN_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"
#include <linux/if_vlan.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_VLAN            (nm_setting_vlan_get_type ())
#define NM_SETTING_VLAN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_VLAN, NMSettingVlan))
#define NM_SETTING_VLAN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_VLANCONFIG, NMSettingVlanClass))
#define NM_IS_SETTING_VLAN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_VLAN))
#define NM_IS_SETTING_VLAN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_VLAN))
#define NM_SETTING_VLAN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_VLAN, NMSettingVlanClass))

#define NM_SETTING_VLAN_SETTING_NAME "vlan"

#define NM_SETTING_VLAN_PARENT               "parent"
#define NM_SETTING_VLAN_ID                   "id"
#define NM_SETTING_VLAN_FLAGS                "flags"
#define NM_SETTING_VLAN_INGRESS_PRIORITY_MAP "ingress-priority-map"
#define NM_SETTING_VLAN_EGRESS_PRIORITY_MAP  "egress-priority-map"

/**
 * NMSettingVlan:
 */
struct _NMSettingVlan {
	NMSetting parent;
};

typedef struct {
	NMSettingClass parent;

	/*< private >*/
	gpointer padding[4];
} NMSettingVlanClass;

/**
 * NMVlanPriorityMap:
 * @NM_VLAN_INGRESS_MAP: map for incoming data
 * @NM_VLAN_EGRESS_MAP: map for outgoing data
 *
 * A selector for traffic priority maps; these map Linux SKB priorities
 * to 802.1p priorities used in VLANs.
 **/
typedef enum {
	NM_VLAN_INGRESS_MAP,
	NM_VLAN_EGRESS_MAP
} NMVlanPriorityMap;

/**
 * NMVlanFlags:
 * @NM_VLAN_FLAG_REORDER_HEADERS: indicates that this interface should reorder
 *  outgoing packet headers to look more like a non-VLAN Ethernet interface
 * @NM_VLAN_FLAG_GVRP: indicates that this interface should use GVRP to register
 *  itself with it's switch
 * @NM_VLAN_FLAG_LOOSE_BINDING: indicates that this interface's operating
 *  state is tied to the underlying network interface but other details
 *  (like routing) are not.
 * @NM_VLAN_FLAG_MVRP: indicates that this interface should use MVRP to register
 *  itself with it's switch
 *
 * #NMVlanFlags values control the behavior of the VLAN interface.
 **/
typedef enum { /*< flags >*/
	NM_VLAN_FLAG_REORDER_HEADERS = 0x1,
	NM_VLAN_FLAG_GVRP            = 0x2,
	NM_VLAN_FLAG_LOOSE_BINDING   = 0x4,
	NM_VLAN_FLAG_MVRP            = 0x8,

	/* NOTE: if adding flags update nm-setting-vlan.c::verify() */

	/* NOTE: these flags must correspond to the value from the kernel
	 * header files. */
} NMVlanFlags;

#define NM_VLAN_FLAGS_ALL  (NM_VLAN_FLAG_REORDER_HEADERS | \
                            NM_VLAN_FLAG_GVRP | \
                            NM_VLAN_FLAG_LOOSE_BINDING | \
                            NM_VLAN_FLAG_MVRP)

GType nm_setting_vlan_get_type (void);
NMSetting *nm_setting_vlan_new (void);

const char *nm_setting_vlan_get_parent         (NMSettingVlan *setting);
guint32     nm_setting_vlan_get_id             (NMSettingVlan *setting);
guint32     nm_setting_vlan_get_flags          (NMSettingVlan *setting);

gint32   nm_setting_vlan_get_num_priorities (NMSettingVlan *setting, NMVlanPriorityMap map);

gboolean nm_setting_vlan_get_priority       (NMSettingVlan *setting,
                                             NMVlanPriorityMap map,
                                             guint32 idx,
                                             guint32 *out_from,
                                             guint32 *out_to);

gboolean nm_setting_vlan_add_priority       (NMSettingVlan *setting,
                                             NMVlanPriorityMap map,
                                             guint32 from,
                                             guint32 to);

void     nm_setting_vlan_remove_priority    (NMSettingVlan *setting,
                                             NMVlanPriorityMap map,
                                             guint32 idx);

gboolean nm_setting_vlan_remove_priority_by_value (NMSettingVlan *setting,
                                                   NMVlanPriorityMap map,
                                                   guint32 from,
                                                   guint32 to);

gboolean nm_setting_vlan_remove_priority_str_by_value (NMSettingVlan *setting,
                                                       NMVlanPriorityMap map,
                                                       const char *str);

void     nm_setting_vlan_clear_priorities   (NMSettingVlan *setting, NMVlanPriorityMap map);

gboolean nm_setting_vlan_add_priority_str   (NMSettingVlan *setting,
                                             NMVlanPriorityMap map,
                                             const char *str);

G_END_DECLS

#endif /* __NM_SETTING_VLAN_H__ */
