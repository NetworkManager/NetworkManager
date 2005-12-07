/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2004 Red Hat, Inc.
 */

#ifndef NETWORK_MANAGER_DEVICE_H
#define NETWORK_MANAGER_DEVICE_H

#include <net/ethernet.h>
#include <iwlib.h>
#include "NetworkManager.h"
#include "NetworkManagerMain.h"
#include "nm-ip4-config.h"

#if 0
#define IOCTL_DEBUG
#endif

typedef struct NMDevice	NMDevice;

typedef enum NMWirelessScanInterval
{
	NM_WIRELESS_SCAN_INTERVAL_INIT = 0,
	NM_WIRELESS_SCAN_INTERVAL_ACTIVE,
	NM_WIRELESS_SCAN_INTERVAL_INACTIVE
} NMWirelessScanInterval;

NMDevice *	nm_device_new					(const char *iface, const char *udi, gboolean test_device,
											NMDeviceType test_dev_type, NMData *app_data);

void			nm_device_ref						(NMDevice *dev);
gboolean		nm_device_unref					(NMDevice *dev);
void			nm_device_worker_thread_stop			(NMDevice *dev);

int			nm_device_open_sock					(void);

char *		nm_device_get_udi					(NMDevice *dev);
void			nm_device_set_udi					(NMDevice *dev, const char *udi);

const char *	nm_device_get_iface					(NMDevice *dev);

const char *	nm_device_get_driver				(NMDevice *dev);

NMDeviceType	nm_device_get_type					(NMDevice *dev);
guint32		nm_device_get_capabilities			(NMDevice *dev);

gboolean		nm_device_is_802_11_wireless			(NMDevice *dev);
gboolean		nm_device_is_802_3_ethernet			(NMDevice *dev);

NMData *		nm_device_get_app_data				(const NMDevice *dev);

gboolean		nm_device_get_removed				(const NMDevice *dev);
void			nm_device_set_removed				(NMDevice *dev, const gboolean removed);

gboolean		nm_device_has_active_link			(NMDevice *dev);
void			nm_device_set_link_active			(NMDevice *dev, const gboolean active);
gboolean		nm_device_probe_link_state			(NMDevice *dev);

char *		nm_device_get_essid					(NMDevice *dev);
void			nm_device_set_essid					(NMDevice *dev, const char *essid);

void			nm_device_get_ap_address				(NMDevice *dev, struct ether_addr *addr);

int			nm_device_get_mode					(NMDevice *dev);
gboolean		nm_device_set_mode					(NMDevice *dev, const int mode);

guint32		nm_device_get_ip4_address			(NMDevice *dev);
void			nm_device_update_ip4_address			(NMDevice *dev);

void			nm_device_get_hw_address				(NMDevice *dev, struct ether_addr *addr);
void			nm_device_update_hw_address			(NMDevice *dev);

void			nm_device_get_ip6_address			(NMDevice *dev);

gboolean		nm_device_get_supports_wireless_scan	(NMDevice *dev);

gboolean		nm_device_get_supports_carrier_detect	(NMDevice *dev);

gint8		nm_device_get_signal_strength			(NMDevice *dev);
void			nm_device_update_signal_strength		(NMDevice *dev);

NMAccessPoint *nm_device_get_best_ap				(NMDevice *dev);

void			nm_device_set_wireless_scan_interval		(NMDevice *dev, NMWirelessScanInterval interval);

/* There is no function to get the WEP key since that's a slight security risk */
void			nm_device_set_enc_key				(NMDevice *dev, const char *key, NMDeviceAuthMethod auth_method);

NMActRequest *	nm_device_get_act_request						(NMDevice *dev);
gboolean		nm_device_activation_start						(NMActRequest *req);
void			nm_device_activate_schedule_stage4_ip_config_get		(NMActRequest *req);
void			nm_device_activate_schedule_stage4_ip_config_timeout	(NMActRequest *req);
void			nm_device_activation_cancel						(NMDevice *dev);
gboolean		nm_device_activation_should_cancel					(NMDevice *dev);
gboolean		nm_device_is_activating							(NMDevice *dev);
gboolean		nm_device_deactivate_quickly						(NMDevice *dev);
gboolean		nm_device_deactivate							(NMDevice *dev);

NMAccessPoint *nm_device_wireless_get_activation_ap	(NMDevice *dev, const char *essid, const char *key, NMEncKeyType key_type);

void			nm_device_set_user_key_for_network		(NMActRequest *req, const char *key, const NMEncKeyType enc_type);

void			nm_device_bring_up					(NMDevice *dev);
void			nm_device_bring_down				(NMDevice *dev);
gboolean		nm_device_is_up					(NMDevice *dev);

void			nm_device_ap_list_clear				(NMDevice *dev);
struct NMAccessPointList *nm_device_ap_list_get		(NMDevice *dev);
NMAccessPoint *nm_device_ap_list_get_ap_by_essid		(NMDevice *dev, const char *essid);
NMAccessPoint *nm_device_ap_list_get_ap_by_address	(NMDevice *dev, const struct ether_addr *addr);
NMAccessPoint *nm_device_ap_list_get_ap_by_obj_path	(NMDevice *dev, const char *obj_path);
void			nm_device_copy_allowed_to_dev_list		(NMDevice *dev, struct NMAccessPointList *allowed_list);

gboolean		nm_device_get_use_dhcp				(NMDevice *dev);
void			nm_device_set_use_dhcp				(NMDevice *dev, gboolean use_dhcp);

NMIP4Config *	nm_device_get_ip4_config				(NMDevice *dev);
void			nm_device_set_ip4_config				(NMDevice *dev, NMIP4Config *config);

void *		nm_device_get_system_config_data		(NMDevice *dev);

/* Utility routines */
NMDevice *	nm_get_device_by_udi				(NMData *data, const char *udi);
NMDevice *	nm_get_device_by_iface				(NMData *data, const char *iface);

/* Test device routines */
gboolean		nm_device_is_test_device				(NMDevice *dev);

#endif
