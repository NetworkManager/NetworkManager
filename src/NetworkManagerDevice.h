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


typedef struct NMDevice	NMDevice;

NMDevice *	nm_device_new					(const char *iface, const char *udi, gboolean test_device,
											NMDeviceType test_dev_type, NMData *app_data);

void			nm_device_ref					(NMDevice *dev);
gboolean		nm_device_unref				(NMDevice *dev);
void			nm_device_worker_thread_stop		(NMDevice *dev);

int			nm_device_open_sock				(void);

char *		nm_device_get_udi				(NMDevice *dev);
void			nm_device_set_udi				(NMDevice *dev, const char *udi);

const char *	nm_device_get_iface				(NMDevice *dev);

NMDeviceType	nm_device_get_type				(NMDevice *dev);
NMDriverSupportLevel	nm_device_get_driver_support_level	(NMDevice *dev);

gboolean		nm_device_is_wireless			(NMDevice *dev);
gboolean		nm_device_is_wired				(NMDevice *dev);
/* There is no nm_device_set_iface_type() because that's determined when you set the device's iface */

NMData *		nm_device_get_app_data			(const NMDevice *dev);

gboolean		nm_device_get_removed			(const NMDevice *dev);
void			nm_device_set_removed			(NMDevice *dev, const gboolean removed);

gboolean		nm_device_get_link_active		(NMDevice *dev);
void			nm_device_set_link_active		(NMDevice *dev, const gboolean active);
void			nm_device_update_link_active		(NMDevice *dev);

char *		nm_device_get_essid				(NMDevice *dev);
void			nm_device_set_essid				(NMDevice *dev, const char *essid);

void			nm_device_get_ap_address			(NMDevice *dev, struct ether_addr *addr);

NMNetworkMode	nm_device_get_mode				(NMDevice *dev);

guint32		nm_device_get_ip4_address		(NMDevice *dev);
void			nm_device_update_ip4_address		(NMDevice *dev);

void			nm_device_get_hw_address			(NMDevice *dev, unsigned char *eth_addr);
void			nm_device_update_hw_address		(NMDevice *dev);

void			nm_device_get_ip6_address		(NMDevice *dev);

gboolean		nm_device_get_supports_wireless_scan (NMDevice *dev);

gboolean		nm_device_get_supports_carrier_detect (NMDevice *dev);

gboolean		nm_device_set_mode				(NMDevice *dev, const NMNetworkMode mode);

gint8		nm_device_get_signal_strength		(NMDevice *dev);
void			nm_device_update_signal_strength	(NMDevice *dev);

NMAccessPoint *nm_device_get_best_ap			(NMDevice *dev);
void			nm_device_set_best_ap			(NMDevice *dev, NMAccessPoint *ap);
void			nm_device_update_best_ap			(NMDevice *dev);
gboolean		nm_device_need_ap_switch			(NMDevice *dev);

void			nm_device_freeze_best_ap			(NMDevice *dev);
void			nm_device_unfreeze_best_ap		(NMDevice *dev);
gboolean		nm_device_is_best_ap_frozen		(NMDevice *dev);
struct dhcp_interface *nm_device_get_dhcp_iface	(NMDevice *dev);

char *		nm_device_get_path_for_ap		(NMDevice *dev, NMAccessPoint *ap);

/* There is no function to get the WEP key since that's a slight security risk */
void			nm_device_set_enc_key			(NMDevice *dev, const char *key, NMDeviceAuthMethod auth_method);

gboolean		nm_device_activation_schedule_start(NMDevice *dev);
void			nm_device_activation_cancel		(NMDevice *dev);
gboolean		nm_device_activation_should_cancel	(NMDevice *dev);
gboolean		nm_device_is_activating			(NMDevice *dev);
gboolean		nm_device_deactivate			(NMDevice *dev, gboolean just_added);

gboolean		nm_device_get_now_scanning		(NMDevice *dev);

void			nm_device_schedule_force_use		(NMDevice *dev, const char *network, const char *key, NMEncKeyType key_type);

void			nm_device_set_user_key_for_network	(NMDevice *dev, struct NMAccessPointList *invalid_list,
											unsigned char *network, unsigned char *key,
											NMEncKeyType enc_type);

void			nm_device_bring_up				(NMDevice *dev);
void			nm_device_bring_down			(NMDevice *dev);
gboolean		nm_device_is_up				(NMDevice *dev);

void			nm_device_ap_list_clear			(NMDevice *dev);
struct NMAccessPointList *nm_device_ap_list_get	(NMDevice *dev);
NMAccessPoint *nm_device_ap_list_get_ap_by_essid	(NMDevice *dev, const char *essid);
NMAccessPoint *nm_device_ap_list_get_ap_by_address(NMDevice *dev, const struct ether_addr *addr);
void			nm_device_copy_allowed_to_dev_list	(NMDevice *dev, struct NMAccessPointList *allowed_list);

/* System config data accessors */
gboolean		nm_device_config_get_use_dhcp		(NMDevice *dev);
void			nm_device_config_set_use_dhcp		(NMDevice *dev, gboolean use_dhcp);
guint32		nm_device_config_get_ip4_address	(NMDevice *dev);
void			nm_device_config_set_ip4_address	(NMDevice *dev, guint32 addr);
guint32		nm_device_config_get_ip4_gateway	(NMDevice *dev);
void			nm_device_config_set_ip4_gateway	(NMDevice *dev, guint32 gateway);
guint32		nm_device_config_get_ip4_netmask	(NMDevice *dev);
void			nm_device_config_set_ip4_netmask	(NMDevice *dev, guint32 netmask);
guint32		nm_device_config_get_ip4_broadcast	(NMDevice *dev);
void			nm_device_config_set_ip4_broadcast	(NMDevice *dev, guint32 broadcast);

/* Utility routines */
NMDevice *	nm_get_device_by_udi			(NMData *data, const char *udi);
NMDevice *	nm_get_device_by_iface			(NMData *data, const char *iface);

/* Test device routines */
gboolean		nm_device_is_test_device			(NMDevice *dev);

#endif
