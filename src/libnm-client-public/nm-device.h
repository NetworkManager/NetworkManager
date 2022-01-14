/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2013 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_H__
#define __NM_DEVICE_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-object.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE            (nm_device_get_type())
#define NM_DEVICE(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE, NMDevice))
#define NM_DEVICE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE, NMDeviceClass))
#define NM_IS_DEVICE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE))
#define NM_IS_DEVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE))
#define NM_DEVICE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE, NMDeviceClass))

#define NM_DEVICE_DEVICE_TYPE      "device-type"
#define NM_DEVICE_UDI              "udi"
#define NM_DEVICE_PATH             "path"
#define NM_DEVICE_INTERFACE        "interface"
#define NM_DEVICE_IP_INTERFACE     "ip-interface"
#define NM_DEVICE_DRIVER           "driver"
#define NM_DEVICE_DRIVER_VERSION   "driver-version"
#define NM_DEVICE_FIRMWARE_VERSION "firmware-version"
#define NM_DEVICE_CAPABILITIES     "capabilities"
#define NM_DEVICE_REAL             "real"
#define NM_DEVICE_MANAGED          "managed"

_NM_DEPRECATED_SYNC_WRITABLE_PROPERTY
#define NM_DEVICE_AUTOCONNECT "autoconnect"

#define NM_DEVICE_FIRMWARE_MISSING      "firmware-missing"
#define NM_DEVICE_NM_PLUGIN_MISSING     "nm-plugin-missing"
#define NM_DEVICE_IP4_CONFIG            "ip4-config"
#define NM_DEVICE_DHCP4_CONFIG          "dhcp4-config"
#define NM_DEVICE_IP6_CONFIG            "ip6-config"
#define NM_DEVICE_DHCP6_CONFIG          "dhcp6-config"
#define NM_DEVICE_STATE                 "state"
#define NM_DEVICE_STATE_REASON          "state-reason"
#define NM_DEVICE_ACTIVE_CONNECTION     "active-connection"
#define NM_DEVICE_AVAILABLE_CONNECTIONS "available-connections"
#define NM_DEVICE_VENDOR                "vendor"
#define NM_DEVICE_PRODUCT               "product"
#define NM_DEVICE_PHYSICAL_PORT_ID      "physical-port-id"
#define NM_DEVICE_MTU                   "mtu"
#define NM_DEVICE_METERED               "metered"
#define NM_DEVICE_LLDP_NEIGHBORS        "lldp-neighbors"
#define NM_DEVICE_IP4_CONNECTIVITY      "ip4-connectivity"
#define NM_DEVICE_IP6_CONNECTIVITY      "ip6-connectivity"
#define NM_DEVICE_INTERFACE_FLAGS       "interface-flags"
#define NM_DEVICE_HW_ADDRESS            "hw-address"
#define NM_DEVICE_PORTS                 "ports"

/**
 * NMDevice:
 */
typedef struct _NMDeviceClass NMDeviceClass;

/**
 * NMLldpNeighbor:
 *
 * Supported attributes are:
 *
 * - #NM_LLDP_ATTR_CHASSIS_ID_TYPE (type: 'u')
 * - #NM_LLDP_ATTR_CHASSIS_ID (type: 's')
 * - #NM_LLDP_ATTR_DESTINATION (type: 's')
 * - #NM_LLDP_ATTR_IEEE_802_1_PPVID (type: 'u'). This attribute only reports the first PPVID
 *   and therefore it is deprecated in favor of NM_LLDP_ATTR_IEEE_802_1_PPVIDS which reports
 *   all the PPVID.
 * - #NM_LLDP_ATTR_IEEE_802_1_PPVID_FLAGS (type: 'u'). This attribute only reports the first PPVID
 *   and therefore it is deprecated in favor of NM_LLDP_ATTR_IEEE_802_1_PPVIDS which reports
 *   all the PPVID.
 * - #NM_LLDP_ATTR_IEEE_802_1_PPVIDS (type: 'aa{sv}')
 *
 *   An array of dictionaries where each element has keys:
 *   - flags (type: 'u')
 *   - ppvid (type: 'u')
 * - #NM_LLDP_ATTR_IEEE_802_1_PVID (type: 'u')
 * - #NM_LLDP_ATTR_IEEE_802_1_VID (type: 'u'). This attribute only reports the first VLAN
 *   and therefore it is deprecated in favor of NM_LLDP_ATTR_IEEE_802_1_VLANS which reports
 *   all the VLANs.
 * - #NM_LLDP_ATTR_IEEE_802_1_VLAN_NAME (type: 's'). This attribute only reports the first VLAN
 *   and therefore it is deprecated in favor of NM_LLDP_ATTR_IEEE_802_1_VLANS which reports
 *   all the VLANs.
 * - #NM_LLDP_ATTR_IEEE_802_1_VLANS (type: 'aa{sv}')
 *
 *   An array of dictionaries where each element has keys:
 *   - name (type: 's')
 *   - vid (type: 'u')
 * - #NM_LLDP_ATTR_IEEE_802_3_MAC_PHY_CONF (type: 'a{sv}')
 *
 *   Dictionary where each element has keys:
 *   - autoneg (type: 'u')
 *   - operational-mau-type (type: 'u')
 *   - pmd-autoneg-cap (type: 'u')
 * - #NM_LLDP_ATTR_IEEE_802_3_MAX_FRAME_SIZE (type: 'u')
 * - #NM_LLDP_ATTR_IEEE_802_3_POWER_VIA_MDI (type: 'a{sv}')
 *
 *   Dictionary where each element has keys:
 *   - mdi-power-support (type: 'u')
 *   - power-class (type: 'u')
 *   - pse-power-pair (type: 'u')
 * - #NM_LLDP_ATTR_MANAGEMENT_ADDRESSES (type: 'aa{sv}')
 *
 *   An array of dictionaries where each element has keys:
 *   - address (type: 'ay')
 *   - address-subtype (type: 'u')
 *   - interface-number (type: 'u')
 *   - interface-number-subtype (type: 'u')
 *   - object-id (type: 'ay')
 * - #NM_LLDP_ATTR_PORT_DESCRIPTION (type: 's')
 * - #NM_LLDP_ATTR_PORT_ID_TYPE (type: 'u')
 * - #NM_LLDP_ATTR_PORT_ID (type: 's')
 * - #NM_LLDP_ATTR_RAW (type: 'ay')
 * - #NM_LLDP_ATTR_SYSTEM_CAPABILITIES (type: 'u')
 * - #NM_LLDP_ATTR_SYSTEM_DESCRIPTION (type: 's')
 * - #NM_LLDP_ATTR_SYSTEM_NAME (type: 's')
 **/
typedef struct _NMLldpNeighbor NMLldpNeighbor;

GType nm_device_get_type(void);

const char  *nm_device_get_iface(NMDevice *device);
const char  *nm_device_get_ip_iface(NMDevice *device);
NMDeviceType nm_device_get_device_type(NMDevice *device);
const char  *nm_device_get_udi(NMDevice *device);
NM_AVAILABLE_IN_1_26
const char          *nm_device_get_path(NMDevice *device);
const char          *nm_device_get_driver(NMDevice *device);
const char          *nm_device_get_driver_version(NMDevice *device);
const char          *nm_device_get_firmware_version(NMDevice *device);
const char          *nm_device_get_type_description(NMDevice *device);
const char          *nm_device_get_hw_address(NMDevice *device);
NMDeviceCapabilities nm_device_get_capabilities(NMDevice *device);
gboolean             nm_device_get_managed(NMDevice *device);

NM_AVAILABLE_IN_1_34
const GPtrArray *nm_device_get_ports(NMDevice *device);

NM_AVAILABLE_IN_1_2
NM_DEPRECATED_IN_1_22
_NM_DEPRECATED_SYNC_METHOD
void nm_device_set_managed(NMDevice *device, gboolean managed);

gboolean nm_device_get_autoconnect(NMDevice *device);

NM_DEPRECATED_IN_1_22
_NM_DEPRECATED_SYNC_METHOD
void nm_device_set_autoconnect(NMDevice *device, gboolean autoconnect);

gboolean nm_device_get_firmware_missing(NMDevice *device);
NM_AVAILABLE_IN_1_2
gboolean      nm_device_get_nm_plugin_missing(NMDevice *device);
NMIPConfig   *nm_device_get_ip4_config(NMDevice *device);
NMDhcpConfig *nm_device_get_dhcp4_config(NMDevice *device);
NMIPConfig   *nm_device_get_ip6_config(NMDevice *device);
NMDhcpConfig *nm_device_get_dhcp6_config(NMDevice *device);
NM_AVAILABLE_IN_1_16
NMConnectivityState nm_device_get_connectivity(NMDevice *device, int addr_family);
NMDeviceState       nm_device_get_state(NMDevice *device);
NMDeviceStateReason nm_device_get_state_reason(NMDevice *device);
NMActiveConnection *nm_device_get_active_connection(NMDevice *device);
const GPtrArray    *nm_device_get_available_connections(NMDevice *device);
const char         *nm_device_get_physical_port_id(NMDevice *device);
guint32             nm_device_get_mtu(NMDevice *device);
NM_AVAILABLE_IN_1_2
gboolean nm_device_is_real(NMDevice *device);
gboolean nm_device_is_software(NMDevice *device);

const char *nm_device_get_product(NMDevice *device);
const char *nm_device_get_vendor(NMDevice *device);
const char *nm_device_get_description(NMDevice *device);
NM_AVAILABLE_IN_1_2
NMMetered nm_device_get_metered(NMDevice *device);
NM_AVAILABLE_IN_1_2
GPtrArray *nm_device_get_lldp_neighbors(NMDevice *device);
NM_AVAILABLE_IN_1_22
NMDeviceInterfaceFlags nm_device_get_interface_flags(NMDevice *device);

char **nm_device_disambiguate_names(NMDevice **devices, int num_devices);
NM_AVAILABLE_IN_1_2
_NM_DEPRECATED_SYNC_METHOD
gboolean nm_device_reapply(NMDevice     *device,
                           NMConnection *connection,
                           guint64       version_id,
                           guint32       flags,
                           GCancellable *cancellable,
                           GError      **error);
NM_AVAILABLE_IN_1_2
void nm_device_reapply_async(NMDevice           *device,
                             NMConnection       *connection,
                             guint64             version_id,
                             guint32             flags,
                             GCancellable       *cancellable,
                             GAsyncReadyCallback callback,
                             gpointer            user_data);
NM_AVAILABLE_IN_1_2
gboolean nm_device_reapply_finish(NMDevice *device, GAsyncResult *result, GError **error);

NM_AVAILABLE_IN_1_2
_NM_DEPRECATED_SYNC_METHOD
NMConnection *nm_device_get_applied_connection(NMDevice     *device,
                                               guint32       flags,
                                               guint64      *version_id,
                                               GCancellable *cancellable,
                                               GError      **error);
NM_AVAILABLE_IN_1_2
void nm_device_get_applied_connection_async(NMDevice           *device,
                                            guint32             flags,
                                            GCancellable       *cancellable,
                                            GAsyncReadyCallback callback,
                                            gpointer            user_data);
NM_AVAILABLE_IN_1_2
NMConnection *nm_device_get_applied_connection_finish(NMDevice     *device,
                                                      GAsyncResult *result,
                                                      guint64      *version_id,
                                                      GError      **error);

_NM_DEPRECATED_SYNC_METHOD
gboolean nm_device_disconnect(NMDevice *device, GCancellable *cancellable, GError **error);
void     nm_device_disconnect_async(NMDevice           *device,
                                    GCancellable       *cancellable,
                                    GAsyncReadyCallback callback,
                                    gpointer            user_data);
gboolean nm_device_disconnect_finish(NMDevice *device, GAsyncResult *result, GError **error);

_NM_DEPRECATED_SYNC_METHOD
gboolean nm_device_delete(NMDevice *device, GCancellable *cancellable, GError **error);
void     nm_device_delete_async(NMDevice           *device,
                                GCancellable       *cancellable,
                                GAsyncReadyCallback callback,
                                gpointer            user_data);
gboolean nm_device_delete_finish(NMDevice *device, GAsyncResult *result, GError **error);

GPtrArray *nm_device_filter_connections(NMDevice *device, const GPtrArray *connections);

gboolean nm_device_connection_valid(NMDevice *device, NMConnection *connection);

gboolean
nm_device_connection_compatible(NMDevice *device, NMConnection *connection, GError **error);

GType nm_device_get_setting_type(NMDevice *device);

NM_AVAILABLE_IN_1_2
GType nm_lldp_neighbor_get_type(void);
NM_AVAILABLE_IN_1_2
void nm_lldp_neighbor_ref(NMLldpNeighbor *neighbor);
NM_AVAILABLE_IN_1_2
void nm_lldp_neighbor_unref(NMLldpNeighbor *neighbor);
NM_AVAILABLE_IN_1_2
char **nm_lldp_neighbor_get_attr_names(NMLldpNeighbor *neighbor);
NM_AVAILABLE_IN_1_18
GVariant *nm_lldp_neighbor_get_attr_value(NMLldpNeighbor *neighbor, const char *name);

NM_AVAILABLE_IN_1_2
NMLldpNeighbor *nm_lldp_neighbor_new(void);
NM_AVAILABLE_IN_1_2
gboolean nm_lldp_neighbor_get_attr_string_value(NMLldpNeighbor *neighbor,
                                                const char     *name,
                                                const char    **out_value);
NM_AVAILABLE_IN_1_2
gboolean
nm_lldp_neighbor_get_attr_uint_value(NMLldpNeighbor *neighbor, const char *name, guint *out_value);
NM_AVAILABLE_IN_1_2
const GVariantType *nm_lldp_neighbor_get_attr_type(NMLldpNeighbor *neighbor, const char *name);

G_END_DECLS

#endif /* __NM_DEVICE_H__ */
