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
 * Copyright 2018 Red Hat, Inc.
 */

#ifndef __NM_SETTING_WIREGUARD_H__
#define __NM_SETTING_WIREGUARD_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

/*****************************************************************************/

#define NM_WIREGUARD_PUBLIC_KEY_LEN     32
#define NM_WIREGUARD_SYMMETRIC_KEY_LEN  32

/*****************************************************************************/

#define NM_TYPE_SETTING_WIREGUARD            (nm_setting_wireguard_get_type ())
#define NM_SETTING_WIREGUARD(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_WIREGUARD, NMSettingWireGuard))
#define NM_SETTING_WIREGUARD_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_WIREGUARD, NMSettingWireGuardClass))
#define NM_IS_SETTING_WIREGUARD(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_WIREGUARD))
#define NM_IS_SETTING_WIREGUARD_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_WIREGUARD))
#define NM_SETTING_WIREGUARD_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_WIREGUARD, NMSettingWireGuardClass))

#define NM_SETTING_WIREGUARD_SETTING_NAME "wireguard"

#define NM_SETTING_WIREGUARD_PRIVATE_KEY       "private-key"
#define NM_SETTING_WIREGUARD_PRIVATE_KEY_FLAGS "private-key-flags"
#define NM_SETTING_WIREGUARD_LISTEN_PORT       "listen-port"
#define NM_SETTING_WIREGUARD_FWMARK            "fwmark"

/*****************************************************************************/

typedef struct _NMSettingWireGuardClass NMSettingWireGuardClass;

NM_AVAILABLE_IN_1_16
GType nm_setting_wireguard_get_type (void);

NM_AVAILABLE_IN_1_16
NMSetting        *nm_setting_wireguard_new (void);

/*****************************************************************************/

NM_AVAILABLE_IN_1_16
const char *nm_setting_wireguard_get_private_key (NMSettingWireGuard *self);

NM_AVAILABLE_IN_1_16
NMSettingSecretFlags nm_setting_wireguard_get_private_key_flags (NMSettingWireGuard *self);

NM_AVAILABLE_IN_1_16
guint16 nm_setting_wireguard_get_listen_port (NMSettingWireGuard *self);

NM_AVAILABLE_IN_1_16
guint32 nm_setting_wireguard_get_fwmark (NMSettingWireGuard *self);

/*****************************************************************************/

G_END_DECLS

#endif /* __NM_SETTING_WIREGUARD_H__ */
