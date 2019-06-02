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
 * Copyright 2014 - 2015 Red Hat, Inc.
 */

#include "NetworkManager.h"

#include "nm-utils/nm-test-utils.h"

typedef struct {
	GDBusConnection *bus;
	GDBusProxy *proxy;
	GPid pid;
	int keepalive_fd;
} NMTstcServiceInfo;

NMTstcServiceInfo *nmtstc_service_init (void);
void nmtstc_service_cleanup (NMTstcServiceInfo *info);
NMTstcServiceInfo *nmtstc_service_available (NMTstcServiceInfo *info);

static inline void _nmtstc_auto_service_cleanup (NMTstcServiceInfo **info)
{
	nmtstc_service_cleanup (g_steal_pointer (info));
}
#define nmtstc_auto_service_cleanup nm_auto(_nmtstc_auto_service_cleanup)

#define NMTSTC_SERVICE_INFO_SETUP(sinfo) \
	NM_PRAGMA_WARNING_DISABLE ("-Wunused-variable") \
	nmtstc_auto_service_cleanup NMTstcServiceInfo *sinfo = ({ \
		NMTstcServiceInfo *_sinfo; \
		\
		_sinfo = nmtstc_service_init (); \
		if (!nmtstc_service_available (_sinfo)) \
			return; \
		_sinfo; \
	}); \
	NM_PRAGMA_WARNING_REENABLE

NMDevice *nmtstc_service_add_device (NMTstcServiceInfo *info,
                                     NMClient *client,
                                     const char *method,
                                     const char *ifname);

NMDevice * nmtstc_service_add_wired_device (NMTstcServiceInfo *sinfo,
                                            NMClient *client,
                                            const char *ifname,
                                            const char *hwaddr,
                                            const char **subchannels);

void nmtstc_service_add_connection (NMTstcServiceInfo *sinfo,
                                    NMConnection *connection,
                                    gboolean verify_connection,
                                    char **out_path);

void nmtstc_service_add_connection_variant (NMTstcServiceInfo *sinfo,
                                            GVariant *connection,
                                            gboolean verify_connection,
                                            char **out_path);

void nmtstc_service_update_connection (NMTstcServiceInfo *sinfo,
                                       const char *path,
                                       NMConnection *connection,
                                       gboolean verify_connection);

void nmtstc_service_update_connection_variant (NMTstcServiceInfo *sinfo,
                                               const char *path,
                                               GVariant *connection,
                                               gboolean verify_connection);

