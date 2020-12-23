/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2014 - 2015 Red Hat, Inc.
 */

#ifndef __NM_TEST_LIBNM_UTILS_H__
#define __NM_TEST_LIBNM_UTILS_H__

#include "NetworkManager.h"

#include "nm-utils/nm-test-utils.h"

typedef struct {
    GDBusConnection *bus;
    GDBusProxy *     proxy;
    GPid             pid;
    int              keepalive_fd;
} NMTstcServiceInfo;

NMTstcServiceInfo *nmtstc_service_init(void);
void               nmtstc_service_cleanup(NMTstcServiceInfo *info);
NMTstcServiceInfo *nmtstc_service_available(NMTstcServiceInfo *info);

static inline void
_nmtstc_auto_service_cleanup(NMTstcServiceInfo **info)
{
    nmtstc_service_cleanup(g_steal_pointer(info));
}
#define nmtstc_auto_service_cleanup nm_auto(_nmtstc_auto_service_cleanup)

#define NMTSTC_SERVICE_INFO_SETUP(sinfo)                      \
    NM_PRAGMA_WARNING_DISABLE("-Wunused-variable")            \
    nmtstc_auto_service_cleanup NMTstcServiceInfo *sinfo = ({ \
        NMTstcServiceInfo *_sinfo;                            \
                                                              \
        _sinfo = nmtstc_service_init();                       \
        if (!nmtstc_service_available(_sinfo))                \
            return;                                           \
        _sinfo;                                               \
    });                                                       \
    NM_PRAGMA_WARNING_REENABLE

NMDevice *nmtstc_service_add_device(NMTstcServiceInfo *info,
                                    NMClient *         client,
                                    const char *       method,
                                    const char *       ifname);

NMDevice *nmtstc_service_add_wired_device(NMTstcServiceInfo *sinfo,
                                          NMClient *         client,
                                          const char *       ifname,
                                          const char *       hwaddr,
                                          const char **      subchannels);

void nmtstc_service_add_connection(NMTstcServiceInfo *sinfo,
                                   NMConnection *     connection,
                                   gboolean           verify_connection,
                                   char **            out_path);

void nmtstc_service_add_connection_variant(NMTstcServiceInfo *sinfo,
                                           GVariant *         connection,
                                           gboolean           verify_connection,
                                           char **            out_path);

void nmtstc_service_update_connection(NMTstcServiceInfo *sinfo,
                                      const char *       path,
                                      NMConnection *     connection,
                                      gboolean           verify_connection);

void nmtstc_service_update_connection_variant(NMTstcServiceInfo *sinfo,
                                              const char *       path,
                                              GVariant *         connection,
                                              gboolean           verify_connection);

gpointer nmtstc_context_object_new_valist(GType       gtype,
                                          gboolean    allow_iterate_main_context,
                                          const char *first_property_name,
                                          va_list     var_args);

gpointer nmtstc_context_object_new(GType       gtype,
                                   gboolean    allow_iterate_main_context,
                                   const char *first_property_name,
                                   ...);

static inline NMClient *
nmtstc_client_new(gboolean allow_iterate_main_context)
{
    return nmtstc_context_object_new(NM_TYPE_CLIENT, allow_iterate_main_context, NULL);
}

#endif /* __NM_TEST_LIBNM_UTILS_H__ */
