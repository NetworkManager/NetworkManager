/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2019 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_SERVICE_PROVIDERS_H__
#define __NETWORKMANAGER_SERVICE_PROVIDERS_H__

typedef void (*NMServiceProvidersGsmApnCallback)(const char *  apn,
                                                 const char *  username,
                                                 const char *  password,
                                                 const char *  gateway,
                                                 const char *  auth_method,
                                                 const GSList *dns,
                                                 GError *      error,
                                                 gpointer      user_data);

void nm_service_providers_find_gsm_apn(const char *                     service_providers,
                                       const char *                     mccmnc,
                                       GCancellable *                   cancellable,
                                       NMServiceProvidersGsmApnCallback callback,
                                       gpointer                         user_data);

#endif /* __NETWORKMANAGER_SERVICE_PROVIDERS_H__ */
