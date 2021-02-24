/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_LIBNM_AUX_H__
#define __NM_LIBNM_AUX_H__

NMClient *nmc_client_new_async_valist(GCancellable *      cancellable,
                                      GAsyncReadyCallback callback,
                                      gpointer            user_data,
                                      const char *        first_property_name,
                                      va_list             ap);

NMClient *nmc_client_new_async(GCancellable *      cancellable,
                               GAsyncReadyCallback callback,
                               gpointer            user_data,
                               const char *        first_property_name,
                               ...);

gboolean nmc_client_new_waitsync(GCancellable *cancellable,
                                 NMClient **   out_nmc,
                                 GError **     error,
                                 const char *  first_property_name,
                                 ...);

#endif /* __NM_LIBNM_AUX_H__ */
