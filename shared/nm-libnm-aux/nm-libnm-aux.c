// SPDX-License-Identifier: LGPL-2.1+

#include "nm-default.h"

#include "nm-libnm-aux.h"

/*****************************************************************************/

NMClient *
nmc_client_new_async_valist (GCancellable *cancellable,
                             GAsyncReadyCallback callback,
                             gpointer user_data,
                             const char *first_property_name,
                             va_list ap)
{
	NMClient *nmc;

	nmc = NM_CLIENT (g_object_new_valist (NM_TYPE_CLIENT, first_property_name, ap));
	g_async_initable_init_async (G_ASYNC_INITABLE (nmc),
	                             G_PRIORITY_DEFAULT,
	                             cancellable,
	                             callback,
	                             user_data);
	return nmc;
}

NMClient *
nmc_client_new_async (GCancellable *cancellable,
                      GAsyncReadyCallback callback,
                      gpointer user_data,
                      const char *first_property_name,
                      ...)
{
	NMClient *nmc;
	va_list ap;

	va_start (ap, first_property_name);
	nmc = nmc_client_new_async_valist (cancellable,
	                                   callback,
	                                   user_data,
	                                   first_property_name,
	                                   ap);
	va_end (ap);
	return nmc;
}

/*****************************************************************************/

typedef struct {
	GMainLoop *main_loop;
	NMClient *nmc;
	GError *error;
} ClientCreateData;

static void
_nmc_client_new_waitsync_cb (GObject *source_object,
                             GAsyncResult *result,
                             gpointer user_data)
{
	ClientCreateData *data = user_data;

	g_async_initable_init_finish (G_ASYNC_INITABLE (source_object),
	                              result,
	                              &data->error);
	g_main_loop_quit (data->main_loop);
}

/**
 * nmc_client_new:
 * @cancellable: the cancellable to abort the creation.
 * @out_nmc: (out): (transfer full): if give, transfers a reference
 *   to the NMClient instance. Note that this never fails to create
 *   the NMClient GObject, but depending on the return value,
 *   the instance was successfully initialized or not.
 * @error: the error if creation fails.
 * @first_property_name: the name of the first property
 * @...: the value of the first property, followed optionally by more
 *  name/value pairs, followed by %NULL
 *
 * Returns: %TRUE, if the client was successfully initalized.
 *
 * This uses nm_client_new_async() to create a NMClient instance,
 * but it iterates the current GMainContext until the client is
 * ready. As such, it waits for the client creation to complete
 * (like sync nm_client_new()) but it iterates the caller's GMainContext
 * (unlike sync nm_client_new()). This is often preferable, because
 * sync nm_client_new() needs to create an additional internal GMainContext
 * that it can iterate instead. That has a performance overhead that
 * is often unnecessary.
 */
gboolean
nmc_client_new_waitsync (GCancellable *cancellable,
                         NMClient **out_nmc,
                         GError **error,
                         const char *first_property_name,
                         ...)
{
	gs_unref_object NMClient *nmc = NULL;
	nm_auto_unref_gmainloop GMainLoop *main_loop = g_main_loop_new (g_main_context_get_thread_default (), FALSE);
	ClientCreateData data = {
		.main_loop = main_loop,
	};
	va_list ap;

	va_start (ap, first_property_name);
	nmc = nmc_client_new_async_valist (cancellable,
	                                   _nmc_client_new_waitsync_cb,
	                                   &data,
	                                   first_property_name,
	                                   ap);
	va_end (ap);

	g_main_loop_run (main_loop);

	NM_SET_OUT (out_nmc, g_steal_pointer (&nmc));
	if (data.error) {
		g_propagate_error (error, data.error);
		return FALSE;
	}
	return TRUE;
}
