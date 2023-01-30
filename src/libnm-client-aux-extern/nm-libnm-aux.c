/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-client-aux-extern/nm-default-client.h"

#include "nm-libnm-aux.h"

#include "libnm-glib-aux/nm-random-utils.h"

/*****************************************************************************/

NMClient *
nmc_client_new_async_valist(GCancellable       *cancellable,
                            GAsyncReadyCallback callback,
                            gpointer            user_data,
                            const char         *first_property_name,
                            va_list             ap)
{
    NMClient *nmc;

    nmc = NM_CLIENT(g_object_new_valist(NM_TYPE_CLIENT, first_property_name, ap));
    g_async_initable_init_async(G_ASYNC_INITABLE(nmc),
                                G_PRIORITY_DEFAULT,
                                cancellable,
                                callback,
                                user_data);
    return nmc;
}

NMClient *
nmc_client_new_async(GCancellable       *cancellable,
                     GAsyncReadyCallback callback,
                     gpointer            user_data,
                     const char         *first_property_name,
                     ...)
{
    NMClient *nmc;
    va_list   ap;

    va_start(ap, first_property_name);
    nmc = nmc_client_new_async_valist(cancellable, callback, user_data, first_property_name, ap);
    va_end(ap);
    return nmc;
}

/*****************************************************************************/

typedef struct {
    GMainLoop *main_loop;
    NMClient  *nmc;
    GError    *error;
} ClientCreateData;

static void
_nmc_client_new_waitsync_cb(GObject *source_object, GAsyncResult *result, gpointer user_data)
{
    ClientCreateData *data = user_data;

    g_async_initable_init_finish(G_ASYNC_INITABLE(source_object), result, &data->error);
    g_main_loop_quit(data->main_loop);
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
nmc_client_new_waitsync(GCancellable *cancellable,
                        NMClient    **out_nmc,
                        GError      **error,
                        const char   *first_property_name,
                        ...)
{
    gs_unref_object NMClient          *nmc = NULL;
    nm_auto_unref_gmainloop GMainLoop *main_loop =
        g_main_loop_new(g_main_context_get_thread_default(), FALSE);
    ClientCreateData data = {
        .main_loop = main_loop,
    };
    va_list ap;

#if NM_MORE_ASSERTS > 10
    /* The sync initialization of NMClient is generally a bad idea, because it
     * brings the overhead of an additional GMainContext. Anyway, since our own
     * code no longer uses that, we hardly test those code paths. But they should
     * work just the same. Randomly use instead the sync initialization in a debug
     * build... */
    if (nm_random_bool()) {
        gboolean success;

        va_start(ap, first_property_name);
        nmc = NM_CLIENT(g_object_new_valist(NM_TYPE_CLIENT, first_property_name, ap));
        va_end(ap);

        /* iterate the context at least once, just so that the behavior from POV of the
         * caller is roughly the same. */
        g_main_context_iteration(nm_client_get_main_context(nmc), FALSE);

        success = g_initable_init(G_INITABLE(nmc), cancellable, error);
        NM_SET_OUT(out_nmc, g_steal_pointer(&nmc));
        return success;
    }
#endif

    va_start(ap, first_property_name);
    nmc = nmc_client_new_async_valist(cancellable,
                                      _nmc_client_new_waitsync_cb,
                                      &data,
                                      first_property_name,
                                      ap);
    va_end(ap);

    g_main_loop_run(main_loop);

    NM_SET_OUT(out_nmc, g_steal_pointer(&nmc));
    if (data.error) {
        g_propagate_error(error, data.error);
        return FALSE;
    }
    return TRUE;
}

/*****************************************************************************/

guint32
nmc_client_has_version_info_v(NMClient *nmc)
{
    const guint32 *ver;
    gsize          len;

    ver = nm_client_get_version_info(nmc, &len);
    if (len < 1)
        return 0;
    return ver[0];
}

gboolean
nmc_client_has_version_info_capability(NMClient *nmc, NMVersionInfoCapability capability)
{
    const guint32 *ver;
    gsize          len;
    gsize          idx;
    gsize          idx_hi;
    gsize          idx_lo;

    ver = nm_client_get_version_info(nmc, &len);

    if (len < 2)
        return FALSE;

    len--;
    ver++;

    idx = (gsize) capability;
    if (idx >= G_MAXSIZE - 31u)
        return FALSE;

    idx_hi = ((idx + 31u) / 32u);
    idx_lo = (idx % 32u);

    if (idx_hi > len)
        return FALSE;

    return NM_FLAGS_ANY(ver[idx_hi], (1ull << idx_lo));
}

gboolean
nmc_client_has_capability(NMClient *nmc, NMCapability capability)
{
    const guint32 *caps;
    gsize          len;
    gsize          i;

    caps = nm_client_get_capabilities(nmc, &len);

    for (i = 0; i < len; i++) {
        if (caps[i] == capability)
            return TRUE;
    }

    return FALSE;
}
