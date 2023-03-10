/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-client-aux-extern/nm-default-client.h"

#include "nm-cloud-setup-utils.h"

#include <linux/if_ether.h>
#include <linux/if_infiniband.h>

#include "libnm-glib-aux/nm-time-utils.h"
#include "libnm-glib-aux/nm-logging-base.h"
#include "libnm-glib-aux/nm-str-buf.h"

/*****************************************************************************/

G_LOCK_DEFINE_STATIC(_wait_for_objects_lock);
static GSList *_wait_for_objects_list;
static GSList *_wait_for_objects_iterate_loops;

static void
_wait_for_objects_maybe_quit_mainloops_with_lock(void)
{
    GSList *iter;

    if (!_wait_for_objects_list) {
        for (iter = _wait_for_objects_iterate_loops; iter; iter = iter->next)
            g_main_loop_quit(iter->data);
    }
}

static void
_wait_for_objects_weak_cb(gpointer data, GObject *where_the_object_was)
{
    G_LOCK(_wait_for_objects_lock);
    nm_assert(g_slist_find(_wait_for_objects_list, where_the_object_was));
    _wait_for_objects_list = g_slist_remove(_wait_for_objects_list, where_the_object_was);
    _wait_for_objects_maybe_quit_mainloops_with_lock();
    G_UNLOCK(_wait_for_objects_lock);
}

/**
 * nmcs_wait_for_objects_register:
 * @target: a #GObject to wait for.
 *
 * Registers @target as a pointer to wait during shutdown. Using
 * nmcs_wait_for_objects_iterate_until_done() we keep waiting until
 * @target gets destroyed, which means that it gets completely unreferenced.
 */
gpointer
nmcs_wait_for_objects_register(gpointer target)
{
    g_return_val_if_fail(G_IS_OBJECT(target), NULL);

    G_LOCK(_wait_for_objects_lock);
    _wait_for_objects_list = g_slist_prepend(_wait_for_objects_list, target);
    G_UNLOCK(_wait_for_objects_lock);

    g_object_weak_ref(target, _wait_for_objects_weak_cb, NULL);
    return target;
}

typedef struct {
    GMainLoop *loop;
    gboolean   got_timeout;
} WaitForObjectsData;

static gboolean
_wait_for_objects_iterate_until_done_timeout_cb(gpointer user_data)
{
    WaitForObjectsData *data = user_data;

    data->got_timeout = TRUE;
    g_main_loop_quit(data->loop);
    return G_SOURCE_CONTINUE;
}

static gboolean
_wait_for_objects_iterate_until_done_idle_cb(gpointer user_data)
{
    /* This avoids a race where:
     *
     *   - we check whether there are objects to wait for.
     *   - the last object to wait for gets removed (issuing g_main_loop_quit()).
     *   - we run the mainloop (and missed our signal).
     *
     * It's really a missing feature of GMainLoop where the "is-running" flag is always set to
     * TRUE by g_main_loop_run(). That means, you cannot catch a g_main_loop_quit() in a race
     * free way while not iterating the loop.
     *
     * Avoid this, by checking once again after we start running the mainloop.
     */

    G_LOCK(_wait_for_objects_lock);
    _wait_for_objects_maybe_quit_mainloops_with_lock();
    G_UNLOCK(_wait_for_objects_lock);
    return G_SOURCE_REMOVE;
}

/**
 * nmcs_wait_for_objects_iterate_until_done:
 * @context: the #GMainContext to iterate.
 * @timeout_msec: timeout or -1 for no timeout.
 *
 * Iterates the provided @context until all objects that we wait for
 * are destroyed.
 *
 * The purpose of this is to cleanup all objects that we have on exit. That
 * is especially because objects have asynchronous operations pending that
 * should be cancelled and properly completed during exit.
 *
 * Returns: %FALSE on timeout or %TRUE if all objects destroyed before timeout.
 */
gboolean
nmcs_wait_for_objects_iterate_until_done(GMainContext *context, int timeout_msec)
{
    nm_auto_unref_gmainloop GMainLoop         *loop           = g_main_loop_new(context, FALSE);
    nm_auto_destroy_and_unref_gsource GSource *timeout_source = NULL;
    WaitForObjectsData                         data;
    gboolean                                   has_more_objects;

    G_LOCK(_wait_for_objects_lock);
    if (!_wait_for_objects_list) {
        G_UNLOCK(_wait_for_objects_lock);
        return TRUE;
    }
    _wait_for_objects_iterate_loops = g_slist_prepend(_wait_for_objects_iterate_loops, loop);
    G_UNLOCK(_wait_for_objects_lock);

    data = (WaitForObjectsData){
        .loop        = loop,
        .got_timeout = FALSE,
    };

    if (timeout_msec >= 0) {
        timeout_source = nm_g_source_attach(
            nm_g_timeout_source_new(timeout_msec,
                                    G_PRIORITY_DEFAULT,
                                    _wait_for_objects_iterate_until_done_timeout_cb,
                                    &data,
                                    NULL),
            context);
    }

    has_more_objects = TRUE;
    while (has_more_objects && !data.got_timeout) {
        nm_auto_destroy_and_unref_gsource GSource *idle_source = NULL;

        idle_source =
            nm_g_source_attach(nm_g_idle_source_new(G_PRIORITY_DEFAULT_IDLE,
                                                    _wait_for_objects_iterate_until_done_idle_cb,
                                                    &data,
                                                    NULL),
                               context);

        g_main_loop_run(loop);

        G_LOCK(_wait_for_objects_lock);
        has_more_objects = (!!_wait_for_objects_list);
        if (data.got_timeout || !has_more_objects)
            _wait_for_objects_iterate_loops = g_slist_remove(_wait_for_objects_iterate_loops, loop);
        G_UNLOCK(_wait_for_objects_lock);
    }

    return !data.got_timeout;
}

/*****************************************************************************/

char *
nmcs_utils_hwaddr_normalize(const char *hwaddr, gssize len)
{
    gs_free char *hwaddr_clone = NULL;
    char         *hw;
    guint8        buf[ETH_ALEN];
    gsize         l;

    nm_assert(len >= -1);

    if (len < 0) {
        if (!hwaddr)
            return NULL;
        l = strlen(hwaddr);
    } else {
        l = len;
        if (l > 0 && hwaddr[l - 1] == '\0') {
            /* we accept one '\0' at the end of the string. */
            l--;
        }
        if (memchr(hwaddr, '\0', l)) {
            /* but we don't accept other NUL characters in the middle. */
            return NULL;
        }
    }

    if (l == 0)
        return NULL;

    nm_assert(hwaddr);
    hw = nm_strndup_a(300, hwaddr, l, &hwaddr_clone);

    g_strstrip(hw);

    /* we cannot use _nm_utils_hwaddr_aton() because that requires a delimiter.
     * Azure exposes MAC addresses without delimiter, so accept that too. */
    if (!nm_utils_hexstr2bin_full(hw,
                                  FALSE,
                                  FALSE,
                                  FALSE,
                                  ":-",
                                  sizeof(buf),
                                  buf,
                                  sizeof(buf),
                                  NULL))
        return NULL;

    return nm_utils_hwaddr_ntoa(buf, sizeof(buf));
}

/*****************************************************************************/

gboolean
nmcs_utils_ipaddr_normalize_bin(int         addr_family,
                                const char *addr,
                                gssize      len,
                                int        *out_addr_family,
                                gpointer    out_addr_bin)
{
    gs_free char *addr_clone = NULL;
    char         *ad;
    gsize         l;

    nm_assert(len >= -1);

    if (len < 0) {
        if (!addr)
            return FALSE;
        l = strlen(addr);
    } else {
        l = len;
        if (l > 0 && addr[l - 1] == '\0') {
            /* we accept one '\0' at the end of the string. */
            l--;
        }
        if (memchr(addr, '\0', l)) {
            /* but we don't accept other NUL characters in the middle. */
            return FALSE;
        }
    }

    if (l == 0)
        return FALSE;

    nm_assert(addr);
    ad = nm_strndup_a(300, addr, l, &addr_clone);

    g_strstrip(ad);

    return nm_inet_parse_bin(addr_family, ad, out_addr_family, out_addr_bin);
}

char *
nmcs_utils_ipaddr_normalize(int addr_family, const char *addr, gssize len)
{
    NMIPAddr ipaddr;

    if (!nmcs_utils_ipaddr_normalize_bin(addr_family, addr, len, &addr_family, &ipaddr))
        return NULL;

    return nm_inet_ntop_dup(addr_family, &ipaddr);
}

/*****************************************************************************/

const char *
nmcs_utils_parse_memmem(GBytes *mem, const char *needle)
{
    const char *mem_data;
    gsize       mem_size;

    g_return_val_if_fail(mem, NULL);
    g_return_val_if_fail(needle, NULL);

    mem_data = g_bytes_get_data(mem, &mem_size);
    return memmem(mem_data, mem_size, needle, strlen(needle));
}

const char *
nmcs_utils_parse_get_full_line(GBytes *mem, const char *needle)
{
    const char *mem_data;
    gsize       mem_size;
    gsize       c;
    gsize       l;

    const char *line;

    line = nmcs_utils_parse_memmem(mem, needle);
    if (!line)
        return NULL;

    mem_data = g_bytes_get_data(mem, &mem_size);

    if (line != mem_data && line[-1] != '\n') {
        /* the line must be preceeded either by the begin of the data or
         * by a newline. */
        return NULL;
    }

    c = mem_size - (line - mem_data);
    l = strlen(needle);

    if (c != l && line[l] != '\n') {
        /* the end of the needle must be either a newline or the end of the buffer. */
        return NULL;
    }

    return line;
}

/*****************************************************************************/

char *
nmcs_utils_uri_build_concat_v(const char *base, const char **components, gsize n_components)
{
    NMStrBuf strbuf = NM_STR_BUF_INIT(NM_UTILS_GET_NEXT_REALLOC_SIZE_104, FALSE);

    nm_assert(base);
    nm_assert(base[0]);
    nm_assert(!NM_STR_HAS_SUFFIX(base, "/"));

    nm_str_buf_append(&strbuf, base);

    if (n_components > 0 && components[0] && components[0][0] == '/') {
        /* the first component starts with a slash. We allow that, and don't add a duplicate
         * slash. Otherwise, we add a separator after base.
         *
         * We only do that for the first component. */
    } else
        nm_str_buf_append_c(&strbuf, '/');

    while (n_components > 0) {
        if (!components[0]) {
            /* we allow NULL, to indicate nothing to append */
        } else
            nm_str_buf_append(&strbuf, components[0]);
        components++;
        n_components--;
    }

    return nm_str_buf_finalize(&strbuf, NULL);
}

const char *
nmcs_utils_uri_complete_interned(const char *uri)
{
    gs_free char *s = NULL;

    if (nm_str_is_empty(uri))
        return NULL;
    if (NM_STR_HAS_PREFIX(uri, "http://") || NM_STR_HAS_PREFIX(uri, "https://") || strchr(uri, '/'))
        return g_intern_string(uri);

    s = g_strconcat("http://", uri, NULL);
    return g_intern_string(s);
}

/*****************************************************************************/

gboolean
nmcs_setting_ip_replace_ipv4_addresses(NMSettingIPConfig *s_ip,
                                       NMIPAddress      **entries_arr,
                                       guint              entries_len)
{
    gboolean any_changes = FALSE;
    guint    i_next;
    guint    num;
    guint    i;

    num = nm_setting_ip_config_get_num_addresses(s_ip);

    i_next = 0;

    for (i = 0; i < entries_len; i++) {
        NMIPAddress *entry = entries_arr[i];

        if (!any_changes) {
            if (i_next < num) {
                if (nm_ip_address_cmp_full(entry,
                                           nm_setting_ip_config_get_address(s_ip, i_next),
                                           NM_IP_ADDRESS_CMP_FLAGS_WITH_ATTRS)
                    == 0) {
                    i_next++;
                    continue;
                }
            }
            while (i_next < num)
                nm_setting_ip_config_remove_address(s_ip, --num);
            any_changes = TRUE;
        }

        if (!nm_setting_ip_config_add_address(s_ip, entry))
            continue;

        i_next++;
    }
    if (!any_changes) {
        while (i_next < num) {
            nm_setting_ip_config_remove_address(s_ip, --num);
            any_changes = TRUE;
        }
    }

    return any_changes;
}

gboolean
nmcs_setting_ip_replace_ipv4_routes(NMSettingIPConfig *s_ip,
                                    NMIPRoute        **entries_arr,
                                    guint              entries_len)
{
    gboolean any_changes = FALSE;
    guint    i_next;
    guint    num;
    guint    i;

    num = nm_setting_ip_config_get_num_routes(s_ip);

    i_next = 0;

    for (i = 0; i < entries_len; i++) {
        NMIPRoute *entry = entries_arr[i];

        if (!any_changes) {
            if (i_next < num) {
                if (nm_ip_route_equal_full(entry,
                                           nm_setting_ip_config_get_route(s_ip, i_next),
                                           NM_IP_ROUTE_EQUAL_CMP_FLAGS_WITH_ATTRS)) {
                    i_next++;
                    continue;
                }
            }
            while (i_next < num)
                nm_setting_ip_config_remove_route(s_ip, --num);
            any_changes = TRUE;
        }

        if (!nm_setting_ip_config_add_route(s_ip, entry))
            continue;

        i_next++;
    }
    if (!any_changes) {
        while (i_next < num) {
            nm_setting_ip_config_remove_route(s_ip, --num);
            any_changes = TRUE;
        }
    }

    return any_changes;
}

gboolean
nmcs_setting_ip_replace_ipv4_rules(NMSettingIPConfig *s_ip,
                                   NMIPRoutingRule  **entries_arr,
                                   guint              entries_len)
{
    gboolean any_changes = FALSE;
    guint    i_next;
    guint    num;
    guint    i;

    num = nm_setting_ip_config_get_num_routing_rules(s_ip);

    i_next = 0;

    for (i = 0; i < entries_len; i++) {
        NMIPRoutingRule *entry = entries_arr[i];

        if (!any_changes) {
            if (i_next < num) {
                if (nm_ip_routing_rule_cmp(entry,
                                           nm_setting_ip_config_get_routing_rule(s_ip, i_next))
                    == 0) {
                    i_next++;
                    continue;
                }
            }
            while (i_next < num)
                nm_setting_ip_config_remove_routing_rule(s_ip, --num);
            any_changes = TRUE;
        }

        nm_setting_ip_config_add_routing_rule(s_ip, entry);
        i_next++;
    }
    if (!any_changes) {
        while (i_next < num) {
            nm_setting_ip_config_remove_routing_rule(s_ip, --num);
            any_changes = TRUE;
        }
    }

    return any_changes;
}

/*****************************************************************************/

typedef struct {
    GMainLoop    *main_loop;
    NMConnection *connection;
    GError       *error;
    guint64       version_id;
} DeviceGetAppliedConnectionData;

static void
_nmcs_device_get_applied_connection_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    DeviceGetAppliedConnectionData *data = user_data;

    data->connection = nm_device_get_applied_connection_finish(NM_DEVICE(source),
                                                               result,
                                                               &data->version_id,
                                                               &data->error);
    g_main_loop_quit(data->main_loop);
}

NMConnection *
nmcs_device_get_applied_connection(NMDevice     *device,
                                   GCancellable *cancellable,
                                   guint64      *version_id,
                                   GError      **error)
{
    nm_auto_unref_gmainloop GMainLoop *main_loop = g_main_loop_new(NULL, FALSE);
    DeviceGetAppliedConnectionData     data      = {
                 .main_loop = main_loop,
    };

    nm_device_get_applied_connection_async(device,
                                           0,
                                           cancellable,
                                           _nmcs_device_get_applied_connection_cb,
                                           &data);

    g_main_loop_run(main_loop);

    if (data.error)
        g_propagate_error(error, data.error);
    NM_SET_OUT(version_id, data.version_id);
    return data.connection;
}

/*****************************************************************************/

typedef struct {
    GMainLoop *main_loop;
    GError    *error;
} DeviceReapplyData;

static void
_nmcs_device_reapply_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    DeviceReapplyData *data = user_data;

    nm_device_reapply_finish(NM_DEVICE(source), result, &data->error);
    g_main_loop_quit(data->main_loop);
}

gboolean
nmcs_device_reapply(NMDevice     *device,
                    GCancellable *sigterm_cancellable,
                    NMConnection *connection,
                    guint64       version_id,
                    gboolean      maybe_no_preserved_external_ip,
                    gboolean     *out_version_id_changed,
                    GError      **error)
{
    nm_auto_unref_gmainloop GMainLoop *main_loop = g_main_loop_new(NULL, FALSE);
    DeviceReapplyData                  data      = {
                              .main_loop = main_loop,
    };
    NMDeviceReapplyFlags reapply_flags = NM_DEVICE_REAPPLY_FLAGS_PRESERVE_EXTERNAL_IP;

again:
    nm_device_reapply_async(device,
                            connection,
                            version_id,
                            reapply_flags,
                            sigterm_cancellable,
                            _nmcs_device_reapply_cb,
                            &data);

    g_main_loop_run(main_loop);

    if (data.error) {
        if (maybe_no_preserved_external_ip
            && reapply_flags == NM_DEVICE_REAPPLY_FLAGS_PRESERVE_EXTERNAL_IP
            && nm_g_error_matches(data.error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED)) {
            /* Hm? Maybe we running against an older version of NetworkManager that
             * doesn't support "preserve-external-ip" flags? Retry without the flag.
             *
             * Note that recent version would reject invalid flags with NM_DEVICE_ERROR_INVALID_ARGUMENT,
             * but we want to detect old daemon versions here. */
            reapply_flags = NM_DEVICE_REAPPLY_FLAGS_NONE;
            goto again;
        }
        NM_SET_OUT(
            out_version_id_changed,
            g_error_matches(data.error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_VERSION_ID_MISMATCH));
        g_propagate_error(error, data.error);
        return FALSE;
    }

    NM_SET_OUT(out_version_id_changed, FALSE);
    return TRUE;
}
