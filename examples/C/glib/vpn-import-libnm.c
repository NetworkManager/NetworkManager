/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The example shows how to import VPN connection from a file.
 *
 * @author: Jagadeesh Kotra <jagadeesh@stdin.top>
 *
 * Compile with:
 *   gcc -Wall vpn-import-libnm.c -o vpn-import-libnm `pkg-config --cflags --libs libnm`
 */

#include <glib.h>
#include <NetworkManager.h>

/*****************************************************************************/

static NMConnection *
vpn_connection_import(const char *filename)
{
    NMConnection *conn = NULL;
    GSList *      plugins;
    GSList *      iter;

    g_print("Try to import file \"%s\"...\n", filename);

    plugins = nm_vpn_plugin_info_list_load();

    for (iter = plugins; iter; iter = iter->next) {
        GError *           error  = NULL;
        NMVpnPluginInfo *  plugin = iter->data;
        NMVpnEditorPlugin *editor;
        const char *       plugin_name = nm_vpn_plugin_info_get_name(plugin);

        g_print("plugin[%s]: trying import...\n", plugin_name);

        editor = nm_vpn_plugin_info_load_editor_plugin(plugin, &error);
        if (error) {
            g_print("plugin[%s]: error loading plugin: %s\n", plugin_name, error->message);
            g_clear_error(&error);
            continue;
        }

        conn = nm_vpn_editor_plugin_import(editor, filename, &error);
        if (error) {
            g_print("plugin[%s]: error importing file: %s\n", plugin_name, error->message);
            g_clear_error(&error);
            continue;
        }

        if (!nm_connection_normalize(conn, NULL, NULL, &error)) {
            g_print("plugin[%s]: imported connection invalid: %s\n", plugin_name, error->message);
            g_clear_error(&error);
            g_clear_object(&conn);
            continue;
        }

        g_print("plugin[%s]: imported connection \"%s\" (%s)\n",
                plugin_name,
                nm_connection_get_id(conn),
                nm_connection_get_uuid(conn));
        break;
    }
    g_slist_free_full(plugins, g_object_unref);

    if (!conn) {
        g_print("Failure to import the file with any plugin\n");
        return NULL;
    }

    return conn;
}

/*****************************************************************************/

typedef struct {
    GMainLoop *         loop;
    GError *            error;
    NMRemoteConnection *rconn;
} RequestData;

static void
add_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    RequestData *rdata = user_data;

    rdata->rconn = nm_client_add_connection_finish(NM_CLIENT(source), result, &rdata->error);
    g_main_loop_quit(rdata->loop);
}

static NMRemoteConnection *
connection_add(NMConnection *conn)
{
    GError *    error = NULL;
    NMClient *  client;
    RequestData rdata;

    g_print("Adding connection \"%s\" (%s)\n",
            nm_connection_get_id(conn),
            nm_connection_get_uuid(conn));

    client = nm_client_new(NULL, &error);
    if (!client) {
        g_print("Failure to connect with NetworkManager: %s\n", error->message);
        return NULL;
    }

    g_print("Adding connection \"%s\" (%s)\n",
            nm_connection_get_id(conn),
            nm_connection_get_uuid(conn));

    rdata = (RequestData){
        .loop  = g_main_loop_new(NULL, FALSE),
        .rconn = NULL,
        .error = NULL,
    };

    nm_client_add_connection_async(client, conn, TRUE, NULL, add_cb, &rdata);

    g_main_loop_run(rdata.loop);

    g_clear_pointer(&rdata.loop, g_main_loop_unref);

    if (rdata.error != NULL) {
        g_print("Error: %s\n", rdata.error->message);
        g_clear_error(&rdata.error);
    } else {
        g_print("Connection successfully added: %s\n", nm_object_get_path(NM_OBJECT(rdata.rconn)));
    }

    g_clear_object(&client);

    return rdata.rconn;
}

/*****************************************************************************/

int
main(int argc, char **argv)
{
    NMRemoteConnection *rconn;
    NMConnection *      conn;
    const char *        filename;
    gboolean            success;

    if (argc < 2) {
        g_print("program takes exactly one(1) argument.\n");
        return 1;
    }

    filename = argv[1];

    conn = vpn_connection_import(filename);
    if (!conn)
        return 1;

    rconn = connection_add(conn);

    success = (rconn != NULL);

    g_clear_object(&conn);
    g_clear_object(&rconn);

    return success ? 0 : 1;
}
