/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The example shows how to import VPN connection from a file.
 * @author: Jagadeesh Kotra <jagadeesh@stdin.top>
 *
 * Compile with:
 *   gcc -Wall vpn-import-libnm.c -o vpn-import-libnm `pkg-config --cflags --libs libnm`
 */

#include <glib.h>
#include <NetworkManager.h>
#include <stdlib.h>

static void
add_cb(NMClient *client, GAsyncResult *result, GMainLoop *loop)
{
    GError *err = NULL;
    nm_client_add_connection_finish(client, result, &err);
    if (err != NULL) {
        g_print("Error: %s\n", err->message);
    } else {
        g_print("Connection Added.\n");
    }

    g_main_loop_quit(loop);
}

int
main(int argc, char **argv)
{
    GMainLoop *        loop = g_main_loop_new(NULL, FALSE);
    GSList *           plugins;
    GSList *           iter;
    NMVpnEditorPlugin *editor;
    NMClient *         client;
    GError *           err  = NULL;
    NMConnection *     conn = NULL;

    if (argc < 2) {
        g_print("program takes exactly one(1) argument.\n");
        exit(1);
    }

    plugins = nm_vpn_plugin_info_list_load();
    g_assert(plugins != NULL);

    for (iter = plugins; iter; iter = iter->next) {
        const char *plugin_name = nm_vpn_plugin_info_get_name(iter->data);
        g_print("Trying Plugin: %s\n", plugin_name);

        //try to load plugin
        editor = nm_vpn_plugin_info_load_editor_plugin(iter->data, NULL);

        conn = nm_vpn_editor_plugin_import(editor, argv[1], &err);
        if (err != NULL) {
            g_print("Error: %s\n", err->message);
            g_error_free(err);
            err = NULL;
        } else {
            g_print("%s imported with %s plugin.\n", argv[1], plugin_name);
            break;
        }
    }

    g_slist_free_full(plugins, g_object_unref);
    g_assert(conn != NULL);

    client = nm_client_new(NULL, NULL);

    nm_client_add_connection_async(client, conn, TRUE, NULL, (GAsyncReadyCallback) add_cb, loop);
    g_main_loop_run(loop);

    return 0;
}
