/*
 * NetworkManager -- Inhibition management
 *
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

#ifndef __NETWORKMANAGER_KEEP_ALIVE_H__
#define __NETWORKMANAGER_KEEP_ALIVE_H__

#define NM_TYPE_KEEP_ALIVE         (nm_keep_alive_get_type ())
#define NM_KEEP_ALIVE(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), NM_TYPE_KEEP_ALIVE, NMKeepAlive))
#define NM_KEEP_ALIVE_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST ((k), NM_TYPE_KEEP_ALIVE, NMKeepAliveClass))
#define NM_KEEP_ALIVE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), NM_TYPE_KEEP_ALIVE, NMKeepAliveClass))
#define NM_IS_KEEP_ALIVE(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), NM_TYPE_KEEP_ALIVE))
#define NM_IS_KEEP_ALIVE_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), NM_TYPE_KEEP_ALIVE))


#define NM_KEEP_ALIVE_ALIVE           "alive"

typedef struct _NMKeepAliveClass NMKeepAliveClass;

GType nm_keep_alive_get_type (void) G_GNUC_CONST;

NMKeepAlive* nm_keep_alive_new (void);

gboolean nm_keep_alive_is_alive (NMKeepAlive *self);

void nm_keep_alive_arm (NMKeepAlive *self);
void nm_keep_alive_disarm (NMKeepAlive *self);

void nm_keep_alive_destroy (NMKeepAlive *self);

void nm_keep_alive_set_settings_connection_watch_visible (NMKeepAlive         *self,
                                                          NMSettingsConnection *connection);

void nm_keep_alive_set_dbus_client_watch (NMKeepAlive      *self,
                                          GDBusConnection  *connection,
                                          const char       *client_address);

gpointer /* GObject * */ nm_keep_alive_get_owner (NMKeepAlive *self);

/* _nm_keep_alive_set_owner() is reserved for the owner to set/unset itself. */
void                     _nm_keep_alive_set_owner (NMKeepAlive *self,
                                                   GObject *owner);

#endif /* __NETWORKMANAGER_KEEP_ALIVE_H__ */
