/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2011 Eckhart Wörner
 */

/*
 * The example shows how to call the ListConnections() D-Bus method to retrieve
 * the list of all network configuration that NetworkManager knows about.
 */

#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusInterface>
#include <QtDBus/QDBusReply>

#include <QtCore/QDebug>

#include "nm-dbus-interface.h"


void listConnections(QDBusInterface& interface) {
    // Call ListConnections D-Bus method
    QDBusReply<QList<QDBusObjectPath> > result = interface.call("ListConnections");
    foreach (const QDBusObjectPath& connection, result.value()) {
        qDebug() << connection.path();
    }
}

int main() {
    // Create a D-Bus proxy; NM_DBUS_* defined in NetworkManager.h
    QDBusInterface interface(
        NM_DBUS_SERVICE,
        NM_DBUS_PATH_SETTINGS,
        NM_DBUS_INTERFACE_SETTINGS,
        QDBusConnection::systemBus());

    listConnections(interface);
}
