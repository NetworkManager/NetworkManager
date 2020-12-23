/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2011 Eckhart Wörner
 */

/*
 * The example shows how to call the ListConnections() D-Bus method to retrieve
 * the list of all network configuration that NetworkManager knows about.
 */

#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusInterface>
#include <QtDBus/QDBusReply>
#include <QtCore/QDebug>

#include <nm-dbus-interface.h>


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
