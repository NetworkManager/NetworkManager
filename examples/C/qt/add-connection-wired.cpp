// SPDX-License-Identifier: GPL-2.0+
/*
 * (C) Copyright 2011 Eckhart Wörner
 */

/*
 * The example shows how to call AddConnection() D-Bus method to add
 * a connection to settings service using Qt and D-Bus.
 */

#include <QtCore/QUuid>
#include <QtDBus/QDBusArgument>
#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusInterface>
#include <QtDBus/QDBusMetaType>
#include <QtDBus/QDBusReply>
#include <QtCore/QDebug>

#include <nm-dbus-interface.h>

typedef QMap<QString, QMap<QString, QVariant> > Connection;
Q_DECLARE_METATYPE(Connection)


void addConnection(QDBusInterface& interface, const QString& connectionName) {
    qDBusRegisterMetaType<Connection>();

    // Create a new connection object
    Connection connection;

    // Build up the 'connection' Setting
    connection["connection"]["uuid"] = QUuid::createUuid().toString().remove('{').remove('}');
    connection["connection"]["id"] = connectionName;
    connection["connection"]["type"] = "802-3-ethernet";

    // Build up the '802-3-ethernet' Setting
    connection["802-3-ethernet"];

    // Build up the 'ipv4' Setting
    connection["ipv4"]["method"] = "auto";

    // Call AddConnection
    QDBusReply<QDBusObjectPath> result = interface.call("AddConnection", QVariant::fromValue(connection));
    if (!result.isValid()) {
        qDebug() << QString("Error adding connection: %1 %2").arg(result.error().name()).arg(result.error().message());
    } else {
        qDebug() << QString("Added: %1").arg(result.value().path());
    }
}

int main() {
    // Create a D-Bus proxy; NM_DBUS_* defined in NetworkManager.h
    QDBusInterface interface(
        NM_DBUS_SERVICE,
        NM_DBUS_PATH_SETTINGS,
        NM_DBUS_INTERFACE_SETTINGS,
        QDBusConnection::systemBus());

    addConnection(interface, "__Test connection__");

    return 0;
}
