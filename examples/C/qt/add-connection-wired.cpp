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
