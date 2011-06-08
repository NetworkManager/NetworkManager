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
 * (C) Copyright 2011 Red Hat, Inc.
 */

/*
 * This example shows how to set manual IPv4 addresses to a connection.
 * It uses Qt and D-Bus libraries to do that.
 *
 * Standalone compilation:
 * g++ -Wall `pkg-config --libs --cflags NetworkManager QtCore QtDBus QtNetwork` change-ipv4-addresses.cpp -o change-ipv4-addresses
 *
 * You don't need to have NetworkManager devel package installed; you can just
 * grab NetworkManager.h and put it in the path
 */

#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusInterface>
#include <QtDBus/QDBusMetaType>
#include <QtDBus/QDBusReply>
#include <QtCore/QList>
#include <QtCore/QMap>
#include <QtCore/QString>
#include <QtCore/QDebug>
#include <QtNetwork/QHostAddress>

#include "arpa/inet.h"

#include "NetworkManager.h"

typedef QMap<QString, QMap<QString, QVariant> > Connection;
Q_DECLARE_METATYPE(Connection)
Q_DECLARE_METATYPE(QList<uint>);
Q_DECLARE_METATYPE(QList<QList<uint> >);

const QString NM_SETTING_CONNECTION_SETTING_NAME = "connection";
const QString NM_SETTING_CONNECTION_ID = "id";
const QString NM_SETTING_CONNECTION_UUID = "uuid";


const QString getConnection(const QString& connectionUuid, Connection *found_connection)
{
    Connection settings;
    QDBusInterface *ifaceForSettings;

    // Create a D-Bus proxy; NM_DBUS_* defined in NetworkManager.h
    QDBusInterface interface(
        NM_DBUS_SERVICE,
        NM_DBUS_PATH_SETTINGS,
        NM_DBUS_IFACE_SETTINGS,
        QDBusConnection::systemBus());

    // Get connection list and find the connection with 'connectionUuid'
    QDBusReply<QList<QDBusObjectPath> > result1 = interface.call("ListConnections");

    foreach (const QDBusObjectPath& connection, result1.value()) {
        ifaceForSettings = new QDBusInterface(
                                    NM_DBUS_SERVICE,
                                    connection.path(),
                                    NM_DBUS_IFACE_SETTINGS_CONNECTION,
                                    QDBusConnection::systemBus());
        QDBusReply<Connection> result2 = ifaceForSettings->call("GetSettings");
        delete ifaceForSettings;

        settings = result2.value();
        QVariantMap connectionSettings = settings.value(NM_SETTING_CONNECTION_SETTING_NAME);
        QString uuid = connectionSettings.value(NM_SETTING_CONNECTION_UUID).toString();

        if (uuid == connectionUuid) {
            // Connection found; set the settings to found_connection
            // connection object path
            *found_connection = settings;
            return connection.path();
        }
    }

    return QString();
}

void changeConnection(const QString& uuid)
{
    // Register types with D-Bus
    qDBusRegisterMetaType<Connection>();
    qDBusRegisterMetaType<QList<uint> >();
    qDBusRegisterMetaType<QList<QList<uint> > >();

    Connection connection;
    QString conPath;

    // Find connection by provided UUID
    conPath = getConnection(uuid, &connection);

    if (!conPath.isEmpty()) {
        QList<QList<uint> > addresses;
        QList<uint> addr1, addr2;

        // Add some addresses
        addr1 << htonl(QHostAddress("192.168.100.4").toIPv4Address()) << 24 << htonl(QHostAddress("192.168.100.1").toIPv4Address());
        addr2 << htonl(QHostAddress("10.0.1.222").toIPv4Address()) << 8 << htonl(QHostAddress("10.0.1.254").toIPv4Address());
        addresses << addr1 << addr2;

        // Set method to "Manual" and put addresses to the connection map
        connection["ipv4"]["method"] = "manual";
        connection["ipv4"]["addresses"] = QVariant::fromValue(addresses);

        QDBusInterface interface(
            NM_DBUS_SERVICE,
            conPath,
            NM_DBUS_IFACE_SETTINGS_CONNECTION,
            QDBusConnection::systemBus());

        // Call Update() D-Bus method to update connection
        QDBusReply<void> result = interface.call("Update", QVariant::fromValue(connection));
        if (result.isValid()) {
            qDebug() << QString("Connection successfully updated (path %1)").arg(conPath);
        } else {
           qDebug() << QString("Error: could not update connection: %1 %2").arg(result.error().name()).arg(result.error().message());
        }
    } else {
            qDebug() << QString("Error: connection with UUID '%1' not found").arg(uuid);
    }
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        qDebug() << QString("Usage: %1 <UUID>").arg(argv[0]);
        return -1;
    }

    changeConnection(argv[1]);
}
