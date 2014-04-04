/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* vim: set ft=c ts=4 sts=4 sw=4 expandtab smartindent: */
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
 * (C) Copyright 2012 Red Hat, Inc.
 */

/*
 * This example monitors whether NM is running by checking if
 * "org.freedesktop.NetworkManager" is owned by a process on D-Bus.
 * It uses QDBusServiceWatcher class.
 *
 * Standalone compilation:
 *   moc-qt4 monitor-nm-running.cpp -o monitor-nm-running.moc
 *   g++ -Wall `pkg-config --libs --cflags QtCore QtDBus` monitor-nm-running.cpp -o monitor-nm-running
 *
 * You don't need to have NetworkManager devel package installed.
 */

#include <iostream>
#include <QObject>
#include <QCoreApplication>
#include <QtDBus/QDBusServiceWatcher>
#include <QtDBus/QDBusConnection>
#include <QtCore/QDebug>

const QString NM_DBUS_SERVICE = "org.freedesktop.NetworkManager";

// Define a class with slots
class NMWatcher: public QObject {
    Q_OBJECT;

    public slots:
        void serviceRegistered(const QString& name);
        void serviceUnregistered(const QString& name);
};


void NMWatcher::serviceRegistered(const QString& name)
{
    std::cout << "Name '" << name.toUtf8().constData() << "' registered"
              << " => NM is running" << std::endl;
}

void NMWatcher::serviceUnregistered(const QString& name)
{
    std::cout << "Name '" << name.toUtf8().constData() << "' unregistered"
              << " => NM is not running" << std::endl;
}

int main(int argc, char *argv[])
{
    QCoreApplication app (argc, argv);

    qDebug() << "Monitor 'org.freedesktop.NetworkManager' D-Bus name";
    qDebug() << "===================================================";

    NMWatcher nm_watcher;

    // Watch all changes of D-Bus NM_DBUS_SERVICE name
    QDBusServiceWatcher *watcher = new QDBusServiceWatcher(NM_DBUS_SERVICE,
                                                           QDBusConnection::systemBus());

    QObject::connect(watcher, SIGNAL(serviceRegistered(const QString&)),
                     &nm_watcher, SLOT(serviceRegistered(const QString&)));

    QObject::connect(watcher, SIGNAL(serviceUnregistered(const QString&)),
                     &nm_watcher, SLOT(serviceUnregistered(const QString&)));

    app.exec();

    delete watcher;
    return 0;
}

#include "monitor-nm-running.moc"
