/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2012 Red Hat, Inc.
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
