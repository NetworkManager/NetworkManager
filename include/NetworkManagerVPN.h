/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
 *
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2004 Red Hat, Inc.
 */

#ifndef NETWORK_MANAGER_VPN_H
#define NETWORK_MANAGER_VPN_H

/*
 * dbus services details
 */
#define	NM_DBUS_PATH_VPN			"/org/freedesktop/NetworkManager/VPNConnections"
#define	NM_DBUS_INTERFACE_VPN		"org.freedesktop.NetworkManager.VPNConnections"


/*
 * VPN Errors
 */
#define NM_DBUS_NO_ACTIVE_VPN_CONNECTION	"org.freedesktop.NetworkManager.VPNConnections.NoActiveVPNConnection"
#define NM_DBUS_NO_VPN_CONNECTIONS			"org.freedesktop.NetworkManager.VPNConnections.NoVPNConnections"
#define NM_DBUS_INVALID_VPN_CONNECTION		"org.freedesktop.NetworkManager.VPNConnections.InvalidVPNConnection"

#define NM_DBUS_VPN_STARTING_IN_PROGRESS	"StartingInProgress"
#define NM_DBUS_VPN_ALREADY_STARTED		"AlreadyStarted"
#define NM_DBUS_VPN_STOPPING_IN_PROGRESS	"StoppingInProgress"
#define NM_DBUS_VPN_ALREADY_STOPPED		"AlreadyStopped"
#define NM_DBUS_VPN_WRONG_STATE			"WrongState"
#define NM_DBUS_VPN_BAD_ARGUMENTS			"BadArguments"
#define NM_DBUS_VPN_LAUNCH_FAILED			"LaunchFailed"


/*
 * VPN daemon signals
 */
#define NM_DBUS_VPN_SIGNAL_LOGIN_BANNER		"LoginBanner"
#define NM_DBUS_VPN_SIGNAL_LOGIN_FAILED		"LoginFailed"
#define NM_DBUS_VPN_SIGNAL_LAUNCH_FAILED	"LaunchFailed"
#define NM_DBUS_VPN_SIGNAL_CONNECT_FAILED	"ConnectFailed"
#define NM_DBUS_VPN_SIGNAL_VPN_CONFIG_BAD	"VPNConfigBad"
#define NM_DBUS_VPN_SIGNAL_IP_CONFIG_BAD	"IPConfigBad"
#define NM_DBUS_VPN_SIGNAL_STATE_CHANGE		"StateChange"
#define NM_DBUS_VPN_SIGNAL_IP4_CONFIG		"IP4Config"

/*
 * VPN daemon states
 */
typedef enum NMVPNState
{
	NM_VPN_STATE_UNKNOWN = 0,
	NM_VPN_STATE_INIT,
	NM_VPN_STATE_SHUTDOWN,
	NM_VPN_STATE_STARTING,
	NM_VPN_STATE_STARTED,
	NM_VPN_STATE_STOPPING,
	NM_VPN_STATE_STOPPED
} NMVPNState;


/*
 * VPN connection activation stages
 */
typedef enum NMVPNActStage
{
	NM_VPN_ACT_STAGE_UNKNOWN = 0,
	NM_VPN_ACT_STAGE_DISCONNECTED,
	NM_VPN_ACT_STAGE_PREPARE,
	NM_VPN_ACT_STAGE_CONNECT,
	NM_VPN_ACT_STAGE_IP_CONFIG_GET,
	NM_VPN_ACT_STAGE_ACTIVATED,
	NM_VPN_ACT_STAGE_FAILED,
	NM_VPN_ACT_STAGE_CANCELED
} NMVPNActStage;


#endif /* NETWORK_MANAGER_VPN_H */
