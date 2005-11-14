#!/bin/sh

# This is an example of how to install a system-wide connection that
# cannot be edited by unprivileged users using nm-vpn-properties. This
# script needs to be run as root and you may need to restart any
# gconfd daemons after the script has run (logging in and out will
# suffice)

NAME="openvpn-system-wide"
ESCAPED_NAME="openvpn-system-wide"
REMOTE="1.2.3.4"
CA="/etc/openvpn/CA.crt"
CERT="/etc/openvpn/thisclient.crt"
KEY="/etc/openvpn/thisclient.key"
# must be either yes or no
USELZO="no"

IPSEC_ROUTES="[172.16.0.0/16,192.168.4.0/24]"

GCONF_PATH="/system/networking/vpn_connections/$ESCAPED_NAME"

GCONFTOOL2_OPTS="--direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory"

gconftool-2 $GCONFTOOL2_OPTS --type string --set $GCONF_PATH/name "$NAME"
gconftool-2 $GCONFTOOL2_OPTS --type string --set $GCONF_PATH/service_name "org.freedesktop.NetworkManager.openvpn"
gconftool-2 $GCONFTOOL2_OPTS --type list --list-type=string --set $GCONF_PATH/vpn_data ["remote","$REMOTE","ca","$CA","cert",$CERT,"key",$KEY,"comp-lzo",$USELZO]
gconftool-2 $GCONFTOOL2_OPTS --type list --list-type=string --set $GCONF_PATH/routes $IPSEC_ROUTES

