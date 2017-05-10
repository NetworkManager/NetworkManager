#!/usr/bin/env gjs

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
 * Copyright 2014,2017 Red Hat, Inc.
 */

const System = imports.system;
const NM = imports.gi.NM;
const GLib = imports.gi.GLib;

/*
 * This example shows how to get addresses, routes and DNS information
 * from NMIP4Config and NMIP6Config (got out of NMDevice)
 */

function show_addresses (dev, family)
{
	let ip_cfg;
	if (family == GLib.SYSDEF_AF_INET)
		ip_cfg = dev.get_ip4_config ();
	else
		ip_cfg = dev.get_ip6_config ();

	if (ip_cfg == null) {
		print ("None");
		return;
	}

	let nm_addresses = ip_cfg.get_addresses ();
	if (nm_addresses.length == 0) {
		print ("None");
		return;
	}

	for (let nm_address of nm_addresses) {
		let addr = nm_address.get_address ();
		let prefix = nm_address.get_prefix ();

		print (addr + "/" + prefix);
	}
}

function show_gateway (dev, family)
{
	let ip_cfg;
	if ((family == GLib.SYSDEF_AF_INET))
		ip_cfg = dev.get_ip4_config ();
	else
		ip_cfg = dev.get_ip6_config ();

	let gw;
	if (ip_cfg == null)
		gw = "None"
	else {
		gw = ip_cfg.get_gateway ();
		if (gw == '')
			gw = "None"
	}

	print (gw);
}

function show_routes (dev, family)
{
	let ip_cfg;
	if ((family == GLib.SYSDEF_AF_INET))
		ip_cfg = dev.get_ip4_config ();
	else
		ip_cfg = dev.get_ip6_config ();

	if (ip_cfg == null) {
		print ("None");
		return;
	}

	let nm_routes = ip_cfg.get_routes ();
	if (nm_routes.length == 0) {
		print ("None");
		return;
	}

	for (let nm_route of nm_routes) {
		let dest = nm_route.get_dest ();
		let prefix = nm_route.get_prefix ();
		let next_hop = nm_route.get_next_hop ();
		let metric = nm_route.get_metric ();

		print (dest + "/" + prefix + "  " + next_hop + "  " + metric);
	}
}

function show_dns (dev, family)
{
	let ip_cfg;
	if ((family == GLib.SYSDEF_AF_INET))
		ip_cfg = dev.get_ip4_config ();
	else
		ip_cfg = dev.get_ip6_config ();

	if (ip_cfg == null) {
		print ("None");
		return;
	}

	print ("Nameservers: " + ip_cfg.get_nameservers ());
	print ("Domains: " + ip_cfg.get_domains ());
	print ("Searches: " + ip_cfg.get_searches ());
	if ((family == GLib.SYSDEF_AF_INET))
		print ("WINS: " + ip_cfg.get_wins_servers ());
}

if (ARGV.length != 1) {
	print ("Usage: get_ips.js <interface>");
	System.exit (1);
}


let dev_iface = ARGV[0];
let c = NM.Client.new (null);

let dev = c.get_device_by_iface (dev_iface);

if (dev == null) {
	print ("Device '%s' not found " + dev_iface);
	System.exit (1);
}

print ("Device: " + dev_iface + " - " + dev.get_type_description ());
print ("---------------------------------------");
print ();

print ("IPv4 addresses:");
print ("---------------");
show_addresses (dev, GLib.SYSDEF_AF_INET);
print ();

print ("IPv4 gateway:");
print ("-------------");
show_gateway (dev, GLib.SYSDEF_AF_INET);
print ();

print ("IPv4 routes:");
print ("------------");
show_routes (dev, GLib.SYSDEF_AF_INET);
print ();

print ("IPv6 addresses:");
print ("---------------");
show_addresses (dev, GLib.SYSDEF_AF_INET6);
print ();

print ("IPv6 gateway:");
print ("-------------");
show_gateway (dev, GLib.SYSDEF_AF_INET6);
print ();

print ("IPv6 routes:");
print ("------------");
show_routes (dev, GLib.SYSDEF_AF_INET6);
print ();

print ("IPv4 DNS:");
print ("------------");
show_dns (dev, GLib.SYSDEF_AF_INET);
print ();

print ("IPv6 DNS:");
print ("------------");
show_dns (dev, GLib.SYSDEF_AF_INET6);
print ();
