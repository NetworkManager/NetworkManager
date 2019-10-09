#!/usr/bin/env perl
# SPDX-License-Identifier: GPL-2.0+

# Copyright (C) 2019 Red Hat, Inc.

# $ perldoc btmodem.pl if you'd like to read the manual, poor you:

=head1 NAME

btmodem.pl - emulate a bluetooth DUN modem

=head1 SYNOPSIS

btmodem.pl [<hci>] [-- <pppd> ...]

=head1 DESCRIPTION

B<btmodem.pl> registers a Bluetooth DUN profile with Bluez, accepts incoming
connections and pretends there's modem there.

It answers a basic subset of AT commands, sufficient making ModemManager
recognize it as a 3GPP capable modem registered to a network.

Upon receiving the dial (ATD) command, it spawns C<pppd> so that
NetworkManager can establish a connection.

=head1 OPTIONS

=over 4

=item B<< <hci> >>

Create a service on this particular HCI.

Defaults to I<hci0>.

=item B<< <pppd> >>

Specifies extra arguments to be prepended before C<pppd> to the default
set of I<nodetach notty local logfd 2 nopersist>.

Defaults to I<pppd noauth dump debug 172.31.82.1:172.31.82.2>.

=back

=cut

use strict;
use warnings;

use IO::Handle;
use Net::DBus;
use Net::DBus::Reactor;

# Parse command line arguments
my $hci_name;
my @pppd = qw/pppd noauth dump debug 172.31.82.1:172.31.82.2/;
while (@ARGV) {
	$_ = shift @ARGV;
	if ($_ eq '--') {
		@pppd = @ARGV;
		last;
	} else {
		die "Extra argument: '$_'" if $hci_name;
		$hci_name = $_;
	}
};
$hci_name ||= 'hci0';

sub modemu
{
	my $fh = shift;

	while (<$fh>) {
		chomp;

		if (/^AT$/ or /^ATE0$/ or /^ATV1$/ or /^AT\+CMEE=1$/ or /^ATX4$/ or /^AT&C1$/ or /^ATZ$/) {
			# Standard Hayes commands that are basically used to
			# ensure the modem is in a known state. Accept them all.
			print $fh "\r\n";
			print $fh "OK\r\n";

		} elsif (/^AT\+CPIN\?$/) {
			# PIN unlocked. Required.
			print $fh "\r\n";
			print $fh "+CPIN:READY\r\n";
			print $fh "\r\n";
			print $fh "OK\r\n";

		} elsif (/^AT\+COPS=0$/) {
			# Select access technology (we just accept 0=automatic)
			print $fh "\r\n";
			print $fh "OK\r\n";

		} elsif (/^AT\+CGREG\?$/) {
			# 3GPP Registration status.
			print $fh "\r\n";
			print $fh "+CGREG: 0,1\r\n";
			print $fh "\r\n";
			print $fh "OK\r\n";

		} elsif (/^AT\+CGDCONT=\?$/) {
			# Get supported PDP contexts
			print $fh "\r\n";
			print $fh "+CGDCONT: (1-10),(\"IP\"),,,(0-1),(0-1)\r\n";
			print $fh "+CGDCONT: (1-10),(\"IPV6\"),,,(0-1),(0-1)\r\n";
			print $fh "OK\r\n";

		} elsif (/^AT\+CGACT=0,1$/) {
			# Activate a PDP context
			print $fh "\r\n";
			print $fh "OK\r\n";

		} elsif (/^AT\+CGDCONT=1,"(.*)","(.*)"$/) {
			# Set PDP context. We accept any.
			print $fh "\r\n";
			print $fh "OK\r\n";

		} elsif (/^ATD/) {
			print $fh "\r\n";
			print $fh "CONNECT 28800000\r\n";

			my $ppp = fork;
			die "Can't fork: $!" unless defined $ppp;
			if ($ppp == 0) {
				close STDIN;
				close STDOUT;
				open STDIN, '<&', $fh or die "Can't dup pty to a pppd stdin: $!";
				open STDOUT, '>&', $fh or die "Can't dup pty to a pppd stdout: $!";
				close $fh;
				exec @pppd, qw/nodetach notty local logfd 2 nopersist/;
				die "Can't exec pppd: $!";
			}
			waitpid $ppp, 0;
		} else {
			print $fh "\r\n";
			print $fh "ERROR\r\n";
		}
	}
}

my $bus = Net::DBus->system;

$bus->get_connection->register_object_path("/", sub {
	my $bus = shift;
	my $call = shift;

	# We only support the NewConnection call
	next unless $call->get_type eq &Net::DBus::Binding::Message::MESSAGE_TYPE_METHOD_CALL;
	if (   $call->get_interface ne 'org.bluez.Profile1'
	    or $call->get_path ne '/'
	    or $call->get_member ne 'NewConnection'
	    or $call->get_signature ne 'oha{sv}') {

	       $bus->send ($bus->make_error_message (
			replyto => $call,
			name => ' org.freedesktop.DBus.Error.Failed',
			description => "Forgive me caller for I don't know what to do"));
		next;
	}

	my ($path, $fd, $args) = $call->get_args_list;
	open (my $fh, "+>&=", $fd) or die $!;

	my $pid = fork;
	die unless defined $pid;

	if ($pid == 0) {
		# This allows us to use buffered read for lines from ModemManager
		# despite not ending with \n
		IO::Handle->input_record_separator ("\r");
		$fh->autoflush (1);
		$fh->blocking (1);
		modemu ($fh);
		exit 0;
		die;
	}

	$bus->send ($bus->make_method_return_message ($call))
		unless $call->get_no_reply;
});

my $bluez = $bus->get_service ('org.bluez');
my $profile_manager = $bluez->get_object ('/org/bluez', 'org.bluez.ProfileManager1');

$profile_manager->RegisterProfile('/', '00001103-0000-1000-8000-00805f9b34fb', {});

Net::DBus::Reactor->main->run;

=head1 SETTING UP BLUETOOTH

In order for this script useful, you need to have two Bluetooth interfaces
paired together. It's somewhat easier if you've got two machines to test.

The pairing can be done withing the C<bluetoothctl> shell. Launch it after
you started C<btmodem.pl>, so that the right profile UUIDs are discovered
by the client. These commands come in handy:

=over

=item [bluetooth]# B<default-agent>

This makes C<bluetoothctl> ask for pairing PIN in the shell session. That is
useful if you're ssh-ing into a machine instead of using a desktop shell with
its own agent. Run this on both machines.

=item [bluetooth]# B<discoverable on>

Broadcast the server service. You don't need to run this on the client.

=item [bluetooth]# B<scan on>

Turn on discovery of the devices. You need to don't run this on the server.

After you've turned the discovery on, wait for a minute or so for your
server to get discovered.

=item [bluetooth]# B<devices>

List the known devices, both those who've been discovered and those that have
been paired with.

=item [bluetooth]# B<pair 00:AA:01:00:00:23>

Initiate the pairing. Run it from the machine that has scanning enabled.
Assumes your server is C<00:AA:01:00:00:23> -- check your real address with the
C<devices> command.

After a short while, you should see the pairing confirmation prompt on both machines.

=item [bluetooth]# B<trust 00:AA:01:00:00:24>

Allow incoming connections from C<00:AA:01:00:00:24>. Run this on the server.

=item B<nmcli c add type bluetooth ifname '*' gsm.apn internet bluetooth.type dun bluetooth.bdaddr 00:AA:01:00:00:23>

If everything went right, you can now connect.

=back

=head1 EXAMPLES

=over

=item B<btmodem.pl>

Just emulate a DUN modem on I<hci0>, with the default PPP arguments.

=item B<btmodem.pl hci666>

Same as above, just on the I<hci666> interface.

=item B<btmodem.pl -- unshare --net pppd 172.31.82.1:172.31.82.2>

Avoid polluting the namespace with the modem end of PPP connection.

=item B<btmodem.pl -- pppd 10.0.0.1:10.0.0.2>

Override the C<pppd> parameters: no debug logging and different set of
addresses.

=item B<btmodem.pl mymodem -- pppd 10.0.0.1:10.0.0.2>

Same as above, with a modem name different from default.

=back

=head1 BUGS

Haha. You tell me.

=head1 SEE ALSO

L<ModemManager(8)>, L<pppd(8)>, C<modemu.pl>

=head1 COPYRIGHT

Copyright (C) 2019 Lubomir Rintel

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

=head1 AUTHOR

Lubomir Rintel C<lkundrak@v3.sk>

Like, it's me who wrote it, but if you're running it it's your problem.

=cut
