use XML::LibXML;
use Data::Dumper;
use Text::Wrap;

use strict;
use warnings;

$Text::Wrap::columns = 75;
my $xml = XML::LibXML->load_xml(location => shift @ARGV) or die;

sub docstring
{
	my $node = shift;
	my $fold = shift;

	my ($ann) = grep { $_->getAttribute('name') eq 'org.gtk.GDBus.Doc'.'String' }
		$node->getChildrenByLocalName ('annotation');

	return '' unless $ann;

	my $doc = $ann->getAttribute('value');
	$ann->nextSibling->unbindNode;
	$ann->unbindNode;

	$doc =~ s/\s+/ /g;
	$doc =~ s/^\s+//mg;
	$doc =~ s/\s+$//mg;
	$doc = wrap ('', '', $doc) if $fold;
	$doc =~ s/^\s+//mg;

	unless ($node->nonBlankChildNodes) {
		$_->unbindNode foreach $node->childNodes;
	}

	return $doc;
}

sub type
{
	my $node = shift;

	my $type = $node->getAttribute ('tp:type') or return '';
	$node->removeAttribute ('tp:type');
	return '' unless $type =~ /^NM/;

	$type =~ s/_([^_]*)/\L\u$1\E/g;

	$type =~ s/NM80211ApSec/NM80211ApSecurityFlags/;
	$type =~ s/NMConnectivity/NMConnectivityState/;
	$type =~ s/NMBtCapabilities/NMBluetoothCapabilities/;
	$type =~ s/NM80211DeviceCap/NMDeviceWifiCapabilities/;
	$type =~ s/NMDeviceCap/NMDeviceCapabilities/;

	return $type;
}

sub annotate_node
{
	my $node = shift;;
	my $comment = shift;

	my $indent = $node->localname eq 'interface' ? '  ' : '    ';

	$comment =~ s/^/$indent    /gm;
	$comment = "\n$comment$indent";
	$node->parentNode->insertBefore ($xml->createTextNode ("\n$indent"), $node);
	$node->parentNode->insertBefore ($xml->createComment ($comment), $node);
	$node->parentNode->insertBefore ($xml->createTextNode ("\n$indent"), $node);
}

for my $m (
	$xml->getElementsByLocalName ('method'),
	$xml->getElementsByLocalName ('signal'),
	$xml->getElementsByLocalName ('property'),
	$xml->getElementsByLocalName ('interface'),
) {
	my $name = $m->getAttribute('name');
	my $doc = docstring ($m, 1);
	my $type = type ($m);
	my $arg = '';

	for my $a ($m->getChildrenByLocalName ('arg')) {
		my $name = $a->getAttribute('name');
		my $type = type ($a);
		my $doc = docstring ($a);
		if ($type) {
			$doc = $doc ? "(#$type) $doc" : "#$type";
		}
		$arg .= "\@$name: $doc\n";
	}

	next unless $arg or $doc or $type;
	my $ann = "$name:\n$arg";
	$ann .= "\n$doc\n" if $doc;
	$ann .= "\nReturns: #$type\n" if $type;
	annotate_node ($m, $ann);
}

for my $m (
	$xml->getElementsByLocalName ('enum'),
	$xml->getElementsByLocalName ('flags'),
	$xml->getElementsByLocalName ('struct'),
	$xml->getElementsByLocalName ('possible-errors'),
) {
	$m->previousSibling->unbindNode;
	$m->unbindNode;
}

$xml = "$xml";
$xml =~ s/\s+$/\n/gm;
$xml =~ s/ xmlns:tp="http:\/\/telepathy.freedesktop.org\/wiki\/DbusSpec#extensions-v0"//gm;
print $xml;
