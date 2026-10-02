#!/usr/bin/perl
# Fixed local read operations, using the same handlers/environment as pvesh.
# Load PVE once per observation; never expose arbitrary paths or mutations.
use strict;
use warnings;
use JSON qw(encode_json);
use PVE::API2;
use PVE::INotify;
use PVE::RPCEnvironment;

my $mode = shift @ARGV // '';
die "expected inventory or topology\n" if @ARGV || $mode !~ /\A(?:inventory|topology)\z/;
PVE::RPCEnvironment->setup_default_cli_env();
my $node = PVE::INotify::nodename();

sub get {
    my ($path) = @_;
    my $params = {};
    my ($handler, $info) = PVE::API2->find_handler('GET', $path, $params);
    die "missing local PVE read handler\n" unless $handler && $info;
    return $handler->handle($info, $params);
}

my $result;
if ($mode eq 'inventory') {
    $result = {
        volumes => get("/nodes/$node/storage/local-lvm/content"),
        resources => get('/cluster/resources'),
        storage => get("/nodes/$node/storage/local-lvm/status"),
        status => get("/nodes/$node/status"),
    };
} else {
    my $vnets = get('/cluster/sdn/vnets');
    my %subnets;
    for my $vnet (@$vnets) {
        my $name = $vnet->{vnet};
        next unless $name =~ /\At[0-9]{3}\z/;
        $subnets{$name} = get("/cluster/sdn/vnets/$name/subnets");
    }
    $result = {vnets => $vnets, subnets => \%subnets};
}
print encode_json($result), "\n";
