#!/usr/bin/env perl
use strict;
use lib qw( lib );
use YAML::Any qw();
use Data::Dumper;
use String::Random qw( random_string );

use Net::OAuth;
$Net::OAuth::PROTOCOL_VERSION = Net::OAuth::PROTOCOL_VERSION_1_0A;

use LWP::UserAgent;
use HTTP::Request::Common;

use XMLRPC::Lite;

use SigningTransport;

my $ua = LWP::UserAgent->new;

die "Missing consumer.yml" unless -e "consumer.yml";
my $consumer_info = YAML::Any::LoadFile("consumer.yml");
my $domain_prefix = $consumer_info->{domain_prefix};

my $mode = $ARGV[0] // "";

my $access_info;
unless ( -e "access.yml" ) {
    print STDERR "Access token missing, run authenticate.pl\n";
    exit(-1);
} else {
    $access_info = YAML::Any::LoadFile("access.yml");
}

my $transport = SigningTransport->new( endpoint => $domain_prefix . "/interface/xmlrpc" );
$transport->oauth_args({
    consumer_key    => $consumer_info->{token},
    consumer_secret => $consumer_info->{secret},
    token           => $access_info->{token},
    token_secret    => $access_info->{secret},
});

my $xmlrpc = XMLRPC::Lite->new( transport => $transport );
my $res = run_request( 'LJ.XMLRPC.login', { auth_method => 'oauth' } );
printf "Hello userid %d with fullname %s\n",$res->{userid},$res->{fullname};

$res = run_request( 'LJ.XMLRPC.getevents', {
    auth_method => 'oauth',
    selecttype  => 'lastn',
    howmany     => 20,
    ver => 1 } );
my $ct = scalar @{ $res->{events} };
printf("The subject of your most recent %i %s\n", $ct, $ct == 1 ? "entry" : "entries" );
printf("    %s\n      %s ( posted on %s )\n",
        $_->{subject} || "(no subject)", 
        $_->{url},
        $_->{eventtime}, 
    ) foreach @{ $res->{events} };

sub run_request {
    my $rv = $xmlrpc->call( @_ );
    if ( $rv->fault ) {
        print STDERR "Fail: " . $rv->fault->{faultString} . "\n";
        print STDERR Dumper($rv->fault);
        exit(-2);
    }
    return $rv->result;
}
    
