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

use JSON;

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

my $request = Net::OAuth->request("protected resource")->new(
    consumer_key        => $consumer_info->{token},
    consumer_secret     => $consumer_info->{secret},
    request_url         => $domain_prefix . "/api/v1/file/upload",
    request_method      => 'GET',
    signature_method    => 'HMAC-SHA1',
    timestamp           => time,
    nonce               => random_string('.' x 20),
    token               => $access_info->{token},
    token_secret        => $access_info->{secret},
);
$request->sign;

my $res = $ua->request(GET $request->to_url);
if ($res->is_success) {
    print Dumper( JSON::decode_json $res->content );
} else {
    print "ERROR!\n";
    print Dumper( JSON::decode_json $res->content );
} 
