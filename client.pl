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
    print "Access token missing, authorizing...\n";
    authorize();
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
    
sub authorize {
    my $request = Net::OAuth->request('request token')->new(
            consumer_key        => $consumer_info->{token},
            consumer_secret     => $consumer_info->{secret},
            request_url         => $domain_prefix . "/oauth/request_token",
            request_method      => 'GET',
            signature_method    => 'HMAC-SHA1',
            timestamp           => time,
            nonce               => random_string('.' x 20),
            callback            => 'oob',
            extra_params        => {
                simple_verifier => 1,
                simple_token    => 1,
            },
    );
    $request->sign;

    my $res = $ua->request(GET $request->to_url);
    if ($res->is_success) {
        my $response = Net::OAuth->response('request token')->from_post_body($res->content);
        $request = Net::OAuth->request("user auth")->new(
            token => $response->token,
            request_url => $domain_prefix . '/oauth/authorize'
        );
        print "!!! Please visit "  . $request->to_url( $request->{'request_url'} ) . " and follow the instructions\n";
        print "Verifier: ";
        my $verifier = <STDIN>;
        chomp $verifier; chomp $verifier;

        authorize_handle_verifier( $response, $verifier );
    } else {
        print STDERR "Failed to authorize: " . $res->code . "\n";
        print STDERR $res->content . "\n";
        exit(-1);
    }
}

sub authorize_handle_verifier {
    my ( $request_token, $verifier ) = @_;

    my $request = Net::OAuth->request("access token")->new(
        consumer_key        => $consumer_info->{token},
        consumer_secret     => $consumer_info->{secret},
        request_url         => $domain_prefix . "/oauth/access_token",
        request_method      => 'GET',
        signature_method    => 'HMAC-SHA1',
        timestamp           => time,
        nonce               => random_string('.' x 20),
        token               => $request_token->token,
        token_secret        => $request_token->token_secret,
        verifier            => $verifier,
    );
    $request->sign;

    my $res = $ua->request(GET $request->to_url);
    if ($res->is_success) {
        my $response = Net::OAuth->response('access token')->from_post_body($res->content);
        $access_info = {
            token       => $response->token,
            secret      => $response->token_secret,
            username    => $response->extra_params->{dw_username},
        };
        YAML::Any::DumpFile("access.yml",$access_info);
        print "Authorized!\n\n";
    } else {
        print STDERR "Failed to authorize (access token): " . $res->code . "\n";
        print STDERR $res->content . "\n";
        exit(-1);
    }
}
