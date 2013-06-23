package SigningTransport;
use strict;

use XMLRPC::Lite;
use SOAP::Transport::HTTP;

use String::Random qw( random_string );
use Digest::SHA qw/sha1_base64/;

our @ISA = qw(SOAP::Transport::HTTP::Client);
our $COMPRESS = 'deflate';
our $USERAGENT_CLASS = 'LWP::UserAgent';

my ( %redirect, %mpost, %nocompress );

sub new {
    my ($class,@params) = @_;
    my $self = $class->SUPER::new($class, @params);
    return $self;
}

sub proxy {
    return $_[0];
}

sub oauth_args {
    my $self = shift;
    if ( @_ ) {
        $self->{_oauth_args} = shift;
    }
    return $self->{_oauth_args} // {};
}

sub send_receive {
    my ( $self, %parameters ) = @_;
    my ( $context, $envelope, $endpoint, $action, $encoding, $parts ) =
      @parameters{qw(context envelope endpoint action encoding parts)};

    $encoding ||= 'UTF-8';

    $endpoint ||= $self->endpoint;

    my $method = 'POST';
    $COMPRESS = 'gzip';

    $self->options->{is_compress} ||=
      exists $self->options->{compress_threshold}
      && eval { require Compress::Zlib };

    # Initialize the basic about the HTTP Request object
    my $http_request = $self->http_request()->clone();


    # $self->http_request(HTTP::Request->new);
    $http_request->headers( HTTP::Headers->new );

    # TODO - add application/dime
    $http_request->header(
        Accept => ['text/xml', 'multipart/*', 'application/soap'] );
    $http_request->method($method);
    $http_request->url($endpoint);

    no strict 'refs';
    if ($parts) {
        my $packager = $context->packager;
        $envelope = $packager->package( $envelope, $context );
        for my $hname ( keys %{$packager->headers_http} ) {
            $http_request->headers->header(
                $hname => $packager->headers_http->{$hname} );
        }

        # TODO - DIME support
    }

  COMPRESS: {
        my $compressed =
             !exists $nocompress{$endpoint}
          && $self->options->{is_compress}
          && ( $self->options->{compress_threshold} || 0 ) < length $envelope;


        my $original_encoding = $http_request->content_encoding;

        while (1) {

            # check cache for redirect
            $endpoint = $redirect{$endpoint} if exists $redirect{$endpoint};

            # check cache for M-POST
            $method = 'M-POST' if exists $mpost{$endpoint};

          # what's this all about?
          # unfortunately combination of LWP and Perl 5.6.1 and later has bug
          # in sending multibyte characters. LWP uses length() to calculate
          # content-length header and starting 5.6.1 length() calculates chars
          # instead of bytes. 'use bytes' in THIS file doesn't work, because
          # it's lexically scoped. Unfortunately, content-length we calculate
          # here doesn't work either, because LWP overwrites it with
          # content-length it calculates (which is wrong) AND uses length()
          # during syswrite/sysread, so we are in a bad shape anyway.
          #
          # what to do? we calculate proper content-length (using
          # bytelength() function from SOAP::Utils) and then drop utf8 mark
          # from string (doing pack with 'C0A*' modifier) if length and
          # bytelength are not the same
            my $bytelength = SOAP::Utils::bytelength($envelope);
            if ($] < 5.008) {
                $envelope = pack( 'C0A*', $envelope );
            }
            else {
                require Encode;
                $envelope = Encode::encode($encoding, $envelope);
            }
            #  if !$SOAP::Constants::DO_NOT_USE_LWP_LENGTH_HACK
            #      && length($envelope) != $bytelength;

            # compress after encoding
            # doing it before breaks the compressed content (#74577)
            $envelope = Compress::Zlib::memGzip($envelope) if $compressed;

            $http_request->content($envelope);
            $http_request->protocol('HTTP/1.1');

            $http_request->proxy_authorization_basic( $ENV{'HTTP_proxy_user'},
                $ENV{'HTTP_proxy_pass'} )
              if ( $ENV{'HTTP_proxy_user'} && $ENV{'HTTP_proxy_pass'} );

            # by Murray Nesbitt
            if ( $method eq 'M-POST' ) {
                my $prefix = sprintf '%04d', int( rand(1000) );
                $http_request->header(
                    Man => qq!"$SOAP::Constants::NS_ENV"; ns=$prefix! );
                $http_request->header( "$prefix-SOAPAction" => $action )
                  if defined $action;
            }
            else {
                $http_request->header( SOAPAction => $action )
                  if defined $action;
            }

            #            $http_request->header(Expect => '100-Continue');

            # allow compress if present and let server know we could handle it
            $http_request->header( 'Accept-Encoding' =>
                  [$SOAP::Transport::HTTP::Client::COMPRESS] )
              if $self->options->{is_compress};

            $http_request->content_encoding(
                $SOAP::Transport::HTTP::Client::COMPRESS)
              if $compressed;

            if ( !$http_request->content_type ) {
                $http_request->content_type(
                    join '; ',
                    $SOAP::Constants::DEFAULT_HTTP_CONTENT_TYPE,
                    !$SOAP::Constants::DO_NOT_USE_CHARSET && $encoding
                    ? 'charset=' . lc($encoding)
                    : () );
            }
            elsif ( !$SOAP::Constants::DO_NOT_USE_CHARSET && $encoding ) {
                my $tmpType = $http_request->headers->header('Content-type');

                # $http_request->content_type($tmpType.'; charset=' . lc($encoding));
                my $addition = '; charset=' . lc($encoding);
                $http_request->content_type( $tmpType . $addition )
                  if ( $tmpType !~ /$addition/ );
            }

            $http_request->content_length($bytelength);

            SOAP::Trace::transport($http_request);
            SOAP::Trace::debug( $http_request->as_string );

            $self->SUPER::env_proxy if $ENV{'HTTP_proxy'};

            # !!! Modifications START
            my $oargs = $self->oauth_args;
            my %args = (
                consumer_key        => $oargs->{consumer_key},
                consumer_secret     => $oargs->{consumer_secret},
                token               => $oargs->{token},
                token_secret        => $oargs->{token_secret},
                request_url         => $http_request->uri,
                request_method      => uc( $http_request->method ),
                signature_method    => 'HMAC-SHA1',
                timestamp           => time,
                nonce               => random_string('.' x 20),
                body_hash           => sha1_base64( $http_request->content ) . '=',
            );
            my $oa_request = SigningTransport::ProtectedResourceRequest->new(%args);
            $oa_request->sign;
            $http_request->header("Authorization", $oa_request->to_authorization_header);
            # !!! Modifications END            

            # send and receive the stuff.
            # TODO maybe eval this? what happens on connection close?
            $self->http_response( $self->SUPER::request($http_request) );
            SOAP::Trace::transport( $self->http_response );
            SOAP::Trace::debug( $self->http_response->as_string );

            # 100 OK, continue to read?
            if ( (
                       $self->http_response->code == 510
                    || $self->http_response->code == 501
                )
                && $method ne 'M-POST'
              ) {
                $mpost{$endpoint} = 1;
            }
            elsif ( $self->http_response->code == 415 && $compressed ) {

                # 415 Unsupported Media Type
                $nocompress{$endpoint} = 1;
                $envelope = Compress::Zlib::memGunzip($envelope);
                $http_request->headers->remove_header('Content-Encoding');
                redo COMPRESS;    # try again without compression
            }
            else {
                last;
            }
        }
    }
    
    $redirect{$endpoint} = $self->http_response->request->url
      if $self->http_response->previous
          && $self->http_response->previous->is_redirect;

    $self->code( $self->http_response->code );
    $self->message( $self->http_response->message );
    $self->is_success( $self->http_response->is_success );
    $self->status( $self->http_response->status_line );
    return if ($self->http_response->is_success == 0);

    # Pull out any cookies from the response headers
    $self->{'_cookie_jar'}->extract_cookies( $self->http_response )
      if $self->{'_cookie_jar'};

    my $content =
      ( $self->http_response->content_encoding || '' ) =~
      /\b$SOAP::Transport::HTTP::Client::COMPRESS\b/o
      && $self->options->{is_compress}
      ? Compress::Zlib::memGunzip( $self->http_response->content )
      : ( $self->http_response->content_encoding || '' ) =~ /\S/ ? die
"Can't understand returned Content-Encoding (@{[$self->http_response->content_encoding]})\n"
      : $self->http_response->content;

    return $self->http_response->content_type =~ m!^multipart/!i
      ? join( "\n", $self->http_response->headers_as_string, $content )
      : $content;
}

package SigningTransport::ProtectedResourceRequest;
use base 'Net::OAuth::ProtectedResourceRequest';

__PACKAGE__->add_optional_message_params(qw/body_hash/);

1;
