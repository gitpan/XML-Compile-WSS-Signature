# Copyrights 2012 by [Mark Overmeer].
#  For other contributors see ChangeLog.
# See the manual pages for details on the licensing terms.
# Pod stripped from pm file by OODoc 2.00.
use warnings;
use strict;

package XML::Compile::WSS::SecToken::X509v3;
use vars '$VERSION';
$VERSION = '0.91';

use base 'XML::Compile::WSS::SecToken';

use Log::Report 'xml-compile-wss-sig';

use XML::Compile::WSS::Util qw/XTP10_X509v3 WSM10_BASE64/;

use MIME::Base64         qw/decode_base64 encode_base64/;
use Scalar::Util         qw/blessed/;
use Crypt::OpenSSL::X509 qw/FORMAT_ASN1/;
use Crypt::OpenSSL::RSA  ();


sub init($)
{   my ($self, $args) = @_;
    $args->{type} ||= XTP10_X509v3;
    $self->SUPER::init($args);

    my $cert;
    if($cert = $args->{certificate}) {}
    elsif(my $fn = $args->{cert_file})
    {   # openssl's error message are a bit poor
        -f $fn or error __x"key file {fn} does not exit", fn => $fn;

        $cert = eval { Crypt::OpenSSL::X509->new_from_file($fn) };
        if($@)
        {   my $err = $@;
            $err    =~ s/\. at.*//;
            error __x"in file {file}: {err}" , file => $fn, err => $err;
        }
    }
    elsif(my $bin = $args->{binary})
    {   $cert = Crypt::OpenSSL::X509->new_from_string($bin, FORMAT_ASN1);
    }
    else
    {   error __x"certificate, cert_file or binary required for X509 token";
    }

    blessed $cert && $cert->isa('Crypt::OpenSSL::X509')
        or error __x"X509 certificate object not supported (yet)";

    $self->{XCWSX_cert} = $cert;
    $self;
}

#------------------------

sub certificate() {shift->{XCWSX_cert}}

#------------------------

sub asBinary()
{   my $self = shift;
    my $cert = $self->certificate;
    ( WSM10_BASE64, encode_base64 $cert->as_string(FORMAT_ASN1));
}

1;
