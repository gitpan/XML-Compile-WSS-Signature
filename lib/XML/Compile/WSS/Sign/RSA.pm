# Copyrights 2012 by [Mark Overmeer].
#  For other contributors see ChangeLog.
# See the manual pages for details on the licensing terms.
# Pod stripped from pm file by OODoc 2.00.
use warnings;
use strict;

package XML::Compile::WSS::Sign::RSA;
use vars '$VERSION';
$VERSION = '0.90';

use base 'XML::Compile::WSS::Sign';

use Log::Report 'xml-compile-wss-sig';

use Crypt::OpenSSL::RSA ();
use File::Slurp         qw/read_file/;
use Scalar::Util        qw/blessed/;


sub init($)
{   my ($self, $args) = @_;
    $self->SUPER::init($args);
    $self->privateKey($args->{private_key}, $args->{hashing})
        if $args->{private_key};

    $self->publicKey($args->{public_key});
    $self;
}

#-----------------

sub hashing() {shift->{XCWSR_hash}}


sub privateKey(;$)
{   my $self    = shift;
    @_ or return $self->{XCWSR_privkey};
    my $priv    = shift;
    my $hashing = shift || 'SHA1';

    my ($key, $rsa);
    if(blessed $priv && $priv->isa('Crypt::OpenSSL::RSA'))
    {   ($key, $rsa) = ($rsa->get_private_key_string, $priv);
    }
    elsif(ref $priv)
    {   error __x"unrecognized private key object `{object}'", object => $priv;
    }
    elsif(index($priv, "\n") >= 0)
    {   ($key, $rsa) = ($priv, Crypt::OpenSSL::RSA->new_private_key($priv));
    }
    else
    {   $key = read_file $priv;
        $rsa = Crypt::OpenSSL::RSA->new_private_key($key);
    }

    my $use_hash = "use_\L$hashing\E_hash";
    $rsa->can($use_hash)
        or error __x"hash {type} not supported by {pkg}"
            , type => $hashing, pkg => ref $key;
    $rsa->$use_hash();

    $self->{XCWSR_privrsa} = $rsa;
    $self->{XCWSR_privkey} = $key;
}


sub privateKeyRSA() {shift->{XCWSR_privrsa}}


sub publicKey(;$)
{   my $self = shift;
    @_ or return $self->{XCWSR_pubkey};

    my $token = $self->{XCWSR_pubkey} = shift || $self->privateKeyRSA;
    $self->{XCWSR_pubrsa}
      = $token->isa('Crypt::OpenSSL::RSA') ? $token
      : $token->isa('XML::Compile::WSS::SecToken::X509v3')
      ? Crypt::OpenSSL::RSA->new_public_key($token->certificate->pubkey)
      : $token->isa('Crypt::OpenSSL::X509')
      ? Crypt::OpenSSL::RSA->new_public_key($token->pubkey)
      : error __x"unsupported public key `{token}' for check RSA"
           , token => $token;
}


sub publicKeyString($)
{   my $rsa = shift->publicKeyRSA;
    my $how = shift || '(NONE)';

      $how eq 'PKCS1' ? $rsa->get_public_key_string
    : $how eq 'X509'  ? $rsa->get_public_key_x509_string
    : error __x"unknown public key string format `{name}'", name => $how;
}



sub publicKeyRSA() {shift->{XCWSR_pubrsa}}
 
#-----------------

sub sign(@)
{   my ($self, $reftext) = @_;
    my $priv = $self->privateKeyRSA
        or error "signing rsa requires the private_key";
    $priv->sign($reftext);
}


sub check($$)
{   my ($self, $reftext, $signature) = @_;
    my $rsa = $self->publicKeyRSA
        or error "checking signature with rsa requires the public_key";

    $rsa->verify($$reftext, $signature);
}

#-----------------


1;
