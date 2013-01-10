# Copyrights 2012-2013 by [Mark Overmeer].
#  For other contributors see ChangeLog.
# See the manual pages for details on the licensing terms.
# Pod stripped from pm file by OODoc 2.00.
use warnings;
use strict;

package XML::Compile::WSS::Sign;
use vars '$VERSION';
$VERSION = '1.06';


use Log::Report 'xml-compile-wss-sig';

use XML::Compile::WSS::Util   qw/:wss11 :dsig/;
use Scalar::Util              qw/blessed/;

my ($signs, $sigmns) = (DSIG_NS, DSIG_MORE_NS);
my $sign_algorithm   = qr/^(?:$signs|$sigmns)([a-z0-9]+)\-([a-z0-9]+)$/;


sub new(@)
{   my $class = shift;
    my $args  = @_==1 ? shift : {@_};
    my $type  = delete $args->{type} || DSIG_RSA_SHA1;

    if($class eq __PACKAGE__)
    {   $type =~ $sign_algorithm
            or error __x"unsupported sign algorithm `{algo}'", algo => $type;

        my $algo = uc $1;;
        $args->{hashing} ||= uc $2;
        $class .= '::'.$algo;

        eval "require $class"; panic $@ if $@;
    }

    (bless {XCWS_type => $type}, $class)->init($args);
}

sub init($)
{   my ($self, $args) = @_;
    $self;
}


sub fromConfig($;$)
{   my ($class, $config, $priv) = @_;
    defined $config
        or return undef;

    if(ref $config eq 'HASH')
    {   $config->{private_key} ||= $priv;
        return $class->new($config);
    }

    return $class->new({type => $config, private_key => $priv})
        if !ref $config && $config =~ $sign_algorithm;

    blessed $config
        or panic "signer configuration requires HASH, OBJECT or TYPE.";

    if($config->isa(__PACKAGE__))
    {    $config->privateKey($priv) if $priv;
         return $config
    }

    panic "signer configuration `$config' not recognized";
}

#-----------------

sub type() {shift->{XCWS_type}}

#-----------------

sub check() {panic "not extended"}

#-----------------

1;
