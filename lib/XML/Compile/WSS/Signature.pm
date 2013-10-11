# Copyrights 2012-2013 by [Mark Overmeer].
#  For other contributors see ChangeLog.
# See the manual pages for details on the licensing terms.
# Pod stripped from pm file by OODoc 2.01.
use warnings;
use strict;

package XML::Compile::WSS::Signature;
use vars '$VERSION';
$VERSION = '2.01';

use base 'XML::Compile::WSS';

use Log::Report 'xml-compile-wss-sig';

use XML::Compile::WSS::Util     qw/:wss11 :wsm10 :dsig :xtp10/;
use XML::Compile::WSS::SecToken ();
use XML::Compile::WSS::Sign     ();
use XML::Compile::WSS::KeyInfo  ();
use XML::Compile::WSS::SignedInfo ();

use XML::Compile::C14N::Util    qw/:c14n/;
use XML::Compile::C14N          ();

use Digest          ();
use XML::LibXML     ();
use File::Basename  qw/dirname/;
use File::Glob      qw/bsd_glob/;
use Scalar::Util    qw/blessed/;

my %prefixes =
  ( # ds=DSIG_NS defined in ::WSS
    dsig11 => DSIG11_NS
  , dsp    => DSP_NS
  , dsigm  => DSIG_MORE_NS
  , xenc   => XENC_NS
  );

#use Data::Dumper;
#$Data::Dumper::Indent    = 1;
#$Data::Dumper::Quotekeys = 0;


sub init($)
{   my ($self, $args) = @_;
    my $wss_v = $args->{wss_version} ||= '1.1';

    $self->SUPER::init($args);

    my $signer  = delete $args->{signer} || {};
    blessed $signer || ref $signer
        or $signer  = { sign_method => $signer };            # pre 2.00
    $signer->{$_} ||= delete $args->{$_}                     # pre 2.00
        for qw/private_key/;
    $self->{XCWS_signer}  = XML::Compile::WSS::Sign
      ->fromConfig(%$signer, wss => $self);

    my $si      = delete $args->{signed_info} || {};
    $si->{$_} ||= delete $args->{$_}
        for qw/digest_method cannon_method prefix_list/;     # pre 2.00

    $self->{XCWS_siginfo} = XML::Compile::WSS::SignedInfo
      ->fromConfig(%$si, wss => $self);

    my $ki      = delete $args->{key_info} || {};
    $ki->{$_} ||= delete $args->{$_}
        for qw/publish_token/;                               # pre 2.00

    $self->{XCWS_keyinfo} = XML::Compile::WSS::KeyInfo
      ->fromConfig(%$ki, wss => $self);

    if(my $subsig = delete $args->{signature})
    {   $self->{XCWS_subsig} = (ref $self)->new(wss_version => $wss_v
          , schema => $self->schema, %$subsig);
    }

    $self->{XCWS_token}    = $args->{token};

    $self->{XCWS_config}   = $args;  # the left-overs are for me
    $self;
}

#-----------------------------


sub keyInfo()    {shift->{XCWS_keyinfo}}
sub signedInfo() {shift->{XCWS_siginfo}}
sub signer()     {shift->{XCWS_signer}}

#-----------------------------


sub token()       {shift->{XCWS_token}}
sub remoteToken() {shift->{XCWS_rem_token}}

#-----------------------------
#### HELPERS

sub prepareReading($)
{   my ($self, $schema) = @_;
    $self->SUPER::prepareReading($schema);

    my $config = $self->{XCWS_config};
    if(my $r   = $config->{remote_token})
    {   $self->{XCWS_rem_token} = XML::Compile::WSS::SecToken->fromConfig($r);
    }

    my (@elems_to_check, $container, @signature_elems);
    $schema->addHook
      ( action => 'READER'
      , type   =>  ($config->{sign_types} or panic)
      , before => sub {
          my ($node, $path) = @_;
          push @elems_to_check, $node;
          $node;
        }
      );

    # we need the unparsed node to canonicalize and check
    $schema->addHook
      ( action => 'READER'
      , type   => 'ds:SignedInfoType'
      , after  => 'XML_NODE'
      );

    # collect the elements to check, while decoding them
    $schema->addHook
      ( action => 'READER'
      , type   => ($config->{sign_put} || panic)
      , after  => sub {
          my ($xml, $data, $path) = @_;
#warn "Located signature at $path";
          push @signature_elems, $data->{ds_Signature}
              if $data->{ds_Signature};
          $container = $data;
          $data;
        }
      );

    my $check_signature = $self->checker;
    $schema->addHook
      ( action => 'READER'
      , type   => ($config->{sign_when} || panic)
      , after  => sub {
          my ($xml, $data, $path) = @_;
#warn "Checking signatures when at $path";
          @signature_elems
              or error __x"signature element not found in answer";

          # We can leave the checking via exceptions, so have to reset
          # the counters for the next message first.
          my @e = @elems_to_check;  @elems_to_check  = ();
          my @s = @signature_elems; @signature_elems = ();

          $check_signature->($container, $_, \@e) for @s;
          $data;
        }
      );

    $self;
}

# The checker routines throw an exception on error
sub checker($@)
{   my $self   = shift;
    my $config = $self->{XCWS_config};
    my %args   = (%$config, @_);

    my $si         = $self->signedInfo;
    my $si_checker = $si->checker($self, %args);
    my $get_tokens = $self->keyInfo->getTokens($self, %args);

    sub {
        my ($container, $sig, $elems) = @_;
        my $ki        = $sig->{ds_KeyInfo};
        my @tokens    = $ki ? $get_tokens->($ki, $container, $sig->{Id}) : ();

        # Hey, you try to get tokens up in the hierachy in a recursive
        # nested program yourself!
        $ki->{__TOKENS} = \@tokens;

        ### check the signed-info content

        my $info      = $sig->{ds_SignedInfo};
        $si_checker->($info, $elems, \@tokens);

        ### Check the signature of the whole block

        my $canon    = $info->{ds_CanonicalizationMethod};
        my $preflist = $canon->{c14n_InclusiveNamespaces}{PrefixList}; # || [];
        my $canonic  = $si->_get_canonic($canon->{Algorithm}, $preflist);
        my $sigvalue = $sig->{ds_SignatureValue}{_};

        my $signer   = XML::Compile::WSS::Sign->new
          ( sign_method => $info->{ds_SignatureMethod}{Algorithm}
          , public_key  => $tokens[0]
          );

        $signer->checker->($canonic->($info->{_XML_NODE}), $sigvalue)
            or error __x"received signature value is incorrect";

    };
}

sub builder(%)
{   my $self   = shift;
    my $config = $self->{XCWS_config};
    my %args   = (%$config, @_);
 
    my $signer     = $self->signer;
    my $signmeth   = $signer->signMethod;
    my $sign       = $signer->builder($self, %args);
    my $signedinfo = $self->signedInfo->builder($self, %args);
    my $keylink    = $self->keyInfo->builder($self, %args);
    my $token      = $self->token;
    my $tokenw     = $token->isa('XML::Compile::WSS::SecToken::EncrKey')
      ? $token->builder($self, %args) : undef;

    my $sigw       = $self->schema->writer('ds:Signature');

    # sign the signature!
    my $subsign;
    if(my $subsig = $self->{XCWS_subsig})
    {   $subsign = $subsig->builder;
    }

    my $unique = time;

    sub {
        my ($doc, $elems, $sec_node) = @_;
        my ($sinfo, $si_canond) = $signedinfo->($doc, $elems, $signmeth);

        $sec_node->appendChild($tokenw->($doc, $sec_node))
           if $tokenw;

        my $signature = $sign->($si_canond);
        my %sig =
          ( ds_SignedInfo     => $sinfo
          , ds_SignatureValue => {_ => $signature}
          , ds_KeyInfo        => $keylink->($doc, $token, $sec_node)
          , Id                => 'SIG-'.$unique++
          );
        my $signode   = $sigw->($doc, \%sig);
        $sec_node->appendChild($signode);

        $subsign->($doc, [$signode], $sec_node)
            if $subsign;

        $sec_node;
    };
}

sub prepareWriting($)
{   my ($self, $schema) = @_;
    $self->SUPER::prepareWriting($schema);

    $self->token
        or error __x"creating signatures needs a token";

    my $config = $self->{XCWS_config};

    my @elems_to_sign;
    $schema->addHook
      ( action   => 'WRITER'
      , type     => ($config->{sign_types} or panic)
      , after    => sub {
          my ($doc, $xml) = @_;

          unless($xml->getAttributeNS(WSU_10, 'Id'))
          {   my $wsuid = 'node-'.($xml+0);      # configurable?
              $xml->setNamespace(WSU_10, wsu => 0);
              $xml->setAttributeNS(WSU_10, Id => $wsuid);

              # Above two lines do add a xml:wsu per Id.  Below does not,
              # which is not always enough: elements live in weird places
              #  my $wsu   = $schema->prefixFor(WSU_10);
              #  $xml->setAttribute("$wsu:Id", $wsuid);
          }

#use XML::Compile::Util qw/type_of_node/;
#warn "Registering to sign ".type_of_node($xml);
          push @elems_to_sign, $xml;
          $xml;
        }
      );

    my $container;
    $schema->addHook
      ( action => 'WRITER'
      , type   => ($config->{sign_put} || panic)
      , after  => sub {
          my ($doc, $xml) = @_;
#warn "Located signature container";
#         $schema->prefixFor(WSU_10);
          $container = $xml;
        }
      );

    my $add_signature = $self->builder;
    $schema->addHook
      ( action => 'WRITER'
      , type   => ($config->{sign_when} || panic)
      , after  => sub {
          my ($doc, $xml) = @_;
#warn "Creating signature";
          $add_signature->($doc, \@elems_to_sign, $container);
          @elems_to_sign = ();
          $xml;
        }
      );

    $self;
}

sub loadSchemas($$)
{   my ($self, $schema, $version) = @_;
    return if $schema->{XCWS_sig_loaded}++;

    $self->SUPER::loadSchemas($schema, $version);

    my $xsddir = dirname __FILE__;
    trace "loading wss-dsig schemas from $xsddir/(dsig|encr)/*.xsd";

    my @xsds   =
      ( bsd_glob("$xsddir/dsig/*.xsd")
      , bsd_glob("$xsddir/encr/*.xsd")
      );

    $schema->addPrefixes(\%prefixes);
    my $prefixes = join ',', sort keys %prefixes;
    $schema->addKeyRewrite("PREFIXED($prefixes)");

    $schema->importDefinitions(\@xsds);

    $schema;
}

1;
