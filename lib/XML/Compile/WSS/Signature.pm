# Copyrights 2012-2013 by [Mark Overmeer].
#  For other contributors see ChangeLog.
# See the manual pages for details on the licensing terms.
# Pod stripped from pm file by OODoc 2.01.
use warnings;
use strict;

package XML::Compile::WSS::Signature;
use vars '$VERSION';
$VERSION = '1.08';

use base 'XML::Compile::WSS';

use Log::Report 'xml-compile-wss-sig';

use XML::Compile::WSS::Util     qw/:wss11 :wsm10 :dsig :xtp10/;
use XML::Compile::C14N          ();
use XML::Compile::C14N::Util    qw/:c14n/;
use XML::Compile::WSS::SecToken ();
use XML::Compile::WSS::Sign     ();

use Digest          ();
use XML::LibXML     ();
use File::Basename  qw/dirname/;

my $unique = $$.time;
my @default_canon_ns = qw/ds wsu xenc SOAP-ENV/;
my @prefixes = (dsig11 => DSIG11_NS, dsp => DSP_NS, dsigm => DSIG_MORE_NS);

#use Data::Dumper;
#$Data::Dumper::Indent    = 1;
#$Data::Dumper::Quotekeys = 0;

my ($digest_algorithm, $sign_algorithm);
{  my ($signs, $sigmns) = (DSIG_NS, DSIG_MORE_NS);
   # the digest algorithms can be distiguish by pure lowercase, no dash.
   $digest_algorithm = qr/^(?:$signs|$sigmns)([a-z0-9]+)$/;
}


sub init($)
{   my ($self, $args) = @_;
    $args->{wss_version} ||= '1.1';

    $self->SUPER::init($args);

    # Run digest to initialize modules (and detect what is not installed)
    # Usually client and server use the same algorithms
    my $digest = $self->{XCWS_digmeth}  = $args->{digest_method} || DSIG_SHA1;
    $self->digest($digest, \"test digest");

    my $schema = $self->schema or panic;
    my $c14n   = XML::Compile::C14N->new(version => '1.1', schema => $schema);

    $self->_make_canon
      ( $c14n
      , $args->{canon_method} || C14N_EXC_NO_COMM
      , $args->{prefix_list}  || \@default_canon_ns
      );

    my $publ_token = $args->{publish_token} || 'INCLUDE_BY_REF';
    my $token      = $self->{XCWS_token}  # usually an ::X509
                   = XML::Compile::WSS::SecToken->fromConfig($args->{token});
    $self->_make_publish_token($token, $publ_token);
    $self->_make_key_info($token, $publ_token);

    my $sign_method = $args->{signer} || DSIG_RSA_SHA1;
    my $priv_key    = $args->{private_key}
        or error __x"private_key required";

    $self->_make_signer($sign_method, $priv_key);
    $self->_make_checker($args->{checker}) if $args->{checker};

    if(my $r = $args->{remote_token})
    {   $self->{XCWS_rem_token} = XML::Compile::WSS::SecToken->fromConfig($r);
    }

    $self;
}

#-----------------------------


sub defaultDigestMethod() { shift->{XCWS_digmeth} }


sub digester($)
{   my ($self, $method) = @_;
    $method =~ $digest_algorithm
        or error __x"digest {name} is not a correct constant";
    my $algo = uc $1;

    sub {
        my $data = shift;
        my $digest = try { my $d = Digest->new($algo)->add($$data)->digest };
        $@ or return $digest;

        error __x"cannot use digest method {short}, constant {name}: {err}"
          , short => $algo, name => $method, err => $@->wasFatal;
    };
}


sub digest($$)
{   my ($self, $method, $text) = @_;
    $self->digester($method)->($text);
}

sub _digest_elem_check($$)
{   my ($self, $elem, $ref) = @_;
    my $transf   = $ref->{ds_Transforms}{ds_Transform}[0]; # only 1 transform
    my ($inclns, $preflist) = %{$transf->{cho_any}[0]};    # only 1 kv pair
    my $elem_c14n = $self
        ->applyCanon($transf->{Algorithm}, $elem, $preflist->{PrefixList});

    my $digmeth = $ref->{ds_DigestMethod}{Algorithm} || '(none)';
    $self->digest($digmeth, \$elem_c14n) eq $ref->{ds_DigestValue};
}
#-----------------------------


# produces a sub which does correct canonicalization.
sub _make_canon($$$)
{   my ($self, $c14n, $method, $prefixes) = @_;
    $self->{XCWS_c14n}       = $c14n;
    $self->{XCWS_canonmeth}  = $method;
    $self->{XCWS_prefixlist} = $prefixes;
    $self->{XCWS_do_canon}   = sub
      { my $node = shift or return '';
        $c14n->normalize($method, $node, prefix_list => $prefixes);
      };
}


sub canonicalizer() {shift->{XCWS_do_canon}}
sub defaultCanonMethod() {shift->{XCWS_canonmeth}}
sub defaultPrefixList() {shift->{XCWS_prefixlist}}
sub c14n() {shift->{XCWS_c14n}}


sub applyCanon($$$)
{   my ($self, $algo, $elem, $prefixlist) = @_;
    $self->c14n->normalize($algo, $elem, prefix_list => $prefixlist);
}

# XML::Compile has to trick with prefixes, because XML::LibXML does not
# permit the creation of nodes with explicit prefix, only by namespace.
# The next can be slow and is ugly, Sorry.  MO
sub _repair_xml($$@)
{   my ($self, $xc_out_dom, @prefixes) = @_;

    # only doc element does charsets correctly
    my $doc    = $xc_out_dom->ownerDocument;

    # building bottom up: be sure we have all namespaces which may be
    # declared later, on higher in the hierarchy.
    my $env    = $doc->createElement('Dummy');
    my $schema = $self->schema;
    $env->setNamespace($schema->prefix($_)->{uri}, $_, 0)
        for @prefixes;

    # reparse tree
    $env->addChild($xc_out_dom);
    my $fixed_dom = XML::LibXML->load_xml(string => $env->toString(0));
    my $new_out   = ($fixed_dom->documentElement->childNodes)[0];
    $doc->importNode($new_out);
#warn $new_out->toString(1);
    $new_out;
}


#-----------------------------


sub token() {shift->{XCWS_token}}
sub remoteToken() {shift->{XCWS_rem_token}}


sub _make_publish_token($$)
{   my ($self, $token, $how) = @_;
    my $publ
      = ref $how eq 'CODE'       ? $how
      : $how eq 'INCLUDE_BY_REF' ? $token->makeBinSecTokenWriter($self)
      : $how eq 'NO'             ? sub {}
      : error __x"do not understand how to publish token";

    $self->{XCWS_publ_token} = $publ;
}

sub publishToken() {shift->{XCWS_publ_token}}


sub _make_key_info($$)
{   my ($self, $token, $how) = @_;
    return $how if ref $how eq 'CODE';
 
    $how eq 'INCLUDE_BY_REF'
        or error __x"publish_token either CODE or 'INCLUDE_BY_REF'";

    my %ref   = 
      ( URI       => '#'.$token->id
      , ValueType => $token->type
      );
    my $schema  = $self->schema;
    $schema->prefixFor(WSU_10);   # force inclusion of namespace decl

    my $krt = $schema->findName('wsse:Reference');
    my $krw = $schema->writer($krt, include_namespaces => 0);

    my $kit = $schema->findName('wsse:SecurityTokenReference');
    my $kiw = $schema->writer($kit, include_namespaces => 0);

    $self->{XCWS_key_info} = sub ($) {
       my ($doc) = @_;
       my $kr  = $krw->($doc, \%ref);
       my $ki  = $kiw->($doc, {cho_any => {$krt => $kr}});
       +{ cho_ds_KeyName => [{$kit => $ki}] };
    };
}
sub includeKeyInfo() {shift->{XCWS_key_info}}

#-----------------------------

sub signer()  {shift->{XCWS_signer}}
sub checker() {shift->{XCWS_checker}}

sub _make_signer($$)
{   my ($self, $config, $privkey) = @_;
    $self->{XCWS_signer} = XML::Compile::WSS::Sign
     ->fromConfig($config, $privkey);
}

sub _make_checker($)
{   my ($self, $config) = @_;
    $config or return;
    $self->{XCWS_checker} = XML::Compile::WSS::Sign->fromConfig($config);
}


sub signElement(%)
{   my ($self, $node, %args) = @_;
    my $wsuid = $node->getAttributeNS(WSU_10, 'Id');
    unless($wsuid)
    {   $wsuid = $args{id} || 'elem-'.$unique++;
        $node->setNamespace(WSU_10, 'wsu', 0);
        $node->setAttributeNS(WSU_10, 'Id', $wsuid);
    }
    push @{$self->{XCWS_to_sign}}, +{node => $node,  id => $wsuid};
    $node;
}


sub takeElementsToSign() { delete shift->{XCWS_to_sign} || [] }


sub checkElement($%)
{   my ($self, $node, %args) = @_;
    my $id = $node->getAttributeNS(WSU_10, 'Id')
        or error "element to check {name} has no wsu:Id"
             , name => $node->nodeName;

    $self->{XCWS_to_check}{$id} = $node;
}


sub elementsToCheck()
{   my $self = shift;
    my $to_check = delete $self->{XCWS_to_check};
    $self->{XCWS_to_check} =  {};
    $to_check;
}

#-----------------------------
#### HELPERS

sub _get_sec_token($$)
{   my ($self, $sec, $sig) = @_;
    my $sec_tokens = $sig->{ds_KeyInfo}{cho_ds_KeyName}[0]
        ->{wsse_SecurityTokenReference}{cho_any}[0];
    my ($key_type, $key_data) = %$sec_tokens;
    $key_type eq 'wsse_Reference'
        or error __x"key-type {type} not yet supported", type => $key_type;
    my $key_uri    = $key_data->{URI} or panic;
    (my $key_id    = $key_uri) =~ s/^#//;

    my $token;
    if(my $data = $sec->{wsse_BinarySecurityToken})
    {   $token = XML::Compile::WSS::SecToken->fromBinSecToken($self, $data);
    }
    else
    {   error __x"cannot collect token from response";
    }
    
    $token->id eq $key_id
        or error __x"token does not match reference";

    $token->type eq $key_data->{ValueType}
        or error __x"token type {type1} does not match expected {type2}"
             , type1 => $token->type, type2 => $key_data->{ValueType};

    $token;
}

sub _get_signer($$)
{   my ($self, $sig_meth, $token) = @_;
    XML::Compile::WSS::Sign->new(type => $sig_meth
      , public_key => $token);
}

sub prepareReading($)
{   my ($self, $schema) = @_;
    $self->SUPER::prepareReading($schema);

    $schema->declare(READER => 'ds:Signature',
      , hooks => {type => 'ds:SignedInfoType', after => 'XML_NODE'});

    my $checker = $self->checker;

    $self->{XCWS_reader} = sub {
        my $sec  = shift;
#warn Dumper $sec;
        my $sig  = $sec->{ds_Signature};
        unless($sig)
        {   # When the signature is missing, we only die if we expect one
            $self->checker or return;
            error __x"requires signature block missing from remote";
        }

        my $info       = $sig->{ds_SignedInfo} || {};

        # Check signature on SignedInfo
        my $can_meth   = $info->{ds_CanonicalizationMethod};
        my $can_pref   = $can_meth->{c14n_InclusiveNamespaces}{PrefixList};
        my $si_canon   = $self->applyCanon($can_meth->{Algorithm}
          , $info->{_XML_NODE}, $can_pref);

        unless($checker)
        {   # We only create the checker once: at the first received
            # message.  We may need to invalidate it for reuse of this object.
            my $sig_meth = $info->{ds_SignatureMethod}{Algorithm};
            my $token    = $self->_get_sec_token($sec, $sig);
            $checker     = $self->_get_signer($sig_meth, $token);
        }
#warn "#3 $si_canon";
        $checker->check(\$si_canon, $sig->{ds_SignatureValue}{_})
#           or error __x"signature on SignedInfo incorrect";
            or warning __x"signature on SignedInfo incorrect";

        # Check digest of the elements
        my %references;
        foreach my $ref (@{$info->{ds_Reference}})
        {   my $uri = $ref->{URI};
            $references{$uri} = $ref;
        }

        my $check = $self->elementsToCheck;
#print "FOUND: ", Dumper \%references, $info, $check;
        foreach my $id (sort keys %$check)
        {   my $node = $check->{$id};
            my $ref  = delete $references{"#$id"}
                or error __x"cannot find digest info for {elem}", elem => $id;
            $self->_digest_elem_check($node, $ref)
                or warning __x"digest info of {elem} is wrong", elem => $id;
        }
    };

    $self;
}

sub check($)
{   my ($self, $data) = @_;
    $self->{XCWS_reader}->($data);
}

### BE WARNED: created nodes can only be used once!!! in XML::LibXML

sub _create_inclns($)
{   my ($self, $prefixes) = @_;
    $prefixes ||= [];
    my $schema  = $self->schema;
    my $type    = $schema->findName('c14n:InclusiveNamespaces');
    my $incns   = $schema->writer($type, include_namespaces => 0);

    ( $type, sub {$incns->($_[0], {PrefixList => $prefixes})} );
}

sub _fill_signed_info()
{   my $self = shift;
    my $prefixes  = $self->defaultPrefixList;
    my ($incns, $incns_make) = $self->_create_inclns($prefixes);
    my $canonical = $self->canonicalizer;
    my $canon     = $self->defaultCanonMethod;
    my $signmeth  = $self->signer->type;

    my $digest    = $self->defaultDigestMethod;
    my $digester  = $self->digester($digest);

    sub {
        my ($doc, $parts) = @_;
        my $canon_method =
         +{ Algorithm => $canon
          , $incns    => $incns_make->($doc)
          };
    
        my @refs;
        foreach my $part (@$parts)
        {   my $transform =
              { Algorithm => $canon
              , cho_any => [ {$incns => $incns_make->($doc)} ]
              };
    
            my $repaired = $self->_repair_xml($part->{node}, qw/wsu SOAP-ENV/);
            push @refs,
             +{ URI             => '#'.$part->{id}
              , ds_Transforms   => { ds_Transform => [$transform] }
              , ds_DigestValue  => $digester->(\$canonical->($repaired))
              , ds_DigestMethod => { Algorithm => $digest }
              };
        }
    
         +{ ds_CanonicalizationMethod => $canon_method
          , ds_Reference              => \@refs
          , ds_SignatureMethod        => { Algorithm => $signmeth }
          };
    };
}

sub prepareWriting($)
{   my ($self, $schema) = @_;
    $self->SUPER::prepareWriting($schema);
    return $self if $self->{XCWS_sign};
    my @elements_to_sign;

    my $fill_signed_info = $self->_fill_signed_info;
    my $signer = $self->signer;

    # encode by hand, because we need the signature immediately
    my $infow  = $schema->writer('ds:SignedInfo');

    my $sigt   = $schema->findName('ds:Signature');
    my $sigw   = $schema->writer($sigt);

    my $canonical     = $self->canonicalizer;
    my $publish_token = $self->publishToken;
    my $key_info      = $self->includeKeyInfo;

    $self->{XCWS_sign} = sub {
        my ($doc, $sec) = @_;
        my $to_sign   = $self->takeElementsToSign;
        return $sec if $sec->{$sigt};           # signature already produced?
        my $info      = $fill_signed_info->($doc, $to_sign);
        my $info_node = $self->_repair_xml($infow->($doc, $info), 'SOAP-ENV');
        my $signature = $signer->sign(\$canonical->($info_node));
#warn "Sign %3 ",$canonical->($info_node);

        # The signature value is only known when the Info is ready,
        # but gladly they are produced in the same order.
        my %sig =
          ( ds_SignedInfo     => $info_node
          , ds_SignatureValue => {_ => $signature}
          , ds_KeyInfo        => $key_info->($doc)
          );

        $sec->{$sigt}     = $sigw->($doc, \%sig);
        $publish_token->($doc, $sec);
        $sec;
    };
    $self;
}

sub create($$)
{   my ($self, $doc, $sec) = @_;
    # cannot do much yet, first the Body must be ready.
    $self->{XCWS_sec_hdr} = $sec;
    $self;
}


sub createSignature($)
{   my ($self, $doc) = @_;
    $self->{XCWS_sign}->($doc, $self->{XCWS_sec_hdr});
}

#---------------------------
sub loadSchemas($$)
{   my ($self, $schema, $version) = @_;
    return if $schema->{XCWS_sig_loaded}++;

    $self->SUPER::loadSchemas($schema, $version);
    my $xsddir = (dirname __FILE__).'/dsig';

    trace "loading wss-dsig schemas";

    $schema->prefixes(@prefixes);
    $schema->importDefinitions( [glob "$xsddir/*.xsd"] );


}

1;
