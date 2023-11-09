---
title: "TODO - Your title"
abbrev: "TODO - Abbreviation"
category: info

docname: draft-vesco-vcauthtls-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
# area: AREA
# workgroup: WG Working Group
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
#  group: WG
#  type: Working Group
#  mail: WG@example.com
#  arch: https://example.com/WG
  github: "Cybersecurity-LINKS/draft-vesco-perugini-tls-ssi"
  latest: "https://Cybersecurity-LINKS.github.io/draft-vesco-perugini-tls-ssi/draft-vesco-perugini-tuveri-tls-ssi.html"

author:
 -
    fullname: "Andrea Vesco"
    organization: LINKS Foundation
    email: "andrea.vesco@linksfoundation.com"
 -
    fullname: "Leonardo Perugini"
    organization: LINKS Foundation
    email: "leonardo.perugini@linksfoundation.com"
 -
    fullname: "Nicola Tuveri"
    organization: Tampere University
    email: "nic.tuv@gmail.com"


normative:

informative:

--- abstract
This document defines a new certificate type and a new extension to exchange Verifiable Credentials (VCs) in Transport Layer Security (TLS). The new certificate type allows VC to be used for authentication purpose.

--- middle

# Introduction

W3C defined VC

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# VC Certificate type

~~~
opaque ASN.1Cert<1..2^24-1>;

struct {
   select(certificate_type){
      // RawPublicKey certificate type defined in RFC 7250
      case RawPublicKey:
         opaque ASN.1_subjectPublicKeyInfo<1..2^24-1>;

      // X.509 certificate defined in RFC 5246
      case X.509:
         ASN.1Cert certificate_list<0..2^24-1>;

      // The new certificate type definied in this document
      case VC:
         opaque ASN.1_subjectPublicKeyInfo<1..2^24-1>;

      // Additional certificate type based on
      // "TLS Certificate Types" subregistry
   };
} Certificate;
~~~

TLS Certificate types (IANA)


| value | name | recommended | Reference | comment |
|-------|------|-------------|-----------|---------|
| 4 | Verifiable Credential | | This document | |


# Structure of the FOOBAR Extensions

## ssi_parameters

## foobar1

## foobar2

# Possibly the new Messages

# TLS Client and Server Handshake Behavior

## ClientHello

## CertificateRequest

## Certificate

## CertificateVerify

# An alternative Design / Design Consideration

# Examples

## TLS Server Uses a VP

## TLS Client and Server Use VPs

## TLS Client Uses VP and Server Uses Certificate

## TLS Client Uses Certificate and Server Uses VP

it happens when the server does not send ssi_paramters extension in certificate request or it does but the client does not have a DID in the list of supported DLT (i.e. DID Methods) by the server

## Fallback to Traditional Handshake

server ignores ssi_parameters extension in the clientHello

## Empty intersection of Client and Server DID Methods

HelloRetryRequest + foobar extension
server replies with the list of its DID Methods, this implies that the server has a DID stored in each of the DLT of the listed DID Methods.

## TLS Server Enforces SSI Server Authentication

server enforces SSI client authentication (no fall back bu enforce SSI to the client)

HelloRetryRequest

# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
