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

W3C defined VC and DID

How to create identity in SSI and how to verify the VP (in HS sections describe how the hs covers the VP presentation).

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Extensions

## VC Certificate Type

The TLS extensions "client_certificate_type" and "server_certificate_type" [RFC7250] are used to negotiate the type of Certificate messages used in TLS to authenticate the server and, optionally, the client. Using separate extensions allows for mixed deployments where the client and server can use certificates of different types.
~~~
   /* Managed by IANA */
   enum {
      X509(0),
      RawPublicKey(2),
      VC(224),
      (255)
   } CertificateType;

   struct {
      select(certificate_type){
         // The new certificate type defined in this document
         case VC:
            opaque cert_data<1..2^24-1>;

         // RawPublicKey certificate type defined in RFC 7250
         case RawPublicKey:
            opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;

         // X.509 certificate defined in RFC 5246
         case X509:
            opaque cert_data<1..2^24-1>;

         // Additional certificate type based on
         // "TLS Certificate Types" subregistry
      };
   } Certificate;
~~~

# did_methods extension

~~~
   /* Managed by IANA */
   enum {
      iota(0),
      ..
      (65535)
   } DIDMethod

   struct {
      DIDMethod did_methods<2..2^16-2>
   } DIDMethodList

   [did-registry](https://www.w3.org/TR/did-spec-registries/#did-methods)
~~~

did_methods extension could be sent only in ClientHello and CertificateRequest messages.

# TLS Client and Server Handshake

~~~plantuml
@startuml
participant DLT_A order 1
participant Client order 2
participant Server order 3
participant DLT_B order 4
skinparam sequenceMessageAlign direction

Client -> Server : Client Hello \n+ client_cert_types* \n+ server_cert_types* \n+ key_share* \n+ sig_algs* \n+ <font color = green>did_methods</font>
Server -> Client : Server Hello \n+ key_share*
Server -> Client : { Encrypted Extensions \n+ client_cert_types* \n+ server_cert_types* }
Server -> Client : { Certificate request* \n+ <font color = green>did_methods*</font> }
Server -> Client : { Certificate* }
Server -> Client : { Certificate Verify* }
Server -> Client : { Finished }
Client --> DLT_A : DID Resolve
Client -> Server : { Certificate* }
Client -> Server : { Certificate Verify* }
Client -> Server : { Finished }
Server --> DLT_B : DID Resolve
@enduml
~~~


## ClientHello

## CertificateRequest

## Certificate

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

# Normative References

[DID] W3C, Decentralized Identifiers (DIDs) v1.0. Core architecture, data model, and representations. W3C Recommendation, 2022. https://www.w3.org/TR/did-core/

[VC] W3C, Verifiable Credentials Data Model v2.0. W3C Recommendation, 2023. https://www.w3.org/TR/vc-data-model-2.0/

# Informative References

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.

