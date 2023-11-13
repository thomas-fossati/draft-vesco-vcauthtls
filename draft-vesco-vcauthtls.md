---
title: "Transport Layer Security (TLS) Authentication with Verifiable Credential (VC)"
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
  github: "Cybersecurity-LINKS/draft-vesco-vcauthtls"
  latest: "https://Cybersecurity-LINKS.github.io/draft-vesco-perugini-tls-ssi/draft-vcauthtls.html"

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
  VC:
   title: "Verifiable Credentials Data Model v2.0"
   date: November 2023
   author:
      org: W3C
   seriesinfo:
      W3C TR/vc-data-model-2.0/
   target:
      https://www.w3.org/TR/2023/WD-vc-data-model-2.0-20231104/

  DID:
   title: "Decentralized Identifiers (DIDs) v1.0 Core architecture, data model, and representations"
   date: July 2022
   author:
      org: W3C
   seriesinfo:
      W3C TR/did-core
   target:
      https://www.w3.org/TR/2022/REC-did-core-20220719/


informative:

--- abstract
This document defines a new certificate type and extension for the exchange of Verifiable Credentials (VCs) in Transport Layer Security (TLS). The new certificate type is intended to add the VC as a new means of authentication. The validation process of the VC uses a distributed ledger as the Root of Trust (RoT) of the TLS node's public keys. The nodes can use different distributed ledger technologies to store their public key and to perform the TLS handshake.

--- middle

# Introduction and motivation

The Self-Sovereign Identity (SSI) is a decentralised identity model that gives a node control over the data it uses to generate and prove its identity. SSI model relies on three fundamental elements: a distributed ledger as the Root of Trust (RoT) for public keys, Decentralized IDentifier [DID](https://www.w3.org/TR/did-core/), and Verifiable Credential [VC](https://www.w3.org/TR/vc-data-model-2.0/). An SSI aware node builds his identity starting from generating the identity key pair ($sk, pk$). Then the node stores $pk$ in the distributed ledger of choice for other nodes to authenticate it.
A node's DID is a pointer to the distributed ledger where other nodes can retrieve its $pk$. A DID is a Uniform Resource Identifier (URI) in the form _did:did-method-name:method-specific-id_ where _method-name_ is the name of the [DID Method](https://www.w3.org/TR/did-core/) used to interact with the distributed ledger and _method-specific-id_ is the pointer to the [DID Document](https://www.w3.org/TR/did-core/) that contains $pk$, stored in the distributed ledger.
After that, the node can request a VC from one of the Issuers available in the system. The VC contains the metadata to describe properties of the credential, the DID and the claims about the identity of the node <!--in the _credentialSubject_ field,--> and the signature of the Issuer.
The combination of the key pair ($sk, pk$), the DID and at least one VC forms the identity compliant with the SSI model.
A node requests access to services by presenting a Verfiable Presentation [VP](https://www.w3.org/TR/vc-data-model-2.0/). The VP is an envelop of the VC signed by the node holding the VC with its $sk$. The verifier authenticates the node checking the authenticity of the VP and the validity and authenticity of the inner VC before granting or denying access to the requesting node.
<!-- The SSI model subtends the peer-to-peer model of interaction where both types of authentication are possible using VP; one node authenticates the other, or the nodes can authenticate each other. --> 
The current implementations of the authentication process involves the combination of two different identity technologies. A client node estabhlishes a TLS channel authenticating the server node with the server's X.509 certificate. Then the server node authenticate the client node that sends its VP at application layer (i.e. over the TLS channel already established). The mutual authentication with VPs occours when also the server node exchange its VP with the client node again at application layer.

SSI is emerging as an identity option for Internet of Thing and Edge nodes in computing continuum environments. In this scenarios, (mutual) authentication with VP can be directly done at TLS protocol layer making the the peer-to-peer model of interaction, envisioned by the SSI model, a reality. 
This document describes the extensions to TLS protocol to support the use of VCs for authentication while preserving the interoperability with TLS endpoints that use X.509 certificates.
The extensions enable server-only and mutual authentication using VC, X.509, Raw Public Key or a combination of VC and X.509 certificates at the TLS endpoints. The ability to perform hybrid authenticated handshakes supports the gradual deployment of SSI in existing systems. Moreover, the extension allow TLS endpoints to use different distributed ledger technologies to store their public keys and during the TLS handshake for authentication purpose.

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
~~~

[did-registry](https://www.w3.org/TR/did-spec-registries/#did-methods)

did_methods extension could be sent only in ClientHello and CertificateRequest messages.

# TLS Client and Server Handshake

{{tls-full}} below shows the basic full TLS handshake:

~~~plantuml
participant DLT_A order 1
participant Client order 2
participant Server order 3
database DLT_B order 4
skinparam sequenceMessageAlign direction
skinparam ParticipantPadding 100

Client -> Server : Client Hello \n+ client_cert_types* \n+ server_cert_types* \n+ key_share* \n+ sig_algs* \n+ did_methods
Server -> Client : Server Hello \n+ key_share*
Server -> Client : { Encrypted Extensions \n+ client_cert_types* \n+ server_cert_types* }
Server -> Client : { Certificate request* \n+ did_methods* }
Server -> Client : { Certificate* }
Server -> Client : { Certificate Verify* }
Server -> Client : { Finished }
Client --> DLT_A : DID Resolve
Client -> Server : { Certificate* }
Client -> Server : { Certificate Verify* }
Client -> Server : { Finished }
Server --> DLT_B : DID Resolve
~~~
{: #tls-full title="Message Flow for Full TLS Handshake"}

## Client Hello

The following comes as is from [RFC 8902](https://www.rfc-editor.org/rfc/rfc8902.html#name-tls-server-and-tls-client-u)

In order to indicate the support of VC, a client MUST include an extension of type "client_certificate_type" or "server_certificate_type" in the extended Client Hello message as described in Section 4.1.2 of [RFC8446] (TLS 1.3).For TLS 1.3, the rules for when the Client Certificate and CertificateVerify messages appear are as follows:

- The client's Certificate message is present if and only if the server sent a CertificateRequest message.
- The client's CertificateVerify message is present if and only if the client's Certificate message is present and contains a non-empty certificate_list. For maximum compatibility, all implementations SHOULD be prepared to handle "potentially" extraneous certificates and arbitrary orderings from any TLS version, with the exception of the end-entity certificate, which MUST be first.
 

## Server Hello

The following comes as is from [RFC 8902](https://www.rfc-editor.org/rfc/rfc8902.html#name-tls-server-and-tls-client-u)

When the server receives the Client Hello containing the client_certificate_type extension and/or the server_certificate_type extension, the following scenarios are possible:

- If both the client and server indicate support for the ITS certificate type, the server MAY select the first (most preferred) certificate type from the client's list that is supported by both peers.
- The server does not support any of the proposed certificate types and terminates the session with a fatal alert of type "unsupported_certificate".
- The server supports the certificate types specified in this document. In this case, it MAY respond with a certificate of this type. It MAY also include the client_certificate_type and did_methods extensions in Encrypted Extension and Certificate Request respectively. Then, the server requests a certificate from the client (via the CertificateRequest message).
- The server supports the VC certificate type, but owns a DID that is not compatible with the did_methods extension sent by the client. [It terminates the session with a fatal alert of type "unsupported_did_methods"/ It sends an HelloRetryRequest message equipped with the did_methods extension containing the list of DLTs on which owns at least a DID document.]

The certificates in the TLS client or server certificate chain MAY be sent as part of the handshake, MAY be obtained from an online repository, or might already be known to and cached at the endpoint. If the handshake does not contain all the certificates in the chain, and the endpoint cannot access the repository and does not already know the certificates from the chain, then it SHALL reject the other endpoint's certificate and close the connection. Protocols to support retrieving certificates from a repository are specified in ETSI [TS102941].

## Certificate Request

The server must send the did_methods extension in this message when client_certificate_type extension is set to VC. If the client has previously sent the did_methods extension, the extension sent by the server must be a list of DID methods client and server have in common. If the client did not send "did_methods" extension the server is free to select the values that it wants.

A client processing this extension realizes that does not have a DID that belongs to one of the DLTs specified by the server MUST terminate the handshake with a fatal alert "unsupported_did_methods".

# Certificate

In the case of TLS 1.3, and when the certificate_type is VC, the Certificate contents and processing are different than for the Certificate message specified for other values of certificate_type in [RFC8446]. The party that process a Certificate message containing a VC must check that the VC follows the scheme specified in the @context field, then check the validity of the VC metadata, verify the signature of the Issuer on the VC, and then extract the server DID from the credentialSubject field of the VC and resolve the server DID to retrieve the server public key from the distributed ledger.
The public is employed to verify the signature in the CertificateVerify message sent by the peer.

# Certificate Verify

The signature is computed in the same way as before, but now the private key associated to public key of the sender DID document is employed.

# Examples

## TLS Server Uses a VC

This section shows an example that the client is willing to receive and validate a VC from the server. The client does not own an identity at the TLS level and so omits the server_cert_type extension.

~~~plantuml
@startuml
skinparam sequenceMessageAlign direction
skinparam ParticipantPadding 100

database OTT order 1
participant Client order 2
participant Server order 3

Client -> Server : Client Hello \n+ server_cert_types*=VC \n+ key_share* \n+ sig_algs* \n+ did_methods*=OTT
Server -> Client : Server Hello \n+ key_share*
Server -> Client : { Encrypted Extensions \n+ server_cert_types*=VC }
Server -> Client : { Certificate* }
Server -> Client : { Certificate Verify* }
Server -> Client : { Finished }
Client --> OTT : DID Resolve
Client -> Server : { Finished }
@enduml
~~~

## TLS Client and Server Use VCs

~~~plantuml
@startuml
database DLT_A order 1
participant Client order 2
participant Server order 3
database DLT_B order 4
skinparam sequenceMessageAlign direction
skinparam ParticipantPadding 100

Client -> Server : Client Hello \n+ client_cert_types*=VC \n+ server_cert_types*=VC \n+ key_share* \n+ sig_algs* \n+ did_methods=OTT
Server -> Client : Server Hello \n+ key_share*
Server -> Client : { Encrypted Extensions \n+ client_cert_types*=VC \n+ server_cert_types*=VC }
Server -> Client : { Certificate request* \n+ did_methods*=OTT }
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

## TLS Client Uses VC and Server Uses Certificate

~~~plantuml
@startuml
participant Client order 2
participant Server order 3
database DLT_B order 4
skinparam sequenceMessageAlign direction
skinparam ParticipantPadding 100

Client -> Server : Client Hello \n+ client_cert_types*=(VC, X.509) \n+ server_cert_types*=(X.509, RPK) \n+ key_share* \n+ sig_algs*
Server -> Client : Server Hello \n+ key_share*
Server -> Client : { Encrypted Extensions \n+ client_cert_types*=VC \n+ server_cert_types*=X.509 }
Server -> Client : { Certificate request* }
Server -> Client : { Certificate* }
Server -> Client : { Certificate Verify* }
Server -> Client : { Finished }
Client -> Server : { Certificate* }
Client -> Server : { Certificate Verify* }
Client -> Server : { Finished }
Server -> DLT_B : DID Resolve
@enduml
~~~

## TLS Client Uses Certificate and Server Uses VC

~~~plantuml
@startuml
participant Client order 2
participant Server order 3
database DLT_A order 1
skinparam sequenceMessageAlign direction
skinparam ParticipantPadding 100

Client -> Server : Client Hello \n+ client_cert_types*=(X.509) \n+ server_cert_types*=(VC, RPK) \n+ key_share* \n+ sig_algs* \n+ did_methods*=OTT
Server -> Client : Server Hello \n+ key_share*
Server -> Client : { Encrypted Extensions \n+ client_cert_types*=X.509 \n+ server_cert_types*=VC }
Server -> Client : { Certificate request* }
Server -> Client : { Certificate* }
Server -> Client : { Certificate Verify* }
Server -> Client : { Finished }
Client -> DLT_A : DID Resolve
Client -> Server : { Certificate* }
Client -> Server : { Certificate Verify* }
Client -> Server : { Finished }
@enduml
~~~

## Fallback to Traditional Handshake

<!--server ignores ssi_parameters extension in the clientHello-->

## Empty intersection of Client and Server DID Methods

<!--HelloRetryRequest + foobar extension
server replies with the list of its DID Methods, this implies that the server has a DID stored in each of the DLT of the listed DID Methods.-->

## TLS Server Enforces SSI Server Authentication

<!--server enforces SSI client authentication (no fall back bu enforce SSI to the client) HelloRetryRequest -->

# Security Considerations

TODO Security

# IANA Considerations

<!--This document has no IANA actions.-->

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.

