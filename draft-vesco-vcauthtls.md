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
area: AREA
workgroup: WG
keyword:
 - TLS
 - VC
 - DID
 - DLT
venue:
  group: WG
  type: Working Group
  mail: WG@example.com
  arch: https://example.com/WG
  github: Cybersecurity-LINKS/draft-vesco-vcauthtls
  latest: https://example.com/LATEST

author:
 -
    fullname: Andrea Vesco
    organization: LINKS Foundation
    email: andrea.vesco@linksfoundation.com

 -
    fullname: Leonardo Perugini
    organization: LINKS Foundation
    email: leonardo.perugini@linksfoundation.com

 -
    fullname: Nicola Tuveri
    organization: Tampere University
    email: nic.tuv@gmail.com

normative:
    RFC8446:
    RFC7250:

informative:
      DID:
         title: Decentralized Identifiers (DIDs) v1.0
         date: July 2022
         target: https://www.w3.org/TR/did-core/
         author:
            - ins: W3C
      DID-Registries:
         title: DID Specification Registries
         date: September 2023
         target: https://www.w3.org/TR/did-spec-registries/#did-methods
         author:
            - ins: W3C
      VC:
         title: Verifiable Credentials Data Model v2.0
         date: November 2023
         target: https://www.w3.org/TR/vc-data-model-2.0/
         author:
            - ins: W3C
      VP:
         title: Verifiable Credentials Data Model v2.0
         date: November 2023
         target: https://www.w3.org/TR/vc-data-model-2.0/
         author:
            - ins: W3C


--- abstract

This document defines a new certificate type and extension for the exchange of Verifiable Credentials in the handshake of the Transport Layer Security (TLS) protocol. The new certificate type is intended to add the Verifiable Credentials as a new means of authentication. The resulting authentication process leverages a distributed ledger as the root-of-trust of the TLS endpoints' public keys. The endpoints can use different distributed ledger technologies to store their public keys and to perform the TLS handshake.


--- middle

# Introduction {#sec-intro}

The Self-Sovereign Identity (SSI) is a decentralised identity model that gives a node control over the data it uses to generate and prove its identity. SSI model relies on three fundamental elements: a distributed ledger as the Root of Trust (RoT) for public keys, Decentralized IDentifier {{DID}}, and Verifiable Credential {{VC}}. An SSI aware node builds his identity starting from generating the identity key pair (_sk_, _pk_). Then the node stores _pk_ in the distributed ledger of choice for other nodes to authenticate it.
A node's DID is a pointer to the distributed ledger where other nodes can retrieve its _pk_. A DID is a Uniform Resource Identifier (URI) in the form ``did:did-method-name:method-specific-id`` where ``method-name`` is the name of the {{DID}} Method used to interact with the distributed ledger and ``method-specific-id`` is the pointer to the {{DID}} Document that contains _pk_, stored in the distributed ledger.
After that, the node can request a VC from one of the Issuers available in the system. The VC contains the metadata to describe properties of the credential, the DID and the claims about the identity of the node and the signature of the Issuer.
The combination of the key pair (_sk_, _pk_), the DID and at least one VC forms the identity compliant with the SSI model.
A node requests access to services by presenting a Verfiable Presentation {{VP}}. The VP is an envelop of the VC signed by the node holding the VC with its _sk_. The verifier authenticates the node checking the validity and authenticity of the VP and the inner VC before granting or denying access to the requesting node.

The current implementations of the authentication process run at the Application layer. A client node estabhlishes a TLS channel authenticating the server node with the server's X.509 certificate. Then the server node authenticates the client node that sends its VP at application layer (i.e. over the TLS channel already established). The mutual authentication with VPs occurs when also the server node exchanges its VP with the client node again at application layer.

SSI is emerging as an identity option for Internet of Thing and Edge nodes in computing continuum environments. In these scenarios, (mutual) authentication with VP can take place directly at the TLS protocol layer, enabling the peer-to-peer interaction model envisaged by the SSI model.
This document describes the extensions to TLS handshake protocol to support the use of VCs for authentication while preserving the interoperability with TLS endpoints that use X.509 certificates.
The extensions enable server and mutual authentication using VC, X.509, Raw Public Key or a combination of two of them. The ability to perform hybrid authenticated handshakes supports the gradual deployment of SSI in existing systems. Moreover, the extension allows TLS endpoints to use different distributed ledger technologies to store their public keys and to authenticate the peer. The authentication process is successful if the TLS endpoints implement the DID Method to resolve the peer's DID.

This document uses _italic formatting_ in the following sections to mark some paragraphs discussing items still under design: [](#serverhello-message) and [](#certificate-message).

# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Extensions

## client_certificate_type and server_certificate_type extensions

The TLS extensions ``client_certificate_type`` and ``server_certificate_type`` defined in {{RFC7250}} are used to negotiate the type of ``Certificate`` messages used in TLS to authenticate the server and, optionally, the client. This section defines a new certificate type, called ``VC``, for the TLS 1.3 handshake. The updated ``CertificateType`` enumeration, the corresponding addition to the ``CertificateEntry`` structure, and the ``Certificate`` message structure are shown below.
In the current version of the document ``VC`` certificate type is set to 224, one of the values indicated by IANA for private use. ``CertificateType`` values are sent in the ``server_certificate_type`` and ``client_certificate_type`` extensions, and the ``CertificateEntry`` structures are included in the certificate chain sent in the ``Certificate`` message.

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
   };
   Extension extensions<0..2^16-1>;
} CertificateEntry;

struct {
   opaque certificate_request_context<0..2^8-1>;
   CertificateEntry certificate_list<0..2^24-1>;
} Certificate;
~~~

As per {{RFC7250}}, the client will send a list of certificate types in ``[endpoint]_certificate_type`` extension(s), the server processes the received extension(s) and selects one of the offered certificate types, returning the negotiated value in the ``EncryptedExtensions`` message. Note that there is no requirement for the negotiated value to be the same in ``client_certificate_type`` and ``server_certificate_type`` extensions sent in the same message. Client and server can use different certificate types as long as the peer is able to verify that specific type of certificate.

# did_methods extension

This section defines the ``did_methods`` extension, used as part of an extended TLS 1.3 handshake when ``VC`` certificate type is used. This extension contains a list of DID Methods an endpoint supports, i.e. a set of DLTs an endpoint can interact with to resolve the peer's DID. A client MUST send this extension in the extended ``ClientHello`` message only when it indicates Verifiable Credential support in the ``server_certificate_type`` extension. The server MUST send this extension in a ``CertificateRequest`` message only if it indicates Verifiable Credential in ``client_certificate_type`` extension. The extension format which uses the ``extension_data`` field, is used to carry the ``DIDMethodList`` structure. The structure of this new extension is shown below.

~~~
enum {
   btcr(0),
   ethr(1),
   iota(2),
   ..
   (65535)
} DIDMethod

struct {
   DIDMethod did_methods<2..2^16-2>
} DIDMethodList
~~~

The list of existing DID Methods is currently maintained by the W3C in {{DID-Registries}}. Each DID Method is expressed in the form of a string. This document proposes the ``DIDMethod`` enum to map these strings into integer values.

# TLS Client and Server Handshake

{{fig-full-handshake}} shows the message flow for full TLS handshake.

~~~~~
DLT          Client                               Server           DLT

      Key  ^ ClientHello
      Exch | + server_certificate_type*
           | + client_certificate_type*
           | + did_methods*
           | + signature_algorithms*
           v + key_share*  -------->
                                             ServerHello ^ Key
                                            + key_share* v Exch,
                                   {EncryptedExtensions} ^ Server
                            {+ server_certificate_type*} | Params
                            {+ client_certificate_type*} |
                                   {CertificateRequest*} |
                                        {+ did_methods*} v
                                          {Certificate*} ^
                                    {CertificateVerify*} | Auth
                                              {Finished} v
                           <-------- [Application Data*]
 DID Resolve
 <==========
           ^ {Certificate*}
      Auth | {CertificateVerify*}
           v {Finished}    -------->
                                                         DID Resolve
                                                         ==========>
             [Application Data] <---> [Application Data]

        +  Indicates noteworthy extensions sent in the
           previously noted message.
        *  Indicates optional or situation-dependent
           messages/extensions that are not always sent.
        {} Indicates messages protected using keys
           derived from a
           [sender]_handshake_traffic_secret.
        [] Indicates messages protected using keys
           derived from [sender]_application_traffic_secret_N.
~~~~~
{: #fig-full-handshake artwork-align="center"
    title="Message Flow for full TLS Handshake"}


## ClientHello message

To express support for ``VC`` certificate type, a client MUST include the extension of type ``client_certificate_type`` or ``server_certificate_type`` in the extended ``ClientHello`` message as described in {{Section 4.1.2 of RFC8446}}. If the client sends the ``server_certificate_type`` extension indicating ``VC``, it MUST also send the ``did_methods`` extension.

## ServerHello message

When the server receives the ``ClientHello`` message containing the ``server_certificate_type`` extension and/or the ``client_certificate_type`` extension, the following scenarios are possible:

- The server does not support the extensions, omits them in ``EncryptedExtensions`` and the handshake proceeds with X.509 certificate(s).
- The server does not support any of the proposed certificate types and terminates the session with a fatal alert of type ``unsupported_certificate``.
- Both client and server indicate support for the ``VC`` certificate type. The server selects ``VC`` certificate type, but the client did not send the ``did_methods`` extension in addition to the ``server_certificate_type`` extension. The server MUST terminate the session with a fatal alert of type ``missing_extension``.
- Both client and server indicate support for the ``VC`` certificate type. The server selects ``VC`` certificate type, but the server's DID is not compatible with any of the DID Methods supported by the client and listed in the ``did_methods`` extension sent with the ``ClientHello`` message. _This document defines two possible server behaviours (a) the server terminates the session with a fatal alert of type ``unsupported_did_methods``, (b) the server sends a HelloRetryRequest (HRR) message with a new extension listing the DLTs in which it owns a DID_.

_These design considerations apply: solution (a) requires defining a new fatal alert message type, and the client has no clues to perform a new successful TLS handshake; solution (b) requires defining a new HRR extension which could have privacy implications as it discloses the DLTs where the server owns its DIDs; on the other hand, this extension provides the client with clues to retry a successful new TLS handshake_.

- Both client and server indicate support for the ``VC`` certificate type, the server MAY select the first (most preferred) certificate type from the client's list that is supported by both endpoints. It MAY include the ``client_certificate_type`` in the ``EncryptedExtensions`` message to request a certificate from the client. In case the server selects ``VC`` certificate type, it MUST also send the ``did_methods`` extension in the ``CertificateRequest`` message.

## CertificateRequest message

The server sends the ``CertificateRequest`` message to request client authentication. It MUST include the ``did_methods`` extension if it indicates ``VC`` in the ``client_certificate_type`` extension. If the ``ClientHello`` contains the ``did_methods`` extension, the server MUST send a list of DID Methods client and server have in common. If the client does not send the ``did_methods`` extension the server MUST select a list of DID Methods it supports. A client that processes the ``CertificateRequest`` message that does not own a DID compatible with the DID Methods selected by the server MUST send a ``Certificate`` message containing no certificates, i.e. with the ``certificate_list`` field having length 0.

## Certificate message

When the selected certificate type is ``VC``, the ``certificate_list`` in the ``Certificate`` message MUST contain no more than one ``CertificateEntry`` with the content of the endpoint's Verifiable Credential. The content of the Verifiable Credential SHOULD be CBOR encoded. After decoding, the endpoint MUST follows the procedure in {{VC}} to verify the Verifiable Credential.

## CertificateVerify message

As discussed in {{sec-intro}}, an Holder wraps its own Verifiable Credential into a Verifiable Presentation and signs it before presenting it to a Verifier for authentication purposes. During the TLS handshake, when the selected certificate type is ``VC``, the subsequent ``CertificateVerify`` message acts also as the Holder signature on the Verifiable Presentation. In fact, the signature is computed over the transcript hash that contains also the Verifiable Credential of the sender inside the ``Certificate`` message.

# TLS handshake Examples

This section shows some examples of TLS handshakes using different combinations of certificate types.

## Server authentication with Verifiable Credential

The example in {{fig-server-vc}} shows a TLS 1.3 handshake with server authentication. The client sends the ``server_certificate_type`` extension indicating both ``VC`` and ``X.509`` certificate types. In addition, the client sends the ``did_methods`` extension with the list of supported DID Methods. The client does not own an identity at the TLS level, therefore omits the ``client_certificate_type`` extension.
The server selects ``VC`` certificate type, sends the EncryptedExtensions message with
the ``server_certificate_type`` extension set to VC, and sends its Verifiable Credential into the Certificate message.
After receiving the ``CertificateVerify`` and ``Finished`` messages, the client resolves the server's DID to retrieve the server _pk_ and authenticate it.

~~~~~
DLT         Client                                              Server

            ClientHello
            server_certificate_type=(VC,X.509)
            did_methods=(btcr,iota) -------->
                                                            ServerHello
                                                  {EncryptedExtensions}
                                           {server_certificate_type=VC}
                                                          {Certificate}
                                                    {CertificateVerify}
                                                             {Finished}
                                    <--------        [Application Data]
 DID Resolve
 <==========
            {Finished}              -------->
            [Application Data]      <------->        [Application Data]
~~~~~
{: #fig-server-vc artwork-align="center"
    title="TLS Server Uses Verifiable Credential"}


## Mutual authentication with Verifiable Credentials

The example in {{fig-mutual-vc}} shows a TLS 1.3 handshake with mutual authentication where both client and server authenticate the peer using Verifiable Credentials.
The client sends the ``server_certificate_type`` extension indicating both ``VC`` and ``X.509`` certificate types along with the ``did_methods`` extension containing the list of supported DID Methods. The client also sends the ``client_certificate_type`` extension indicating its capability to provide both a Verifiable Credential and an X.509 certificate.
The server sends the ``server_certificate_type`` set to ``VC``, the ``client_certificate_type`` set to ``VC`` and the ``CertificateRequest`` message with the ``did_methods`` extension containig a set of DID Methods in common with the client. Client and server send their Verifiable Credential into their respective ``Certificate`` messages.
After receiving the ``CertificateVerify`` and ``Finished`` messages, the client and then the server resolve the peer's DID to retrieve the associated _pk_ and authenticate each other.

~~~~~
DLT        Client                                    Server         DLT

           ClientHello
           server_certificate_type=(VC,X.509)
           client_certificate_type=(VC,X.509)
           did_methods=(btcr,ethr)
                              -------->
                                                ServerHello
                                      {EncryptedExtensions}
                               {server_certificate_type=VC}
                               {client_certificate_type=VC}
                                       {CertificateRequest}
                                  {did_methods=(btcr,ethr)}
                                              {Certificate}
                                        {CertificateVerify}
                                                 {Finished}
                              <--------  [Application Data]
 DID Resolve
 <==========
           {Certificate}
           {CertificateVerify}
           {Finished}         -------->
                                                           DID Resolve
                                                           ==========>
           [Application Data] <------->  [Application Data]
~~~~~
{: #fig-mutual-vc artwork-align="center"
    title="TLS Client and TLS Server Use Verifiable Credentials"}

## Mutual authentication with Client using Verifiable Credential and Server using X.509 Certificate

The example in {{fig-mutual-vc-x509}} shows a TLS 1.3 handshake with mutual authentication that combines the use of Verifiable Credential and X.509 certificate. The client uses a Verifiable Credential, and the server uses an X.509 certificate.
The client sends the ``server_certificate_type`` extension indicating ``X.509`` certificate types. The client also sends the ``client_certificate_type`` extension indicating its capability to provide both a Verifiable Credential and an X.509 certificate.
The server sends the ``server_certificate_type`` set to ``X.509``, the ``client_certificate_type`` set to ``VC`` and the ``CertificateRequest`` message with the ``did_methods`` extension containig the set of suported DID Methods. The server sends its X.509 certificate and the client its Verifiable Credential into their respective ``Certificate`` messages.
After receiving the ``CertificateVerify`` and ``Finished`` messages, the server resolves the client DID to retrieve the client _pk_ and authenticate it.

~~~~~
Client                                               Server         DLT

ClientHello
server_certificate_type=(X.509)
client_certificate_type=(VC,X.509)
                        -------->
                                                ServerHello
                                      {EncryptedExtensions}
                            {server_certificate_type=X.509}
                               {client_certificate_type=VC}
                                       {CertificateRequest}
                             {did_methods=(btcr,ethr,iota)}
                                              {Certificate}
                                        {CertificateVerify}
                                                 {Finished}
                        <--------        [Application Data]
{Certificate}
{CertificateVerify}
{Finished}              -------->
                                                           DID Resolve
                                                           ==========>
[Application Data]      <------->        [Application Data]
~~~~~
{: #fig-mutual-vc-x509 artwork-align="center"
    title="TLS Client Uses a Verifiable Credential and TLS Server Uses an X.509 Certificate"}

## Mutual authentication with Client using X.509 Certificate and Server using Verifiable Credential

The example in {{fig-mutual-x509-vc}} complements the previous one showing a TLS 1.3 handshake with mutual authentication where the client uses X.509 certificate and the server a Verifiable Credential.
The client sends the ``server_certificate_type`` extension indicating both ``VC`` and ``X.509`` certificate types along with the ``did_methods`` extension containing the list of supported DID Methods. The client also sends the ``client_certificate_type`` extension indicating its capability to provide only an X.509 certificate.
The server sends the ``server_certificate_type`` set to ``VC``, the ``client_certificate_type`` set to ``X.509`` and the ``CertificateRequest`` message. The server sends its Verifiable Credential, and the client its X.509 certificate into their respective ``Certificate`` messages.
After receiving the ``CertificateVerify`` and ``Finished`` messages, the client resolves the server's DID to retrieve the server _pk_ and authenticate the client.

~~~~~
DLT          Client                                              Server

             ClientHello
             server_certificate_type=(VC,X.509)
             client_certificate_type=(X.509)
             did_methods=(btcr,ethr,iota)
                                       -------->
                                                            ServerHello
                                                  {EncryptedExtensions}
                                           {server_certificate_type=VC}
                                        {client_certificate_type=X.509}
                                                   {CertificateRequest}
                                                          {Certificate}
                                                    {CertificateVerify}
                                                             {Finished}
                                       <--------     [Application Data]
 DID Resolve
 <==========
            {Certificate}
            {CertificateVerify}
            {Finished}                 -------->
            [Application Data]         <------->     [Application Data]
~~~~~
{: #fig-mutual-x509-vc artwork-align="center"
    title="TLS Client Uses an X.509 Certificate and TLS Server Uses a Verifiable Credential"}

# Security Considerations

All the security considerations presented in {{RFC8446}} applies to this document as well.
Further considerations can be made on the DID resolution process. Assuming that a DID resolution is performed in clear, a man-in-the-middle could impersonate the DLT node, forge a DID Document containing the authenticating endpoint's DID, associate it with a key pair that he owns, and then return it to the DID resolver. Thus, the attacker is able to compute a valid CertificateVerify message by possessing the long term private key. In practice, the man-in-the-middle attacker breaks in transit the immutability feature provided by the DLT, i.e. the RoT for the public keys.
A possible solution to this attack is to esthablish a TLS channel towards the DLT node and authenticate only the latter to rely on the received data. The DLT node MUST be authenticated through an X.509 certificate. The session resumption and 0 round-trip time (0-RTT) features of TLS 1.3 can be used to reduce the overhead of establishing this TLS channel.
In addition, since confidentiality is not a requirement for DID resolution, another solution is to configure the DLT node to sign the replies such that the DID resolver can verify the origin and the integrity of the data received.


# IANA Considerations

To be addressed


--- back

# Acknowledgments
{:numbered="false"}

To be done.
