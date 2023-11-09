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

TODO Abstract


--- middle

# Introduction



# Conventions and Definitions

{::boilerplate bcp14-tagged}

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
