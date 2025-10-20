---
title: "Concrete Hybrid PQ/T Key Encapsulation Mechanisms"
abbrev: concrete-hybrid-kems
category: info

docname: draft-irtf-cfrg-concrete-hybrid-kems-latest
submissiontype: IRTF
number:
date:
consensus: true
v: 3
area: "IRTF"
workgroup: "Crypto Forum"
keyword:
 - post quantum
 - kem
 - PQ
 - hpke
 - hybrid encryption

venue:
  group: "Crypto Forum"
  type: "Research Group"
  mail: "cfrg@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/search/?email_list=cfrg"
  github: "cfrg/draft-irtf-cfrg-concrete-hybrid-kems"
  latest: "https://cfrg.github.io/draft-irtf-cfrg-concrete-hybrid-kems/draft-irtf-cfrg-concrete-hybrid-kems.html"

author:
  -
    fullname: Deirdre Connolly
    organization: SandboxAQ
    email: durumcrustulum@gmail.com
  -
    fullname: Richard Barnes
    organization: Cisco
    email: rlb@ipv.sx

normative:
  FIPS202: DOI.10.6028/NIST.FIPS.202
  FIPS203: DOI.10.6028/NIST.FIPS.203
  SP800-186: DOI.10.6028/NIST.SP.800-186

informative:
  ABH+21:
    title: "Analysing the HPKE standard."
    date: April, 2021
    author:
      -
        fullname: Joël Alwen
      -
        fullname: Bruno Blanchet
      -
        fullname: Eduard Hauck
      -
        fullname: Eike Kiltz
      -
        fullname: Benjamin Lipp
      -
        fullname: Doreen Riepel
  ACM+25:
    title: "The Sponge is Quantum Indifferentiable"
    target: https://eprint.iacr.org/2025/731.pdf
    date: 2025
    author:
      -
        fullname: Gorjan Alagic
      -
        fullname: Joseph Carolan
      -
        fullname: Christian Majenz
      -
        fullname: Saliha Tokat
  ANSIX9.62:
    title: "Public Key Cryptography for the Financial Services Industry: the Elliptic Curve Digital Signature Algorithm (ECDSA)"
    date: Nov, 2005
    seriesinfo:
      "ANS": X9.62-2005
    author:
      -
        org: ANSI
  BDP+08:
    title: "On the Indifferentiability of the Sponge Construction"
    target: https://www.iacr.org/archive/eurocrypt2008/49650180/49650180.pdf
    date: 2008
    author:
      -
        fullname: Guido Bertoni
      -
        fullname: Joan Daemen
      -
        fullname: Michael Peeters
      -
        fullname: Gilles Van Assche
  SCHMIEG2024:
    title: "Unbindable Kemmy Schmidt: ML-KEM is neither MAL-BIND-K-CT nor MAL-BIND-K-PK"
    target: https://eprint.iacr.org/2024/523.pdf
    date: 2024
    author:
      -
        ins: S. Schmieg
        name: Sophie Schmieg
  SEC1:
    title: "Elliptic Curve Cryptography, Standards for Efficient Cryptography Group, ver. 2"
    target: https://secg.org/sec1-v2.pdf
    date: 2009
  XWING:
    title: "X-Wing: The Hybrid KEM You’ve Been Looking For"
    target: https://eprint.iacr.org/2024/039.pdf
    date: 2024
  XWING-SPEC: I-D.connolly-cfrg-xwing-kem
  CDM23:
    title: "Keeping Up with the KEMs: Stronger Security Notions for KEMs and automated analysis of KEM-based protocols"
    target: https://eprint.iacr.org/2023/1933.pdf
    date: 2023
    author:
      -
        ins: C. Cremers
        name: Cas Cremers
        org: CISPA Helmholtz Center for Information Security
      -
        ins: A. Dax
        name: Alexander Dax
        org: CISPA Helmholtz Center for Information Security
      -
        ins: N. Medinger
        name: Niklas Medinger
        org: CISPA Helmholtz Center for Information Security
  KSMW2024:
    target: https://eprint.iacr.org/2024/1233
    title: "Binding Security of Implicitly-Rejecting KEMs and Application to BIKE and HQC"
    author:
      -
        ins: J. Kraemer
      -
        ins: P. Struck
      -
        ins: M. Weishaupl


--- abstract

PQ/T Hybrid Key Encapsulation Mechanisms (KEMs) combine "post-quantum"
cryptographic algorithms, which are safe from attack by a quantum computer,
with "traditional" algorithms, which are not.  CFRG has developed a general
framework for creating hybrid KEMs.  In this document, we define concrete
instantiations of this framework to illustrate certain properties of the
framework and simplify implementors' choices.

--- middle

# Introduction

PQ/T Hybrid Key Encapsulation Mechanisms (KEMs) combine "post-quantum"
cryptographic algorithms, which are safe from attack by a quantum computer,
with "traditional" algorithms, which are not.  Such KEMs are secure against a
quantum attacker as long as the PQ algorithm is secure, and remain secure
against traditional attackers even if the PQ algorithm is not secure.

{{!HYBRID-KEMS=I-D.irtf-cfrg-hybrid-kems}} defines a general framework for
creating hybrid KEMs. It includes multiple specific mechanisms for combining
a PQ algorithm with a traditional algorithm, with different performance
properties and security requirements for the underlying algorithms.

In this document, we describe instances of these different specific
combiners, with specific choices for the underlying algorithms.  The choices
described here illustrate the security analysis required to make choices that
meet the requirements of the general framework, and can serve as a baseline
for application designers.  We also provide test vectors for these instances
so that implementors can verify the correctness of their implementations.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

We make extensive use of the terminology in {{HYBRID-KEMS}}.

# Concrete Nominal Group and KEM Instances

This document introduces concrete hybrid KEM instances that in turn depend on
concrete KEM and nominal group instances. This section introduces the nominal
groups and KEM instances used for concrete hybrid KEM instances, specified in
line with the abstraction from {{HYBRID-KEMS}}. {{nominal-groups}} defines
the concrete nominal groups, and {{nominal-kems}} defines the nominal KEMs.

## Nominal Groups {#nominal-groups}

This section specifies concrete nominal groups that implement the abstraction
in {{HYBRID-KEMS}}. It includes groups based on the NIST curves P-256 and
P-384, as well as a group based on Curve25519.

### P-256 and P-384 Nominal Groups {#group-nist}

The NIST P-256 and P-384 elliptic curves are defined in {{SP800-186}}.  They
are widely used for key agreement and digital signature.  In this section, we
define how they meet the Nominal Group interface described in
{{HYBRID-KEMS}}.

Group elements are elliptic curve points, represented as byte strings in the
uncompressed representation defined by the Elliptic-Curve-Point-to-Octet-String
function in {{SEC1}}.  Scalars are represented as integers in big-endian byte
order.

The Nominal Group algorithms are the same for both groups:

- `Exp(p, x) -> q`: This function computes scalar multiplication between the
  input element (or point) `p` and the scalar `x`, according to the group law
  for the curve specified in {{SP800-186}}.
- `RandomScalar(seed) -> k`: Implemented using rejection sampling from a PRG,
  as described below.
- `ElementToSharedSecret(p) -> ss`: The shared secret is the X coordinate of
  the elliptic curve point `p`, encoded as an `Nss`-byte string using the
  Field-Element-to-Octet-String function in {{SEC1}}.

The RandomScalar algorithm depends on an pseudo-random generator (PRG), with the
following API:

- `Init(seed) -> state`: Initialize a new state of the pseudo-random generator
  based on the provided seed.
- `Read(state, n) -> data`: Read `n` pseudo-random bytes from the PRG, updating
  `state` to reflect that this read has happened.

A hybrid KEM using these curves MUST specify the PRG that should be used.  All
of the hybrid KEMs in this document use SHAKE256 {{FIPS202}}.

Given a PRG, the RandomScalar algorithm is defined as follows:

~~~ pseudocode
def RandomScalar(seed):
  state = XOF.Init(seed)
  sk = OS2IP(XOF.Read(state, Nscalar))
  while sk == 0 || sk >= order:
    sk = OS2IP(XOF.Read(state, Nscalar))
  return (sk, pk(sk))
~~~

The OS2IP function converts a byte string to a non-negative integer, as
described in {{!RFC8017}}, assuming big-endian byte order.  The `order` variable
represents the order of the curve being used (see Section 3.2.1 of
{{SP800-186}}), reproduced here for reference:

~~~ ascii-art
P-256:
0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

P-384:
0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf
  581a0db248b0a77aecec196accc52973
~~~

The group constants for the P-256 group are as follows:

- `Nseed`: 32
- `Nscalar`: 32
- `Nelem`: 65
- `Nss`: 32

The group constants for the P-384 group are as follows:

- `Nseed`: 48
- `Nscalar`: 48
- `Nelem`: 97
- `Nss`: 48

### Curve25519 Nominal Group {#group-curve25519}

The following functions for the Curve25519 nominal group are defined:

- `Exp(p, x) -> q`: Implemented by X25519(x, p) from {{!RFC7748}}.
- `RandomScalar(seed) -> k`: Implemented by sampling and outputting 32 random
  bytes from a cryptographically secure pseudorandom number generator.
- `ElementToSharedSecret(p) -> ss`: Implemented by the identity function,
  i.e., by outputting P.

The following constants are also defined.

- `Nseed`: 32
- `Nscalar`: 32
- `Nelem`: 32
- `Nss`: 32

## Concrete KEM Instances {#nominal-kems}

This section specifies concrete KEM instances that implement the KEM
abstraction from {{HYBRID-KEMS}}.

### ML-KEM-768 and ML-KEM-1024 {#mlkem}

The ML-KEM-768 and ML-KEM-1024 KEMs are defined in {{FIPS203}}.  The
algorithms defined in that specification map to the KEM abstraction in
{{HYBRID-KEMS}} as follows:

- `GenerateKeyPair() -> (ek, dk)`: Implemented as KeyGen in Section 7.1 of
  {{FIPS203}}.
- `DeriveKeyPair(seed) -> (ek, dk)`: Implemented as
  KeyGen_internal(seed[0:32], seed[32:64]), where KeyGen_internal is defined
  in Section 6 of {{FIPS203}}.
- `Encaps(ek) -> (ct, ss)`: Implemented as Encaps in Section 7.2 of
  {{FIPS203}}.
- `Decaps(dk, ct) -> ss`: Implemented as Encaps in Section 7.3 of
  {{FIPS203}}.

The KEM constants for ML-KEM-768 are as follows:

- `Nseed`: 64
- `Nek`: 1216
- `Ndk`: 32
- `Nct`: 1120
- `Nss`: 32

The KEM constants for ML-KEM-1024 are as follows:

- `Nseed`: 64
- `Nek`: 1629
- `Ndk`: 32
- `Nct`: 1629
- `Nss`: 32

## Concrete PRG instances {#prgs}

This section specifies concrete PRG instances that implement the PRG
abstraction from {{HYBRID-KEMS}} and meet the required security definitions.

### SHAKE256

SHAKE256 is an extendable-output function (XOF) defined in the SHA-3
specification {{FIPS202}}.  It can be used as a PRG for arbitrary values of
`Nout`.  When SHAKE256 is used as the PRG component in a hybrid KEM, it is
implcit that `Nout == KEM_T.Nseed + KEM_PQ.Nseed` or `Nout == Group_T.Nseed +
KEM_PQ.Nseed` as appropriate.

## Concrete KDF instances {#kdfs}

This section specifies concrete KDF instances that implement the KDF
abstraction from {{HYBRID-KEMS}} and meet the required security definitions.

### SHA-3

The SHA-3 hash function is defined in {{FIPS202}}.  It produces a 32-byte
output, so it is appropriate for use in hybrid KEMs with `Nss = 32`.

# Concrete Hybrid KEM Instances

This section instantiates the following concrete KEMs:

MLKEM768-P256:
: A hybrid KEM composing ML-KEM-768 and P-256 using the CG framework, with
  SHAKE256 as the PRG and SHA3-256 as the KDF.

MLKEM768-X25519:
: A hybrid KEM composing ML-KEM-768 and Curve25519 using the CG framework, with
  SHAKE256 as the PRG and SHA3-256 as the KDF. This construction is identical
  to the X-Wing construction in {{XWING-SPEC}}.

MLKEM1024-P384:
: A hybrid KEM composing ML-KEM-1024 and P-384 using the CG framework, with
  SHAKE256 as the PRG and SHA3-256 as the KDF.

Each instance specifies the PQ and traditional KEMs being combined, the
combiner construction from {{HYBRID-KEMS}}, the `label` to use for domain
separation in the combiner function, as well as the PRG and KDF functions to
use throughout.

## MLKEM768-P256

This hybrid KEM combines ML-KEM-768 with P-256 using the CG framework from
{{HYBRID-KEMS}}. It has the following components:

* `Group_T`: P-256 {{group-nist}}
* `KEM_PQ`: ML-KEM-768 {{mlkem}}
* `PRG`: SHAKE-256 {{FIPS202}}
* `KDF`: SHA3-256 {{FIPS202}}
* `Label`: `|-()-|` (0x7C2D28292D7C)

The KEM constants for the resulting hybrid KEM are as follows:

- `Nseed`: 32
- `Nek`: 1217
- `Ndk`: 32
- `Nct`: 1121
- `Nss`: 32

## MLKEM768-X25519

This hybrid KEM combines ML-KEM-768 with X25519 using the CG framework from
{{HYBRID-KEMS}}. It is identical to the X-Wing construction from {{XWING-SPEC}}.
It has the following components:

* `KEM_PQ`: ML-KEM-768 {{mlkem}}
* `Group_T`: Curve25519 {{group-curve25519}}
* `PRG`: SHAKE-256 {{FIPS202}}
* `KDF`: SHA3-256 {{FIPS202}}
* `Label`: `\.//^\` (0x5C2E2F2F5E5C)

The following constants for the hybrid KEM are also defined:

- `Nseed`: 32
- `Nek`: 1216
- `Ndk`: 32
- `Nct`: 1120
- `Nss`: 32

## MLKEM1024-P384

This hybrid KEM combines ML-KEM-1024 with P-384 using the CG framework from
{{HYBRID-KEMS}}. It has the following components:

* `Group_T`: P-384 {{group-nist}}
* `KEM_PQ: ML-KEM-1024 {{mlkem}}
* `PRG`: SHAKE-256 {{FIPS202}}
* `KDF`: SHA3-256 {{FIPS202}}
* `Label`: ` \| /-\` (0x207C202F2D5C)

The following constants for the hybrid KEM are also defined:

- `Nseed`: 32
- `Nek`: 1629
- `Ndk`: 32
- `Nct`: 1629
- `Nss`: 32

# Security Considerations

The Security Considerations section in generic hybrid KEM framework lays out the
requirements for component algorithms in order for a hybrid KEM constructed
according to the framework to be secure {{HYBRID-KEMS}}.  In brief:

* A nominal group needs to be one in which the Strong Diffie-Hellman problem is
  hard.
* A KEM need to be IND-CCA secure.
* When the C2PRI combiner is used (as it is here), the PQ KEM also needs to
  satisfy the C2PRI property.
* KDFs need to be indifferentiable from a random oracle, even by a quantum
  attacker.
* A PRG needs to be a secure pseudo-random generator

The components used in this document meet these requirements:

* The security of X25519, P-256, and P-384 as nominal groups is shown in
  {{ABH+21}}.
* ML-KEM is shown to be IND-CCA in {{https://eprint.iacr.org/2024/843}} and
  shown to be C2PRI in {{XWING}}.
* The sponge construction used by SHA3-256 is shown to be indifferentiable from a
  random oracle by a classical attacker in {{BDP+08}}.  Indifferentiability with
  respect to quantum attackers is shown in {{ACM+25}}.
* Since SHAKE256 is built on the same sponge construction as SHA3-256, it is
  also indifferentiable from a random oracle, which is a sufficient condition
  for being a secure pseudorandom generator.

# IANA Considerations

This document requests that the following values be added to the "Hybrid KEM
Labels" registry:

| Label      | Fw | PQ Component | T Component | KDF      | PRG       | Nseed | Nss | Reference |
|============|====|==============|=============|==========|===========|=======|=====|===========|
| "\|-()-\|" | CG | ML-KEM-768   | Curve25519  | SHA3-256 | SHAKE-256 | 32    | 32  | [RFCXXXX] |
| "\\.//^\\" | CG | ML-KEM-768   | Curve25519  | SHA3-256 | SHAKE-256 | 32    | 32  | [RFCXXXX] |
| " \| /-\\" | CG | ML-KEM-768   | Curve25519  | SHA3-256 | SHAKE-256 | 32    | 32  | [RFCXXXX] |
{: #iana-table title="Hybrid KEM Labels" }

[ RFC EDITOR: Please replace "XXXX" above with the number assigned to this RFC ]

--- back

# Test Vectors

This section provides test vectors for the three concrete hybrid KEM
instantiations defined in this document. Each test vector represents a single
key generation followed by an encapsulation:

* `seed` - the seed used for deterministic key generation
* `decapsulation_key` - the derived decapsulation key
* `decapsulation_key_pq` - the decapsulation key sub-key for the PQ component
* `decapsulation_key_t` - the decapsulation key sub-key for the T component
* `encapsulation_key` - the derived encapsulation key
* `randomness` - the randomness used for encapsulation
* `ciphertext` - the ciphertext produced by the encapsulation operation
* `shared_secret` - the shared secret produced by the encapsulation operation

{::include test-vectors.md}

# Acknowledgments
{:numbered="false"}

Thanks to Chris Wood and Britta Hale for contributions to early versions of this
document. Thanks to Filippo Valsorda for the ASCII art labels for the
non-X-Wing hybrid KEMs.
