# Recovering Stream-Cipher Round Counts from Empty Authenticated Messages

### With a case study on a deployed mobile game transport

**Calum Gannon**
calum.gannon@proton.me
October 2026

---

## Abstract

Implementations of NaCl-family authenticated encryption occasionally deviate from the
standardised round counts of their underlying permutation. Recovering those parameters
normally requires reading the implementation, which is costly when the binary is packed or
obfuscated, and which establishes only what the code contains rather than what the deployed
protocol does. We observe that any such transport which emits an *empty* authenticated message
leaks its parameters in closed form. Because Poly1305 over the empty string reduces to its
additive term alone, the authentication tag of an empty message equals a fixed window of the
keystream with no polynomial evaluation. Each such message is therefore a direct equation in
the round counts, solvable by exhaustive search over a small candidate set and verifiable to
128 bits per message. We apply the technique to the record layer of a widely deployed mobile
game, recovering a construction that reduces *both* cryptographic stages: HChaCha at 10 rounds
in place of 20, and ChaCha at 8 in place of 20. Seventeen empty messages from a single capture
identify the parameters uniquely among sixty-four candidates, and the recovered construction
reproduces captured ciphertext byte for byte. We then quantify the resulting margin: published cryptanalysis
now reaches 7.25 rounds of ChaCha, leaving the deployed primitive three-quarters of a round of
margin where ChaCha20 retains twelve and three-quarters. No attack is presented.

**Keywords:** ChaCha, Poly1305, parameter recovery, reduced-round primitives, protocol
reverse engineering, authenticated encryption.

---

## 1. Introduction

Deployed cryptographic protocols are not always the protocols their designers' documentation
describes. Implementations substitute primitives, vary parameters for performance, and vendor
modified copies of standard libraries. Where the implementation is distributed as an obfuscated
binary, establishing what is actually deployed becomes a reverse-engineering problem rather
than a specification-reading one.

The standard approach is to read the implementation. This is expensive against modern
protections, and it carries a subtler weakness: an instruction in a binary establishes what the
code *contains*, not what the protocol *does*. Obfuscated binaries routinely retain code that
never executes, and a confident static trace of a dead function is a common and expensive
error.

This paper describes a complementary approach for one specific and consequential class of
parameter: the round count of the permutation underlying a NaCl-family authenticated encryption
construction. The observation is elementary once stated, but we have not found it in the
literature, and it has a useful property: it operates entirely on captured ciphertext and the
session key, requiring neither the binary nor an emulator.

### Contributions

1. **The empty-message identity** (§4). For any secretbox-family construction, the tag of an
   empty authenticated message equals a fixed keystream window, with no polynomial evaluation.
   This makes the message a closed-form equation in the construction's round counts.
2. **A case study** (§3, §5) on a deployed mobile game transport, recovering a construction in
   which both stages are reduced, with verification to 128 bits per observation and a byte-exact
   round trip over 459 frames.
3. **A security-margin analysis** (§6) of the recovered parameters against current ChaCha
   cryptanalysis.
4. **A note on provenance** (§7). Three mutually inconsistent sets of round counts for this
   vendor's protocols are in public circulation with no stated derivation for any of them. The
   technique presented here produces a figure that a third party can falsify against their own
   capture.

### What this paper does not claim

No cryptanalytic attack on ChaCha or Poly1305 is presented. The session key used in the case
study was read from process memory on a device under the author's full control, which is always
possible against a symmetric protocol on an attacker-controlled endpoint and constitutes no
protocol weakness. The technique recovers *parameters*, not keys, and presupposes that the key
is already known.

---

## 2. Background

### 2.1 secretbox and the extended-nonce construction

NaCl's `crypto_secretbox` combines a stream cipher with a Poly1305 message authentication code.
The keystream's first 32 bytes serve as the one-time Poly1305 key; the remainder encrypts the
plaintext by exclusive-or. The tag is transmitted before the ciphertext and the construction
expands the message by exactly 16 bytes. No additional authenticated data is supported.

The extended-nonce variants (XSalsa20, XChaCha20) widen the nonce to 24 bytes by first deriving
a subkey. The subkey derivation (HSalsa20, HChaCha20) applies the same permutation to the key
and the first 16 nonce bytes, retaining a subset of the output words. The remaining 8 nonce
bytes then parametrise the stream. The security argument for the extension rests on the
derivation function behaving as a secure pseudorandom function.

### 2.2 Round counts as a deployment parameter

ChaCha is defined with a parametrised round count; Bernstein's original proposal specifies
ChaCha8, ChaCha12 and ChaCha20. Reduced variants see legitimate use where performance
dominates: XChaCha12 is implemented in the Linux kernel for precisely this reason. A reduced
round count is therefore a deliberate engineering choice rather than an error, and the relevant
question is not whether it is permitted but how much margin it leaves.

### 2.3 Poly1305 on the empty string

Poly1305 evaluates a polynomial over the message blocks in the field modulo 2^130 − 5, then adds
a secret 128-bit term. Writing the one-time key as the pair (r, s):

> tag = ( ( Σᵢ mᵢ · r^(n−i+1) mod p ) + s ) mod 2^128

For the empty message the summation is empty, the accumulator remains zero, and the expression
collapses to

> **tag = s mod 2^128**

In the secretbox construction `s` is bytes 16 to 32 of the keystream. This is a well-known
property of the polynomial evaluation and is not itself novel; what appears to be new is its
application as a parameter-recovery oracle.

---

## 3. The deployed construction

The case study targets the transport of a widely deployed mobile game, version 16.402 on
Android arm64-v8a, protected by a commercial packer. The record layer is a secretbox variant
with an extended nonce. Its framing is entirely conventional:

| Property | Value |
|---|---|
| Expansion | exactly 16 bytes |
| Tag placement | before the ciphertext |
| Additional data | none; the 7-byte header is unauthenticated |
| Nonce | 24 bytes, never transmitted |
| Key | 32 bytes, shared by both directions |

The header carries a 2-byte message type, a 3-byte length and a 2-byte version in clear.

The nonce's first 32-bit word is a per-message counter advancing by exactly two; the remaining
96 bits are constant for the session and differ by direction. The counter advances per message
rather than per block: a 1,139-byte frame advances it by the same two as an empty one.

What is unconventional is the round counts. Both stages are reduced:

| Stage | Standard | Deployed |
|---|---|---|
| Subkey derivation | HChaCha20, 10 double rounds | **HChaCha10, 5 double rounds** |
| Keystream | ChaCha20, 10 double rounds | **ChaCha8, 4 double rounds** |

Everything else — the permutation itself, the quarter-round rotation sequence 16/12/8/7, the
sigma constants, the original NaCl state layout with a 64-bit block counter — is stock.

---

## 4. Parameter recovery from traffic

### 4.1 The identity

Let a transport use a secretbox-family construction whose keystream is produced by a permutation
parametrised by round counts (h, c) for the subkey derivation and the stream respectively. Let
the attacker hold the session key and observe a ciphertext frame of exactly 16 bytes.

A 16-byte frame carries no ciphertext: the whole frame is the tag. The underlying plaintext is
therefore the empty string, and by §2.3 the tag equals the second 16-byte block of the
keystream. Writing KS(h, c, key, nonce) for the keystream,

> **tag = KS(h, c, key, nonce)[16:32]**

This is a closed-form equation in (h, c) alone. Every other quantity is either known (key,
nonce, tag) or absent (there is no message to evaluate a polynomial over).

### 4.2 Recovery procedure

Given a capture and the session key:

1. Identify frames of exactly the construction's expansion size.
2. Bind each to its nonce.
3. For each candidate pair (h, c) in a small set, compute KS(h, c, ·)[16:32] and compare to the
   observed tag.

The candidate set need not be large. Deployed round counts are drawn from a short list of
plausible engineering choices, and the search is linear in the product of the two candidate
sets.

### 4.3 Properties

The identity has three properties that make it a good oracle.

**It is exact.** Each observation is a 128-bit equality. A wrong pair does not produce a near
miss; it produces an unrelated value. The probability that an incorrect (h, c) satisfies a
single observation by chance is 2^−128.

**It is independent of the implementation.** No binary, no emulator and no disassembly is
required. The result therefore establishes what the deployed protocol *does*, which reading an
instruction does not.

**It is abundant.** Empty authenticated messages are not rare. Keepalive and acknowledgement
frames routinely carry no fields, and a transport that emits one on a timer supplies a fresh
observation every few seconds.

### 4.4 Applicability and limits

The technique requires a construction whose MAC is a Wegman–Carter polynomial evaluation with
an additive final term, and a protocol that actually emits empty authenticated messages. It
therefore applies to the secretbox family and to ChaCha20-Poly1305 and its variants, and not to
constructions whose MAC includes a length block or associated data in a manner that survives an
empty message. Where a construction authenticates a length field, the identity acquires a known
non-zero term and the method still applies with that term carried through.

It recovers parameters only. It does not recover keys, and it presupposes the key.

---

## 5. Case study results

### 5.1 Parameter recovery

A single capture of 48 frames contained 17 of exactly 16 bytes. Testing all 64 combinations of
{4, 5, 6, 8, 10, 12, 17, 20} double rounds for each stage:

| HChaCha ↓ / ChaCha → | 4 | 5 | 6 | 8 | 10 | 12 | 17 | 20 |
|---|---|---|---|---|---|---|---|---|
| 4 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| **5** | **17** | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 6 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 8 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 10 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 12 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 17 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 20 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

Exactly one pair reproduces every tag. With 17 independent 128-bit confirmations, the
probability of this arising from an incorrect hypothesis is negligible.

### 5.2 End-to-end verification

The recovered construction was then verified against full traffic:

| Check | Result |
|---|---|
| Capture A, both directions | 48 / 48 frames authenticate |
| Capture B | 390 / 390 |
| Capture C, separate session | 21 / 21 |
| Decrypt followed by re-seal | byte-for-byte identical to the original |

Round-trip equality is the strong check. It confirms the keystream, the counter schedule, the
nonce layout and the MAC placement simultaneously: a construction incorrect in any one of them
cannot reproduce the original ciphertext.

The largest frame verified was 363,180 bytes, confirming that the keystream and counter schedule
hold well beyond a single block.

### 5.3 Corroboration from the implementation

Independently of the traffic analysis, the round count is readable in a dumped image of the
mapped library as a move-immediate adjacent to the four sigma constants that identify the
cipher. The two methods agree. We present the traffic-based result as primary because it is
reproducible by a third party holding only a capture, and because it establishes deployed
behaviour rather than code presence.

---

## 6. Security analysis

ChaCha's security rests on its round count. The cryptanalytic frontier has moved since the
results most often cited, and the current position needs stating carefully because the
literature contains complexity estimates that later work disputes.

**Attacks reach 7.25 rounds.** The best results at 7 and 7.25 rounds, with their data
complexities, are:

| Result | Rounds | Time | Data |
|---|---|---|---|
| Xu et al., ToSC 2024 | 7 | 2^189.7 | 2^102.63 |
| Sharma, Dey, Sarkar, Maitra (2025), re-estimating Xu et al. | 7 | **2^178.12** | 2^101.09 |
| Xu et al., ToSC 2024 | 7.25 | 2^223.9 | 2^100.80 |
| Sharma, Dey, Sarkar, Maitra (2025) | 7.25 | **2^212.43** | 2^100.56 |

Earlier 7-round results, for context: Beierle et al. (CRYPTO 2020) at 2^230.86, Dey et al.
(EUROCRYPT 2022) at 2^221.95, and Wang et al. (CRYPTO 2023) at 2^210.3.

**One figure is contested.** Ghafoori and Miyaji (IEEE Access, 2024) report a higher-order
differential-linear attack on 7-round ChaCha at 2^135.07. Sharma et al. (2025) examine
complexity estimation across this literature and give the best-known 7-round result as the Xu
et al. line rather than that figure. We report both and take no position: the margin argument
below does not depend on which is correct, since both are far below the 2^256 key space and the
relevant quantity is the round count reached, not the cost of reaching it.

**The margin.** ChaCha20 stands twelve and three-quarter rounds above the frontier. The
construction deployed here is **ChaCha8**, which stands **three-quarters of a round above it**.

Two qualifications belong with that. None of these attacks is practical, and nothing described
in this paper is exploitable. But cryptanalysis against ChaCha has advanced in each of the last
five years — 7 rounds in 2020, improved in 2022, 2023 and 2024, and extended to 7.25 with
revised estimates in 2025 — and a primitive deployed three-quarters of a round above that
trajectory has no capacity to absorb a further advance that ChaCha20 absorbs without
consequence. The appropriate reading is not that the deployment is broken but that it has
spent its margin.

The subkey derivation is reduced in the same direction. The extended-nonce security argument
rests on the derivation function behaving as a secure pseudorandom function; halving its rounds
weakens the premise of that argument rather than only its quantitative margin. We note this as
a structural observation and do not evaluate it further.

We have not assessed whether the reduction is exploitable. That is the natural next piece of
work and we do not pre-empt its result.

---

## 7. Related work and the provenance problem

The framing of this transport is not new. Secretbox with a tag-first Poly1305, 16 bytes of
expansion, no associated data and a short cleartext header has been publicly documented since
2016 and is implemented in several open projects. That a variant with non-standard round counts
is in use has also been reported.

Those reports conflict. At least three mutually inconsistent sets of round counts for this
vendor's protocols are in circulation: a modified Salsa core with 19 single rounds, an
11-iteration ChaCha-shaped loop, and 17 and 8 double rounds. **None states how it was derived.**
Against the capture analysed here, the (17, 8) figure reproduces none of the seventeen tags.

We do not claim those figures are wrong for their own targets. Different titles and generations
from this vendor demonstrably differ, and the most likely reconciliation is simply that they
describe different binaries. The point is methodological rather than adversarial: a parameter
claim unaccompanied by a derivation cannot be checked, reconciled or superseded. The identity in
§4 produces claims that can be, in an afternoon, by anyone with a capture.

Prior reverse-engineering of this vendor's protocols has relied on emulating the obfuscated
cipher core, an approach stated as doctrine in public write-ups since 2018. Notably, one such
write-up from 2018 identified the round counts as the hardest part of the problem — a judgement
this work confirms, and which the technique presented here is intended to dissolve.

---

## 8. Limitations

- The reduction's exploitability is not evaluated. This paper reports margin.
- The case study covers one version on one platform. Whether other builds or titles share the
  construction is unverified.
- The technique presupposes the session key. Obtaining it required full control of an endpoint.
- The construction described is the transport's TCP record layer. A separate UDP channel in the
  same application uses a different mechanism, whose payloads expand by zero bytes.
- All traffic analysed came from a dedicated research account. No third-party account data
  appears in this paper.

---

## 9. Conclusion

An authenticated transport that emits empty messages discloses its permutation's round counts in
closed form, to anyone holding the session key, without reference to the implementation. The
identity is elementary, the verification is exact to 128 bits per observation, and the oracle is
abundant in any protocol with a fieldless keepalive.

Applied to a deployed mobile game transport, it establishes a construction reduced in both
stages — HChaCha at 10 rounds and ChaCha at 8 — and does so with evidence a third party can
reproduce. The resulting margin is three-quarters of a round against the published cryptanalytic frontier.

The broader point concerns how deployment parameters are established and reported. Reading an
obfuscated binary is expensive and establishes code presence rather than deployed behaviour.
Where a construction admits an identity of this kind, traffic is the better evidence, and claims
derived from it carry something that claims derived from disassembly often lack: the means for
someone else to check them.

---

## References

1. D. J. Bernstein. *ChaCha, a variant of Salsa20.* 2008.
2. D. J. Bernstein. *The Poly1305-AES message-authentication code.* FSE 2005.
3. S. Arciszewski. *XChaCha: eXtended-nonce ChaCha and AEAD_XChaCha20_Poly1305.* IRTF CFRG
   Internet-Draft, draft-irtf-cfrg-xchacha-03.
4. C. Beierle, G. Leander, Y. Todo. *Improved Differential-Linear Attacks with Applications to
   ARX Ciphers.* CRYPTO 2020.
5. S. Dey, H. K. Garai, S. Sarkar, N. K. Sharma. *Revamped Differential-Linear Cryptanalysis on
   Reduced Round ChaCha.* EUROCRYPT 2022. IACR ePrint 2022/536.
6. S. Wang, M. Liu, S. Hou, D. Lin. *Moving a Step of ChaCha in Syncopated Rhythm.* CRYPTO 2023.
   IACR ePrint 2023/1087.
7. N. Ghafoori, A. Miyaji. *Higher-Order Differential-Linear Cryptanalysis of ChaCha Stream
   Cipher.* IEEE Access, January 2024.
8. N. K. Sharma, S. Dey, S. Sarkar, S. Maitra. *On Improved Cryptanalytic Results against ChaCha
   for Reduced Rounds ≥ 7.* IACR ePrint 2025/428.
9. Xu et al. *Boosting Differential-Linear Cryptanalysis of ChaCha7 with MILP.* IACR
   Transactions on Symmetric Cryptology, 2024.
10. NaCl: Networking and Cryptography library. `crypto_secretbox` specification.
    https://nacl.cr.yp.to/secretbox.html
