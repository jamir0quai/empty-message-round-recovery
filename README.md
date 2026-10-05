# Recovering Stream-Cipher Round Counts from Empty Authenticated Messages

**Calum Gannon** · October 2026

A closed-form method for recovering an implementation's round-count parameters from captured
traffic alone, without reading the binary.

Because Poly1305 over the empty string reduces to its additive term, the authentication tag of
an *empty* authenticated message equals a fixed window of the keystream with no polynomial
evaluation. Each such message is therefore a direct equation in the round counts, solvable by
exhaustive search over a small candidate set and verifiable to 128 bits per message.

Applied as a case study to a deployed mobile game record layer, seventeen empty messages from a
single capture identify the parameters uniquely among sixty-four candidates, and the recovered
construction reproduces captured ciphertext byte for byte across 459 frames.

No attack on ChaCha or Poly1305 is presented. The technique recovers parameters, not keys.

**Read the paper: [PAPER.md](PAPER.md)**
