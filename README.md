```
KIP: XXXX
Layer: Application (wallet/tooling)
Title: P2PKH-Blake2b-256-via-P2SH Shor's Algorithm Resistant Addresses
Type: Standards Track
Author: Gaurav Rana <BitcoinsSSG@gmail.com>
Created: 2025-05-27
Updated: 2025-XX-XX
Status: Draft
```
# Abstract

This KIP proposes a wallet-layer address upgrade that enables **Shor's algorithm resistance**[1][2][3] via the introduction of **P2PKH-Blake2b-256-via-P2SH** addresses. By hiding public keys behind a cryptographic commitment until spend time, this approach mitigates the risk of quantum adversaries extracting private keys from exposed public keys. This change requires no consensus modification and can be adopted voluntarily by users, wallets, and exchanges. The specific changes and technical specifications are provided to help with clarity.

# Motivation

Quantum computers running Shor's algorithm can solve the Elliptic Curve Discrete Logarithm Problem (ECDLP), thereby breaking Schnorr signature security. Kaspa's current address format (P2PK) exposes public keys upon funding, making them vulnerable to such attacks. As projections estimate quantum threats maturing within 10–15 years, preemptive mitigation at the wallet layer is both prudent and timely.

A migration to P2PKH-Blake2b-256-via-P2SH allows for:

* Postponed public key revelation until spending,
* Backward-compatible usage through existing script validation infrastructure,
* Quantum threat mitigation without hard forks or consensus disruptions.

# Specification

### [Rough Draft of Technical Specifications](./technical_specifications-v-2-0-6.md)

## Address Generation

1. **Input**: 32-byte Schnorr public key
2. **Script Creation**: Create the script `<public key> OP_CHECKSIG`
3. **Script Hashing**: Apply Blake2b-256 to the script → `script_hash`
4. **P2SH Address**: Encode the `script_hash` using existing Kaspa address serialization

## Redeem Script

The redeem script is:

```
<public key> OP_CHECKSIG
```

## Transaction Construction

To spend from such an address, the user must provide:

* The Schnorr signature
* The Blake2b-256 hash of the redeem script (which is the `script_hash` used in address generation)

The unlock script (scriptSig) would be:

```
<signature> <script_hash>
```

The full validation process would then:

1. Verify that the provided `script_hash` matches the one in the P2SH address
2. Execute the redeem script (`<public key> OP_CHECKSIG`) with the provided signature

This approach ensures that:

* The public key is not revealed until spending
* The address is secured by the Blake2b-256 hash of the script
* It's compatible with Kaspa's existing P2SH infrastructure

## Quantum Attack Mitigation

| Attack Vector       | P2PK (current)       | P2PKH-Blake2b-via-P2SH     |
| ------------------- | -------------------- | -------------------------- |
| Public Key Exposure | Immediate            | Deferred (at spend time)   |
| Quantum Risk        | High (ECDLP exposed) | Mitigated (hash pre-image) |
| Protection Timeline | 0 years              | Effective immediately      |

# Implementation Strategy

## Phase 1: Wallet Layer Upgrade

* Wallets default to generating P2PKH-Blake2b-via-P2SH addresses.
* CLI tools and SDKs updated to support this address format.
* Wallet UIs display new addresses and explain quantum protection.

## Phase 2: Ecosystem Integration

* Major exchanges and custodians support sending to and spending from these addresses.
* New address types whitelisted and parsed correctly.
* Security benefits clearly communicated to users.

## Phase 3: Legacy Format Deprecation

* Gradual transition from P2PK addresses, accompanied by UI warnings.
* Optional signing prompts for P2PK indicating exposure risk.
* Recommended time horizon: 1-3 months.

# Economic Impact

* **Script Size Overhead**: Minimal additional bytes vs. P2PK
* **Cost Tradeoff**: Acceptable given long-term protection benefits
* **No Protocol Overhead**: No changes to block structure, consensus, or mempool logic

# Backwards Compatibility

This KIP introduces no consensus changes:

* All node software remains untouched.
* Mining and validation infrastructure continue using existing P2SH handling.
* Wallets can interoperate with both legacy and upgraded addresses.

# Migration Path

* **Voluntary**: Users may opt in as needed.
* **Secure-by-default**: Wallets default to protected addresses for new users.
* **Awareness campaign**: Promote understanding of quantum risks and timelines.

# Implementation

* `kaspa-p2pkh-blake2b`: Rust library for address and script creation
* CLI utilities: Key generation, signing, and script building
* Test suite: Ensures compatibility and regression testing
* Developer guide: Detailed technical specifications

# Community Benefits

## Short-Term

* Immediate mitigation of quantum attacks on new addresses
* User trust bolstered by proactive security posture
* Competitive positioning vs. quantum-insecure chains

## Long-Term

* Ecosystem maturity with cryptographic agility
* Attracts security-conscious applications and institutions
* Fosters additional research on wallet-level post-quantum defenses

# Acknowledgments

Thanks to Ori Newman (@someone235), Michael Sutton(@missutton), FreshAir08(@FreshAir08), Maxim Biryukov(@Max143672), KaffinPX(@KaffinPX), Ro Ma (@dimdumon), Shai (@DesheShai), (Yonatan Sompolinsky (@hashdag). Sorry if I missed some names, if I did, send a pull request.

# Abbreviations

* **ECDLP**: Elliptic Curve Discrete Logarithm Problem
* **P2PK**: Pay-to-Public-Key
* **P2PKH**: Pay-to-Public-Key-Hash
* **P2SH**: Pay-to-Script-Hash
* **PQC**: Post-Quantum Cryptography
* **BLAKE2b-256**: Cryptographic hash function
* **KIP**: Kaspa Improvement Proposal

# Copyright

This KIP is licensed under the [MIT License](./LICENSE).

# References

[1] P. W. Shor, "Algorithms for quantum computation: discrete logarithms and factoring," in Proceedings 35th Annual Symposium on Foundations of Computer Science, 1994, pp. 124-134. doi: 10.1109/SFCS.1994.365700

[2] P. W. Shor, "Polynomial-time algorithms for prime factorization and discrete logarithms on a quantum computer," SIAM Journal on Computing, vol. 26, no. 5, pp. 1484-1509, 1997. [Online]. Available: https://arxiv.org/abs/quant-ph/9508027

[3] National Institute of Standards and Technology, "NIST Releases First 3 Finalized Post-Quantum Encryption Standards," Aug. 13, 2024. [Online]. Available: https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards

# Additional References

4] National Institute of Standards and Technology, "Federal Information Processing Standard (FIPS) 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard," 2024. [Online]. Available: https://csrc.nist.gov/news/2024/postquantum-cryptography-fips-approved

[5] National Institute of Standards and Technology, "Federal Information Processing Standard (FIPS) 204: Module-Lattice-Based Digital Signature Standard," 2024. [Online]. Available: https://csrc.nist.gov/news/2024/postquantum-cryptography-fips-approved

[6] National Institute of Standards and Technology, "Federal Information Processing Standard (FIPS) 205: Stateless Hash-Based Digital Signature Standard," 2024. [Online]. Available: https://csrc.nist.gov/news/2024/postquantum-cryptography-fips-approved

[7] National Institute of Standards and Technology, "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption," Mar. 11, 2025. [Online]. Available: https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption

[8] Deloitte Netherlands, "Quantum risk to the Ethereum blockchain - a bump in the road or a brick wall?," 2024. [Online]. Available: https://www2.deloitte.com/nl/nl/pages/risk/articles/quantum-risk-to-the-ethereum-blockchain.html

[9] Deloitte Netherlands, "Quantum computers and the Bitcoin blockchain," 2024. [Online]. Available: https://www.deloitte.com/nl/en/services/risk-advisory/perspectives/quantum-computers-and-the-bitcoin-blockchain.html

[10] I. Barmes, I. Kohn, and C. Soutar, "What does the dawn of quantum computing mean for blockchain?," World Economic Forum, 2022. [Online]. Available: https://www.weforum.org/stories/2022/04/could-quantum-computers-steal-the-bitcoins-straight-out-of-your-wallet/

[11] Y. Baseri, A. Hafid, Y. Shahsavari, D. Makrakis, and H. Khodaiemehr, "Blockchain Security Risk Assessment in Quantum Era: Migration Strategies and Proactive Defense," arXiv preprint arXiv:2501.xxxxx, 2025.

[12] T. M. Fernandez-Carames and P. Fraga-Lamas, "Towards post-quantum blockchain: A review on blockchain cryptography resistant to quantum computing attacks," arXiv preprint arXiv:2024.xxxxx, 2024.

[13] J. J. Kearney and C. A. Perez-Delgado, "Vulnerability of Blockchain Technologies to Quantum Attacks," arXiv preprint arXiv:2009.12562, 2021.

[14] "Quantum-resistance in blockchain networks," Nature Scientific Reports, vol. 13, 2023. [Online]. Available: https://www.nature.com/srep/

[15] "A Looming Threat to Bitcoin: The Risk of a Quantum Hack," Wall Street Journal, Dec. 23, 2024. [Online]. Available: https://www.wsj.com/

[16] "The Quantum Apocalypse Is Coming. Be Very Afraid," WIRED Magazine, Mar. 24, 2025. [Online]. Available: https://www.wired.com/

[17] Quantum Computing Cybersecurity Preparedness Act, Public Law No: 117-103, U.S. Congress, 2022.

[18] National Security Agency, "Commercial National Security Algorithm (CNSA) Suite 2.0," 2022. [Online]. Available: https://www.nsa.gov/

