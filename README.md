# 🛡️ Lattice-Based ECDSA Recovery Toolset

Advanced tools for detecting and exploiting ECDSA nonce bias in Bitcoin signatures.

---

## 🔍 [Analyzer](anlyserlll.py)
**Biased Nonce Lattice Analyzer v4.0**
Extracts and analyzes signatures from the blockchain.

- **Mempool.space API Integration:** Automatic signature extraction.
- **Strict DER Decoding:** Supports Legacy (P2PKH) and SegWit (P2WPKH).
- **Bias Detection:** Identifies nonce reuse and bit-length distribution.
- **Export:** Saves targets for the lattice cracker.

---

## ⚡ [Cracker](cracker.py)
**Advanced Lattice Cracker v4.2**
High-performance private key recovery using LLL/BKZ.

- **16 Attacks:** From GCD detection to Stochastic Lattice Annealing (SLA).
- **Optimized:** Multi-core processing & memory-safe execution.
- **SageMath Powered:** Leveraging state-of-the-art lattice reduction.
- **Diverse Support:** MSB, LSB, Middle-Bit, and Polynomial leaks.

---

## 🚀 Quick Start

### Prerequisites
- **Python 3.x**
- **SageMath** (Required for the Cracker)
- **Requests** library

### Usage
1. **Analyze Address:**
   ```bash
   python3 anlyserlll.py <bitcoin_address>
   ```
2. **Crack Signatures:**
   ```bash
   sage cracker.py <data.json>
   ```

---

## ⚠️ Disclaimer
This tool is for educational and research purposes only. Use it responsibly.
