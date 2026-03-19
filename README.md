<p align="center">
  <h1 align="center">⚡ Lattice Hunter</h1>
  <p align="center">
    <b>ECDSA Nonce Leakage Scanner & Private Key Recovery Suite</b>
    <br/>
    <i>Automated lattice-based cryptanalysis for Bitcoin signatures</i>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/Python-3.8+-blue?logo=python&logoColor=white" />
    <img src="https://img.shields.io/badge/SageMath-9+-green?logo=data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=&logoColor=white" />
    <img src="https://img.shields.io/badge/Methods-5-red" />
    <img src="https://img.shields.io/badge/License-Research_Only-yellow" />
  </p>
</p>

---

## 🔍 Overview

Lattice Hunter is a two-part toolkit that scans Bitcoin addresses for ECDSA signatures vulnerable to nonce leakage and automatically recovers private keys using advanced lattice reduction algorithms.

```
┌──────────────────────┐          ┌──────────────────────┐
│   lattice_analyzer   │  ─────►  │   lattice_cracker    │
│                      │  JSON    │                      │
│  • Fetch signatures  │  files   │  • 5 attack methods  │
│  • Fingerprint era   │          │  • LLL + BKZ engines │
│  • Filter & validate │          │  • Auto key recovery │
└──────────────────────┘          └──────────────────────┘
```

---

## 📁 Project Structure

```
lattice_hunter/
├── lattice_analyzer.py      # Step 1: Scan & extract signatures
├── lattice_cracker.sage     # Step 2: Crack with lattice attacks
├── gen_dummies.py           # Generate test data
├── reports/
│   ├── pass/                # Addresses with enough sigs
│   ├── fail/                # Addresses without enough sigs
│   ├── pass_targets.json    # Consolidated pass results
│   └── fail_targets.json    # Consolidated fail results
└── LATTICE_RECOVERED_KEYS.csv   # Recovered private keys
```

---

## 🚀 Quick Start

### 1️⃣ Prepare Address List

Create a `.txt` file with one Bitcoin address per line:
```
1ExampleAddress1111111111111
1AnotherAddress2222222222222
```

### 2️⃣ Scan Addresses

```bash
python lattice_analyzer.py
```
> Enter your address file and max transactions. The tool fetches signatures from the blockchain, fingerprints historical vulnerabilities, and saves results.

### 3️⃣ Crack Signatures

```bash
sage lattice_cracker.sage.py
```
> Automatically loads all targets from `reports/pass/` and runs every attack method. Recovered keys are saved to CSV.

### 🧪 Test With Dummy Data

```bash
python gen_dummies.py          # Generate 6 test targets
sage lattice_cracker.sage.py   # Should crack 5 out of 6
```

---

## ⚔️ Attack Methods

| Phase | Method | Algorithm | Vulnerability |
|:-----:|--------|:---------:|---------------|
| **1** | 🔴 MSB Leak | LLL | Top bits of nonce are zero (weak RNG) |
| **2** | 🟠 LSB Leak | LLL | Bottom bits of nonce are zero |
| **3** | 🟡 Polynonce | LLL | Nonces share hidden polynomial relationships |
| **4** | 🟢 Known-Prefix | LLL | Nonces start with fixed bytes |
| **5** | 🔵 BKZ Fallback | BKZ | Retries phases 1-3 with stronger reduction |

Each phase tests multiple bit-leak sizes from **128-bit** down to **4-bit**, automatically calculating the optimal number of signatures needed.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔄 **Auto-Resume** | Skips already-scanned addresses on restart |
| 🛑 **Graceful Ctrl+C** | Saves all collected data before exiting |
| ✅ **Address Validation** | Base58Check + Bech32 verification |
| 🔗 **Deduplication** | Removes duplicate addresses and targets |
| 🏷️ **Fingerprinting** | Flags 2013-2015 danger zone, legacy patterns, suspicious fees |
| 📊 **Progress Tracking** | Real-time fetch and processing counters |
| 🗂️ **Dual Output** | Individual JSON files + consolidated master files |
| 🔍 **Sender Filtering** | Only extracts signatures belonging to the target address |

---

## 🏷️ Historic Fingerprints

The analyzer detects these vulnerability indicators:

| Tag | Meaning |
|-----|---------|
| `[CRITICAL]` | Transaction in 2013-2015 danger zone (blocks 250k-400k) |
| `[WARNING]` | Hardcoded fees (10000/50000 sats) or zero sequence numbers |
| `[INFO]` | Legacy P2PKH pattern, Version 1 tx, non-zero nLockTime |

---

## 📋 Requirements

```bash
pip install requests ecdsa
```

| Dependency | Version | Purpose |
|------------|---------|---------|
| Python | 3.8+ | Analyzer runtime |
| SageMath | 9+ | Lattice reduction (LLL/BKZ) |
| requests | latest | Mempool API calls |
| ecdsa | latest | Key verification |

---

## ⚠️ Disclaimer

This tool is for **educational and research purposes only**. It targets historically known vulnerabilities from 2013-2015 era wallet software. Only use on addresses you own or that are publicly documented as compromised.

---

<p align="center">
  <b>Built with 🧮 Mathematics & ⚡ SageMath</b>
</p>
