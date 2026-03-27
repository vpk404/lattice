"""
ADVANCED DUMMY SIGNATURE GENERATOR v3.0 (8GB RAM)
Generates test vectors for ALL 15 attacks in the advanced cracker.
All sig counts capped at 80 to match cracker MAX_SIGS.
"""
import json
import os
import secrets
from sage.all import *

print("=" * 70)
print(" ADVANCED DUMMY SIG GENERATOR v3.0 — 8GB RAM SAFE")
print("=" * 70)

# Secp256k1
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
Fp = GF(p)
E = EllipticCurve(Fp, [0, 7])
G_point = E(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
             0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

# Known test private key
d_hex = "1337133713371337133713371337133713371337133713371337133713371337"
d = int(d_hex, 16)
pub = d * G_point
pub_hex = "02" + hex(int(pub[0]))[2:].zfill(64)

REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports", "pass")
os.makedirs(REPORT_DIR, exist_ok=True)

def sign(k, z):
    k = int(k) % N
    if k == 0: k = 1
    R = k * G_point
    r = int(R[0]) % N
    s = (int(inverse_mod(k, N)) * (z + r * d)) % N
    return hex(r)[2:].zfill(64), hex(s)[2:].zfill(64)

def dump(filename, sigs, address, extra_fields=None):
    entries = []
    for item in sigs:
        if len(item) == 3:
            r, s, z = item
            entry = {"r": r, "s": s, "z": z, "txid": "dummy_adv"}
        else:
            entry = item  # Already a dict
        entries.append(entry)
    data = {
        "address": address, "pubkey": pub_hex,
        "historic_fingerprints": ["Advanced Dummy v2.0"],
        "signature_count": len(entries), "signatures": entries,
    }
    if extra_fields:
        data.update(extra_fields)
    path = os.path.join(REPORT_DIR, filename)
    with open(path, "w") as f:
        json.dump(data, f, indent=4)
    print(f"  [+] {path} ({len(entries)} sigs → {address})")

print(f"[*] Key: {d_hex[:20]}...\n")

# ══════════════════════════════════════════════════════════════════════════════
# 1. GCD SMALL-DELTA: Sequential nonces k, k+1, k+2, ...
# ══════════════════════════════════════════════════════════════════════════════
print("[1] GCD Small-Delta (sequential nonces)...")
k_base = secrets.randbits(256) % N
sigs = []
for i in range(20):
    k = (k_base + i) % N
    z = secrets.randbits(256)
    r, s = sign(k, z)
    sigs.append((r, s, hex(z)[2:].zfill(64)))
dump("adv_gcd_sequential.json", sigs, "Attack_GCD_Sequential")

# ══════════════════════════════════════════════════════════════════════════════
# 2. LCG PHANTOM: k_{i+1} = a*k_i + c (mod N)
# ══════════════════════════════════════════════════════════════════════════════
print("[2] LCG Phantom (linear congruential nonces)...")
a_lcg = secrets.randbits(256) % N
c_lcg = secrets.randbits(256) % N
k_lcg = secrets.randbits(256) % N
sigs = []
for i in range(20):
    z = secrets.randbits(256)
    r, s = sign(k_lcg, z)
    sigs.append((r, s, hex(z)[2:].zfill(64)))
    k_lcg = (a_lcg * k_lcg + c_lcg) % N
dump("adv_lcg_phantom.json", sigs, "Attack_LCG_Phantom")

# ══════════════════════════════════════════════════════════════════════════════
# 3. BABAI MSB (6-bit leak, tight count — LLL often misses, Babai catches)
# ══════════════════════════════════════════════════════════════════════════════
print("[3] Babai MSB (6-bit, tight count)...")
sigs = []
for i in range(60):  # Just above theoretical min of 59
    k = secrets.randbits(256 - 6) % N
    if k == 0: k = 1
    z = secrets.randbits(256)
    r, s = sign(k, z)
    sigs.append((r, s, hex(z)[2:].zfill(64)))
dump("adv_babai_msb_6bit.json", sigs, "Attack_Babai_MSB_6bit")

# ══════════════════════════════════════════════════════════════════════════════
# 4. BABAI LSB (6-bit leak)
# ══════════════════════════════════════════════════════════════════════════════
print("[4] Babai LSB (6-bit)...")
sigs = []
for i in range(60):
    k_high = secrets.randbits(256 - 6)
    k = (k_high << 6) % N
    if k == 0: k = 1
    z = secrets.randbits(256)
    r, s = sign(k, z)
    sigs.append((r, s, hex(z)[2:].zfill(64)))
dump("adv_babai_lsb_6bit.json", sigs, "Attack_Babai_LSB_6bit")

# ══════════════════════════════════════════════════════════════════════════════
# 5. MONTE CARLO: 60 biased (32-bit MSB leak) hidden in 80 sigs
# ══════════════════════════════════════════════════════════════════════════════
print("[5] Monte Carlo (60 biased hidden in 80 clean)...")
sigs = []
biased_indices = set()
while len(biased_indices) < 60:
    biased_indices.add(secrets.choice(range(80)))
for i in range(80):
    z = secrets.randbits(256)
    if i in biased_indices:
        k = secrets.randbits(256 - 32) % N  # 32-bit MSB leak
    else:
        k = secrets.randbits(256) % N  # Fully random (no bias)
    if k == 0: k = 1
    r, s = sign(k, z)
    sigs.append((r, s, hex(z)[2:].zfill(64)))
dump("adv_montecarlo_hidden.json", sigs, "Attack_MonteCarlo_Hidden")

# ══════════════════════════════════════════════════════════════════════════════
# 6. SLA: 50 biased (32-bit MSB leak) hidden in 70 sigs
# ══════════════════════════════════════════════════════════════════════════════
print("[6] SLA (50 biased hidden in 70)...")
sigs = []
biased_indices = set()
while len(biased_indices) < 50:
    biased_indices.add(secrets.choice(range(70)))
for i in range(70):
    z = secrets.randbits(256)
    if i in biased_indices:
        k = secrets.randbits(256 - 32) % N  # 32-bit MSB leak
    else:
        k = secrets.randbits(256) % N
    if k == 0: k = 1
    r, s = sign(k, z)
    sigs.append((r, s, hex(z)[2:].zfill(64)))
dump("adv_sla_hidden.json", sigs, "Attack_SLA_Hidden")

# ══════════════════════════════════════════════════════════════════════════════
# 7. SIGNATURE FILTERING: Some sigs intentionally have small r values
# ══════════════════════════════════════════════════════════════════════════════
print("[7] Filtered Lattice (small-r biased sigs)...")
sigs = []
for i in range(40):
    z = secrets.randbits(256)
    # Use small nonces to produce small r values
    k = secrets.randbits(200) % N  # ~56-bit MSB leak
    if k == 0: k = 1
    r, s = sign(k, z)
    sigs.append((r, s, hex(z)[2:].zfill(64)))
dump("adv_filtered_smallr.json", sigs, "Attack_Filtered_SmallR")

# ══════════════════════════════════════════════════════════════════════════════
# 8. MIDDLE-BIT WINDOW: 32-bit zero window at bit 112
# ══════════════════════════════════════════════════════════════════════════════
print("[8] Middle-Bit Window (w32@112)...")
sigs = []
for i in range(30):
    k_high = secrets.randbits(256 - 112 - 32)
    k_low = secrets.randbits(112)
    k = ((k_high << (112 + 32)) + k_low) % N
    if k == 0: k = 1
    z = secrets.randbits(256)
    r, s = sign(k, z)
    sigs.append((r, s, hex(z)[2:].zfill(64)))
dump("adv_middlebit_w32_s112.json", sigs, "Attack_MiddleBit_w32_s112")

# ══════════════════════════════════════════════════════════════════════════════
# 9. LINEAR NONCE BIAS: k = a*z + b + noise
# ══════════════════════════════════════════════════════════════════════════════
print("[9] Linear Nonce Bias (64-bit noise)...")
a_secret = secrets.randbits(256) % N
b_secret = secrets.randbits(256) % N
sigs = []
for i in range(25):
    z = secrets.randbits(256)
    noise = secrets.randbits(64)
    k = (a_secret * z + b_secret + noise) % N
    if k == 0: k = 1
    r, s = sign(k, z)
    sigs.append((r, s, hex(z)[2:].zfill(64)))
dump("adv_linearbias_64bit.json", sigs, "Attack_LinearBias_64bit")

# ══════════════════════════════════════════════════════════════════════════════
# 10. SHARED LSB: All nonces share same lower 32 bits
# ══════════════════════════════════════════════════════════════════════════════
print("[10] Shared LSB (32-bit fixed suffix)...")
c_fixed = secrets.randbits(32)
sigs = []
for i in range(20):
    k_high = secrets.randbits(256 - 32)
    k = (k_high << 32) + c_fixed
    k = k % N
    if k == 0: k = 1
    z = secrets.randbits(256)
    r, s = sign(k, z)
    sigs.append((r, s, hex(z)[2:].zfill(64)))
dump("adv_sharedlsb_32bit.json", sigs, "Attack_SharedLSB_32bit")

# ══════════════════════════════════════════════════════════════════════════════
# 11. SEQUENTIAL NONCE: k_i = base + i*step + small_noise
# ══════════════════════════════════════════════════════════════════════════════
print("[11] Sequential Nonce (32-bit noise)...")
base_k = secrets.randbits(256) % N
step = secrets.randbelow(1000) + 1
sigs = []
for i in range(20):
    noise = secrets.randbits(32)
    k = (base_k + i * step + noise) % N
    if k == 0: k = 1
    z = secrets.randbits(256)
    r, s = sign(k, z)
    sigs.append((r, s, hex(z)[2:].zfill(64)))
dump("adv_sequential_32bit.json", sigs, "Attack_Sequential_32bit")

# ══════════════════════════════════════════════════════════════════════════════
# 12. MULTI-LEAK FUSION: Half MSB, half LSB leak with metadata
# ══════════════════════════════════════════════════════════════════════════════
print("[12] Multi-Leak Fusion (MSB+LSB mixed)...")
entries = []
for i in range(30):
    z = secrets.randbits(256)
    if i % 2 == 0:
        k = secrets.randbits(256 - 8) % N  # MSB 8-bit leak
        leak_type = "msb"
    else:
        k = (secrets.randbits(256 - 8) << 8) % N  # LSB 8-bit leak
        leak_type = "lsb"
    if k == 0: k = 1
    r, s = sign(k, z)
    entries.append({"r": r, "s": s, "z": hex(z)[2:].zfill(64),
                    "txid": "dummy_adv", "leak_type": leak_type, "leak_bits": 8})
dump("adv_multifusion_8bit.json", entries, "Attack_MultiFusion_8bit")

# ══════════════════════════════════════════════════════════════════════════════
# 13. KANNAN EMBEDDING: 8-bit MSB leak (Kannan embedding catches what LLL misses)
# ══════════════════════════════════════════════════════════════════════════════
print("[13] Kannan Embedding (8-bit MSB, tight)...")
sigs = []
for i in range(40):
    k = secrets.randbits(256 - 8) % N
    if k == 0: k = 1
    z = secrets.randbits(256)
    r, s = sign(k, z)
    sigs.append((r, s, hex(z)[2:].zfill(64)))
dump("adv_kannan_8bit.json", sigs, "Attack_Kannan_8bit")

# ══════════════════════════════════════════════════════════════════════════════
# 14. PROGRESSIVE BKZ: 4-bit MSB leak at exact theoretical minimum
# ══════════════════════════════════════════════════════════════════════════════
print("[14] Progressive BKZ (4-bit MSB, capped at 80)...")
sigs = []
for i in range(80):  # Capped at MAX_SIGS=80 (theoretical min ~87 but we cap)
    k = secrets.randbits(256 - 4) % N
    if k == 0: k = 1
    z = secrets.randbits(256)
    r, s = sign(k, z)
    sigs.append((r, s, hex(z)[2:].zfill(64)))
dump("adv_progressive_4bit.json", sigs, "Attack_Progressive_4bit")

# ══════════════════════════════════════════════════════════════════════════════
# 15. GREEDY ROUND-OFF: 6-bit MSB leak, count where LLL is borderline
# ══════════════════════════════════════════════════════════════════════════════
print("[15] Greedy Round-Off (6-bit MSB, borderline)...")
sigs = []
for i in range(60):  # Exactly at theoretical minimum — rounding errors likely
    k = secrets.randbits(256 - 6) % N
    if k == 0: k = 1
    z = secrets.randbits(256)
    r, s = sign(k, z)
    sigs.append((r, s, hex(z)[2:].zfill(64)))
dump("adv_roundoff_6bit.json", sigs, "Attack_RoundOff_6bit")

# ══════════════════════════════════════════════════════════════════════════════
# 16. POLYNONCE: k_i = base_k + small_delta (Differential relationship)
# ══════════════════════════════════════════════════════════════════════════════
print("[16] Polynonce (64-bit differential delta)...")
base_k_poly = secrets.randbits(256) % N
sigs = []
for i in range(15):
    delta = secrets.randbits(64)
    k = (base_k_poly + delta) % N
    if k == 0: k = 1
    z = secrets.randbits(256)
    r, s = sign(k, z)
    sigs.append((r, s, hex(z)[2:].zfill(64)))
dump("adv_polynonce_64bit.json", sigs, "Attack_Polynonce_64bit")

print(f"\n{'=' * 70}")
print(f" [SUCCESS] All 16 test vectors generated!")
print(f" Target key: {d_hex}")
print(f" Run: sage advanced_attacks/advanced_cracker.sage.py")
print(f"{'=' * 70}")
