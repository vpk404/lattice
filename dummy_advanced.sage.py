"""
ADVANCED DUMMY SIGNATURE GENERATOR v4.0 (8GB RAM)
Generates test vectors for ALL 14 attacks in the advanced cracker v4.0.
All sig counts securely bounded to math minimums and MAX_SIGS=120.
Removed: Multi-Leak Fusion (requires metadata that real-world sigs never have).
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
for i in range(40):
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
for i in range(40):
    z = secrets.randbits(256)
    r, s = sign(k_lcg, z)
    sigs.append((r, s, hex(z)[2:].zfill(64)))
    k_lcg = (a_lcg * k_lcg + c_lcg) % N
dump("adv_lcg_phantom.json", sigs, "Attack_LCG_Phantom")

# ══════════════════════════════════════════════════════════════════════════════
# 3. BABAI MSB (6-bit leak, tight count — LLL often misses, Babai catches)
# ══════════════════════════════════════════════════════════════════════════════
print("[3] Babai MSB (6-bit, comfortable count)...")
sigs = []
for i in range(95):  # Adjusted up so Babai has the 90+ signatures it geometrically needs
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
for i in range(95): # Mathematical bound required > 85
    while True:
        k_high = secrets.randbits(256 - 6)
        k = (k_high << 6)
        if 0 < k < N:
            break
    z = secrets.randbits(256)
    r, s = sign(k, z)
    sigs.append((r, s, hex(z)[2:].zfill(64)))
dump("adv_babai_lsb_6bit.json", sigs, "Attack_Babai_LSB_6bit")

# ══════════════════════════════════════════════════════════════════════════════
# 5. MONTE CARLO: 60 biased (32-bit MSB leak) hidden in 80 sigs
# ══════════════════════════════════════════════════════════════════════════════
print("[5] Monte Carlo (65 biased hidden in 80 clean)...")
sigs = []
biased_indices = set()
while len(biased_indices) < 65:
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
print("[6] SLA (60 biased hidden in 80)...")
sigs = []
biased_indices = set()
while len(biased_indices) < 60:
    biased_indices.add(secrets.choice(range(80)))
for i in range(80):
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
for i in range(80):
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
for i in range(45):
    while True:
        k_high = secrets.randbits(256 - 112 - 32)
        k_low = secrets.randbits(112)
        k = (k_high << (112 + 32)) + k_low
        if 0 < k < N:
            break
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
for i in range(40):
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
for i in range(40):
    while True:
        k_high = secrets.randbits(256 - 32)
        k = (k_high << 32) + c_fixed
        if 0 < k < N:
            break
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
for i in range(40):
    noise = secrets.randbits(32)
    k = (base_k + i * step + noise) % N
    if k == 0: k = 1
    z = secrets.randbits(256)
    r, s = sign(k, z)
    sigs.append((r, s, hex(z)[2:].zfill(64)))
dump("adv_sequential_32bit.json", sigs, "Attack_Sequential_32bit")

# ══════════════════════════════════════════════════════════════════════════════
# 12. KANNAN EMBEDDING: 8-bit MSB leak (Kannan embedding catches what LLL misses)
# ══════════════════════════════════════════════════════════════════════════════
print("[12] Kannan Embedding (8-bit MSB, comfortable count)...")
sigs = []
for i in range(80):
    k = secrets.randbits(256 - 8) % N
    if k == 0: k = 1
    z = secrets.randbits(256)
    r, s = sign(k, z)
    sigs.append((r, s, hex(z)[2:].zfill(64)))
dump("adv_kannan_8bit.json", sigs, "Attack_Kannan_8bit")

# ══════════════════════════════════════════════════════════════════════════════
# 13. ALGEBRAIC PROGRESSIVE BKZ: 6-bit MSB leak (Real-World Extreme)
# ══════════════════════════════════════════════════════════════════════════════
print("[13] Algebraic Progressive BKZ (6-bit MSB, edge limit)...")
sigs = []
for i in range(95):  # Adjusted up to strictly test 60 signature matrix block
    k = secrets.randbits(256 - 6) % N
    if k == 0: k = 1
    z = secrets.randbits(256)
    r, s = sign(k, z)
    sigs.append((r, s, hex(z)[2:].zfill(64)))
dump("adv_progressive_6bit_msb.json", sigs, "Attack_Progressive_6bit_MSB")

# ══════════════════════════════════════════════════════════════════════════════
# 15. POLYNONCE: k_i = base_k + small_delta (Differential relationship)
# ══════════════════════════════════════════════════════════════════════════════
print("[15] Polynonce (64-bit differential delta)...")
base_k_poly = secrets.randbits(256) % N
sigs = []
for i in range(30):
    delta = secrets.randbits(64)
    k = (base_k_poly + delta) % N
    if k == 0: k = 1
    z = secrets.randbits(256)
    r, s = sign(k, z)
    sigs.append((r, s, hex(z)[2:].zfill(64)))
dump("adv_polynonce_64bit.json", sigs, "Attack_Polynonce_64bit")

print(f"\n{'=' * 70}")
print(f" [SUCCESS] All 14 test vectors generated!")
print(f" Target key: {d_hex}")
print(f" Run: sage advanced_attacks/advanced_cracker.sage.py")
print(f"{'=' * 70}")
