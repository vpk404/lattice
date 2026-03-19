#!/usr/bin/env python3
"""
Generate 6 dummy JSON files in reports/pass/ — one per attack method.
Each file contains signatures with the MINIMUM leakage that the cracker can still solve.
Output format matches lattice_analyzer.py exactly.
"""
import os, json, hashlib, secrets
from ecdsa import SECP256k1, SigningKey

N = SECP256k1.order
G = SECP256k1.generator

def make_sigs(d_int, nonce_gen_fn, count):
    """Sign `count` random messages using nonces from nonce_gen_fn(). Return (pubkey_hex, sigs_list)."""
    sk = SigningKey.from_secret_exponent(d_int, curve=SECP256k1)
    vk = sk.verifying_key
    pt = vk.pubkey.point
    prefix = b'\x02' if pt.y() % 2 == 0 else b'\x03'
    pub_hex = (prefix + int(pt.x()).to_bytes(32, 'big')).hex()

    sigs = []
    for i in range(count):
        z = int.from_bytes(hashlib.sha256(secrets.token_bytes(32)).digest(), 'big') % N
        k = nonce_gen_fn(i)
        r = int((k * G).x()) % N
        s = (pow(k, -1, N) * (z + r * d_int)) % N
        if r == 0 or s == 0:
            continue
        sigs.append({
            "r": hex(r), "s": hex(s), "z": hex(z),
            "txid": hashlib.sha256(f"dummy_tx_{i}_{secrets.token_hex(4)}".encode()).hexdigest()
        })
    return pub_hex, sigs

def save(name, pub, sigs, fingerprints):
    os.makedirs("reports/pass", exist_ok=True)
    data = {
        "address": name,
        "pubkey": pub,
        "historic_fingerprints": fingerprints,
        "signature_count": len(sigs),
        "signatures": sigs
    }
    path = os.path.join("reports", "pass", f"{name}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=4)
    print(f"[+] Saved {path}  ({len(sigs)} sigs)")

def main():
    print("=" * 60)
    print("  DUMMY GENERATOR — 6 Attack Methods (Hardest Settings)")
    print("=" * 60)

    # ---- 1. MSB Leak (8-bit) — Top 8 bits of nonce are zero ----
    d = secrets.randbelow(N - 1) + 1
    def msb_nonce(i):
        return secrets.randbelow(2 ** 248)  # top 8 bits always zero
    pub, sigs = make_sigs(d, msb_nonce, 120)
    save("1DummyMSB8bit", pub, sigs,
         ["[TEST] MSB 8-bit Leak", "[INFO] Standard Legacy P2PKH Pattern",
          "[CRITICAL] 2013-2015 Danger Zone Timestamp"])

    # ---- 2. LSB Leak (8-bit) — Bottom 8 bits of nonce are zero ----
    d = secrets.randbelow(N - 1) + 1
    def lsb_nonce(i):
        return secrets.randbelow(2 ** 248) * (2 ** 8)  # bottom 8 bits zero
    pub, sigs = make_sigs(d, lsb_nonce, 120)
    save("1DummyLSB8bit", pub, sigs,
         ["[TEST] LSB 8-bit Leak", "[INFO] Standard Legacy P2PKH Pattern"])

    # ---- 3. Polynonce (128-bit shared relationship) ----
    d = secrets.randbelow(N - 1) + 1
    base_k = secrets.randbelow(N - 1) + 1
    small_range = 2 ** 128
    def poly_nonce(i):
        # All nonces cluster near base_k — differ by at most 128 bits
        offset = secrets.randbelow(small_range)
        return (base_k + offset) % N
    pub, sigs = make_sigs(d, poly_nonce, 80)
    save("1DummyPolynonce128", pub, sigs,
         ["[TEST] Polynonce 128-bit Relationship",
          "[WARNING] Suspicious Hardcoded Fee (10000 sats)"])

    # ---- 4. Known-Prefix (8-bit prefix = 0x00) ----
    d = secrets.randbelow(N - 1) + 1
    def prefix_nonce(i):
        # First byte is always 0x00 → top 8 bits zero (same as MSB for 0x00 prefix)
        return secrets.randbelow(2 ** 248)
    pub, sigs = make_sigs(d, prefix_nonce, 80)
    save("1DummyPrefix8bit", pub, sigs,
         ["[TEST] Known-Prefix 0x00 (8-bit)", "[INFO] Standard Legacy P2PKH Pattern",
          "[CRITICAL] 2013-2015 Danger Zone Timestamp"])

    # ---- 5. Bleichenbacher Bias (k = random_256_bit % N) ----
    d = secrets.randbelow(N - 1) + 1
    def bleich_nonce(i):
        # This is the classic Bleichenbacher bias: take a full 256-bit random and mod N
        # The bias is extremely subtle: P(k < 2^256 - N) is slightly higher
        raw = secrets.randbelow(2 ** 256)
        return (raw % N) if raw % N != 0 else 1
    pub, sigs = make_sigs(d, bleich_nonce, 120)
    save("1DummyBleichenbacher", pub, sigs,
         ["[TEST] Bleichenbacher Modular Bias",
          "[WARNING] Suspicious Hardcoded Fee (10000 sats)"])

    # ---- 6. BKZ-only (very subtle 6-bit MSB leak, LLL likely fails) ----
    d = secrets.randbelow(N - 1) + 1
    def bkz_nonce(i):
        return secrets.randbelow(2 ** 250)  # top 6 bits zero — very subtle
    pub, sigs = make_sigs(d, bkz_nonce, 120)
    save("1DummyBKZ6bit", pub, sigs,
         ["[TEST] 6-bit Deep Leak (BKZ Required)",
          "[CRITICAL] 2013-2015 Danger Zone Timestamp"])

    print("\n" + "=" * 60)
    print("  All 6 dummy files generated in reports/pass/")
    print("  Run: sage lattice_cracker.sage.py")
    print("=" * 60)

if __name__ == "__main__":
    main()
