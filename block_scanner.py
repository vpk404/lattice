import requests
import time
import os
import sys
import signal

# ==============================================================================
# CONFIG
# ==============================================================================
BLOCK_DIR = "block"
BALANCE_FILE = os.path.join(BLOCK_DIR, "balance.txt")
ZERO_FILE = os.path.join(BLOCK_DIR, "zero.txt")
BALZERO_FILE = os.path.join(BLOCK_DIR, "balzero.txt")

MIN_TX_COUNT = 7  # Minimum transactions required for lattice cracker
BATCH_CHECK_SIZE = 20  # Check 20 addresses per API call
API_DELAY = 0.35  # Seconds between API calls
REQ_TIMEOUT = 15
MAX_RETRIES = 5

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "LatticeBlockScanner/1.0"})

EXIT_FLAG = False
LAST_API_TIME = 0.0

def signal_handler(sig, frame):
    global EXIT_FLAG
    print("\n[!] Stopping gracefully... (saving progress)")
    EXIT_FLAG = True

signal.signal(signal.SIGINT, signal_handler)

# ==============================================================================
# RATE-LIMITED API CALL
# ==============================================================================
def api_get(url):
    global LAST_API_TIME
    now = time.time()
    diff = now - LAST_API_TIME
    if diff < API_DELAY:
        time.sleep(API_DELAY - diff)
    
    for attempt in range(MAX_RETRIES):
        try:
            r = SESSION.get(url, timeout=REQ_TIMEOUT)
            LAST_API_TIME = time.time()
            
            if r.status_code == 200:
                return r.json()
            elif r.status_code == 429:
                wait = min(2 ** (attempt + 1) * 2, 60)
                print(f"\r    [429] Rate limited, waiting {wait}s...", end="", flush=True)
                time.sleep(wait)
            elif r.status_code == 404:
                return None
            else:
                time.sleep(2)
        except requests.exceptions.RequestException:
            time.sleep(2)
    return None

# ==============================================================================
# LOAD ALREADY-PROCESSED ADDRESSES
# ==============================================================================
def load_known_addresses():
    known = set()
    if os.path.isfile(BALZERO_FILE):
        with open(BALZERO_FILE, "r") as f:
            for line in f:
                addr = line.strip()
                if addr:
                    known.add(addr)
    return known

def append_to_file(filepath, text):
    with open(filepath, "a") as f:
        f.write(text + "\n")

# ==============================================================================
# EXTRACT SENDER ADDRESSES FROM A BLOCK
# ==============================================================================
def get_block_addresses(block_height):
    """Get all SENDER addresses from a block (addresses that spent coins)."""
    url = f"https://blockchain.info/block-height/{block_height}?format=json"
    data = api_get(url)
    if data is None:
        return None
    if "blocks" not in data:
        return []
    
    senders = set()
    for block in data["blocks"]:
        for tx in block.get("tx", []):
            for inp in tx.get("inputs", []):
                prev = inp.get("prev_out", {})
                addr = prev.get("addr")
                if addr and addr.startswith("1"):  # Legacy P2PKH only
                    senders.add(addr)
    return list(senders)

# ==============================================================================
# BATCH CHECK: 20 ADDRESSES IN ONE API CALL
# ==============================================================================
def check_addresses_batch(addresses):
    """Check multiple addresses in ONE API call via multiaddr. Returns dict."""
    if not addresses:
        return {}
    joined = "|".join(addresses)
    url = f"https://blockchain.info/multiaddr?active={joined}&n=0"
    data = api_get(url)
    if not data:
        return {}
    
    results = {}
    for addr_data in data.get("addresses", []):
        addr = addr_data.get("address", "")
        tx_count = addr_data.get("n_tx", 0)
        balance = addr_data.get("final_balance", 0)
        results[addr] = (tx_count, balance)
    return results

# ==============================================================================
# MAIN
# ==============================================================================
def main():
    os.makedirs(BLOCK_DIR, exist_ok=True)
    
    print("=" * 60)
    print("  BLOCK ADDRESS SCANNER v1.1 (Batch 20)")
    print("  Extract → Filter → Balance Check")
    print("=" * 60)
    
    # Show previous session info
    progress_file = os.path.join(BLOCK_DIR, "last_block.txt")
    if os.path.isfile(progress_file):
        try:
            with open(progress_file, "r") as f:
                prev_block = int(f.read().strip())
            print(f"\n  [*] Previous session ended at block: {prev_block:,}")
        except:
            pass
    
    known_count = 0
    if os.path.isfile(BALZERO_FILE):
        with open(BALZERO_FILE, "r") as f:
            known_count = sum(1 for line in f if line.strip())
    if known_count > 0:
        print(f"  [*] Total addresses collected so far: {known_count:,}")
    
    # Get block start
    while True:
        try:
            start = int(input("\nStart block number: ").strip().replace(",", ""))
            break
        except ValueError:
            print("Enter valid numbers!")
    
    print(f"\n[*] Scanning from block: {start:,} onwards continuously")
    print(f"[*] Min TX requirement: {MIN_TX_COUNT}")
    print(f"[*] Batch size: {BATCH_CHECK_SIZE} addresses per API call")
    print(f"[*] Output: {BLOCK_DIR}/")
    
    # Load already-processed addresses
    known = load_known_addresses()
    print(f"[*] Already processed: {len(known):,} addresses (will skip)")
    
    # Stats
    total_found = 0
    total_checked = 0
    total_balance = 0
    total_zero = 0
    total_skipped_known = 0
    total_skipped_low_tx = 0
    
    # Resume from last block
    resume_block = start
    if os.path.isfile(progress_file):
        try:
            with open(progress_file, "r") as f:
                saved = int(f.read().strip())
                if saved >= start:
                    resume_block = saved + 1
                    print(f"[*] Resuming from block {resume_block:,}")
        except:
            pass
    
    print(f"\n{'=' * 60}")
    print("  Scanning blocks...")
    print(f"{'=' * 60}\n")
    
    # Batch buffer for address checking
    batch_buffer = []
    
    def flush_batch():
        """Check all buffered addresses in one API call."""
        nonlocal total_checked, total_balance, total_zero, total_skipped_low_tx
        if not batch_buffer:
            return
        
        results = check_addresses_batch(batch_buffer)
        for addr in batch_buffer:
            if addr not in results:
                continue
            tx_count, balance = results[addr]
            total_checked += 1
            
            if tx_count < MIN_TX_COUNT:
                total_skipped_low_tx += 1
                continue
            
            if balance > 0:
                total_balance += 1
                append_to_file(BALANCE_FILE, addr)
                print(f"\n  [$$] BALANCE FOUND: {addr} = {balance / 1e8:.8f} BTC ({tx_count} txs)")
            else:
                total_zero += 1
                append_to_file(ZERO_FILE, addr)
        
        batch_buffer.clear()
    
    height = resume_block
    while not EXIT_FLAG:
        
        # Progress
        print(f"\r[Block {height:,}] | Found: {total_found} | Balance: {total_balance} | Zero: {total_zero} | Batch: {len(batch_buffer)}/{BATCH_CHECK_SIZE}", end="", flush=True)
        
        # Get senders from this block
        addresses = get_block_addresses(height)
        
        if addresses is None:
            # Hit the tip of the blockchain, wait for new block
            time.sleep(30)
            continue
        
        for addr in addresses:
            if EXIT_FLAG:
                break
            
            if addr in known:
                total_skipped_known += 1
                continue
            
            known.add(addr)
            append_to_file(BALZERO_FILE, addr)
            total_found += 1
            
            batch_buffer.append(addr)
            
            # Flush when batch is full
            if len(batch_buffer) >= BATCH_CHECK_SIZE:
                flush_batch()
        
        # Save block progress
        with open(progress_file, "w") as f:
            f.write(str(height))
            
        height += 1
    
    # Flush remaining addresses in buffer
    flush_batch()
    
    # Final summary
    print(f"\n\n{'=' * 60}")
    print("  SCAN COMPLETE!")
    print(f"{'=' * 60}")
    print(f"  Blocks scanned:    {height - resume_block + 1:,}")
    print(f"  Addresses found:   {total_found:,}")
    print(f"  Already known:     {total_skipped_known:,} (skipped)")
    print(f"  Low TX (<{MIN_TX_COUNT}):     {total_skipped_low_tx:,} (skipped)")
    print(f"  Checked:           {total_checked:,}")
    print(f"  With balance:      {total_balance:,} -> {BALANCE_FILE}")
    print(f"  Zero balance:      {total_zero:,} -> {ZERO_FILE}")
    print(f"  All addresses:     {len(known):,} -> {BALZERO_FILE}")
    print(f"{'=' * 60}")

if __name__ == "__main__":
    main()
