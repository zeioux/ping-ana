#!/usr/bin/env python3
import argparse
import os
import sys
import time
import csv
import tempfile
import threading
from collections import deque
from datetime import datetime, timedelta
import logging
from logging.handlers import RotatingFileHandler
import ctypes
try:
    from scapy.all import sniff, IP, ICMP
except Exception as e:
    print("Scapy required. pip install scapy")
    raise

MAX_PENDING = 20000
EXPIRE_SECONDS = 10
LOG_FILE = "icmp_sniffer.log"
LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUP_COUNT = 3
CSV_FLUSH_FREQ = 1

logger = logging.getLogger("icmp_sniffer")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

lock = threading.Lock()
pending_reqs = {}
pending_queue = deque()
rtts = []
stop_event = threading.Event()

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def percentile(data, p):
    if not data:
        return None
    s = sorted(data)
    k = (len(s)-1) * (p/100.0)
    f = int(k)
    c = f + 1
    if c >= len(s):
        return s[-1]
    return s[f] * (c-k) + s[c] * (k-f)

def safe_write_csv_row(path, row, header=False):
    mode = "a"
    first_write = False
    if not os.path.exists(path) and header:
        first_write = True
    try:
        with open(path, mode, newline='') as f:
            writer = csv.writer(f)
            if first_write:
                writer.writerow(["timestamp_iso", "src", "dst", "id", "seq", "rtt_ms"])
            writer.writerow(row)
            f.flush()
            os.fsync(f.fileno())
    except Exception as ex:
        logger.exception("Erreur écriture CSV: %s", ex)

def expire_old_requests():
    now = time.time()
    cutoff = now - EXPIRE_SECONDS
    removed = 0
    with lock:
        while pending_queue and (pending_queue[0][1] < cutoff):
            key, _ts = pending_queue.popleft()
            if key in pending_reqs:
                del pending_reqs[key]
                removed += 1
    if removed:
        logger.info("Expired %d old pending requests", removed)

def handle_packet(pkt, args):
    try:
        if not pkt.haslayer(ICMP) or not pkt.haslayer(IP):
            return
        ip = pkt[IP]
        icmp = pkt[ICMP]
        if icmp.type == 8:
            key = (int(icmp.id if hasattr(icmp, "id") else 0),
                   int(icmp.seq if hasattr(icmp, "seq") else 0),
                   ip.src, ip.dst)
            ts = pkt.time
            with lock:
                if len(pending_reqs) >= MAX_PENDING:
                    try:
                        old_key, _old_ts = pending_queue.popleft()
                        if old_key in pending_reqs:
                            del pending_reqs[old_key]
                    except IndexError:
                        pass
                pending_reqs[key] = ts
                pending_queue.append((key, ts))
        elif icmp.type == 0:
            key = (int(icmp.id if hasattr(icmp, "id") else 0),
                   int(icmp.seq if hasattr(icmp, "seq") else 0),
                   ip.dst, ip.src)
            ts_reply = pkt.time
            t_req = None
            with lock:
                t_req = pending_reqs.pop(key, None)
            if t_req is not None:
                rtt_ms = (ts_reply - t_req) * 1000.0
                if rtt_ms >= 0:
                    now_iso = datetime.utcfromtimestamp(ts_reply).isoformat() + "Z"
                    row = [now_iso, ip.src, ip.dst, key[0], key[1], f"{rtt_ms:.6f}"]
                    safe_write_csv_row(args.out, row, header=True)
                    with lock:
                        rtts.append(rtt_ms)
                    if len(rtts) % 10 == 0:
                        with lock:
                            mean = sum(rtts)/len(rtts)
                            p90 = percentile(rtts, 90)
                        logger.info("RTT stats count=%d mean=%.3f ms p90=%.3f ms", len(rtts), mean, p90)
    except Exception as e:
        logger.exception("Erreur handle_packet: %s", e)

def run_sniff(args):
    if not is_admin():
        logger.warning("Le processus n'est pas exécuté en administrateur. La capture peut échouer (npcap required).")
        print("Warning: run as Administrator for packet capture to work.")
    def expirer():
        while not stop_event.wait(1.0):
            expire_old_requests()
    t = threading.Thread(target=expirer, daemon=True)
    t.start()
    bpf = f"icmp and host {args.target}" if args.target else "icmp"
    logger.info("Start sniff iface=%s filter=%s max_packets=%s", args.iface, bpf, args.max_packets)
    print(f"Sniffing on iface={args.iface} filter='{bpf}' (CTRL-C to stop)")
    try:
        sniff(iface=args.iface, filter=bpf, prn=lambda p: handle_packet(p, args), store=0,
              timeout=args.timeout if args.timeout else None, count=args.max_packets if args.max_packets else 0)
    except PermissionError:
        logger.exception("PermissionError: likely need to run as Administrator or Npcap not installed.")
        print("Permission error: run as Administrator and ensure Npcap installed (admin-only).")
    except Exception as e:
        logger.exception("Sniff failed: %s", e)
        print("Sniff failed:", e)
    finally:
        stop_event.set()
        with lock:
            if rtts:
                mean = sum(rtts)/len(rtts)
                p90 = percentile(rtts, 90)
                p99 = percentile(rtts, 99)
                print("---- Final stats ----")
                print(f"Count: {len(rtts)}")
                print(f"Mean: {mean:.3f} ms")
                print(f"p90: {p90:.3f} ms p99: {p99:.3f} ms")
                logger.info("Stopped. Final stats count=%d mean=%.3f p90=%.3f p99=%.3f", len(rtts), mean, p90, p99)
            else:
                print("No RTT collected.")
                logger.info("Stopped. No RTT collected.")

def main():
    parser = argparse.ArgumentParser(description="ICMP live RTT sniffer (hardened)")
    parser.add_argument("--iface", required=True, help="Interface name (use scapy.show_interfaces() if unsure)")
    parser.add_argument("--target", required=False, help="Target IP to filter (strongly recommended)")
    parser.add_argument("--max-packets", type=int, required=False, help="Max packets to capture (safety limit)")
    parser.add_argument("--timeout", type=int, required=False, help="Timeout in seconds for sniffing")
    parser.add_argument("--out", default="rtts.csv", help="Output CSV file")
    parser.add_argument("--dry-run", action="store_true", help="Validate config and exit")
    args = parser.parse_args()
    if not args.target:
        logger.warning("Aucune cible fournie. Il est fortement recommandé de spécifier --target pour réduire la surface.")
    if args.max_packets and args.max_packets > 10_000_000:
        logger.error("max-packets trop grand")
        parser.error("max-packets too large")
    if args.dry_run:
        print("Dry-run OK. Config validated.")
        logger.info("Dry-run ok. Exiting.")
        sys.exit(0)
    try:
        outdir = os.path.dirname(os.path.abspath(args.out))
        if outdir and not os.path.exists(outdir):
            os.makedirs(outdir, exist_ok=True)
    except Exception:
        logger.exception("Impossible de préparer le répertoire de sortie.")
        raise
    run_sniff(args)

if __name__ == "__main__":
    main()
