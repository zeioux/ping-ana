import sys
from scapy.all import rdpcap, ICMP, IP
import statistics

def percentile(data, p):
    if not data: 
        return None
    data = sorted(data)
    k = (len(data)-1) * (p/100.0)
    f = int(k)
    c = f + 1
    if c >= len(data):
        return data[-1]
    d0 = data[f] * (c - k)
    d1 = data[c] * (k - f)
    return d0 + d1

def main(pcapfile):
    pkts = rdpcap(pcapfile)
    reqs = {}
    rtts_ms = []

    for p in pkts:
        if not p.haslayer(ICMP) or not p.haslayer(IP):
            continue
        icmp = p[ICMP]
        ip = p[IP]
        if icmp.type == 8:  # request
            key = (icmp.id, icmp.seq, ip.src, ip.dst)
            reqs[key] = p.time
        elif icmp.type == 0:  # reply
            key = (icmp.id, icmp.seq, ip.dst, ip.src)
            t_req = reqs.get(key)
            if t_req is not None:
                rtt = (p.time - t_req) * 1000.0  # ms
                if rtt >= 0:
                    rtts_ms.append(rtt)
                del reqs[key]

    if not rtts_ms:
        print("Aucun RTT calculé. Vérifie que le pcap contient des Echo Request + Reply.")
        return

    rtts_ms.sort()
    print(f"Count: {len(rtts_ms)}")
    print(f"Min: {min(rtts_ms):.3f} ms")
    print(f"Max: {max(rtts_ms):.3f} ms")
    print(f"Mean: {statistics.mean(rtts_ms):.3f} ms")
    print(f"Median: {statistics.median(rtts_ms):.3f} ms")
    print(f"Std dev: {statistics.pstdev(rtts_ms):.3f} ms")
    print(f"p50: {percentile(rtts_ms, 50):.3f} ms")
    print(f"p90: {percentile(rtts_ms, 90):.3f} ms")
    print(f"p99: {percentile(rtts_ms, 99):.3f} ms")

    # écrire CSV détaillé
    with open("rtts_per_packet.csv", "w") as f:
        f.write("rtt_ms\n")
        for v in rtts_ms:
            f.write(f"{v:.6f}\n")
    print("CSV -> rtts_per_packet.csv")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 read_icmp_rtt.py icmp_dump.pcap")
        sys.exit(1)
    main(sys.argv[1])
