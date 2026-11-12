from scapy.all import sniff, IP, IPv6, TCP, UDP
from collections import defaultdict
import pandas as pd

# each flow stores the timestamps and sizes of its packets
flows = defaultdict(lambda: {"times": [], "sizes": []})


def get_key(pkt):
    """Return the 5-value flow ID for a packet, or None if not usable."""
    if IP in pkt:
        ip = pkt[IP]
    elif IPv6 in pkt:
        ip = pkt[IPv6]
    else:
        return None

    if TCP in pkt:
        proto, layer = "TCP", pkt[TCP]
    elif UDP in pkt:
        proto, layer = "UDP", pkt[UDP]
    else:
        return None

    # sort both ends so A->B and B->A land in the same flow
    end_a = (ip.src, layer.sport)
    end_b = (ip.dst, layer.dport)
    end_a, end_b = sorted([end_a, end_b])
    return (end_a[0], end_a[1], end_b[0], end_b[1], proto)


def process(pkt):
    key = get_key(pkt)
    if key is None:
        return
    flows[key]["times"].append(float(pkt.time))
    flows[key]["sizes"].append(len(pkt))


print("Capturing for 30 seconds... use your browser now.")
sniff(timeout=30, prn=process)

rows = []
for key, d in flows.items():
    n = len(d["times"])
    duration = max(d["times"]) - min(d["times"])
    total_bytes = sum(d["sizes"])
    rows.append({
        "src_ip": key[0], "src_port": key[1],
        "dst_ip": key[2], "dst_port": key[3],
        "protocol": key[4],
        "packet_count": n,
        "duration": duration,
        "total_bytes": total_bytes,
        "byte_rate": total_bytes / duration if duration > 0 else 0,
        "packet_rate": n / duration if duration > 0 else 0,
    })

df = pd.DataFrame(rows)
print(df.to_string())
df.to_csv("features/sample_flows.csv", index=False)
print(f"\nSaved {len(df)} flows to features/sample_flows.csv")