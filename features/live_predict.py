import sys
sys.path.append(".") 
from scapy.all import sniff, IP, IPv6, TCP, UDP
from collections import defaultdict
import pandas as pd
import joblib

bundle = joblib.load("model/anomflow_rf.joblib")
model, FEATURES = bundle["model"], bundle["features"]

flows = defaultdict(lambda: {"times": [], "sizes": []})


def get_key(pkt):
    """Return (flow_id, payload_size) or None."""
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

    end_a, end_b = sorted([(ip.src, layer.sport), (ip.dst, layer.dport)])
    key = (end_a[0], end_a[1], end_b[0], end_b[1], proto)
    payload = len(layer.payload)   # data only, like the training dataset
    return key, payload


def process(pkt):
    result = get_key(pkt)
    if result is None:
        return
    key, payload = result
    flows[key]["times"].append(float(pkt.time))
    flows[key]["sizes"].append(payload)


print("Capturing for 30 seconds... use your browser now.")
sniff(timeout=30, prn=process)

rows = []
for key, d in flows.items():
    n = len(d["times"])
    duration = max(d["times"]) - min(d["times"])
    total = sum(d["sizes"])
    rows.append({
        "src_ip": key[0], "src_port": key[1],
        "dst_ip": key[2], "dst_port": key[3], "protocol": key[4],
        "duration": duration,
        "packet_count": n,
        "total_bytes": total,
        "byte_rate": total / duration if duration > 0 else 0,
        "packet_rate": n / duration if duration > 0 else 0,
    })

df = pd.DataFrame(rows)

# the training data only has flows with 2+ packets, so skip 1-packet flows
df = df[df["packet_count"] >= 2].copy()

df["prediction"] = model.predict(df[FEATURES])
df["attack_prob"] = model.predict_proba(df[FEATURES])[:, 1].round(3)

print(f"\n{len(df)} flows scored, {(df['prediction'] == 1).sum()} flagged as attack\n")
show = ["src_ip", "dst_ip", "dst_port", "protocol", "packet_count",
        "total_bytes", "duration", "attack_prob"]
print(df.sort_values("attack_prob", ascending=False)[show].head(15).to_string())
from db.database import init_db, save_flows
init_db()
print(f"\nSaved {save_flows(df)} flows to db/anomflow.db")