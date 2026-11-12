import os
import socket
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from scapy.all import sniff, PcapReader, IP, IPv6, TCP, UDP, conf

from db.database import BASE, save_flows

MODEL_PATH = os.path.join(BASE, "model", "anomflow_rf.joblib")
_bundle = None

# smooth rate features so near-zero durations don't produce extreme, unstable values
RATE_FLOOR = 0.001  # 1 ms


def get_active_iface():
    """Find whichever network adapter currently has the internet-facing IP,
    so capture always uses the right one — even if you switch between
    Ethernet, Wi-Fi, or a hotspot between runs. Returns None (= Scapy's
    own default) if detection fails for any reason."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))   # doesn't actually send anything
        local_ip = s.getsockname()[0]
        s.close()
    except OSError:
        return None
    for iface in conf.ifaces.values():
        if getattr(iface, "ip", None) == local_ip:
            return iface
    return None


def get_model():
    global _bundle
    if _bundle is None:
        _bundle = joblib.load(MODEL_PATH)
    return _bundle["model"], _bundle["features"]


def feature_importance():
    model, features = get_model()
    return {f: float(v) for f, v in zip(features, model.feature_importances_)}

def get_metadata():
    """Training details saved alongside the model, if available."""
    get_model()  # ensures the bundle is loaded
    return _bundle.get("meta", {})


def packet_info(pkt):
    """Return (flow_key, src, dst, payload_len, tcp_flags) or None."""
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
    src, dst = (ip.src, layer.sport), (ip.dst, layer.dport)
    end_a, end_b = sorted([src, dst])
    key = (end_a[0], end_a[1], end_b[0], end_b[1], proto)
    flags = str(layer.flags) if proto == "TCP" else ""
    return key, src, dst, len(layer.payload), flags


class FlowTable:
    """Groups packets into flows and tracks the same statistics CIC-IDS2017 uses,
    with running sums only (memory friendly for long captures and big pcaps)."""

    def __init__(self):
        self.flows = {}

    def add(self, pkt):
        info = packet_info(pkt)
        if info is None:
            return
        key, src, dst, payload, flags = info
        t = float(pkt.time)
        f = self.flows.get(key)
        if f is None:
            f = self.flows[key] = {
                "forward": src, "first": t, "last": t, "prev_t": t,
                "fwd_n": 0, "fwd_bytes": 0, "bwd_n": 0, "bwd_bytes": 0,
                "len_sum": 0, "len_sumsq": 0, "len_max": 0, "len_min": None,
                "iat_sum": 0.0, "iat_sumsq": 0.0, "iat_n": 0,
                "syn": 0, "ack": 0, "fin": 0, "rst": 0, "psh": 0,
            }
        else:
            f["last"] = max(f["last"], t)
            dt = t - f["prev_t"]
            if dt > 0:
                f["iat_sum"] += dt
                f["iat_sumsq"] += dt * dt
                f["iat_n"] += 1
            f["prev_t"] = t

        if src == f["forward"]:
            f["fwd_n"] += 1
            f["fwd_bytes"] += payload
        else:
            f["bwd_n"] += 1
            f["bwd_bytes"] += payload

        f["len_sum"] += payload
        f["len_sumsq"] += payload * payload
        f["len_max"] = max(f["len_max"], payload)
        f["len_min"] = payload if f["len_min"] is None else min(f["len_min"], payload)

        if "S" in flags: f["syn"] += 1
        if "A" in flags: f["ack"] += 1
        if "F" in flags: f["fin"] += 1
        if "R" in flags: f["rst"] += 1
        if "P" in flags: f["psh"] += 1

    def to_df(self):
        rows = []
        for key, f in self.flows.items():
            n = f["fwd_n"] + f["bwd_n"]
            duration = f["last"] - f["first"]
            total_bytes = f["fwd_bytes"] + f["bwd_bytes"]
            safe_duration = max(duration, RATE_FLOOR)
            pkt_mean = f["len_sum"] / n if n else 0
            pkt_var = max(0, f["len_sumsq"] / n - pkt_mean ** 2) if n else 0
            iat_mean = f["iat_sum"] / f["iat_n"] if f["iat_n"] else 0
            iat_var = max(0, f["iat_sumsq"] / f["iat_n"] - iat_mean ** 2) if f["iat_n"] else 0
            rows.append({
                "src_ip": key[0], "src_port": key[1], "dst_ip": key[2], "dst_port": key[3],
                "protocol": key[4], "start": f["first"], "duration": duration,
                "fwd_packets": f["fwd_n"], "bwd_packets": f["bwd_n"],
                "fwd_bytes": f["fwd_bytes"], "bwd_bytes": f["bwd_bytes"],
                "packet_count": n, "total_bytes": total_bytes,
                "byte_rate": total_bytes / safe_duration,
                "packet_rate": n / safe_duration,
                "pkt_len_mean": pkt_mean, "pkt_len_std": pkt_var ** 0.5,
                "pkt_len_max": f["len_max"], "pkt_len_min": f["len_min"] or 0,
                "iat_mean": iat_mean, "iat_std": iat_var ** 0.5,
                "syn_count": f["syn"], "ack_count": f["ack"], "fin_count": f["fin"],
                "rst_count": f["rst"], "psh_count": f["psh"],
                "down_up_ratio": (f["bwd_n"] / f["fwd_n"]) if f["fwd_n"] else 0,
            })
        return pd.DataFrame(rows)


def score_flows(df):
    if df.empty:
        return df
    df = df[df["packet_count"] >= 2].copy()   # the model was trained on flows with 2+ packets
    if df.empty:
        return df
    model, features = get_model()
    probs = model.predict_proba(df[features])
    classes = model.classes_
    benign_idx = list(classes).index("BENIGN") if "BENIGN" in classes else None
    attack_prob = 1 - probs[:, benign_idx] if benign_idx is not None else probs.max(axis=1)
    df["attack_prob"] = attack_prob
    df["prediction"] = (attack_prob >= 0.5).astype(int)
    df["attack_type"] = classes[probs.argmax(axis=1)]   # bonus: which class it most resembles
    return df.reset_index(drop=True)


def capture_and_score(seconds, stop_event=None):
    table = FlowTable()
    stop = (lambda p: stop_event.is_set()) if stop_event is not None else None
    iface = get_active_iface()
    sniff(timeout=seconds, prn=table.add, store=False, stop_filter=stop, iface=iface)
    df = score_flows(table.to_df())
    if not df.empty:
        df["seen_at"] = datetime.now().strftime("%H:%M:%S")
        save_flows(df)
    return df


def analyze_pcap(path, progress=None):
    table = FlowTable()
    reader = PcapReader(path)
    n = 0
    try:
        for pkt in reader:
            table.add(pkt)
            n += 1
            if progress and n % 5000 == 0:
                progress(n)
    finally:
        reader.close()
    df = table.to_df()
    if df.empty:
        return df
    t0 = df["start"].min()
    df = score_flows(df)
    if not df.empty:
        df["seen_at"] = [f"+{s - t0:.1f}s" for s in df["start"]]
    return df


# CIC-IDS2017 column -> our feature name (duration-like columns are microseconds there)
CIC_MAP = {
    "duration": ("Flow Duration", 1_000_000),
    "fwd_packets": ("Total Fwd Packets", 1),
    "bwd_packets": ("Total Backward Packets", 1),
    "fwd_bytes": ("Total Length of Fwd Packets", 1),
    "bwd_bytes": ("Total Length of Bwd Packets", 1),
    "byte_rate": ("Flow Bytes/s", 1),
    "packet_rate": ("Flow Packets/s", 1),
    "pkt_len_mean": ("Packet Length Mean", 1),
    "pkt_len_std": ("Packet Length Std", 1),
    "pkt_len_max": ("Max Packet Length", 1),
    "pkt_len_min": ("Min Packet Length", 1),
    "iat_mean": ("Flow IAT Mean", 1_000_000),
    "iat_std": ("Flow IAT Std", 1_000_000),
    "syn_count": ("SYN Flag Count", 1),
    "ack_count": ("ACK Flag Count", 1),
    "fin_count": ("FIN Flag Count", 1),
    "rst_count": ("RST Flag Count", 1),
    "psh_count": ("PSH Flag Count", 1),
    "down_up_ratio": ("Down/Up Ratio", 1),
}


def load_csv_flows(path):
    raw = pd.read_csv(path, encoding_errors="replace")
    raw.columns = raw.columns.str.strip()
    _, features = get_model()

    if all(c in raw.columns for c in features):          # a CSV exported by ANOMFLOW
        flows = raw.copy()
    elif "Flow Duration" in raw.columns:                  # CIC-IDS2017 style CSV
        flows = pd.DataFrame({
            name: raw[col] / div for name, (col, div) in CIC_MAP.items() if col in raw.columns
        })
        if "Destination Port" in raw.columns:
            flows["dst_port"] = raw["Destination Port"]
        if "Total Fwd Packets" in raw.columns and "Total Backward Packets" in raw.columns:
            flows["packet_count"] = raw["Total Fwd Packets"] + raw["Total Backward Packets"]
        if "Total Length of Fwd Packets" in raw.columns:
            flows["total_bytes"] = (raw["Total Length of Fwd Packets"]
                                    + raw["Total Length of Bwd Packets"])
        # recompute rates with the same duration floor used live, instead of the
        # dataset's raw Flow Bytes/s & Flow Packets/s, which have the same
        # divide-by-near-zero instability we just fixed for live capture
        if "duration" in flows.columns and "fwd_bytes" in flows.columns:
            safe_duration = flows["duration"].clip(lower=RATE_FLOOR)
            flows["byte_rate"] = (flows["fwd_bytes"] + flows["bwd_bytes"]) / safe_duration
            flows["packet_rate"] = (flows["fwd_packets"] + flows["bwd_packets"]) / safe_duration
        if "Label" in raw.columns:
            flows["true_label"] = raw["Label"].astype(str).str.strip()
    else:
        raise ValueError("This CSV is not a flow file ANOMFLOW understands. "
                         "Use a CIC-IDS2017 CSV or a CSV exported from ANOMFLOW.")

    flows = flows.replace([np.inf, -np.inf], np.nan).dropna(subset=features)
    defaults = {"src_ip": "-", "dst_ip": "-", "src_port": 0, "dst_port": 0,
                "protocol": "-", "seen_at": "-"}
    for col, val in defaults.items():
        if col not in flows.columns:
            flows[col] = val
    return score_flows(flows)