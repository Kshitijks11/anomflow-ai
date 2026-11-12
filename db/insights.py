import numpy as np
import pandas as pd

SERVICES = {
    53: "DNS lookup", 80: "Web (HTTP)", 8080: "Web (HTTP)", 443: "Secure web (HTTPS)",
    8443: "Secure web (HTTPS)", 22: "Remote login (SSH)", 21: "File transfer (FTP)",
    25: "Email (SMTP)", 587: "Email (SMTP)", 110: "Email (POP3)", 143: "Email (IMAP)",
    993: "Email (IMAP)", 3389: "Remote Desktop", 445: "Windows file sharing",
    139: "Windows file sharing", 137: "Windows network names", 138: "Windows network names",
    123: "Time sync", 5353: "Local device discovery", 1900: "Device discovery (UPnP)",
    67: "Network setup (DHCP)", 68: "Network setup (DHCP)", 3306: "Database (MySQL)",
    5228: "Google push notifications",
}

# median values from the training data (Friday DDoS file), shown to the AI as context
REFERENCE = {
    "Typical normal connection": {"packets": 6, "bytes": 248, "seconds": 0.17,
                                  "bytes_per_s": 2226, "packets_per_s": 27.5},
    "Typical DDoS connection": {"packets": 8, "bytes": 11627, "seconds": 1.88,
                                "bytes_per_s": 160, "packets_per_s": 2.6},
}


def service_name(a, b, proto="-"):
    for p in sorted((int(a), int(b))):
        if p == 443 and proto == "UDP":
            return "Secure web (QUIC)"
        if p in SERVICES:
            return SERVICES[p]
    return "Other traffic"


def human_size(n):
    n = float(n)
    if n < 1024:
        return f"{n:.0f} B"
    for unit in ("KB", "MB", "GB"):
        n /= 1024
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}"


def human_time(s):
    s = float(s)
    if s < 1:
        return f"{s * 1000:.0f} ms"
    if s < 60:
        return f"{s:.1f} s"
    return f"{s / 60:.1f} min"


def endpoint(ip, port):
    if not ip or ip == "-":
        return "-"
    return f"[{ip}]:{port}" if ":" in str(ip) else f"{ip}:{port}"


def prepare(df):
    """Add the friendly columns (service, verdict, risk_band) to a scored DataFrame."""
    df = df.drop(columns=[c for c in ("service", "verdict", "risk_band") if c in df.columns])
    for col in ("src_port", "dst_port"):
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)
    combos = df[["src_port", "dst_port", "protocol"]].drop_duplicates().copy()
    combos["service"] = [service_name(a, b, p)
                         for a, b, p in combos.itertuples(index=False, name=None)]
    df = df.merge(combos, on=["src_port", "dst_port", "protocol"], how="left")
    df["verdict"] = np.where(df["prediction"] == 1, "Suspicious", "Normal")
    df["risk_band"] = pd.cut(df["attack_prob"], bins=[-0.01, 0.2, 0.5, 1.01],
                             labels=["Low", "Medium", "High"], right=False).astype(str)
    return df


def build_summary(df, source):
    """Plain-English paragraphs describing what happened."""
    total = len(df)
    if total == 0:
        return ["No usable connections were found in this data."]
    bad = df[df["prediction"] == 1]
    n_bad = len(bad)
    out = [f"ANOMFLOW checked {total:,} network connections from {source}."]

    if n_bad == 0:
        out.append("None of them looked suspicious. The traffic resembles ordinary browsing, "
                   "apps and background activity.")
    else:
        top = bad["service"].value_counts().head(2)
        kinds = " and ".join(f"{name} ({cnt:,})" for name, cnt in top.items())
        normal_bytes = df.loc[df["prediction"] == 0, "total_bytes"].sum()
        out.append(f"{n_bad:,} connections ({n_bad / total:.1%}) looked suspicious, mostly {kinds}.")
        out.append(f"The suspicious ones carried {human_size(bad['total_bytes'].sum())} of data, "
                   f"compared with {human_size(normal_bytes)} for the normal ones.")

    if "true_label" in df.columns:
        actual = df["true_label"] != "BENIGN"
        n_att = int(actual.sum())
        n_norm = total - n_att
        caught = int(((df["prediction"] == 1) & actual).sum())
        false_alarms = int(((df["prediction"] == 1) & ~actual).sum())
        if n_att:
            out.append(f"This file includes answer labels: {n_att:,} connections are real attacks "
                       f"and ANOMFLOW caught {caught:,} of them ({caught / n_att:.0%}).")
        else:
            out.append("This file includes answer labels and contains no attacks.")
        if n_norm:
            out.append(f"It wrongly flagged {false_alarms:,} of {n_norm:,} normal connections "
                       f"({false_alarms / n_norm:.1%}).")
        untrained = sorted(set(df.loc[actual, "true_label"]) - {"DDoS"})
        if untrained:
            out.append("The file also contains attack types the model has not been trained on "
                       f"({', '.join(untrained)}), so missed detections are expected.")

    out.append("Note: 'suspicious' is a statistical hint, not proof of an attack.")
    return out