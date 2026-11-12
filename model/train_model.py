import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import GroupShuffleSplit
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score


# Monday is deliberately excluded - it's pure benign traffic, kept aside as a
# clean, never-trained-on file to test false positives in File Analysis
FILES = [
    "data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",             # DDoS
    "data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",         # PortScan
    "data/Friday-WorkingHours-Morning.pcap_ISCX.csv",                    # Botnet
    "data/Tuesday-WorkingHours.pcap_ISCX.csv",                           # FTP/SSH brute force
    "data/Wednesday-workingHours.pcap_ISCX.csv",                         # DoS variants
    "data/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",       # Web attacks
    "data/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",  # Infiltration
]

CIC_MAP = {
    "duration": ("Flow Duration", 1_000_000),
    "fwd_packets": ("Total Fwd Packets", 1),
    "bwd_packets": ("Total Backward Packets", 1),
    "fwd_bytes": ("Total Length of Fwd Packets", 1),
    "bwd_bytes": ("Total Length of Bwd Packets", 1),
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
FEATURES = list(CIC_MAP.keys()) + ["byte_rate", "packet_rate"]
RATE_FLOOR = 0.001  # 1 ms, must match RATE_FLOOR in engine.py

# ---------- 1. load and combine ----------
frames = []
for path in FILES:
    df = pd.read_csv(path, encoding_errors="replace")
    df.columns = df.columns.str.strip()
    print(f"{path}: {len(df):,} rows")
    frames.append(df)
df = pd.concat(frames, ignore_index=True)
print(f"\nLoaded {len(df):,} rows total from {len(FILES)} files")

# some files (notably Thursday WebAttacks) have garbled dash characters in Label
df["Label"] = (df["Label"].astype(str).str.strip()
              .str.replace("\ufffd", "-", regex=False)
              .str.replace(r"\s+", " ", regex=True))
print(df["Label"].value_counts())

# ---------- 2. build features ----------
built = pd.DataFrame({name: df[col] / div for name, (col, div) in CIC_MAP.items()})
built["Label"] = df["Label"]

# smooth rate features so near-zero durations don't produce extreme, unstable values
safe_duration = built["duration"].clip(lower=RATE_FLOOR)
built["byte_rate"] = (built["fwd_bytes"] + built["bwd_bytes"]) / safe_duration
built["packet_rate"] = (built["fwd_packets"] + built["bwd_packets"]) / safe_duration

built = built.replace([np.inf, -np.inf], np.nan).dropna()

# ---------- 3. remove duplicate rows, PER CLASS, with a safeguard ----------
# some attacks (like PortScan) naturally produce near-identical flows -
# if dedup would gut a class, the "duplicates" are real signal, so keep them
kept = []
for label, group in built.groupby("Label"):
    deduped = group.drop_duplicates(subset=FEATURES)
    if len(deduped) < 0.3 * len(group):
        print(f"{label}: dedup would remove {len(group) - len(deduped):,} of {len(group):,} rows "
              f"({1 - len(deduped) / len(group):.0%}) - keeping duplicates, they're real repeated traffic")
        kept.append(group)
    else:
        print(f"{label}: removed {len(group) - len(deduped):,} duplicate rows, {len(deduped):,} remain")
        kept.append(deduped)
built = pd.concat(kept, ignore_index=True)
print(f"\nTotal after cleanup: {len(built):,} rows")
print(built["Label"].value_counts())

X = built[FEATURES]
y = built["Label"]

# ---------- 4. leak-safe split ----------
# identical/duplicate flows get the same group id, so copies of the same flow
# can never end up split across both train and test
built["group"] = (built[FEATURES].round(3).astype(str).sum(axis=1) + "|" + built["Label"])
splitter = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
train_idx, test_idx = next(splitter.split(X, y, groups=built["group"]))
X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
print(f"\nTrain: {len(X_train):,} rows, Test: {len(X_test):,} rows (grouped split, no leakage)")

# ---------- 5. train ----------
model = RandomForestClassifier(
    n_estimators=300, max_depth=20, class_weight="balanced",
    random_state=42, n_jobs=-1,
)
print("\nTraining... this can take several minutes with this much data.")
model.fit(X_train, y_train)

# ---------- 6. evaluate on the held-out test set ----------
pred = model.predict(X_test)
print("\nTest set performance:")
print(classification_report(y_test, pred, zero_division=0))
print("Confusion matrix (rows=actual, cols=predicted):")
print("Classes:", list(model.classes_))
print(confusion_matrix(y_test, pred, labels=model.classes_))

print("\nFeature importance:")
for f, v in sorted(zip(FEATURES, model.feature_importances_), key=lambda kv: -kv[1]):
    print(f"  {f:14s} {v:.3f}")

metadata = {
    "trained_at": __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M"),
    "files": [p.split("/")[-1] for p in FILES],
    "feature_count": len(FEATURES),
    "classes": list(model.classes_),
    "n_estimators": model.n_estimators,
    "max_depth": model.max_depth,
    "rows_trained": len(X_train),
    "test_macro_f1": round(float(f1_score(y_test, pred, average="macro")), 3),
}

# ---------- 7. save ----------
joblib.dump({"model": model, "features": FEATURES, "meta": metadata}, "model/anomflow_rf.joblib")
print("\nModel saved to model/anomflow_rf.joblib")