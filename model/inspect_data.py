import pandas as pd

df = pd.read_csv("data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
df.columns = df.columns.str.strip()   # some column names have hidden spaces

print(df.shape)
print(df["Label"].value_counts())
print(list(df.columns))

# build the same features your Scapy code produces
df["packet_count"] = df["Total Fwd Packets"] + df["Total Backward Packets"]
df["total_bytes"] = df["Total Length of Fwd Packets"] + df["Total Length of Bwd Packets"]
df["duration"] = df["Flow Duration"] / 1_000_000   # microseconds -> seconds

cols = ["duration", "packet_count", "total_bytes", "Flow Bytes/s", "Flow Packets/s"]
print(df[cols + ["Label"]].head(10))

# compare typical (median) values for normal vs attack flows
print(df.groupby("Label")[cols].median())