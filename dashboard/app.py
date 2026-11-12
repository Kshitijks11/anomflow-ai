import sqlite3
import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
import seaborn as sns

st.set_page_config(page_title="ANOMFLOW AI", layout="wide")
st.title("ANOMFLOW AI - Network Anomaly Dashboard")


@st.cache_data(ttl=5)
def load_data():
    with sqlite3.connect("db/anomflow.db") as conn:
        return pd.read_sql("SELECT * FROM flow_results ORDER BY id DESC", conn)


if st.button("Refresh"):
    st.cache_data.clear()
    st.rerun()

df = load_data()
if df.empty:
    st.warning("No data yet. Run features/live_predict.py first.")
    st.stop()

total = len(df)
anomalous = int((df["label"] == "ANOMALOUS").sum())

c1, c2, c3 = st.columns(3)
c1.metric("Flows analysed", total)
c2.metric("Flagged anomalous", anomalous)
c3.metric("Anomaly rate", f"{anomalous / total:.1%}")

left, right = st.columns(2)
with left:
    st.subheader("Benign vs anomalous")
    st.bar_chart(df["label"].value_counts())
with right:
    st.subheader("Attack probability distribution")
    fig, ax = plt.subplots()
    sns.histplot(df["confidence"], bins=20, ax=ax)
    ax.set_xlabel("Attack probability")
    st.pyplot(fig)

st.subheader("Top destination ports")
st.bar_chart(df["dst_port"].astype(str).value_counts().head(10))

show = ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol",
        "packet_count", "total_bytes", "duration", "label", "confidence"]

st.subheader("Most suspicious flows")
st.dataframe(df.sort_values("confidence", ascending=False).head(20)[show])

st.subheader("Latest flows")
st.dataframe(df.head(50)[show])