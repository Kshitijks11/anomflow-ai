# AnomFlow AI

A modular, ML-based network intrusion detection system (NIDS) that captures live network traffic, groups packets into bidirectional flows, and classifies each flow as benign or as a specific cyberattack.

## Features
* **Live Capture:** Real-time packet sniffing via Scapy paired with a custom flow-building engine.
* **ML Detection:** Random Forest classifier (300 trees, 19 flow features) trained on the CIC-IDS2017 dataset.
* **Offline File Analysis:** Upload `.pcap` or `.csv` files for batch analysis with visual graphs and plain-language summaries.
* **AI Explanations:** Built-in *"Explain this flow"* assistant powered by the Gemini API to break down suspicious traffic.
* **Reporting:** Export detection logs and analysis reports to PDF or CSV.
* **Persistent Storage:** Automatically logs predictions, confidence scores, and timestamps to a local SQLite database.
* **Desktop UI:** Dark-blue desktop interface featuring a Start screen, attack-type filtering, and real-time or file-analysis modes.

## Supported Attack Types

| Status | Attack Categories |
| :--- | :--- |
| **Active** | DDoS, PortScan, DoS, FTP-Patator, SSH-Patator |
| **Planned** | Web Attacks, Botnet, Infiltration |

## How It Works

```text
Scapy Capture ──▶ Flow Extraction ──▶ Preprocessing ──▶ Random Forest ──▶ SQLite ──▶ Desktop App