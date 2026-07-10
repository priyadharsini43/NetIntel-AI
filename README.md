# Net Intel AI - Network Intrusion Detection System

Net Intel AI is a machine-learning powered Network Intrusion Detection System (NIDS) built with Flask. It analyzes PCAP files using Scapy, extracting packet-level features, and classifies traffic as Normal or Anomalous using a Random Forest Classifier.

## Features
- **PCAP Analysis:** Upload `.pcap` files for deep packet inspection.
- **Machine Learning Classification:** Traffic is classified by an inline-trained RandomForest model.
- **Advanced Dashboard:** Visualizes traffic breakdowns, protocol distributions, and confidence scores.
- **Analysis History:** Tracks all previous uploads in a local SQLite database.
- **Report Export:** Export packet-level results as CSV or JSON.
- **Model Management:** View model health, feature sets, and manually trigger retraining.
- **Security Hardened:** Includes magic bytes verification, duplicate file detection, and auto-purge of old uploads.

## Getting Started
See [DEPLOYMENT.md](DEPLOYMENT.md) for setup and run instructions.

## Documentation
- [Architecture](ARCHITECTURE.md)
- [API Documentation](API_DOCS.md)
- [Database Schema](DB_SCHEMA.md)
- [Deployment Guide](DEPLOYMENT.md)
