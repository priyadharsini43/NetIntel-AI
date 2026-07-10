# Architecture Overview

Net Intel AI uses a modular Flask architecture following the application factory pattern.

## Directory Structure
- `app.py` - Application factory, configures logging and registers blueprints.
- `config.py` - Environment-specific configuration classes.
- `core/`
  - `database.py` - SQLite connection and query layer.
  - `model.py` - Wrapper for Scikit-Learn `RandomForestClassifier`.
  - `model_service.py` - Service layer for model metadata and retraining logic.
  - `pcap_parser.py` - Uses `scapy` to extract feature vectors from `.pcap` files.
- `routes/`
  - `main.py` - Blueprint defining all web and API routes.
- `templates/` - Jinja2 HTML templates.
- `static/` - CSS (`style.css`) and Vanilla JS (`script.js`).
- `uploads/` - Temporary storage for uploaded PCAP files (auto-purged).
- `data/` - Persistent storage for `nids.db` and `rf_model.pkl`.

## Data Flow (Upload & Analyze)
1. User uploads a PCAP via frontend.
2. `POST /upload` validates magic bytes, computes hash, saves file, and triggers background purge.
3. Frontend redirects to `/results?filename=...`
4. Frontend fetches `GET /analyze/<filename>`.
5. Backend (`pcap_parser.py`) extracts IP/TCP/UDP/ICMP packets into feature dicts.
6. Backend (`model.py`) predicts anomalies on feature dicts.
7. Backend (`database.py`) saves analysis summary.
8. Frontend renders summary cards, 3 Chart.js charts, and a paginated data table.
