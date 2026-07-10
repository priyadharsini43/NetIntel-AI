# Database Schema

Net Intel AI uses a lightweight SQLite database stored at `data/nids.db`. 
Table creation and schema migrations are handled automatically in `core/database.py`.

## Table: `analysis_history`

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY, AUTOINCREMENT | Unique identifier for the analysis record |
| `filename` | TEXT | NOT NULL | The sanitized, unique filename saved on disk |
| `file_hash` | TEXT | | SHA-256 hash of the uploaded PCAP file, used for duplicate detection |
| `upload_time` | DATETIME | DEFAULT CURRENT_TIMESTAMP | When the analysis was performed |
| `total_packets` | INTEGER | | Total number of valid IP packets analyzed |
| `normal_packets` | INTEGER | | Count of packets classified as normal (0) |
| `anomalous_packets` | INTEGER | | Count of packets classified as anomalous (1) |

> Note: Detailed packet-level results are not stored in the database to prevent unbounded database growth. The full results can be exported as JSON or CSV immediately after analysis via the dashboard endpoints.
