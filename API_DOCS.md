# API Documentation

## `POST /upload`
Uploads a PCAP file for analysis.
- **Form Data:** `file` (the .pcap file)
- **Response (200):** `{"message": "File uploaded successfully", "filename": "<unique_id>_filename.pcap"}`
- **Security:** Validates magic bytes, checks for duplicates via SHA-256 hash. If duplicate, returns 200 with the existing filename.

## `GET /analyze/<filename>`
Analyzes a previously uploaded file and returns JSON results.
- **Response (200):**
  ```json
  {
    "summary": {
      "filename": "...",
      "file_hash": "...",
      "timestamp": "...",
      "total_packets": 100,
      "normal_packets": 90,
      "anomalous_packets": 10
    },
    "details": [
      {
        "packet_id": 1,
        "protocol": 6,
        "src_ip": "192.168.1.1",
        "dst_ip": "10.0.0.1",
        "src_port": 12345,
        "dst_port": 80,
        "packet_size": 1500,
        "tcp_flags": 2,
        "is_anomalous": false,
        "confidence": 98.5
      }
    ]
  }
  ```

## `GET /export/json/<filename>`
Returns the same payload as `/analyze` but forces a file download (`attachment`).

## `GET /export/csv/<filename>`
Returns the flattened packet details in CSV format as a file download.

## `POST /model/retrain`
Forces the NIDSModel to generate new synthetic data and overwrite the existing `rf_model.pkl`.
- **Response (200):** `{"message": "Model retrained successfully", "status": {...}}`

## `GET /health`
Returns system health status.
- **Response (200):** `{"status": "healthy", "service": "NIDS Application"}`
