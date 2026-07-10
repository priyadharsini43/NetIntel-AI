# Deployment Guide

This guide explains how to deploy Net Intel AI locally for development or in a production-like environment.

## Prerequisites
- Windows, macOS, or Linux
- Python 3.9+
- pip (Python package installer)

## Local Development Setup

1. **Install Dependencies:**
   Navigate to the project root and run:
   ```bash
   pip install -r requirements.txt
   ```

2. **Set Environment Variables:**
   ```bash
   # Windows (PowerShell)
   $env:FLASK_ENV="development"
   $env:SECRET_KEY="your-secret-key-here"
   ```

3. **Run the Application:**
   ```bash
   python app.py
   ```
   The server will start on `http://127.0.0.1:5000`.

## Production Considerations
- **WSGI Server:** Do not use the built-in Flask development server in production. Use a production WSGI server like `gunicorn` (Linux) or `waitress` (Windows).
  ```bash
  pip install waitress
  waitress-serve --port=5000 app:create_app
  ```
- **Reverse Proxy:** Place the application behind a reverse proxy like Nginx or Apache to handle HTTPS termination and serve static files efficiently.
- **Environment:** Ensure `FLASK_ENV` is set to `production`.
- **Database:** While SQLite is sufficient for moderate usage, consider migrating to PostgreSQL or MySQL using SQLAlchemy if scaling is required.

## Testing
Run the included end-to-end test script to verify core flow:
```bash
python test_flow.py
```
This script generates a synthetic `test.pcap`, uploads it to the running server, triggers analysis, and verifies the response.
