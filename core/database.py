import sqlite3
import os
import logging
from flask import current_app

logger = logging.getLogger('flask.app')

def get_db_connection():
    db_path = os.path.join(current_app.config['DATA_DIR'], 'nids.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(app):
    """Initialize the SQLite database and create tables if they don't exist."""
    db_path = os.path.join(app.config['DATA_DIR'], 'nids.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            file_hash TEXT,
            upload_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            total_packets INTEGER,
            normal_packets INTEGER,
            anomalous_packets INTEGER
        )
    ''')
    conn.commit()
    conn.close()
    app.logger.info("Database initialized.")

def save_analysis(filename, file_hash, total_packets, normal_packets, anomalous_packets):
    """Save an analysis record to the database."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO analysis_history (filename, file_hash, total_packets, normal_packets, anomalous_packets)
            VALUES (?, ?, ?, ?, ?)
        ''', (filename, file_hash, total_packets, normal_packets, anomalous_packets))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to save analysis history: {e}")

def get_all_history():
    """Retrieve all analysis history ordered by newest first."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM analysis_history ORDER BY upload_time DESC')
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Failed to retrieve history: {e}")
        return []

def get_analysis_by_hash(file_hash):
    """Check if a file hash already exists and return the filename if it does."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT filename FROM analysis_history WHERE file_hash = ? ORDER BY upload_time DESC LIMIT 1', (file_hash,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return row['filename']
        return None
    except Exception as e:
        logger.error(f"Failed to retrieve by hash: {e}")
        return None
