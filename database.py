import sqlite3

def create_table():
    conn = sqlite3.connect('scans.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            domain TEXT,
            path TEXT,
            query TEXT,
            status TEXT
        )
    ''')
    conn.commit()
    conn.close()

def insert_scan(url, domain, path, query, status):
    conn = sqlite3.connect('scans.db')
    c = conn.cursor()
    c.execute('''
        INSERT INTO scans (url, domain, path, query, status)
        VALUES (?, ?, ?, ?, ?)
    ''', (url, domain, path, query, status))
    conn.commit()
    conn.close()

def get_recent_scans():
    conn = sqlite3.connect('scans.db')
    c = conn.cursor()
    c.execute('SELECT url, status FROM scans ORDER BY id DESC LIMIT 5')
    scans = c.fetchall()
    conn.close()
    return scans
