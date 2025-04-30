# app.py
from flask import Flask, request, render_template, redirect, url_for
from datetime import datetime
import csv
import os
import uuid

app = Flask(__name__)

LOG_FILE = 'logs.csv'
LINKS_FILE = 'links.csv'

# Crear archivos si no existen
def init_files():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, mode='w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['timestamp', 'id', 'ip', 'user_agent'])

    if not os.path.exists(LINKS_FILE):
        with open(LINKS_FILE, mode='w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['unique_id', 'user_id'])

@app.route('/')
def index():
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, newline='') as f:
            reader = csv.reader(f)
            next(reader)  # skip header
            logs = list(reader)

    links = []
    if os.path.exists(LINKS_FILE):
        with open(LINKS_FILE, newline='') as f:
            reader = csv.reader(f)
            next(reader)  # skip header
            links = [(row[1], request.url_root + 'log?id=' + row[0]) for row in reader]

    return render_template('index.html', logs=logs, links=links)

@app.route('/generate', methods=['POST'])
def generate():
    user_id = request.form.get('user_id')
    if not user_id:
        return 'Missing user_id parameter', 400

    unique_id = str(uuid.uuid4())
    with open(LINKS_FILE, mode='a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([unique_id, user_id])

    return redirect(url_for('index'))

@app.route('/log')
def log_event():
    user_id = request.args.get('id', 'unknown')
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    with open(LOG_FILE, mode='a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, user_id, ip, user_agent])

    return '', 204  # No Content

if __name__ == '__main__':
    init_files()
    app.run(host='0.0.0.0', port=5000)