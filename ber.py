from flask import Flask, request, session, redirect, url_for, render_template, jsonify
import json
import os
import requests
import sys
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'secret123'  # Ganti dengan secret key yang aman

DATABASE_PATH = 'database.json'
LISTBAN_PATH = 'listban.json'
RECAPTCHA_SECRET_KEY = 'your-secret-key'  # Ganti dengan kunci secret reCAPTCHA Anda

def ensure_database():
    if not os.path.exists(DATABASE_PATH):
        with open(DATABASE_PATH, 'w') as f:
            json.dump({"users": [], "codes": []}, f, indent=2)

def ensure_listban():
    if not os.path.exists(LISTBAN_PATH):
        with open(LISTBAN_PATH, 'w') as f:
            json.dump([], f)

def read_db():
    with open(DATABASE_PATH, 'r') as f:
        return json.load(f)

def write_db(data):
    with open(DATABASE_PATH, 'w') as f:
        json.dump(data, f, indent=2)

def read_banned_ips():
    with open(LISTBAN_PATH, 'r') as f:
        return json.load(f)

def write_banned_ips(data):
    with open(LISTBAN_PATH, 'w') as f:
        json.dump(data, f, indent=2)

ensure_database()
ensure_listban()

@app.before_request
def block_banned_ips():
    ip = request.remote_addr
    banned_ips = read_banned_ips()
    if ip in banned_ips:
        return "Akses ditolak. IP Anda telah diblokir.", 403

@app.route('/')
def index():
    if 'user_email' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].lower()
        password = request.form['password']
        recaptcha_response = request.form['g-recaptcha-response']

        recaptcha_url = 'https://www.google.com/recaptcha/api/siteverify'
        payload = {
            'secret': RECAPTCHA_SECRET_KEY,
            'response': recaptcha_response
        }
        recaptcha_result = requests.post(recaptcha_url, data=payload).json()
        if not recaptcha_result.get('success'):
            return render_template('login.html', error='Verifikasi CAPTCHA gagal.')

        db = read_db()
        for user in db['users']:
            if user['email'].lower() == email and check_password_hash(user['password'], password):
                session['user_email'] = email
                return redirect(url_for('dashboard'))
        return render_template('login.html', error='Email atau password salah')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email'].lower()
        password = request.form['password']
        recaptcha_response = request.form['g-recaptcha-response']

        recaptcha_url = 'https://www.google.com/recaptcha/api/siteverify'
        payload = {
            'secret': RECAPTCHA_SECRET_KEY,
            'response': recaptcha_response
        }
        recaptcha_result = requests.post(recaptcha_url, data=payload).json()
        if not recaptcha_result.get('success'):
            return render_template('register.html', error='Verifikasi CAPTCHA gagal.')

        db = read_db()
        if any(user['email'].lower() == email for user in db['users']):
            return render_template('register.html', error='Email sudah terdaftar')

        hashed_password = generate_password_hash(password)
        db['users'].append({
            'name': name,
            'email': email,
            'password': hashed_password
        })
        write_db(db)
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user_email' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/redeem', methods=['GET', 'POST'])
def redeem():
    if 'user_email' not in session:
        return redirect(url_for('login'))

    message = ''
    if request.method == 'POST':
        code_input = request.form['code'].strip()
        if not code_input:
            message = 'Kode tidak boleh kosong.'
        else:
            db = read_db()
            for code in db['codes']:
                if code['code'] == code_input:
                    if code['used']:
                        message = 'Kode sudah digunakan.'
                    else:
                        code['used'] = True
                        message = f"Berhasil! Kamu mendapatkan: {code['reward']}"
                        write_db(db)
                    break
            else:
                message = 'Kode tidak valid.'
    return render_template('redeem.html', message=message)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'user_email' not in session or session['user_email'].lower() != 'admin@admin.com':
        return redirect(url_for('login'))

    db = read_db()
    banned_ips = read_banned_ips()
    message = ''

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add_code':
            new_code = request.form['new_code'].strip()
            reward = request.form['reward'].strip()
            if not new_code or not reward:
                message = 'Kode dan reward tidak boleh kosong.'
            elif any(c['code'] == new_code for c in db['codes']):
                message = 'Kode sudah ada.'
            else:
                db['codes'].append({
                    'code': new_code,
                    'reward': reward,
                    'used': False
                })
                write_db(db)
                message = 'Kode berhasil ditambahkan.'
        elif action == 'ban_ip':
            ip_to_ban = request.form['ip'].strip()
            if ip_to_ban and ip_to_ban not in banned_ips:
                banned_ips.append(ip_to_ban)
                write_banned_ips(banned_ips)
                message = f'IP {ip_to_ban} berhasil diblokir.'
        elif action == 'unban_ip':
            ip_to_unban = request.form['ip'].strip()
            if ip_to_unban in banned_ips:
                banned_ips.remove(ip_to_unban)
                write_banned_ips(banned_ips)
                message = f'IP {ip_to_unban} berhasil di-unban.'

    return render_template('admin.html', codes=db['codes'], message=message, banned_ips=banned_ips)

@app.route('/ban_ip', methods=['POST'])
def ban_ip():
    if 'user_email' not in session or session['user_email'].lower() != 'admin@admin.com':
        return redirect(url_for('login'))

    ip_to_ban = request.form['ip'].strip()
    banned_ips = read_banned_ips()

    if ip_to_ban and ip_to_ban not in banned_ips:
        banned_ips.append(ip_to_ban)
        write_banned_ips(banned_ips)
        return jsonify({"status": "success", "message": f"IP {ip_to_ban} berhasil diblokir."}), 200
    else:
        return jsonify({"status": "error", "message": "IP sudah terdaftar atau tidak valid."}), 400

@app.route('/unban_ip', methods=['POST'])
def unban_ip():
    if 'user_email' not in session or session['user_email'].lower() != 'admin@admin.com':
        return redirect(url_for('login'))

    ip_to_unban = request.form['ip'].strip()
    banned_ips = read_banned_ips()

    if ip_to_unban in banned_ips:
        banned_ips.remove(ip_to_unban)
        write_banned_ips(banned_ips)
        return jsonify({"status": "success", "message": f"IP {ip_to_unban} berhasil di-unban."}), 200
    else:
        return jsonify({"status": "error", "message": "IP tidak ditemukan dalam daftar blokir."}), 400

@app.route('/logout')
def logout():
    session.pop('user_email', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    app.run(debug=True, host='0.0.0.0', port=port)