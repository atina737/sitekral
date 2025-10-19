#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import hashlib
import secrets
import time
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, abort
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import re
import requests

# Flask uygulaması oluştur
app = Flask(__name__)

# Konfigürasyon
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'atina:'
app.config['SESSION_FILE_DIR'] = './flask_session'
app.config['SESSION_FILE_THRESHOLD'] = 500

# Session'ı başlat
Session(app)

# Veri dosyaları için dizin oluştur
DATA_DIR = Path('data')
DATA_DIR.mkdir(exist_ok=True)

# Online kullanıcı takibi
online_users = {}  # email -> {name, last_active}
recent_logins = {}  # email -> timestamp

# Rate limiting için
rate_limit_store = {}
blocked_ips = {}
suspicious_ips = set()

# Güvenlik log dosyası
SECURITY_LOG_PATH = DATA_DIR / 'security.log'

def log_security_event(event_type, request, details=None):
    """Güvenlik olaylarını logla"""
    timestamp = datetime.now().isoformat()
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    url = request.url
    
    log_entry = {
        'timestamp': timestamp,
        'type': event_type,
        'ip': ip,
        'user_agent': user_agent,
        'url': url,
        'details': details or {}
    }
    
    try:
        with open(SECURITY_LOG_PATH, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
    except Exception as e:
        print(f"Security log yazılamadı: {e}")
    
    print(f"🚨 [{event_type}] {ip} - {url} - {user_agent[:50]}")

def rate_limit(max_requests=1000, window_seconds=900):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = request.remote_addr
            now = time.time()
            window_start = now - window_seconds
            
            # Rate limit store'u temizle
            if ip in rate_limit_store:
                rate_limit_store[ip] = [req_time for req_time in rate_limit_store[ip] if req_time > window_start]
            else:
                rate_limit_store[ip] = []
            
            # Limit kontrolü
            if len(rate_limit_store[ip]) >= max_requests:
                log_security_event('RATE_LIMIT_EXCEEDED', request, {
                    'request_count': len(rate_limit_store[ip]),
                    'max_requests': max_requests
                })
                return jsonify({'ok': False, 'message': 'İstek limitiniz aşıldı. Lütfen bekleyin.'}), 429
            
            # İsteği kaydet
            rate_limit_store[ip].append(now)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def bot_detection(f):
    """Bot tespiti middleware"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_agent = request.headers.get('User-Agent', '')
        ip = request.remote_addr
        
        # Bot pattern'leri
        bot_patterns = [
            r'bot', r'crawler', r'spider', r'scraper', r'curl', r'wget',
            r'python', r'java', r'php', r'perl', r'ruby', r'go-http',
            r'postman', r'insomnia', r'httpie', r'requests', r'scrapy',
            r'selenium', r'phantom', r'headless', r'automation'
        ]
        
        # Scanner pattern'leri
        scanner_patterns = [
            r'sqlmap', r'nikto', r'nmap', r'masscan', r'zap', r'burp',
            r'havij', r'sqlninja', r'pangolin', r'acunetix', r'nessus',
            r'openvas', r'retire\.js', r'snyk', r'veracode', r'checkmarx'
        ]
        
        # Censys.io ve benzeri servisler
        censys_patterns = [
            r'censys\.io', r'search\.censys\.io', r'api\.censys\.io',
            r'shodan\.io', r'api\.shodan\.io', r'shodan\.net',
            r'zoomeye\.org', r'api\.zoomeye\.org',
            r'binaryedge\.io', r'api\.binaryedge\.io',
            r'fofa\.so', r'quake\.360\.cn'
        ]
        
        is_bot = any(re.search(pattern, user_agent, re.IGNORECASE) for pattern in bot_patterns)
        is_scanner = any(re.search(pattern, user_agent, re.IGNORECASE) for pattern in scanner_patterns)
        is_censys = any(re.search(pattern, user_agent, re.IGNORECASE) for pattern in censys_patterns)
        
        # Sadece gerçek tehditleri engelle
        if is_censys or (is_scanner and ('sqlmap' in user_agent or 'nikto' in user_agent)):
            log_security_event('THREAT_DETECTED', request, {
                'user_agent': user_agent,
                'is_censys': is_censys,
                'is_scanner': is_scanner
            })
            
            blocked_ips[ip] = time.time()
            return jsonify({'ok': False, 'message': 'Erişim reddedildi.'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

def xss_protection(f):
    """XSS koruması"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        def check_xss(data):
            if isinstance(data, str):
                xss_patterns = [
                    r'<script[^>]*>.*?</script>',
                    r'javascript:',
                    r'on\w+\s*=',
                    r'<iframe[^>]*>.*?</iframe>',
                    r'<object[^>]*>.*?</object>',
                    r'<embed[^>]*>.*?</embed>',
                    r'<link[^>]*>.*?</link>',
                    r'<meta[^>]*>.*?</meta>'
                ]
                return any(re.search(pattern, data, re.IGNORECASE | re.DOTALL) for pattern in xss_patterns)
            
            if isinstance(data, dict):
                return any(check_xss(value) for value in data.values())
            
            if isinstance(data, list):
                return any(check_xss(item) for item in data)
            
            return False
        
        if check_xss(request.form) or check_xss(request.args) or check_xss(request.json or {}):
            log_security_event('XSS_ATTEMPT', request, {
                'form': dict(request.form),
                'args': dict(request.args),
                'json': request.json
            })
            return jsonify({'ok': False, 'message': 'Güvenlik ihlali tespit edildi.'}), 400
        
        return f(*args, **kwargs)
    return decorated_function

def sql_injection_protection(f):
    """SQL injection koruması"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        sql_patterns = [
            r'union\s+select',
            r'select\s+.*\s+from',
            r'insert\s+into',
            r'update\s+.*\s+set',
            r'delete\s+from',
            r'drop\s+table',
            r'create\s+table',
            r'alter\s+table',
            r'exec\s*\(',
            r'execute\s*\(',
            r'sp_',
            r'xp_',
            r'0x[0-9a-f]+'
        ]
        
        def check_sql(data):
            if isinstance(data, str):
                return any(re.search(pattern, data, re.IGNORECASE) for pattern in sql_patterns)
            
            if isinstance(data, dict):
                return any(check_sql(value) for value in data.values())
            
            if isinstance(data, list):
                return any(check_sql(item) for item in data)
            
            return False
        
        if check_sql(request.form) or check_sql(request.args) or check_sql(request.json or {}):
            log_security_event('SQL_INJECTION_ATTEMPT', request, {
                'form': dict(request.form),
                'args': dict(request.args),
                'json': request.json
            })
            return jsonify({'ok': False, 'message': 'Güvenlik ihlali tespit edildi.'}), 400
        
        return f(*args, **kwargs)
    return decorated_function

def ip_blocking(f):
    """IP engelleme kontrolü"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        
        # Localhost IP'lerini engelleme
        if ip in ['::1', '127.0.0.1', 'localhost']:
            return f(*args, **kwargs)
        
        # Engellenmiş IP kontrolü (5 dakika)
        if ip in blocked_ips:
            block_time = blocked_ips[ip]
            now = time.time()
            
            # 5 dakika sonra engeli kaldır
            if now - block_time > 300:
                del blocked_ips[ip]
            else:
                log_security_event('BLOCKED_IP_ACCESS', request)
                return jsonify({'ok': False, 'message': 'IP adresiniz geçici olarak engellenmiştir. 5 dakika sonra tekrar deneyin.'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

def security_headers(f):
    """Güvenlik header'ları"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = f(*args, **kwargs)
        
        if hasattr(response, 'headers'):
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'SAMEORIGIN'
            response.headers['Server'] = 'Apache/2.4.41 (Ubuntu)'
            response.headers['X-Powered-By'] = 'PHP/7.4.3'
        
        return response
    return decorated_function

def honeypot_protection(f):
    """Honeypot koruması"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        url = request.path
        ip = request.remote_addr
        
        # Localhost IP'lerini engelleme
        if ip in ['::1', '127.0.0.1', 'localhost']:
            return f(*args, **kwargs)
        
        # Şüpheli path'ler
        suspicious_paths = [
            '/admin', '/wp-admin', '/administrator', '/phpmyadmin',
            '/.env', '/config', '/backup', '/.git', '/.svn',
            '/robots.txt', '/sitemap.xml', '/.htaccess',
            '/api/v1', '/api/v2', '/api/v3',
            '/test', '/debug', '/dev', '/staging'
        ]
        
        is_suspicious = any(path in url.lower() for path in suspicious_paths)
        
        if is_suspicious:
            log_security_event('HONEYPOT_TRIGGERED', request, {'url': url})
            blocked_ips[ip] = time.time()
            return jsonify({'ok': False, 'message': 'Sayfa bulunamadı.'}), 404
        
        return f(*args, **kwargs)
    return decorated_function

# Global middleware'ler
@app.before_request
def before_request():
    # CSRF token oluştur
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    
    # Güvenlik middleware'lerini uygula
    if request.endpoint and not request.endpoint.startswith('static'):
        # Rate limiting
        ip = request.remote_addr
        now = time.time()
        window_start = now - 900  # 15 dakika
        
        if ip in rate_limit_store:
            rate_limit_store[ip] = [req_time for req_time in rate_limit_store[ip] if req_time > window_start]
        else:
            rate_limit_store[ip] = []
        
        # Çok hızlı istekleri engelle (20+ istek 5 saniyede)
        recent_requests = [req_time for req_time in rate_limit_store[ip] if now - req_time < 5]
        if len(recent_requests) > 20:
            log_security_event('RAPID_FIRE_DETECTED', request, {
                'recent_requests': len(recent_requests)
            })
            return jsonify({'ok': False, 'message': 'Çok hızlı istek gönderiyorsunuz. Lütfen yavaşlayın.'}), 429
        
        # Bot detection
        user_agent = request.headers.get('User-Agent', '')
        if not user_agent or len(user_agent) < 10:
            suspicious_ips.add(ip)
        
        # Honeypot protection
        url = request.path
        suspicious_paths = ['/admin', '/wp-admin', '/.env', '/config', '/backup']
        if any(path in url.lower() for path in suspicious_paths):
            log_security_event('HONEYPOT_TRIGGERED', request, {'url': url})
            blocked_ips[ip] = time.time()
            return jsonify({'ok': False, 'message': 'Sayfa bulunamadı.'}), 404

# Kullanıcı yönetimi fonksiyonları
def load_users():
    """Kullanıcıları yükle"""
    users_file = DATA_DIR / 'users.json'
    if not users_file.exists():
        return []
    
    try:
        with open(users_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            # Eğer şifrelenmiş veri ise (Node.js'den geliyorsa), boş liste döndür
            if isinstance(data, dict) and 'v' in data and 'alg' in data:
                return []
            # Eğer liste ise, kullanıcı listesi
            elif isinstance(data, list):
                return data
            else:
                return []
    except Exception:
        return []

def save_users(users):
    """Kullanıcıları kaydet"""
    users_file = DATA_DIR / 'users.json'
    try:
        with open(users_file, 'w', encoding='utf-8') as f:
            json.dump(users, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False

def find_user_by_email(email):
    """Email ile kullanıcı bul"""
    users = load_users()
    email_lower = email.lower()
    for user in users:
        if user.get('email', '').lower() == email_lower:
            return user
    return None

def find_user_by_username(username):
    """Kullanıcı adı ile kullanıcı bul"""
    users = load_users()
    username_clean = username.strip()
    for user in users:
        if user.get('name', '').strip() == username_clean:
            return user
    return None

def verify_user(email, password):
    """Kullanıcı doğrula"""
    user = find_user_by_email(email)
    if user and check_password_hash(user.get('password', ''), password):
        return user
    return None

def verify_user_by_username(username, password):
    """Kullanıcı adı ile doğrula"""
    user = find_user_by_username(username)
    if user and check_password_hash(user.get('password', ''), password):
        return user
    return None

# Duyuru yönetimi
def load_duyurular():
    """Duyuruları yükle"""
    duyurular_file = DATA_DIR / 'duyurular.json'
    if not duyurular_file.exists():
        return []
    
    try:
        with open(duyurular_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []

def save_duyurular(duyurular):
    """Duyuruları kaydet"""
    duyurular_file = DATA_DIR / 'duyurular.json'
    try:
        with open(duyurular_file, 'w', encoding='utf-8') as f:
            json.dump(duyurular, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False

# Online kullanıcı yönetimi
def set_user_online(email, name):
    """Kullanıcıyı çevrimiçi olarak işaretle"""
    online_users[email] = {'name': name, 'last_active': time.time()}

def set_user_offline(email):
    """Kullanıcıyı çevrimdışı olarak işaretle"""
    online_users.pop(email, None)

def get_online_users():
    """Çevrimiçi kullanıcıları al"""
    now = time.time()
    return [
        {'email': email, 'name': data['name']}
        for email, data in online_users.items()
        if now - data['last_active'] < 600  # 10 dakika
    ]

def push_recent_login(email):
    """Son girişi kaydet"""
    recent_logins[email] = datetime.now().isoformat()

def load_security_logs():
    """Güvenlik loglarını yükle"""
    try:
        with open('data/security.log', 'r', encoding='utf-8') as f:
            lines = f.readlines()
            logs = []
            for line in lines[-100:]:  # Son 100 log
                try:
                    log_data = json.loads(line.strip())
                    logs.append(log_data)
                except:
                    continue
            return logs[::-1]  # En yeni önce
    except:
        return []

# Decorator'lar
def require_auth(f):
    """Kimlik doğrulama gerektiren sayfalar için decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    """Admin yetkisi gerektiren sayfalar için decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('user_role') != 'admin':
            return jsonify({'ok': False, 'message': 'Bu işlem için admin yetkisi gereklidir.'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Yardımcı fonksiyonlar
def time_ago(timestamp):
    """Zaman farkını hesapla"""
    try:
        if isinstance(timestamp, str):
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        else:
            dt = timestamp
        
        now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
        diff = now - dt
        
        if diff.days > 0:
            return f"{diff.days} gün önce"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} saat önce"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} dakika önce"
        else:
            return "Az önce"
    except Exception:
        return "Bilinmiyor"

def is_admin(user):
    """Kullanıcının admin olup olmadığını kontrol et"""
    return user and user.get('role') == 'admin'

# Route'lar
@app.route('/')
def index():
    """Ana sayfa - login'e yönlendir"""
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@rate_limit(max_requests=100, window_seconds=900)
@bot_detection
@ip_blocking
@security_headers
@honeypot_protection
def login():
    """Giriş sayfası"""
    if request.method == 'POST':
        # JSON veya form data kontrolü
        if request.is_json:
            data = request.get_json()
            username = data.get('username', '').strip()
            password = data.get('password', '')
        else:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
        
        # XSS ve SQL injection kontrolü (POST istekleri için)
        def check_xss(data):
            if isinstance(data, str):
                xss_patterns = [
                    r'<script[^>]*>.*?</script>',
                    r'javascript:',
                    r'on\w+\s*=',
                    r'<iframe[^>]*>.*?</iframe>',
                    r'<object[^>]*>.*?</object>',
                    r'<embed[^>]*>.*?</embed>',
                    r'<link[^>]*>.*?</link>',
                    r'<meta[^>]*>.*?</meta>'
                ]
                return any(re.search(pattern, data, re.IGNORECASE | re.DOTALL) for pattern in xss_patterns)
            return False
        
        def check_sql(data):
            if isinstance(data, str):
                sql_patterns = [
                    r'union\s+select',
                    r'select\s+.*\s+from',
                    r'insert\s+into',
                    r'update\s+.*\s+set',
                    r'delete\s+from',
                    r'drop\s+table',
                    r'create\s+table',
                    r'alter\s+table',
                    r'exec\s*\(',
                    r'execute\s*\(',
                    r'sp_',
                    r'xp_',
                    r'0x[0-9a-f]+'
                ]
                return any(re.search(pattern, data, re.IGNORECASE) for pattern in sql_patterns)
            return False
        
        if check_xss(username) or check_xss(password) or check_sql(username) or check_sql(password):
            log_security_event('SECURITY_VIOLATION', request, {'username': username})
            return jsonify({'ok': False, 'message': 'Güvenlik ihlali tespit edildi.'})
        
        # Honeypot kontrolü
        if request.form.get('honeypot') or request.form.get('website') or request.form.get('url'):
            log_security_event('HONEYPOT_TRIGGERED', request)
            return jsonify({'ok': False, 'message': 'Erişim reddedildi.'})
        
        if not username or not password:
            return jsonify({'ok': False, 'message': 'Lütfen kullanıcı adı ve şifre giriniz.'})
        
        # Kullanıcı doğrula
        user = verify_user_by_username(username, password)
        if not user:
            log_security_event('LOGIN_FAILED', request, {'username': username})
            return jsonify({'ok': False, 'message': 'Kullanıcı adı veya şifre hatalı.'})
        
        # Session oluştur
        session['user_id'] = user['email']
        session['user_name'] = user['name']
        session['user_role'] = user.get('role', 'user')
        
        # Online kullanıcı olarak işaretle
        set_user_online(user['email'], user['name'])
        push_recent_login(user['email'])
        
        log_security_event('LOGIN_SUCCESS', request, {'username': username})
        
        return jsonify({
            'ok': True,
            'message': 'Giriş başarılı. Yönlendiriliyorsunuz...',
            'redirect': url_for('dashboard')
        })
    
    return render_template('auth/login.html', csrf=session.get('csrf_token', ''))

@app.route('/dashboard')
@security_headers
def dashboard():
    """Dashboard sayfası"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_email = session['user_id']
    user_name = session['user_name']
    user_role = session.get('user_role', 'user')
    
    # Kullanıcıyı çevrimiçi olarak işaretle
    set_user_online(user_email, user_name)
    
    # Verileri hazırla
    users = load_users()
    duyurular = load_duyurular()
    online_users_list = get_online_users()
    
    # Son giriş yapanları al
    recent_logins_list = []
    for email, timestamp in recent_logins.items():
        user = find_user_by_email(email)
        if user:
            recent_logins_list.append({
                'name': user['name'],
                'email': email,
                'lastLoginAt': timestamp
            })
    
    # En son 10 girişi al
    recent_logins_list = sorted(recent_logins_list, key=lambda x: x['lastLoginAt'], reverse=True)[:10]
    
    # Üyelik bilgileri
    user = find_user_by_email(user_email)
    membership_text = "Ücretsiz"
    membership_expires_at = None
    
    if user:
        if user.get('role') == 'admin':
            membership_text = "Admin"
        elif user.get('membership_expires'):
            try:
                expires = datetime.fromisoformat(user['membership_expires'])
                if expires > datetime.now():
                    membership_text = "Premium"
                    membership_expires_at = user['membership_expires']
                else:
                    membership_text = "Süresi Dolmuş"
            except:
                membership_text = "Ücretsiz"
    
    # Günlük sorgu hakkı
    daily_credits = get_daily_query_credits(user_email)
    
    return render_template('dashboard.html',
                         name=user_name,
                         totalUsers=len(users),
                         roleName=user_role.title(),
                         onlineCount=len(online_users_list),
                         onlineUsers=online_users_list,
                         membershipText=membership_text,
                         membershipExpiresAt=membership_expires_at,
                         duyurular=duyurular,
                         recentLogins=recent_logins_list,
                         dailyCredits=daily_credits,
                         timeAgo=time_ago,
                         isAdmin=is_admin(user))

@app.route('/logout', methods=['POST'])
def logout():
    """Çıkış yap"""
    if 'user_id' in session:
        user_email = session['user_id']
        set_user_offline(user_email)
        session.clear()
    
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@rate_limit(max_requests=50, window_seconds=900)
@bot_detection
@ip_blocking
@security_headers
@honeypot_protection
def register():
    """Kayıt sayfası"""
    if request.method == 'POST':
        # JSON veya form data kontrolü
        if request.is_json:
            data = request.get_json()
            name = data.get('name', '').strip()
            email = data.get('email', '').strip().lower()
            password = data.get('password', '')
            confirm_password = data.get('confirm_password', '')
        else:
            name = request.form.get('name', '').strip()
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')
        
        # Honeypot kontrolü
        if request.form.get('honeypot') or request.form.get('website') or request.form.get('url'):
            log_security_event('HONEYPOT_TRIGGERED', request)
            return jsonify({'ok': False, 'message': 'Erişim reddedildi.'})
        
        # Validasyon
        if not name or not email or not password:
            return jsonify({'ok': False, 'message': 'Lütfen tüm alanları doldurunuz.'})
        
        if password != confirm_password:
            return jsonify({'ok': False, 'message': 'Şifreler eşleşmiyor.'})
        
        if len(password) < 6:
            return jsonify({'ok': False, 'message': 'Şifre en az 6 karakter olmalıdır.'})
        
        # Email format kontrolü
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return jsonify({'ok': False, 'message': 'Geçerli bir email adresi giriniz.'})
        
        # Kullanıcı zaten var mı kontrol et
        if find_user_by_email(email):
            return jsonify({'ok': False, 'message': 'Bu email adresi zaten kullanılıyor.'})
        
        if find_user_by_username(name):
            return jsonify({'ok': False, 'message': 'Bu kullanıcı adı zaten kullanılıyor.'})
        
        # Yeni kullanıcı oluştur
        users = load_users()
        new_user = {
            'name': name,
            'email': email,
            'password': generate_password_hash(password),
            'role': 'user',
            'created_at': datetime.now().isoformat(),
            'last_login': None
        }
        
        users.append(new_user)
        
        if save_users(users):
            log_security_event('REGISTER_SUCCESS', request, {'email': email, 'name': name})
            return jsonify({
                'ok': True,
                'message': 'Kayıt başarılı. Giriş yapabilirsiniz.',
                'redirect': url_for('login')
            })
        else:
            return jsonify({'ok': False, 'message': 'Kayıt sırasında bir hata oluştu.'})
    
    return render_template('auth/register.html', csrf=session.get('csrf_token', ''))

# Sorgular sayfası
@app.route('/sorgular')
@require_auth
def sorgular():
    """Sorgu sistemi sayfası"""
    return render_template('sorgular.html')

# Admin panel sayfaları
@app.route('/kullanicilar')
@require_auth
def admin_kullanicilar():
    """Kullanıcı yönetimi sayfası"""
    if session.get('user_role') != 'admin':
        return redirect(url_for('dashboard'))
    
    users = load_users()
    online_users = get_online_users()
    
    return render_template('kullanicilar.html', users=users, online_users=online_users)

@app.route('/duyurular')
@require_auth
def admin_duyurular():
    """Duyuru yönetimi sayfası"""
    if session.get('user_role') != 'admin':
        return redirect(url_for('dashboard'))
    
    duyurular = load_duyurular()
    return render_template('duyurular.html', duyurular=duyurular)

@app.route('/admin/logs')
@require_auth
def admin_logs():
    """Log yönetimi sayfası"""
    if session.get('user_role') != 'admin':
        return redirect(url_for('dashboard'))
    
    logs = load_security_logs()
    return render_template('logs.html', logs=logs)

@app.route('/admin/security')
@require_auth
def admin_security():
    """Güvenlik yönetimi sayfası"""
    if session.get('user_role') != 'admin':
        return redirect(url_for('dashboard'))
    
    return render_template('security.html')

@app.route('/admin/siteayar')
@require_auth
def admin_siteayar():
    """Site ayarları sayfası"""
    if session.get('user_role') != 'admin':
        return redirect(url_for('dashboard'))
    
    return render_template('siteayar.html')

# Kullanıcı işlemleri API
@app.route('/admin/users/create', methods=['POST'])
@require_auth
def admin_create_user():
    """Yeni kullanıcı oluştur"""
    if session.get('user_role') != 'admin':
        return jsonify({'ok': False, 'message': 'Yetkisiz erişim'})
    
    data = request.get_json()
    name = data.get('name', '').strip()
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    role = data.get('role', 'user')
    
    if not all([name, username, email, password]):
        return jsonify({'ok': False, 'message': 'Tüm alanlar doldurulmalıdır'})
    
    users = load_users()
    
    # Email kontrolü
    if any(user.get('email') == email for user in users):
        return jsonify({'ok': False, 'message': 'Bu e-posta adresi zaten kullanılıyor'})
    
    # Username kontrolü
    if any(user.get('username') == username for user in users):
        return jsonify({'ok': False, 'message': 'Bu kullanıcı adı zaten kullanılıyor'})
    
    new_user = {
        'name': name,
        'username': username,
        'email': email,
        'password': generate_password_hash(password),
        'role': role,
        'createdAt': datetime.now().isoformat(),
        'lastLoginAt': None
    }
    
    users.append(new_user)
    
    if save_users(users):
        return jsonify({'ok': True, 'message': 'Kullanıcı başarıyla oluşturuldu'})
    else:
        return jsonify({'ok': False, 'message': 'Kullanıcı oluşturulurken hata oluştu'})

@app.route('/admin/users/delete', methods=['POST'])
@require_auth
def admin_delete_user():
    """Kullanıcı sil"""
    if session.get('user_role') != 'admin':
        return jsonify({'ok': False, 'message': 'Yetkisiz erişim'})
    
    data = request.get_json()
    email = data.get('email', '').strip()
    
    if not email:
        return jsonify({'ok': False, 'message': 'E-posta adresi gerekli'})
    
    # Admin kendini silemez
    if email == session.get('user_id'):
        return jsonify({'ok': False, 'message': 'Kendinizi silemezsiniz'})
    
    users = load_users()
    users = [user for user in users if user.get('email') != email]
    
    if save_users(users):
        return jsonify({'ok': True, 'message': 'Kullanıcı başarıyla silindi'})
    else:
        return jsonify({'ok': False, 'message': 'Kullanıcı silinirken hata oluştu'})

# Destek sayfaları
@app.route('/support')
@require_auth
def support():
    """Destek sayfası"""
    return render_template('support.html')

@app.route('/admin/support')
@require_auth
def admin_support():
    """Admin destek yönetimi"""
    if session.get('user_role') != 'admin':
        return redirect(url_for('dashboard'))
    
    return render_template('supportadmin.html')

# Market sayfaları
@app.route('/market')
@require_auth
def market():
    """Market sayfası"""
    return render_template('market.html')

@app.route('/marketv2')
@require_auth
def marketv2():
    """Market V2 sayfası"""
    return render_template('marketv2.html')

# Sorgu sayfaları
@app.route('/tcgsm')
@require_auth
def tcgsm():
    """TC → GSM sorgu sayfası"""
    return render_template('tcgsm.html')

@app.route('/tcsorgu')
@require_auth
def tcsorgu():
    """TC sorgu sayfası"""
    return render_template('tcsorgu.html')

@app.route('/adres')
@require_auth
def adres():
    """Adres sorgu sayfası"""
    return render_template('adres.html')

@app.route('/adsoyad')
@require_auth
def adsoyad():
    """Ad Soyad sorgu sayfası"""
    return render_template('adsoyad.html')

@app.route('/ailepro')
@require_auth
def ailepro():
    """Aile Pro sorgu sayfası"""
    return render_template('ailepro.html')

@app.route('/isyeri')
@require_auth
def isyeri():
    """İşyeri sorgu sayfası"""
    return render_template('isyeri.html')

@app.route('/sulale')
@require_auth
def sulale():
    """Sülale sorgu sayfası"""
    return render_template('sulale.html')

@app.route('/tapu')
@require_auth
def tapu():
    """Tapu sorgu sayfası"""
    return render_template('tapu.html')

@app.route('/gsmtc')
@require_auth
def gsmtc():
    """GSM → TC sorgu sayfası"""
    return render_template('gsmtc.html')

# Static dosyalar için route
@app.route('/assets/<path:filename>')
def assets(filename):
    """Static dosyaları serve et"""
    return app.send_static_file(filename)

# Sorgu API Endpoint'leri
@app.route('/api/adsoyad', methods=['POST'])
@require_auth
def api_adsoyad():
    """Ad Soyad sorgusu"""
    try:
        data = request.get_json()
        ad = data.get('ad', '').strip()
        soyad = data.get('soyad', '').strip()
        il = data.get('il', '').strip()
        
        if not ad or not soyad:
            return jsonify({'ok': False, 'message': 'Ad ve soyad zorunlu ya'})
        
        # Kullanıcı sorgu hakkı kontrolü
        user_email = session.get('user_id')
        if not user_email:
            return jsonify({'ok': False, 'message': 'Oturum bulunamadı'})
        
        users = load_users()
        user = next((u for u in users if u.get('email') == user_email), None)
        if not user:
            return jsonify({'ok': False, 'message': 'Kullanıcı bulunamadı'})
        
        # Günlük sorgu hakkı kontrolü
        daily_credits = get_daily_query_credits(user_email)
        if daily_credits <= 0:
            return jsonify({'ok': False, 'message': 'Günlük sorgu limitini aştınız. Yarın tekrar deneyin.'})
        
        # API çağrısı
        response = requests.get(f'https://api.kahin.org/kahinapi/adsoyadpro?ad={ad}&soyad={soyad}&il={il}')
        if response.status_code != 200:
            return jsonify({'ok': False, 'message': 'API hatası'})
        
        api_data = response.json()
        if not api_data.get('success') or not api_data.get('data'):
            return jsonify({'ok': False, 'message': 'Veri bulunamadı işte'})
        
        # Günlük sorgu hakkını kullan
        if not use_daily_query_credit(user_email):
            return jsonify({'ok': False, 'message': 'Sorgu hakkı kullanılamadı.'})
        
        # Sorgu logunu kaydet
        log_query(user_email, 'adsoyad', {'ad': ad, 'soyad': soyad, 'il': il})
        
        return jsonify({
            'ok': True,
            'data': api_data['data'],
            'message': 'Sorgu başarılı'
        })
        
    except Exception as e:
        return jsonify({'ok': False, 'message': f'Sorgu hatası: {str(e)}'})

@app.route('/api/tcpro', methods=['POST'])
@require_auth
def api_tcpro():
    """TC Pro sorgusu"""
    try:
        data = request.get_json()
        tc = data.get('tc', '').strip()
        
        if not tc or len(tc) != 11:
            return jsonify({'ok': False, 'message': 'Geçerli bir TC kimlik numarası giriniz'})
        
        # Kullanıcı sorgu hakkı kontrolü
        user_email = session.get('user_id')
        if not user_email:
            return jsonify({'ok': False, 'message': 'Oturum bulunamadı'})
        
        users = load_users()
        user = next((u for u in users if u.get('email') == user_email), None)
        if not user:
            return jsonify({'ok': False, 'message': 'Kullanıcı bulunamadı'})
        
        # Günlük sorgu hakkı kontrolü
        daily_credits = get_daily_query_credits(user_email)
        if daily_credits <= 0:
            return jsonify({'ok': False, 'message': 'Günlük sorgu limitini aştınız. Yarın tekrar deneyin.'})
        
        # API çağrısı
        response = requests.get(f'https://api.kahin.org/kahinapi/tcpro?tc={tc}')
        if response.status_code != 200:
            return jsonify({'ok': False, 'message': 'API hatası'})
        
        api_data = response.json()
        if not api_data.get('success') or not api_data.get('data'):
            return jsonify({'ok': False, 'message': 'Veri bulunamadı işte'})
        
        # Günlük sorgu hakkını kullan
        if not use_daily_query_credit(user_email):
            return jsonify({'ok': False, 'message': 'Sorgu hakkı kullanılamadı.'})
        
        # Sorgu logunu kaydet
        log_query(user_email, 'tcpro', {'tc': tc})
        
        return jsonify({
            'ok': True,
            'data': api_data['data'],
            'message': 'Sorgu başarılı'
        })
        
    except Exception as e:
        return jsonify({'ok': False, 'message': f'Sorgu hatası: {str(e)}'})

@app.route('/api/tcgsm', methods=['POST'])
@require_auth
def api_tcgsm():
    """TC GSM sorgusu"""
    try:
        data = request.get_json()
        tc = data.get('tc', '').strip()
        
        if not tc or len(tc) != 11:
            return jsonify({'ok': False, 'message': 'Geçerli bir TC kimlik numarası giriniz'})
        
        # Kullanıcı sorgu hakkı kontrolü
        user_email = session.get('user_id')
        if not user_email:
            return jsonify({'ok': False, 'message': 'Oturum bulunamadı'})
        
        users = load_users()
        user = next((u for u in users if u.get('email') == user_email), None)
        if not user:
            return jsonify({'ok': False, 'message': 'Kullanıcı bulunamadı'})
        
        # Günlük sorgu hakkı kontrolü
        daily_credits = get_daily_query_credits(user_email)
        if daily_credits <= 0:
            return jsonify({'ok': False, 'message': 'Günlük sorgu limitini aştınız. Yarın tekrar deneyin.'})
        
        # API çağrısı
        response = requests.get(f'https://api.kahin.org/kahinapi/tcgsm?tc={tc}')
        if response.status_code != 200:
            return jsonify({'ok': False, 'message': 'API hatası'})
        
        api_data = response.json()
        if not api_data.get('success') or not api_data.get('data'):
            return jsonify({'ok': False, 'message': 'Veri bulunamadı işte'})
        
        # Günlük sorgu hakkını kullan
        if not use_daily_query_credit(user_email):
            return jsonify({'ok': False, 'message': 'Sorgu hakkı kullanılamadı.'})
        
        # Sorgu logunu kaydet
        log_query(user_email, 'tcgsm', {'tc': tc})
        
        return jsonify({
            'ok': True,
            'data': api_data['data'],
            'message': 'Sorgu başarılı'
        })
        
    except Exception as e:
        return jsonify({'ok': False, 'message': f'Sorgu hatası: {str(e)}'})

@app.route('/api/gsmtc', methods=['POST'])
@require_auth
def api_gsmtc():
    """GSM TC sorgusu"""
    try:
        data = request.get_json()
        gsm = data.get('gsm', '').strip()
        
        if not gsm or len(gsm) != 10:
            return jsonify({'ok': False, 'message': 'Geçerli bir GSM numarası giriniz'})
        
        # Kullanıcı sorgu hakkı kontrolü
        user_email = session.get('user_id')
        if not user_email:
            return jsonify({'ok': False, 'message': 'Oturum bulunamadı'})
        
        users = load_users()
        user = next((u for u in users if u.get('email') == user_email), None)
        if not user:
            return jsonify({'ok': False, 'message': 'Kullanıcı bulunamadı'})
        
        # Günlük sorgu hakkı kontrolü
        daily_credits = get_daily_query_credits(user_email)
        if daily_credits <= 0:
            return jsonify({'ok': False, 'message': 'Günlük sorgu limitini aştınız. Yarın tekrar deneyin.'})
        
        # API çağrısı
        response = requests.get(f'https://api.kahin.org/kahinapi/gsmtc?gsm={gsm}')
        if response.status_code != 200:
            return jsonify({'ok': False, 'message': 'API hatası'})
        
        api_data = response.json()
        if not api_data.get('success') or not api_data.get('data'):
            return jsonify({'ok': False, 'message': 'Veri bulunamadı işte'})
        
        # Günlük sorgu hakkını kullan
        if not use_daily_query_credit(user_email):
            return jsonify({'ok': False, 'message': 'Sorgu hakkı kullanılamadı.'})
        
        # Sorgu logunu kaydet
        log_query(user_email, 'gsmtc', {'gsm': gsm})
        
        return jsonify({
            'ok': True,
            'data': api_data['data'],
            'message': 'Sorgu başarılı'
        })
        
    except Exception as e:
        return jsonify({'ok': False, 'message': f'Sorgu hatası: {str(e)}'})

@app.route('/api/adres', methods=['POST'])
@require_auth
def api_adres():
    """Adres sorgusu"""
    try:
        data = request.get_json()
        tc = data.get('tc', '').strip()
        
        if not tc or len(tc) != 11:
            return jsonify({'ok': False, 'message': 'Geçerli bir TC kimlik numarası giriniz'})
        
        # Kullanıcı sorgu hakkı kontrolü
        user_email = session.get('user_id')
        if not user_email:
            return jsonify({'ok': False, 'message': 'Oturum bulunamadı'})
        
        users = load_users()
        user = next((u for u in users if u.get('email') == user_email), None)
        if not user:
            return jsonify({'ok': False, 'message': 'Kullanıcı bulunamadı'})
        
        # Günlük sorgu hakkı kontrolü
        daily_credits = get_daily_query_credits(user_email)
        if daily_credits <= 0:
            return jsonify({'ok': False, 'message': 'Günlük sorgu limitini aştınız. Yarın tekrar deneyin.'})
        
        # API çağrısı
        response = requests.get(f'https://api.kahin.org/kahinapi/adres?tc={tc}')
        if response.status_code != 200:
            return jsonify({'ok': False, 'message': 'API hatası'})
        
        api_data = response.json()
        if not api_data.get('success') or not api_data.get('data'):
            return jsonify({'ok': False, 'message': 'Veri bulunamadı işte'})
        
        # Günlük sorgu hakkını kullan
        if not use_daily_query_credit(user_email):
            return jsonify({'ok': False, 'message': 'Sorgu hakkı kullanılamadı.'})
        
        # Sorgu logunu kaydet
        log_query(user_email, 'adres', {'tc': tc})
        
        return jsonify({
            'ok': True,
            'data': api_data['data'],
            'message': 'Sorgu başarılı'
        })
        
    except Exception as e:
        return jsonify({'ok': False, 'message': f'Sorgu hatası: {str(e)}'})

@app.route('/api/ailepro', methods=['POST'])
@require_auth
def api_ailepro():
    """Aile Pro sorgusu"""
    try:
        data = request.get_json()
        tc = data.get('tc', '').strip()
        
        if not tc or len(tc) != 11:
            return jsonify({'ok': False, 'message': 'Geçerli bir TC kimlik numarası giriniz'})
        
        # Kullanıcı sorgu hakkı kontrolü
        user_email = session.get('user_id')
        if not user_email:
            return jsonify({'ok': False, 'message': 'Oturum bulunamadı'})
        
        users = load_users()
        user = next((u for u in users if u.get('email') == user_email), None)
        if not user:
            return jsonify({'ok': False, 'message': 'Kullanıcı bulunamadı'})
        
        # Günlük sorgu hakkı kontrolü
        daily_credits = get_daily_query_credits(user_email)
        if daily_credits <= 0:
            return jsonify({'ok': False, 'message': 'Günlük sorgu limitini aştınız. Yarın tekrar deneyin.'})
        
        # API çağrısı
        response = requests.get(f'https://api.kahin.org/kahinapi/ailepro?tc={tc}')
        if response.status_code != 200:
            return jsonify({'ok': False, 'message': 'API hatası'})
        
        api_data = response.json()
        if not api_data.get('success') or not api_data.get('data'):
            return jsonify({'ok': False, 'message': 'Veri bulunamadı işte'})
        
        # Günlük sorgu hakkını kullan
        if not use_daily_query_credit(user_email):
            return jsonify({'ok': False, 'message': 'Sorgu hakkı kullanılamadı.'})
        
        # Sorgu logunu kaydet
        log_query(user_email, 'ailepro', {'tc': tc})
        
        return jsonify({
            'ok': True,
            'data': api_data['data'],
            'message': 'Sorgu başarılı'
        })
        
    except Exception as e:
        return jsonify({'ok': False, 'message': f'Sorgu hatası: {str(e)}'})

@app.route('/api/sulale', methods=['POST'])
@require_auth
def api_sulale():
    """Sülale sorgusu"""
    try:
        data = request.get_json()
        tc = data.get('tc', '').strip()
        
        if not tc or len(tc) != 11:
            return jsonify({'ok': False, 'message': 'Geçerli bir TC kimlik numarası giriniz'})
        
        # Kullanıcı sorgu hakkı kontrolü
        user_email = session.get('user_id')
        if not user_email:
            return jsonify({'ok': False, 'message': 'Oturum bulunamadı'})
        
        users = load_users()
        user = next((u for u in users if u.get('email') == user_email), None)
        if not user:
            return jsonify({'ok': False, 'message': 'Kullanıcı bulunamadı'})
        
        # Günlük sorgu hakkı kontrolü
        daily_credits = get_daily_query_credits(user_email)
        if daily_credits <= 0:
            return jsonify({'ok': False, 'message': 'Günlük sorgu limitini aştınız. Yarın tekrar deneyin.'})
        
        # API çağrısı
        response = requests.get(f'https://api.kahin.org/kahinapi/sulale?tc={tc}')
        if response.status_code != 200:
            return jsonify({'ok': False, 'message': 'API hatası'})
        
        api_data = response.json()
        if not api_data.get('success') or not api_data.get('data'):
            return jsonify({'ok': False, 'message': 'Veri bulunamadı işte'})
        
        # Günlük sorgu hakkını kullan
        if not use_daily_query_credit(user_email):
            return jsonify({'ok': False, 'message': 'Sorgu hakkı kullanılamadı.'})
        
        # Sorgu logunu kaydet
        log_query(user_email, 'sulale', {'tc': tc})
        
        return jsonify({
            'ok': True,
            'data': api_data['data'],
            'message': 'Sorgu başarılı'
        })
        
    except Exception as e:
        return jsonify({'ok': False, 'message': f'Sorgu hatası: {str(e)}'})

@app.route('/api/tapu', methods=['POST'])
@require_auth
def api_tapu():
    """Tapu sorgusu"""
    try:
        data = request.get_json()
        tc = data.get('tc', '').strip()
        
        if not tc or len(tc) != 11:
            return jsonify({'ok': False, 'message': 'Geçerli bir TC kimlik numarası giriniz'})
        
        # Kullanıcı sorgu hakkı kontrolü
        user_email = session.get('user_id')
        if not user_email:
            return jsonify({'ok': False, 'message': 'Oturum bulunamadı'})
        
        users = load_users()
        user = next((u for u in users if u.get('email') == user_email), None)
        if not user:
            return jsonify({'ok': False, 'message': 'Kullanıcı bulunamadı'})
        
        # Günlük sorgu hakkı kontrolü
        daily_credits = get_daily_query_credits(user_email)
        if daily_credits <= 0:
            return jsonify({'ok': False, 'message': 'Günlük sorgu limitini aştınız. Yarın tekrar deneyin.'})
        
        # API çağrısı
        response = requests.get(f'https://api.kahin.org/kahinapi/tapu?tc={tc}')
        if response.status_code != 200:
            return jsonify({'ok': False, 'message': 'API hatası'})
        
        api_data = response.json()
        if not api_data.get('success') or not api_data.get('data'):
            return jsonify({'ok': False, 'message': 'Veri bulunamadı işte'})
        
        # Günlük sorgu hakkını kullan
        if not use_daily_query_credit(user_email):
            return jsonify({'ok': False, 'message': 'Sorgu hakkı kullanılamadı.'})
        
        # Sorgu logunu kaydet
        log_query(user_email, 'tapu', {'tc': tc})
        
        return jsonify({
            'ok': True,
            'data': api_data['data'],
            'message': 'Sorgu başarılı'
        })
        
    except Exception as e:
        return jsonify({'ok': False, 'message': f'Sorgu hatası: {str(e)}'})

@app.route('/api/isyeri', methods=['POST'])
@require_auth
def api_isyeri():
    """İşyeri sorgusu"""
    try:
        data = request.get_json()
        tc = data.get('tc', '').strip()
        
        if not tc or len(tc) != 11:
            return jsonify({'ok': False, 'message': 'Geçerli bir TC kimlik numarası giriniz'})
        
        # Kullanıcı sorgu hakkı kontrolü
        user_email = session.get('user_id')
        if not user_email:
            return jsonify({'ok': False, 'message': 'Oturum bulunamadı'})
        
        users = load_users()
        user = next((u for u in users if u.get('email') == user_email), None)
        if not user:
            return jsonify({'ok': False, 'message': 'Kullanıcı bulunamadı'})
        
        # Günlük sorgu hakkı kontrolü
        daily_credits = get_daily_query_credits(user_email)
        if daily_credits <= 0:
            return jsonify({'ok': False, 'message': 'Günlük sorgu limitini aştınız. Yarın tekrar deneyin.'})
        
        # API çağrısı
        response = requests.get(f'https://api.kahin.org/kahinapi/isyeri?tc={tc}')
        if response.status_code != 200:
            return jsonify({'ok': False, 'message': 'API hatası'})
        
        api_data = response.json()
        if not api_data.get('success') or not api_data.get('data'):
            return jsonify({'ok': False, 'message': 'Veri bulunamadı işte'})
        
        # Günlük sorgu hakkını kullan
        if not use_daily_query_credit(user_email):
            return jsonify({'ok': False, 'message': 'Sorgu hakkı kullanılamadı.'})
        
        # Sorgu logunu kaydet
        log_query(user_email, 'isyeri', {'tc': tc})
        
        return jsonify({
            'ok': True,
            'data': api_data['data'],
            'message': 'Sorgu başarılı'
        })
        
    except Exception as e:
        return jsonify({'ok': False, 'message': f'Sorgu hatası: {str(e)}'})

# Duyuru API Endpoint'leri
@app.route('/api/duyurular', methods=['GET'])
@require_auth
@require_admin
def api_get_duyurular():
    """Duyuruları getir"""
    try:
        duyurular = load_duyurular()
        return jsonify({
            'ok': True,
            'duyurular': duyurular
        })
    except Exception as e:
        return jsonify({'ok': False, 'message': f'Duyurular yüklenemedi: {str(e)}'})

@app.route('/api/duyurular', methods=['POST'])
@require_auth
@require_admin
def api_create_duyuru():
    """Yeni duyuru oluştur"""
    try:
        data = request.get_json()
        title = data.get('title', '').strip()
        text = data.get('text', '').strip()
        type_ = data.get('type', 'Genel')
        icon = data.get('icon', 'ti-bell')
        active = data.get('active', True)
        
        if not title or not text:
            return jsonify({'ok': False, 'message': 'Başlık ve içerik zorunludur'})
        
        duyuru = {
            'id': str(int(time.time() * 1000)),
            'title': title,
            'text': text,
            'type': type_,
            'icon': icon,
            'active': active,
            'admin': session.get('user_name', 'Admin'),
            'createdAt': datetime.now().isoformat(),
            'date': datetime.now().isoformat()
        }
        
        duyurular = load_duyurular()
        duyurular.append(duyuru)
        save_duyurular(duyurular)
        
        return jsonify({
            'ok': True,
            'message': 'Duyuru başarıyla oluşturuldu',
            'duyuru': duyuru
        })
        
    except Exception as e:
        return jsonify({'ok': False, 'message': f'Duyuru oluşturulamadı: {str(e)}'})

@app.route('/api/duyurular/<duyuru_id>', methods=['PUT'])
@require_auth
@require_admin
def api_update_duyuru(duyuru_id):
    """Duyuru güncelle"""
    try:
        data = request.get_json()
        title = data.get('title', '').strip()
        text = data.get('text', '').strip()
        type_ = data.get('type', 'Genel')
        icon = data.get('icon', 'ti-bell')
        active = data.get('active', True)
        
        if not title or not text:
            return jsonify({'ok': False, 'message': 'Başlık ve içerik zorunludur'})
        
        duyurular = load_duyurular()
        duyuru_index = next((i for i, d in enumerate(duyurular) if d.get('id') == duyuru_id), None)
        
        if duyuru_index is None:
            return jsonify({'ok': False, 'message': 'Duyuru bulunamadı'})
        
        duyurular[duyuru_index].update({
            'title': title,
            'text': text,
            'type': type_,
            'icon': icon,
            'active': active,
            'updatedAt': datetime.now().isoformat()
        })
        
        save_duyurular(duyurular)
        
        return jsonify({
            'ok': True,
            'message': 'Duyuru başarıyla güncellendi',
            'duyuru': duyurular[duyuru_index]
        })
        
    except Exception as e:
        return jsonify({'ok': False, 'message': f'Duyuru güncellenemedi: {str(e)}'})

@app.route('/api/duyurular/<duyuru_id>', methods=['DELETE'])
@require_auth
@require_admin
def api_delete_duyuru(duyuru_id):
    """Duyuru sil"""
    try:
        duyurular = load_duyurular()
        duyuru_index = next((i for i, d in enumerate(duyurular) if d.get('id') == duyuru_id), None)
        
        if duyuru_index is None:
            return jsonify({'ok': False, 'message': 'Duyuru bulunamadı'})
        
        deleted_duyuru = duyurular.pop(duyuru_index)
        save_duyurular(duyurular)
        
        return jsonify({
            'ok': True,
            'message': 'Duyuru başarıyla silindi',
            'duyuru': deleted_duyuru
        })
        
    except Exception as e:
        return jsonify({'ok': False, 'message': f'Duyuru silinemedi: {str(e)}'})

# Günlük sorgu hakkı sistemi
def get_daily_query_credits(user_email):
    """Kullanıcının günlük sorgu hakkını hesapla"""
    try:
        users = load_users()
        user = next((u for u in users if u.get('email') == user_email), None)
        if not user:
            return 0
        
        # Admin'e sınırsız sorgu hakkı
        if user.get('role') == 'admin':
            return 999999
        
        # Rol bazlı günlük sorgu hakkı
        role = user.get('role', 'user')
        daily_credits = {
            'admin': 999999,
            'vip': 100,
            'normal': 50,
            'free': 10,
            'user': 10
        }
        
        base_daily_credits = daily_credits.get(role, 10)
        
        # Son sorgu tarihini kontrol et
        last_query_date = user.get('last_query_date', '')
        today = datetime.now().strftime('%Y-%m-%d')
        
        # Eğer bugün daha önce sorgu yapmamışsa, günlük hakkı ver
        if last_query_date != today:
            user['daily_query_credits'] = base_daily_credits
            user['last_query_date'] = today
            
            # Kullanıcıyı güncelle
            for i, u in enumerate(users):
                if u.get('email') == user_email:
                    users[i] = user
                    break
            save_users(users)
        
        return user.get('daily_query_credits', base_daily_credits)
        
    except Exception as e:
        print(f"Günlük sorgu hakkı hesaplama hatası: {e}")
        return 0

def use_daily_query_credit(user_email):
    """Günlük sorgu hakkını kullan"""
    try:
        users = load_users()
        user = next((u for u in users if u.get('email') == user_email), None)
        if not user:
            return False
        
        # Admin'e sınırsız sorgu hakkı
        if user.get('role') == 'admin':
            return True
        
        current_credits = user.get('daily_query_credits', 0)
        if current_credits <= 0:
            return False
        
        # Sorgu hakkını azalt
        user['daily_query_credits'] = max(0, current_credits - 1)
        
        # Kullanıcıyı güncelle
        for i, u in enumerate(users):
            if u.get('email') == user_email:
                users[i] = user
                break
        save_users(users)
        
        return True
        
    except Exception as e:
        print(f"Sorgu hakkı kullanma hatası: {e}")
        return False

# Kullanıcı API Endpoint'leri
@app.route('/api/user/daily-credits', methods=['GET'])
@require_auth
def api_get_daily_credits():
    """Kullanıcının günlük sorgu hakkını getir"""
    try:
        user_email = session.get('user_id')
        if not user_email:
            return jsonify({'ok': False, 'message': 'Oturum bulunamadı'})
        
        daily_credits = get_daily_query_credits(user_email)
        
        return jsonify({
            'ok': True,
            'credits': daily_credits
        })
        
    except Exception as e:
        return jsonify({'ok': False, 'message': f'Hata: {str(e)}'})

# Sorgu logu fonksiyonu
def log_query(user_email, query_type, query_data):
    """Sorgu logunu kaydet"""
    try:
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'user_email': user_email,
            'query_type': query_type,
            'query_data': query_data,
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', '')
        }
        
        logs_file = DATA_DIR / 'query-logs.json'
        logs = []
        
        if logs_file.exists():
            try:
                with open(logs_file, 'r', encoding='utf-8') as f:
                    logs = json.load(f)
            except:
                pass
        
        logs.append(log_entry)
        
        # Son 1000 logu tut
        if len(logs) > 1000:
            logs = logs[-1000:]
        
        with open(logs_file, 'w', encoding='utf-8') as f:
            json.dump(logs, f, ensure_ascii=False, indent=2)
            
    except Exception as e:
        print(f"Log kaydetme hatası: {e}")

if __name__ == '__main__':
    # Flask session dizinini oluştur
    os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)
    
    # Varsayılan admin kullanıcısı oluştur
    users = load_users()
    if not any(user.get('role') == 'admin' for user in users):
        admin_user = {
            'name': 'admin',
            'email': 'admin@atina.com',
            'password': generate_password_hash('admin123'),
            'role': 'admin',
            'created_at': datetime.now().isoformat(),
            'last_login': None,
            'queryCredits': 1000  # Admin'e 1000 sorgu hakkı
        }
        users.append(admin_user)
        save_users(users)
        print("🔑 Varsayılan admin kullanıcısı oluşturuldu:")
        print("   Email: admin@atina.com")
        print("   Şifre: admin123")
    
    # Uygulamayı başlat
    app.run(host='0.0.0.0', port=5000, debug=True)
