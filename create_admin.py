#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
from pathlib import Path
from werkzeug.security import generate_password_hash

# Veri dizini
DATA_DIR = Path('data')
DATA_DIR.mkdir(exist_ok=True)

def create_admin_user():
    """Admin kullanıcısı oluştur"""
    users_file = DATA_DIR / 'users.json'
    
    # Mevcut kullanıcıları yükle
    users = []
    if users_file.exists():
        try:
            with open(users_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    users = data
        except:
            pass
    
    # Admin kullanıcısı bilgileri
    admin_user = {
        'email': 'admin@atina.com',
        'username': 'admin',
        'name': 'Admin',
        'password': generate_password_hash('admin123'),
        'role': 'admin',
        'createdAt': '2024-01-01T00:00:00Z',
        'lastLoginAt': None,
        'isActive': True
    }
    
    # Admin kullanıcısı zaten var mı kontrol et
    admin_exists = any(user.get('email') == 'admin@atina.com' for user in users)
    
    if not admin_exists:
        users.append(admin_user)
        
        # Kullanıcıları kaydet
        with open(users_file, 'w', encoding='utf-8') as f:
            json.dump(users, f, ensure_ascii=False, indent=2)
        
        print("✅ Admin kullanıcısı oluşturuldu!")
        print("📧 E-posta: admin@atina.com")
        print("👤 Kullanıcı adı: admin")
        print("🔑 Şifre: admin123")
        print("🔐 Rol: admin")
    else:
        print("⚠️  Admin kullanıcısı zaten mevcut!")
        print("📧 E-posta: admin@atina.com")
        print("👤 Kullanıcı adı: admin")
        print("🔑 Şifre: admin123")

if __name__ == '__main__':
    create_admin_user()
