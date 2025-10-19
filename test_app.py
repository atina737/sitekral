#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os

# Mevcut dizini Python path'e ekle
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from app import app
    print("✅ Flask uygulaması başarıyla yüklendi!")
    print("📁 Mevcut dizin:", os.getcwd())
    print("🔧 Flask app objesi:", app)
    print("🌐 Uygulama çalıştırılabilir durumda!")
    
    # Test route'ları
    with app.test_client() as client:
        print("\n🧪 Route testleri:")
        
        # Ana sayfa testi
        response = client.get('/')
        print(f"   / -> {response.status_code} (beklenen: 302 redirect)")
        
        # Login sayfası testi
        response = client.get('/login')
        print(f"   /login -> {response.status_code} (beklenen: 200)")
        
        # Register sayfası testi
        response = client.get('/register')
        print(f"   /register -> {response.status_code} (beklenen: 200)")
        
        # Dashboard testi (login olmadan)
        response = client.get('/dashboard')
        print(f"   /dashboard -> {response.status_code} (beklenen: 302 redirect)")
        
    print("\n🎉 Tüm testler tamamlandı!")
    print("🚀 Uygulamayı çalıştırmak için: python app.py")
    
except ImportError as e:
    print(f"❌ Import hatası: {e}")
    print("💡 Gerekli paketleri yükleyin: pip install -r requirements.txt")
except Exception as e:
    print(f"❌ Hata: {e}")
    print("🔍 Hata detayları için app.py dosyasını kontrol edin")
