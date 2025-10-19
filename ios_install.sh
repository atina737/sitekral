#!/bin/bash
# iOS iSH Kurulum Scripti

echo "🚀 iOS iSH Kurulum Başlıyor..."

# Paket listesini güncelle
echo "📦 Paket listesi güncelleniyor..."
apk update

# Node.js kur
echo "📱 Node.js kuruluyor..."
apk add nodejs npm

# Python kur
echo "🐍 Python kuruluyor..."
apk add python3 py3-pip

# Gerekli Python paketleri
echo "📚 Python paketleri kuruluyor..."
pip3 install flask flask-session werkzeug requests

# Proje dizinini oluştur
echo "📁 Proje dizini oluşturuluyor..."
mkdir -p /root/project
cd /root/project

echo "✅ Kurulum tamamlandı!"
echo "📝 Sonraki adımlar:"
echo "1. Dosyalarınızı bu klasöre kopyalayın"
echo "2. npm install (Node.js projesi için)"
echo "3. node server.js veya python3 app.py"
