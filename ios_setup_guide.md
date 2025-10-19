# iOS iSH Kurulum Rehberi

## 1. iSH Uygulamasını İndirin
- App Store'dan "iSH" uygulamasını indirin
- Ücretsiz ve açık kaynak

## 2. Dosyaları Telefona Aktarın

### Yöntem A: iCloud Drive
1. Bilgisayarınızda proje klasörünü iCloud Drive'a kopyalayın
2. iPhone'da iCloud Drive'dan dosyaları iSH'a kopyalayın

### Yöntem B: AirDrop
1. Proje klasörünü AirDrop ile iPhone'a gönderin
2. iSH uygulamasında dosyaları açın

### Yöntem C: Email/Cloud
1. Proje klasörünü ZIP'leyin
2. Email veya cloud servise yükleyin
3. iPhone'dan indirin

## 3. iSH'ta Kurulum

```bash
# Paket listesini güncelle
apk update

# Node.js kur
apk add nodejs npm

# Python kur (Flask için)
apk add python3 py3-pip

# Proje klasörüne git
cd /path/to/your/project

# Node.js bağımlılıklarını kur
npm install

# Python bağımlılıklarını kur
pip3 install -r requirements.txt

# Uygulamayı çalıştır
node server.js
# veya
python3 app.py
```

## 4. Erişim
- Localhost: http://localhost:80 (Node.js)
- Localhost: http://localhost:5000 (Flask)

## Notlar
- iSH sınırlı performansa sahip
- Büyük projeler için cloud IDE önerilir
- Terminal komutları tam desteklenir
