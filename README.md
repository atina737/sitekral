# Atina - Python Flask Versiyonu

Bu proje, orijinal Node.js/Express tabanlı Atina sitesinin Python Flask ile yeniden yazılmış versiyonudur.

## 🚀 Kurulum ve Çalıştırma

### 1. Gerekli Paketleri Yükleyin
```bash
pip install -r requirements.txt
```

### 2. Uygulamayı Çalıştırın
```bash
python app.py
```

### 3. Tarayıcıda Açın
```
http://localhost:5000
```

## 🔑 Varsayılan Admin Hesabı

Uygulama ilk çalıştırıldığında otomatik olarak bir admin hesabı oluşturulur:

- **Email:** admin@atina.com
- **Şifre:** admin123

## 📁 Proje Yapısı

```
├── app.py                 # Ana Flask uygulaması
├── requirements.txt       # Python bağımlılıkları
├── data/                 # JSON veri dosyaları
│   ├── users.json        # Kullanıcı verileri
│   ├── duyurular.json    # Duyuru verileri
│   └── security.log      # Güvenlik logları
├── templates/            # Jinja2 template dosyaları
│   ├── base.html         # Ana template
│   ├── dashboard.html    # Dashboard sayfası
│   ├── auth/             # Kimlik doğrulama sayfaları
│   │   ├── login.html
│   │   └── register.html
│   └── includes/         # Ortak template parçaları
│       ├── sidebar.html
│       ├── topbar.html
│       └── footer.html
└── static/               # Statik dosyalar
    └── assets/
        ├── css/
        ├── js/
        └── images/
```

## 🔒 Güvenlik Özellikleri

- **Rate Limiting:** IP bazlı istek sınırlaması
- **Bot Detection:** Otomatik bot tespiti
- **XSS Protection:** Cross-site scripting koruması
- **SQL Injection Protection:** SQL injection koruması
- **IP Blocking:** Şüpheli IP engelleme
- **Honeypot Protection:** Tuzak sayfalar
- **CSRF Protection:** Cross-site request forgery koruması

## 🎨 Özellikler

- **Responsive Design:** Mobil uyumlu tasarım
- **Dark/Light Theme:** Tema değiştirme
- **User Management:** Kullanıcı yönetimi
- **Admin Panel:** Yönetici paneli
- **Announcements:** Duyuru sistemi
- **Online Users:** Çevrimiçi kullanıcı takibi
- **Security Logging:** Güvenlik logları

## 🔧 Konfigürasyon

Uygulama aşağıdaki environment variable'ları destekler:

- `SECRET_KEY`: Flask secret key (varsayılan: otomatik oluşturulur)
- `PORT`: Çalışma portu (varsayılan: 5000)
- `SESSION_SECRET`: Session secret key

## 📝 API Endpoints

### Kimlik Doğrulama
- `GET /login` - Giriş sayfası
- `POST /login` - Giriş işlemi
- `GET /register` - Kayıt sayfası
- `POST /register` - Kayıt işlemi
- `POST /logout` - Çıkış işlemi

### Ana Sayfalar
- `GET /` - Ana sayfa (login'e yönlendirir)
- `GET /dashboard` - Dashboard sayfası

## 🐛 Hata Ayıklama

Eğer uygulama çalışmıyorsa:

1. Python 3.7+ yüklü olduğundan emin olun
2. Gerekli paketlerin yüklü olduğunu kontrol edin
3. Port 5000'in kullanımda olmadığını kontrol edin
4. `data/` klasörünün yazma izinlerine sahip olduğunu kontrol edin

## 📄 Lisans

Bu proje orijinal Node.js versiyonunun Python Flask ile yeniden yazılmış halidir.
