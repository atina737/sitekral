

const express = require('express');
const axios = require('axios');
const path = require('path');
const { existsSync, statSync, readdirSync } = require('fs');
const session = require('express-session');

const userStore = require('./lib/userStore');
const siteConfig = require('./lib/siteConfig');
const duyuruStore = require('./lib/duyuru');
const pendingStore = require('./lib/pending');
const queryLogStore = require('./lib/queryLogStore');
const supportStore = require('./lib/support');
const security = require('./lib/security');


const crypto = require('crypto');




const app = express();
const PORT = process.env.PORT || 80;

// Basit online kullanıcı takibi ve son girişler
const onlineUsers = new Map(); // email -> { name, lastActive }
const lastLoginByEmailMap = new Map(); // email -> ISOString

function setUserOnline(email, name) {
  onlineUsers.set(email, { name, lastActive: Date.now() });
}
function setUserOffline(email) {
  onlineUsers.delete(email);
}
function getOnlineUsers() {
  // 10 dakika aktif olanları göster
  const now = Date.now();
  return Array.from(onlineUsers.entries())
    .filter(([_, v]) => now - v.lastActive < 10 * 60 * 1000)
    .map(([email, v]) => ({ email, name: v.name }));
}

function pushRecentLogin(email) {
  try { lastLoginByEmailMap.set(email, new Date().toISOString()); } catch (_) {}
}

// Advanced Güvenlik middleware'leri (CSS uyumlu)
app.use(security.securityHeaders);
app.use(security.advancedIPProtection);        // Censys.io ve IP tarama koruması
app.use(security.smartRateLimit(2000, 15 * 60 * 1000)); // Akıllı rate limiting
app.use(security.requestAnalysis);             // Request analizi
app.use(security.smartHoneypot);               // Akıllı honeypot
app.use(security.ipFingerprinting);            // IP fingerprinting
app.use(security.ipBlocking);                  // IP engelleme (geçici)

// parsers
app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: true, limit: '20kb' }));

// session
app.use(
  session({
      secret: process.env.SESSION_SECRET || 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true, sameSite: 'lax' },
  })
);

// csrf token işlemini burda gerçekleştirdim olası saldırıya karşı burdaki csrf tokenini lmak zorunda
app.use((req, res, next) => {
  try {
    if (req.session && !req.session.csrf) {
      req.session.csrf = crypto.randomBytes(32).toString('base64url');
    }
    res.locals.csrf = req.session?.csrf || '';
  } catch (_) {}
  next();
});

// frontend kısmı burası
const assetDirs = ['assets', 'public/assets', 'public', 'xhtml/assets'].map((rel) =>
  path.join(__dirname, rel)
);
for (const dir of assetDirs) {
  if (existsSync(dir)) {
    app.use(
      '/assets',
      express.static(dir, {
        fallthrough: true,
        maxAge: process.env.NODE_ENV === 'production' ? '7d' : 0,
      })
    );
  }
}

// frontend kısmını düzgün alsın diye yapıldı
app.use(
  '/assets/vendor',
  express.static(path.join(__dirname, 'node_modules'), {
    fallthrough: true,
    maxAge: process.env.NODE_ENV === 'production' ? '7d' : 0,
  })
);
app.use(
  '/assets',
  express.static(path.join(__dirname, 'node_modules'), {
    fallthrough: true,
    maxAge: process.env.NODE_ENV === 'production' ? '7d' : 0,
    index: false,
  })
);

// js veya assetsleri düzügn alsın
(function mountAssetSubdirs() {
  const base = assetDirs.find((p) => existsSync(p) && statSync(p).isDirectory());
  if (!base) return;

  try {
    const subs = readdirSync(base, { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => e.name);

    for (const name of subs) {
      const subPath = path.join(base, name);
      app.use(
        `/assets/${name}`,
        express.static(subPath, {
          fallthrough: true,
          maxAge: process.env.NODE_ENV === 'production' ? '7d' : 0,
        })
      );
      app.use(
        `/${name}`,
        express.static(subPath, {
          fallthrough: true,
          maxAge: process.env.NODE_ENV === 'production' ? '7d' : 0,
        })
      );
    }
  } catch (_) {}
})();

// views
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ipadresi duzgun alsın
function getClientIp(req) {
  const xf = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return xf || req.ip || 'unknown';
}

const rateMap = new Map();
const rateKey = (ip, id = '') => `${ip}:${id}`;
function hitExceeded(ip, id, windowMs = 600000, max = 10) {
  const key = rateKey(ip, id);
  let rec = rateMap.get(key) || { c: 0, t: Date.now() };
  if (Date.now() - rec.t > windowMs) rec = { c: 0, t: Date.now() };
  rec.c += 1;
  rateMap.set(key, rec);
  return rec.c > max;
}
const clearHits = (ip, id) => rateMap.delete(rateKey(ip, id));

const isAcceptedContentType = (h) =>
  /^(application\/json|application\/x-www-form-urlencoded|text\/plain)/i.test(String(h || ''));

function isRequestAllowed(req) {
  const token =
    req.headers['x-csrf-token'] || (req.body && req.body._csrf) || (req.query && req.query._csrf);
  return isAcceptedContentType(req.headers['content-type']) &&
    String(token || '') === String(req.session?.csrf || '');
}

// Günlük sorgu hakkı reset fonksiyonu
const resetDailyQueryCredits = (user) => {
  const today = new Date().toDateString();
  
  // Eğer kullanıcı free üye (role 0) ve son reset bugün değilse
  if (user.role === 0 && user.lastResetDate !== today) {
    // Kullanıcının kendi dailyQueryCredits'i varsa onu kullan, yoksa siteConfig'den al
    const { dailyQueryCredits: configDailyCredits } = siteConfig.getPublic();
    user.queryCredits = user.dailyQueryCredits || configDailyCredits || 10;
    user.lastResetDate = today;
    return true; // Reset yapıldı
  }
  return false; // Reset yapılmadı
};

// Global bakiye güncelleme middleware'i
const updateUserSession = (req, res, next) => {
  if (req?.session?.user?.email) {
    const userList = userStore.readUsers();
    const currentUser = userList.find(u => u.email === req.session.user.email);
    
    if (currentUser) {
      // Günlük sorgu hakkı reset kontrolü
      const wasReset = resetDailyQueryCredits(currentUser);
      if (wasReset) {
        // Reset yapıldıysa kullanıcı listesini güncelle
        const userIndex = userList.findIndex(u => u.email === req.session.user.email);
        if (userIndex !== -1) {
          userList[userIndex] = currentUser;
          userStore.writeEncryptedUsers(userList);
        }
      }
      
      // Session'ı güncelle
      req.session.user.balance = currentUser.balance;
      req.session.user.queryCredits = currentUser.queryCredits;
      req.session.user.role = currentUser.role;
      req.session.user.package = currentUser.package;
    }
  }
  next();
};

const requireAuth = (req, res, next) => {
  return req?.session?.user ? next() : res.redirect('/login');
};

const requireRole = (allowedRoles = []) => {
  return (req, res, next) => {
    const userRole = req?.session?.user?.role;
    if (allowedRoles.includes(userRole)) {
      return next();
    }
    return res.status(403).json({ ok: false, message: 'Zeki olduğunu biliyorum fakat ben daha zekiyim xD.' });
  };
};

// Admin atama fonksiyonu
function makeAdmin(email) {
  const users = userStore.readUsers();
  const user = users.find(u => (u.email || '').toLowerCase() === email.toLowerCase());

  if (!user) {
    console.log(`Kullanıcı bulunamadı: ${email}`);
    return;
  }

  user.role = 3; // 3 = admin rolü

  const success = userStore.writeEncryptedUsers(users);
  if (success) {
    console.log(`✅ ${email} kullanıcısı admin yapıldı.`);
  } else {
    console.log('❌ Kullanıcı dosyasına yazılamadı.');
  }
}

// ** Burada çağırabilirsin, sadece 1 kere **

 makeAdmin('atina@gmail.com');  // <-- Bunu açıp çalıştır, admin yapar, sonra kapat!


// routes
app.get('/', (req, res) => {
  if (req?.session?.user) return res.redirect('/dashboard');
  return res.redirect('/login');
});

app.get('/login', (req, res) =>
  res.render('auth/login', { error: null, csrf: req.session?.csrf || '' })
);

app.get('/register', (req, res) =>
  res.render('auth/register', { error: null })
);

app.post('/api/login', security.smartBotDetection, security.bruteForceProtection, (req, res) => {
  try {
    if (!isRequestAllowed(req)) {
      return res.status(403).json({ ok: false, message: 'İnternet bağlantınızı kontrol edin.' });
    }

    const body = req.body || {};
    const username = String(body.username || '').trim();
    const password = String(body.password || '');
    const ip = getClientIp(req);
    
    if (hitExceeded(ip, username, 600000, 10)) {
      return res.status(429).json({ ok: false, message: 'İstekleriniz sınırlandırıldı, lütfen daha sonra tekrar deneyin.' });
    }

    if (!username || password.length < 6 || password.length > 128) {
      return res.status(400).json({ ok: false, message: 'Kullanıcı adı ya da Şifre yanlış ama hangisinin yanlış olduğunu söylemeyeceğim :)' });
    }

    const match = userStore.verifyUserByUsername(username, password);
    if (!match) {
      return res.status(401).json({ ok: false, message: 'Kullanıcı adı ya da Şifre yanlış ama hangisinin yanlış olduğunu söylemeyeceğim :)' });
    }

    clearHits(ip, username);
    pushRecentLogin(match.email);

    // Store user session with balance
    req.session.user = {
      email: match.email,
      name: match.name || null,
      role: match.role || null,
      joinDate: match.joinDate || null,
      balance: match.balance || 0, // Include balance in the session
      membershipExpiresAt: match.membershipExpiresAt || null,
    };
    setUserOnline(match.email, match.name || match.email);

    return res.json({
      ok: true,
      message: 'Giriş başarılı. Yönlendiriliyorsunuz...',
      redirect: '/dashboard',
      user: {
        email: match.email,
        name: match.name || null,
        joinDate: match.joinDate || null,
        balance: match.balance || 0, // Return balance in the response
        membershipExpiresAt: match.membershipExpiresAt || null,
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({
      ok: false,
      message: 'Sunucu taraflı güncelleme bulunmaktadır, daha sonra tekrar deneyin.'
    });
  }
});




app.get('/api/admin/site', requireAuth, requireRole([3]), (req, res) => {
    try {
        res.json({ ok: true, data: siteConfig.getPublic() });
    } catch (_) {
        res.status(500).json({ ok: false, message: 'Site ayarları alınamadı.' });
    }
});
app.put('/api/admin/site', requireAuth, requireRole([3]), (req, res) => {
    try {
        if (!isRequestAllowed(req)) return res.status(403).json({ ok: false, message: 'İnternet bağlantınızı kontrol edin.' });
        const body = req.body || {};
        const siteName = typeof body.siteName === 'string' ? body.siteName.trim() : undefined;
        const defaultMembershipDays = typeof body.defaultMembershipDays !== 'undefined' ? Number(body.defaultMembershipDays) : undefined;
        const registerAutoApprove = typeof body.registerAutoApprove !== 'undefined' ? Boolean(body.registerAutoApprove) : undefined;
        const defaultQueryCredits = typeof body.defaultQueryCredits !== 'undefined' ? Number(body.defaultQueryCredits) : undefined;
        const dailyQueryCredits = typeof body.dailyQueryCredits !== 'undefined' ? Number(body.dailyQueryCredits) : undefined;

        if (typeof siteName !== 'undefined') {
            if (siteName.length < 2 || siteName.length > 50) {
                return res.status(400).json({ ok: false, message: 'Site adı 2-50 karakter olmalı.' });
            }
        }
        if (typeof defaultMembershipDays !== 'undefined') {
            if (!Number.isFinite(defaultMembershipDays) || defaultMembershipDays < 0 || defaultMembershipDays > 3650) {
                return res.status(400).json({ ok: false, message: 'Varsayılan üyelik süresi 0-3650 gün arasında olmalı.' });
            }
        }

        if (typeof defaultQueryCredits !== 'undefined') {
            if (!Number.isFinite(defaultQueryCredits) || defaultQueryCredits < 0 || defaultQueryCredits > 1000) {
                return res.status(400).json({ ok: false, message: 'Varsayılan sorgu hakkı 0-1000 arasında olmalı.' });
            }
        }

        if (typeof dailyQueryCredits !== 'undefined') {
            if (!Number.isFinite(dailyQueryCredits) || dailyQueryCredits < 1 || dailyQueryCredits > 1000) {
                return res.status(400).json({ ok: false, message: 'Günlük sorgu hakkı 1-1000 arasında olmalı.' });
            }
        }

        const ok = siteConfig.update({ siteName,  registerAutoApprove, defaultMembershipDays, defaultQueryCredits, dailyQueryCredits });
        if (!ok) return res.status(500).json({ ok: false, message: 'Site ayarları kaydedilemedi.' });

        res.json({ ok: true, data: siteConfig.getPublic() });
    } catch (_) {
        res.status(500).json({ ok: false, message: 'Site ayarları güncellenemedi.' });
    }
});

app.post('/api/register', security.smartBotDetection, security.bruteForceProtection, (req, res) => {
  try {
    if (!isRequestAllowed(req)) return res.status(403).json({ ok: false, message: 'İnternet bağlantınızı kontrol edin.' });

    const body = req.body || {};
    const name = String(body.name || '').trim();
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    const balance = Number(body.balance) || 0;  // Set default balance to 0
    const ip = getClientIp(req);

    if (hitExceeded(ip, 'reg', 600000, 20)) {
      return res.status(429).json({ ok: false, message: 'İstekleriniz sınırlandırıldı, lütfen daha sonra tekrar deneyin.' });
    }


    // Kayıt onay ayarını JSON'dan çek
    const { registerAutoApprove } = siteConfig.getPublic();

    if (!registerAutoApprove) {
      // Otomatik onay kapalı ise pending'e ekle
      const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
      const pending = { id, name, email, password, ip, createdAt: new Date().toISOString() };
      const ok = pendingStore.add(pending);
      if (!ok) return res.status(500).json({ ok: false, message: 'Kayıt isteği alınamadı, lütfen daha sonra tekrar deneyin.' });
      return res.json({ ok: true, message: 'Kayıt isteğiniz alındı. Yönetici onayı sonrası giriş yapabilirsiniz.' });
    }

    const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
    if (!emailOk || password.length < 8 || password.length > 128 || name.length < 2 || name.length > 64) {
      return res.status(400).json({ ok: false, message: 'Şifreniz 8 haneden uzun olmalıdır.' });
    }

    const list = userStore.readUsers();
    const ipCount = list.filter(u => u && u.ip === ip).length;
    if (ipCount >= 2) {
      return res.status(429).json({ ok: false, message: 'IP adresiniz üzerinden mevcut hesap bulunmaktadır.' });
    }

    

    if (userStore.findUserByEmail(email)) {
      return res.status(409).json({ ok: false, message: 'E-posta adresi sistemde zaten mevcut.' });
    }

    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
    const role = 0; // 0: free, 1: normal, 2: vip, 3: admin
    const joinDate = new Date().toISOString();
    const { defaultMembershipDays } = siteConfig.getPublic();
    const days = Number(defaultMembershipDays) || 30;
    const membershipExpiresAt = days > 0 ? new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString() : null;
    
    // Free üyeler için günlük sorgu hakkı (siteConfig'den al)
    const { dailyQueryCredits: configDailyCredits } = siteConfig.getPublic();
    const dailyQueryCredits = configDailyCredits || 10;
    const lastResetDate = new Date().toDateString(); // Bugünün tarihi

    // Add the new user with balance, configurable üyelik süresi and daily query credits
    list.push({ 
      id, 
      email, 
      password, 
      name, 
      role, 
      ip, 
      balance, 
      joinDate, 
      membershipExpiresAt, 
      dailyQueryCredits,
      lastResetDate,
      queryCredits: dailyQueryCredits // İlk gün için 10 sorgu hakkı
    });

    if (!userStore.writeEncryptedUsers(list)) {
      return res.status(500).json({ ok: false, message: 'Kayıt işlemi tamamlanamadı, lütfen yetkiliye başvurun.' });
    }

    let msg = 'Kayıt başarılı. Hesabınız otomatik olarak onaylandı.';

    return res.json({ ok: true, message: msg, redirect: '/login' });
  } catch (_) {
    return res.status(500).json({ ok: false, message: 'Sunucu taraflı güncelleme bulunmaktadır, daha sonra tekrar deneyin.' });
  }
});


app.get('/api/users/info', (req, res) => {
  try {
    const list = userStore.readUsers();

    const totalUsers = list.length;

    // Eğer oturum sistemi yoksa, sadece genel bilgi dönebiliriz.
    // Ama diyelim ki, oturumdan kullanıcı ID veya email alıyorsun, ona göre ismini dönebiliriz.

    // Örnek: Kullanıcı emaili query ile gelsin:
    const email = String(req.query.email || '').toLowerCase();

    const user = list.find(u => u.email === email);

    if (!user) {
      return res.status(404).json({ ok: false, message: 'Kullanıcı bulunamadı.', totalUsers });
    }

    return res.json({ ok: true, totalUsers, name: user.name, queryCredits: user.queryCredits || 0 });
  } catch (error) {
    return res.status(500).json({ ok: false, message: 'Sunucu hatası' });
  }
});

app.post('/api/logout', (req, res) => {
  if (req.session?.user?.email) setUserOffline(req.session.user.email);
  req.session.destroy(() => res.json({ ok: true,  redirect: '/login' }));
});


function timeAgo(date) {
  const now = new Date();
  const past = new Date(date);
  const diffMs = now - past;

  const seconds = Math.floor(diffMs / 1000);
  if (seconds < 60) return `${seconds} saniye önce`;

  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} dakika önce`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} saat önce`;

  const days = Math.floor(hours / 24);
  return `${days} gün önce`;
}

app.get('/dashboard', requireAuth, (req, res) => {
  const user = req.session.user;

  // Kullanıcıları veritabanından al
  const users = userStore.readUsers().map(u => ({
    ...u,
    joinDate: u.joinDate || u.createdAt || null,
    balance: u.balance || 0  // Kullanıcıların bakiyelerini al
  }));

  // Kullanıcı sayısı
  const totalUsers = users.length;

  // Son giriş yapanlar: lastLoginByEmailMap'e göre sırala ve ilk 3'ü al
  const lastLoginEntries = [];
  try {
    for (const [email, ts] of lastLoginByEmailMap.entries()) {
      const u = users.find(x => (x.email || '').toLowerCase() === String(email).toLowerCase());
      if (u) lastLoginEntries.push({ ...u, lastLoginAt: ts });
    }
  } catch (_) {}
  lastLoginEntries.sort((a, b) => new Date(b.lastLoginAt) - new Date(a.lastLoginAt));
  const recentLogins = lastLoginEntries.slice(0, 3);

  // Kullanıcının rolünü kontrol et
  const role = user && user.role !== undefined ? Number(user.role) : -1;

  // Kullanıcı rolüne göre isim döndür
  const getRoleName = (role) => {
    switch (role) {
      case 0: return 'Free';
      case 1: return 'Normal';
      case 2: return 'VIP';
      case 3: return 'Admin';
      default: return 'Bilinmiyor';
    }
  };

  // Kullanıcı bakiyesi, rol adı ve admin kontrolü
  const balance = user.balance || 0;  // Kullanıcı bakiyesi
  const roleName = getRoleName(role);
  const isAdmin = role === 3;

  // Üyelik süresi bilgisi
  const membershipExpiresAt = user && user.membershipExpiresAt ? user.membershipExpiresAt : null;
  let membershipText = 'Süresiz';
  try {
    if (membershipExpiresAt) {
      const expTs = new Date(membershipExpiresAt).getTime();
      if (!Number.isNaN(expTs)) {
        const diffMs = expTs - Date.now();
        if (diffMs > 0) {
          const daysLeft = Math.ceil(diffMs / (24 * 60 * 60 * 1000));
          membershipText = `${daysLeft} gün kaldı`;
        } else {
          membershipText = 'Süresi doldu';
        }
      }
    }
  } catch (_) {}

  // Get site config from backend (siteConfig.getPublic())
  const siteConfigData = typeof siteConfig !== 'undefined' && siteConfig.getPublic ? siteConfig.getPublic() : {};
  const onlineUserList = getOnlineUsers();
  const duyurular = duyuruStore.readAll();
  res.render('dashboard', { 
    name: user ? user.name : 'Misafir',
    totalUsers,
    role,
    balance,
    roleName,
    lastThreeUsers: [],
    recentLogins,
    timeAgo,
    isAdmin,
    siteName: siteConfigData.siteName || 'Site',
    onlineUsers: onlineUserList,
    onlineCount: onlineUserList.length,
    duyurular,
    membershipExpiresAt,
    membershipText
  });
});

// Support API endpoints
app.get('/api/support/my-tickets', requireAuth, (req, res) => {
  try {
    const userEmail = req.session.user.email;
    const tickets = supportStore.getTicketsByUser(userEmail);
    res.json({ ok: true, tickets });
  } catch (error) {
    console.error('Support tickets API error:', error);
    res.status(500).json({ ok: false, message: 'Talepler yüklenemedi' });
  }
});

app.post('/api/support/create-ticket', requireAuth, (req, res) => {
  try {
    const { subject, message, category, priority } = req.body;
    const user = req.session.user;

    if (!subject || !message) {
      return res.status(400).json({ ok: false, message: 'Konu ve mesaj alanları zorunludur' });
    }

    // Kullanıcının açık talebi var mı kontrol et
    const userTickets = supportStore.getTicketsByUser(user.email);
    const hasOpenTicket = userTickets.some(ticket => ticket.status === 'open' || ticket.status === 'in-progress');
    
    if (hasOpenTicket) {
      return res.status(400).json({ ok: false, message: 'Zaten açık bir talebiniz bulunuyor. Önce mevcut talebinizi kapatın.' });
    }

    const ticketData = {
      subject: subject.trim(),
      message: message.trim(),
      category: category || 'Genel',
      priority: priority || 'Normal',
      status: 'open',
      user: user.name,
      userEmail: user.email
    };

    const newTicket = supportStore.addTicket(ticketData);
    res.json({ ok: true, ticket: newTicket });
  } catch (error) {
    console.error('Create ticket API error:', error);
    res.status(500).json({ ok: false, message: 'Talep oluşturulamadı' });
  }
});

// Admin Support API endpoints
app.get('/api/admin/support/tickets', requireAuth, requireRole([3]), (req, res) => {
  try {
    const tickets = supportStore.getAllTickets();
    res.json({ ok: true, tickets });
  } catch (error) {
    console.error('Admin support tickets API error:', error);
    res.status(500).json({ ok: false, message: 'Talepler yüklenemedi' });
  }
});

app.post('/api/admin/support/ticket/:id/reply', requireAuth, requireRole([3]), (req, res) => {
  try {
    const { id } = req.params;
    const { message } = req.body;
    const user = req.session.user;

    if (!message || !message.trim()) {
      return res.status(400).json({ ok: false, message: 'Cevap mesajı boş olamaz' });
    }

    const replyData = {
      message: message.trim(),
      user: user.name,
      userRole: 'Admin'
    };

    const success = supportStore.addReply(id, replyData);
    if (!success) {
      return res.status(404).json({ ok: false, message: 'Talep bulunamadı' });
    }

    res.json({ ok: true, message: 'Cevap başarıyla eklendi' });
  } catch (error) {
    console.error('Add reply API error:', error);
    res.status(500).json({ ok: false, message: 'Cevap eklenemedi' });
  }
});

app.put('/api/admin/support/ticket/:id/status', requireAuth, requireRole([3]), (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!['open', 'answered', 'in-progress', 'closed'].includes(status)) {
      return res.status(400).json({ ok: false, message: 'Geçersiz durum' });
    }

    const success = supportStore.updateTicket(id, { status });
    if (!success) {
      return res.status(404).json({ ok: false, message: 'Talep bulunamadı' });
    }

    res.json({ ok: true, message: 'Durum güncellendi' });
  } catch (error) {
    console.error('Update ticket status API error:', error);
    res.status(500).json({ ok: false, message: 'Durum güncellenemedi' });
  }
});

app.delete('/api/admin/support/ticket/:id', requireAuth, requireRole([3]), (req, res) => {
  try {
    const { id } = req.params;
    const success = supportStore.deleteTicket(id);
    
    if (!success) {
      return res.status(404).json({ ok: false, message: 'Talep bulunamadı' });
    }

    res.json({ ok: true, message: 'Talep silindi' });
  } catch (error) {
    console.error('Delete ticket API error:', error);
    res.status(500).json({ ok: false, message: 'Talep silinemedi' });
  }
});

app.get('/api/admin/support/stats', requireAuth, requireRole([3]), (req, res) => {
  try {
    const stats = supportStore.getTicketStats();
    res.json({ ok: true, stats });
  } catch (error) {
    console.error('Support stats API error:', error);
    res.status(500).json({ ok: false, message: 'İstatistikler yüklenemedi' });
  }
});

// Market API'leri
app.get('/market', requireAuth, (req, res) => {
  const user = req.session.user;
  if (!user) {
    return res.redirect('/login');
  }

  const userList = userStore.readUsers();
  const currentUser = userList.find(u => u.email === user.email);
  if (!currentUser) {
    return res.redirect('/login');
  }

  const totalUsers = userList.length;
  const role = currentUser.role;
  const balance = currentUser.balance;
  const roleName = role === 3 ? 'Admin' : role === 2 ? 'Moderatör' : 'Kullanıcı';
  const isAdmin = role === 3;

  const siteConfigData = typeof siteConfig !== 'undefined' && siteConfig.getPublic ? siteConfig.getPublic() : {};
  const onlineUserList = getOnlineUsers();
  const duyurular = duyuruStore.readAll();
  res.render('market', { 
    name: user ? user.name : 'Misafir',
    user: user,
    totalUsers,
    role,
    balance,
    roleName,
    lastThreeUsers: [],
    recentLogins: [],
    timeAgo: '',
    isAdmin,
    siteName: siteConfigData.siteName || 'Site',
    onlineUsers: onlineUserList,
    onlineCount: onlineUserList.length,
    duyurular,
    membershipExpiresAt: currentUser.membershipExpiresAt,
    membershipText: currentUser.membershipExpiresAt ? 
      (new Date(currentUser.membershipExpiresAt) > new Date() ? 
        `Üyelik: ${new Date(currentUser.membershipExpiresAt).toLocaleDateString('tr-TR')}` : 
        'Üyelik süresi dolmuş') : 
      'Üyelik bilgisi yok'
  });
});

app.post('/api/market/purchase-credits', requireAuth, (req, res) => {
  try {
    const { amount, total } = req.body;
    const user = req.session.user;

    if (!amount || !total || amount < 1 || amount > 1000) {
      return res.status(400).json({ ok: false, message: 'Geçersiz sorgu miktarı' });
    }

    const userList = userStore.readUsers();
    const currentUser = userList.find(u => u.email === user.email);
    if (!currentUser) {
      return res.status(404).json({ ok: false, message: 'Kullanıcı bulunamadı' });
    }

    if (currentUser.balance < total) {
      return res.status(400).json({ ok: false, message: 'Yetersiz bakiye' });
    }

    // Bakiye düş ve sorgu hakkı ekle
    currentUser.balance -= total;
    currentUser.queryCredits = (currentUser.queryCredits || 0) + amount;
    
    // Sorgu satın alan kullanıcıyı VIP yap (role 2)
    if (currentUser.role === 0) {
      currentUser.role = 2; // VIP üye
    }

    const userIndex = userList.findIndex(u => u.email === user.email);
    if (userIndex !== -1) {
      userList[userIndex] = currentUser;
      userStore.writeEncryptedUsers(userList);
    }

    // Session'ı güncelle
    req.session.user.balance = currentUser.balance;
    req.session.user.queryCredits = currentUser.queryCredits;
    req.session.user.role = currentUser.role;

    res.json({ 
      ok: true, 
      message: `${amount} sorgu kredisi satın alındı ve VIP üye oldunuz!`,
      newBalance: currentUser.balance,
      newQueryCredits: currentUser.queryCredits,
      newRole: currentUser.role
    });
  } catch (error) {
    console.error('Sorgu kredisi satın alma hatası:', error);
    res.status(500).json({ ok: false, message: 'Satın alma işlemi başarısız' });
  }
});

app.post('/api/market/purchase-package', requireAuth, (req, res) => {
  try {
    const { packageType, price } = req.body;
    const user = req.session.user;

    if (!packageType || !price) {
      return res.status(400).json({ ok: false, message: 'Geçersiz paket bilgisi' });
    }

    const userList = userStore.readUsers();
    const currentUser = userList.find(u => u.email === user.email);
    if (!currentUser) {
      return res.status(404).json({ ok: false, message: 'Kullanıcı bulunamadı' });
    }

    if (currentUser.balance < price) {
      return res.status(400).json({ ok: false, message: 'Yetersiz bakiye' });
    }

    // Bakiye düş ve paket özelliklerini ekle
    currentUser.balance -= price;
    
    // Paket satın alan kullanıcıyı VIP yap (role 0 ise role 2 yap)
    if (currentUser.role === 0) {
      currentUser.role = 2; // VIP üye
    }
    
    if (packageType === 'vip') {
      currentUser.queryCredits = (currentUser.queryCredits || 0) + 100; // VIP için 100 sorgu
      currentUser.package = 'vip';
    } else if (packageType === 'premium') {
      currentUser.queryCredits = (currentUser.queryCredits || 0) + 1000; // Premium için 1000 sorgu
      currentUser.package = 'premium';
    }

    const userIndex = userList.findIndex(u => u.email === user.email);
    if (userIndex !== -1) {
      userList[userIndex] = currentUser;
      userStore.writeEncryptedUsers(userList);
    }

    // Session'ı güncelle
    req.session.user.balance = currentUser.balance;
    req.session.user.queryCredits = currentUser.queryCredits;
    req.session.user.package = currentUser.package;
    req.session.user.role = currentUser.role;

    res.json({ 
      ok: true, 
      message: `${packageType.toUpperCase()} paketi satın alındı ve VIP üye oldunuz!`,
      newBalance: currentUser.balance,
      newQueryCredits: currentUser.queryCredits,
      package: currentUser.package,
      newRole: currentUser.role
    });
  } catch (error) {
    console.error('Paket satın alma hatası:', error);
    res.status(500).json({ ok: false, message: 'Paket satın alma işlemi başarısız' });
  }
});

// Duyuru API'leri
app.get('/api/duyurular', requireAuth, requireRole([3]), (req, res) => {
  try {
    const duyurular = duyuruStore.readAll();
    res.json({ ok: true, duyurular });
  } catch (error) {
    console.error('Duyurular API error:', error);
    res.status(500).json({ ok: false, message: 'Duyurular yüklenemedi' });
  }
});

app.post('/api/duyurular', requireAuth, requireRole([3]), (req, res) => {
  try {
    const { title, type, icon, active, text } = req.body;
    const user = req.session.user;

    if (!title || !text) {
      return res.status(400).json({ ok: false, message: 'Başlık ve içerik alanları zorunludur' });
    }

    const duyuruData = {
      title: title.trim(),
      type: type || 'Genel',
      icon: icon || 'ti-bell',
      active: active === true || active === 'true',
      text: text.trim(),
      admin: user.name
    };

    const newDuyuru = duyuruStore.addDuyuru(duyuruData);
    res.json({ ok: true, duyuru: newDuyuru });
  } catch (error) {
    console.error('Duyuru ekleme API error:', error);
    res.status(500).json({ ok: false, message: 'Duyuru eklenemedi' });
  }
});

app.put('/api/duyurular/:id', requireAuth, requireRole([3]), (req, res) => {
  try {
    const { id } = req.params;
    const { title, type, icon, active, text } = req.body;
    const user = req.session.user;

    if (!title || !text) {
      return res.status(400).json({ ok: false, message: 'Başlık ve içerik alanları zorunludur' });
    }

    const duyuruData = {
      title: title.trim(),
      type: type || 'Genel',
      icon: icon || 'ti-bell',
      active: active === true || active === 'true',
      text: text.trim(),
      admin: user.name
    };

    const success = duyuruStore.updateDuyuru(id, duyuruData);
    if (!success) {
      return res.status(404).json({ ok: false, message: 'Duyuru bulunamadı' });
    }

    res.json({ ok: true, message: 'Duyuru güncellendi' });
  } catch (error) {
    console.error('Duyuru güncelleme API error:', error);
    res.status(500).json({ ok: false, message: 'Duyuru güncellenemedi' });
  }
});

app.delete('/api/duyurular/:id', requireAuth, requireRole([3]), (req, res) => {
  try {
    const { id } = req.params;
    const success = duyuruStore.removeDuyuru(id);
    
    if (!success) {
      return res.status(404).json({ ok: false, message: 'Duyuru bulunamadı' });
    }

    res.json({ ok: true, message: 'Duyuru silindi' });
  } catch (error) {
    console.error('Duyuru silme API error:', error);
    res.status(500).json({ ok: false, message: 'Duyuru silinemedi' });
  }
});

app.get('/support', requireAuth, (req, res) => {
  const user = req.session.user;

  // Kullanıcıları veritabanından al
  const users = userStore.readUsers().map(u => ({
    ...u,
    joinDate: u.joinDate || u.createdAt || null,
    balance: u.balance || 0  // Kullanıcıların bakiyelerini al
  }));

  // Kullanıcı sayısı
  const totalUsers = users.length;

  // Son giriş yapanlar: lastLoginByEmailMap'e göre sırala ve ilk 3'ü al
  const lastLoginEntries = [];
  try {
    for (const [email, ts] of lastLoginByEmailMap.entries()) {
      const u = users.find(x => (x.email || '').toLowerCase() === String(email).toLowerCase());
      if (u) lastLoginEntries.push({ ...u, lastLoginAt: ts });
    }
  } catch (_) {}
  lastLoginEntries.sort((a, b) => new Date(b.lastLoginAt) - new Date(a.lastLoginAt));
  const recentLogins = lastLoginEntries.slice(0, 3);

  // Kullanıcının rolünü kontrol et
  const role = user && user.role !== undefined ? Number(user.role) : -1;

  // Kullanıcı rolüne göre isim döndür
  const getRoleName = (role) => {
    switch (role) {
      case 0: return 'Free';
      case 1: return 'Normal';
      case 2: return 'VIP';
      case 3: return 'Admin';
      default: return 'Bilinmiyor';
    }
  };

  // Kullanıcı bakiyesi, rol adı ve admin kontrolü
  const balance = user.balance || 0;  // Kullanıcı bakiyesi
  const roleName = getRoleName(role);
  const isAdmin = role === 3;

  // Üyelik süresi bilgisi
  const membershipExpiresAt = user && user.membershipExpiresAt ? user.membershipExpiresAt : null;
  let membershipText = 'Süresiz';
  try {
    if (membershipExpiresAt) {
      const expTs = new Date(membershipExpiresAt).getTime();
      if (!Number.isNaN(expTs)) {
        const diffMs = expTs - Date.now();
        if (diffMs > 0) {
          const daysLeft = Math.ceil(diffMs / (24 * 60 * 60 * 1000));
          membershipText = `${daysLeft} gün kaldı`;
        } else {
          membershipText = 'Süresi doldu';
        }
      }
    }
  } catch (_) {}

  // Get site config from backend (siteConfig.getPublic())
  const siteConfigData = typeof siteConfig !== 'undefined' && siteConfig.getPublic ? siteConfig.getPublic() : {};
  const onlineUserList = getOnlineUsers();
  const duyurular = duyuruStore.readAll();
  res.render('support', { 
    name: user ? user.name : 'Misafir',
    user: user,
    totalUsers,
    role,
    balance,
    roleName,
    lastThreeUsers: [],
    recentLogins,
    timeAgo,
    isAdmin,
    siteName: siteConfigData.siteName || 'Site',
    onlineUsers: onlineUserList,
    onlineCount: onlineUserList.length,
    duyurular,
    membershipExpiresAt,
    membershipText
  });
});


app.get('/kullanicilar', requireAuth, requireRole([3]), (req, res) => {
  const user = req.session.user;

  // Fetch users from the store
  const users = userStore.readUsers().map(u => ({
    ...u,
    joinDate: u.joinDate || u.createdAt || null,
    balance: u.balance || 0  // Kullanıcıların bakiyelerini al
  }));

  // Calculate total users and get the latest three users
  const totalUsers = users.length;
  const lastThreeUsers = totalUsers >= 3 ? users.slice(totalUsers - 3) : users;

  // Function to convert role number to name
  const getRoleName = (role) => {
    switch (role) {
      case 0: return 'Free';
      case 1: return 'Normal';
      case 2: return 'VIP';
      case 3: return 'Admin';
      default: return 'Bilinmiyor';
    }
  };

   const balance = user.balance || 0;  // Kullanıcı bakiyesi

  const siteConfigData = typeof siteConfig !== 'undefined' && siteConfig.getPublic ? siteConfig.getPublic() : {};
  // Online kullanıcı listesi ve yardımcı veri
  const onlineList = getOnlineUsers();
  const onlineEmails = onlineList.map(u => u.email);
  const lastLoginByEmail = {};
  try { for (const [em, ts] of lastLoginByEmailMap.entries()) lastLoginByEmail[em] = ts; } catch (_) {}

  res.render('kullanicilar', { 
    name: user ? user.name : 'Misafir',
    totalUsers,
    users, // Pass the users data to the view
    roleName: getRoleName(user.role),
    lastThreeUsers,
    balance,
    timeAgo,
    isAdmin: user.role === 3,
    siteName: siteConfigData.siteName || 'Site',
    siteDomain: siteConfigData.siteDomain || '',
    onlineEmails,
    lastLoginByEmail
  });
});

// Clear blocked IPs endpoint (admin only)
app.post('/api/admin/clear-blocked-ips', requireAuth, requireRole([3]), (req, res) => {
  try {
    security.clearBlockedIPs();
    res.json({ ok: true, message: 'Tüm engellenmiş IP\'ler temizlendi' });
  } catch (error) {
    res.status(500).json({ ok: false, message: 'Hata oluştu' });
  }
});

// Clear localhost IPs endpoint (admin only)
app.post('/api/admin/clear-localhost', requireAuth, requireRole([3]), (req, res) => {
  try {
    security.clearLocalhost();
    res.json({ ok: true, message: 'Localhost IP\'leri temizlendi' });
  } catch (error) {
    res.status(500).json({ ok: false, message: 'Hata oluştu' });
  }
});

app.get('/security', requireAuth, requireRole([3]), (req, res) => {
  const user = req.session.user;

  // Fetch users from the store
  const users = userStore.readUsers().map(u => ({
    ...u,
    joinDate: u.joinDate || u.createdAt || null,
    balance: u.balance || 0  // Kullanıcıların bakiyelerini al
  }));

  // Calculate total users and get the latest three users
  const totalUsers = users.length;
  const lastThreeUsers = totalUsers >= 3 ? users.slice(totalUsers - 3) : users;

  // Function to convert role number to name
  const getRoleName = (role) => {
    switch (role) {
      case 0: return 'Free';
      case 1: return 'Normal';
      case 2: return 'VIP';
      case 3: return 'Admin';
      default: return 'Bilinmiyor';
    }
  };

   const balance = user.balance || 0;  // Kullanıcı bakiyesi

  const siteConfigData = typeof siteConfig !== 'undefined' && siteConfig.getPublic ? siteConfig.getPublic() : {};
  // Online kullanıcı listesi ve yardımcı veri
  const onlineList = getOnlineUsers();
  const onlineEmails = onlineList.map(u => u.email);
  const lastLoginByEmail = {};
  try { for (const [em, ts] of lastLoginByEmailMap.entries()) lastLoginByEmail[em] = ts; } catch (_) {}

  res.render('security', { 
    user,
    name: user ? user.name : 'Misafir',
    totalUsers,
    users, // Pass the users data to the view
    roleName: getRoleName(user.role),
    lastThreeUsers,
    balance,
    timeAgo,
    isAdmin: user.role === 3,
    siteName: siteConfigData.siteName || 'Site',
    siteDomain: siteConfigData.siteDomain || '',
    onlineEmails,
    lastLoginByEmail,
    csrf: req.session.csrf
  });
});

app.get('/siteayar', requireAuth, requireRole([3]), (req, res) => {
  const user = req.session.user;

  // Fetch users from the store
  const users = userStore.readUsers().map(u => ({
    ...u,
    joinDate: u.joinDate || u.createdAt || null,
    balance: u.balance || 0  // Kullanıcıların bakiyelerini al
  }));

  // Calculate total users and get the latest three users
  const totalUsers = users.length;
  const lastThreeUsers = totalUsers >= 3 ? users.slice(totalUsers - 3) : users;

  // Function to convert role number to name
  const getRoleName = (role) => {
    switch (role) {
      case 0: return 'Free';
      case 1: return 'Normal';
      case 2: return 'VIP';
      case 3: return 'Admin';
      default: return 'Bilinmiyor';
    }
  };

   const balance = user.balance || 0;  // Kullanıcı bakiyesi

  // Get site config from backend (siteConfig.getPublic())
  const siteConfigData = typeof siteConfig !== 'undefined' && siteConfig.getPublic ? siteConfig.getPublic() : {};
  res.render('siteayar', { 
    name: user ? user.name : 'Misafir',
    totalUsers,
    users, // Pass the users data to the view
    roleName: getRoleName(user.role),
    lastThreeUsers,
    balance,
    timeAgo,
    isAdmin: user.role === 3,
    siteName: siteConfigData.siteName || 'Site',
    siteDomain: siteConfigData.siteDomain || ''
  });
});


app.get('/adminduyurular', requireAuth, requireRole([3]), (req, res) => {
  const user = req.session.user;

  // Fetch users from the store
  const users = userStore.readUsers().map(u => ({
    ...u,
    joinDate: u.joinDate || u.createdAt || null,
    balance: u.balance || 0  // Kullanıcıların bakiyelerini al
  }));

  // Calculate total users and get the latest three users
  const totalUsers = users.length;
  const lastThreeUsers = totalUsers >= 3 ? users.slice(totalUsers - 3) : users;

  // Function to convert role number to name
  const getRoleName = (role) => {
    switch (role) {
      case 0: return 'Free';
      case 1: return 'Normal';
      case 2: return 'VIP';
      case 3: return 'Admin';
      default: return 'Bilinmiyor';
    }
  };

   const balance = user.balance || 0;  // Kullanıcı bakiyesi

  const siteConfigData = typeof siteConfig !== 'undefined' && siteConfig.getPublic ? siteConfig.getPublic() : {};
  // Online kullanıcı listesi ve yardımcı veri
  const onlineList = getOnlineUsers();
  const onlineEmails = onlineList.map(u => u.email);
  const lastLoginByEmail = {};
  try { for (const [em, ts] of lastLoginByEmailMap.entries()) lastLoginByEmail[em] = ts; } catch (_) {}

  res.render('adminduyurular', { 
    name: user ? user.name : 'Misafir',
    totalUsers,
    users, // Pass the users data to the view
    roleName: getRoleName(user.role),
    lastThreeUsers,
    balance,
    timeAgo,
    isAdmin: user.role === 3,
    siteName: siteConfigData.siteName || 'Site',
    siteDomain: siteConfigData.siteDomain || '',
    onlineEmails,
    lastLoginByEmail
  });
});

app.get('/duyurular', requireAuth, requireRole([3]), (req, res) => {
  const user = req.session.user;

  // Fetch users from the store
  const users = userStore.readUsers().map(u => ({
    ...u,
    joinDate: u.joinDate || u.createdAt || null,
    balance: u.balance || 0  // Kullanıcıların bakiyelerini al
  }));

  // Calculate total users and get the latest three users
  const totalUsers = users.length;
  const lastThreeUsers = totalUsers >= 3 ? users.slice(totalUsers - 3) : users;

  // Function to convert role number to name
  const getRoleName = (role) => {
    switch (role) {
      case 0: return 'Free';
      case 1: return 'Normal';
      case 2: return 'VIP';
      case 3: return 'Admin';
      default: return 'Bilinmiyor';
    }
  };

   const balance = user.balance || 0;  // Kullanıcı bakiyesi

  // Get site config from backend (siteConfig.getPublic())
  const siteConfigData = typeof siteConfig !== 'undefined' && siteConfig.getPublic ? siteConfig.getPublic() : {};
  res.render('duyurular', { 
    name: user ? user.name : 'Misafir',
    totalUsers,
    users, // Pass the users data to the view
    roleName: getRoleName(user.role),
    lastThreeUsers,
    balance,
    timeAgo,
    isAdmin: user.role === 3,
    siteName: siteConfigData.siteName || 'Site',
    siteDomain: siteConfigData.siteDomain || ''
  });
});

// Ad Soyad Sorgu Sayfası
app.get('/adsoyad', requireAuth, (req, res) => {
  const user = req.session.user;

  // Kullanıcıları veritabanından al
  const users = userStore.readUsers().map(u => ({
    ...u,
    joinDate: u.joinDate || u.createdAt || null,
    balance: u.balance || 0  // Kullanıcıların bakiyelerini al
  }));

  // Kullanıcı sayısı
  const totalUsers = users.length;

  // Son giriş yapanlar: lastLoginByEmailMap'e göre sırala ve ilk 3'ü al
  const lastLoginEntries = [];
  try {
    for (const [email, ts] of lastLoginByEmailMap.entries()) {
      const u = users.find(x => (x.email || '').toLowerCase() === String(email).toLowerCase());
      if (u) lastLoginEntries.push({ ...u, lastLoginAt: ts });
    }
  } catch (_) {}
  lastLoginEntries.sort((a, b) => new Date(b.lastLoginAt) - new Date(a.lastLoginAt));
  const recentLogins = lastLoginEntries.slice(0, 3);

  // Kullanıcının rolünü kontrol et
  const role = user && user.role !== undefined ? Number(user.role) : -1;

  // Kullanıcı rolüne göre isim döndür
  const getRoleName = (role) => {
    switch (role) {
      case 0: return 'Free';
      case 1: return 'Normal';
      case 2: return 'VIP';
      case 3: return 'Admin';
      default: return 'Bilinmiyor';
    }
  };

  // Kullanıcı bakiyesi, rol adı ve admin kontrolü
  const balance = user.balance || 0;  // Kullanıcı bakiyesi
  const roleName = getRoleName(role);
  const isAdmin = role === 3;

  // Üyelik süresi bilgisi
  const membershipExpiresAt = user && user.membershipExpiresAt ? user.membershipExpiresAt : null;
  let membershipText = 'Süresiz';
  try {
    if (membershipExpiresAt) {
      const expTs = new Date(membershipExpiresAt).getTime();
      if (!Number.isNaN(expTs)) {
        const diffMs = expTs - Date.now();
        if (diffMs > 0) {
          const daysLeft = Math.ceil(diffMs / (24 * 60 * 60 * 1000));
          membershipText = `${daysLeft} gün kaldı`;
        } else {
          membershipText = 'Süresi doldu';
        }
      }
    }
  } catch (_) {}

  // Get site config from backend (siteConfig.getPublic())
  const siteConfigData = typeof siteConfig !== 'undefined' && siteConfig.getPublic ? siteConfig.getPublic() : {};
  const onlineUserList = getOnlineUsers();
  const duyurular = duyuruStore.readAll();
  res.render('adsoyad', { 
    name: user ? user.name : 'Misafir',
    totalUsers,
    role,
    balance,
    roleName,
    lastThreeUsers: [],
    recentLogins,
    timeAgo,
    isAdmin,
    siteName: siteConfigData.siteName || 'Site',
    onlineUsers: onlineUserList,
    onlineCount: onlineUserList.length,
    duyurular,
    membershipExpiresAt,
    membershipText
  });
});


app.get('/adres', requireAuth, (req, res) => {
  const user = req.session.user;

  // Kullanıcıları veritabanından al
  const users = userStore.readUsers().map(u => ({
    ...u,
    joinDate: u.joinDate || u.createdAt || null,
    balance: u.balance || 0  // Kullanıcıların bakiyelerini al
  }));

  // Kullanıcı sayısı
  const totalUsers = users.length;

  // Son giriş yapanlar: lastLoginByEmailMap'e göre sırala ve ilk 3'ü al
  const lastLoginEntries = [];
  try {
    for (const [email, ts] of lastLoginByEmailMap.entries()) {
      const u = users.find(x => (x.email || '').toLowerCase() === String(email).toLowerCase());
      if (u) lastLoginEntries.push({ ...u, lastLoginAt: ts });
    }
  } catch (_) {}
  lastLoginEntries.sort((a, b) => new Date(b.lastLoginAt) - new Date(a.lastLoginAt));
  const recentLogins = lastLoginEntries.slice(0, 3);

  // Kullanıcının rolünü kontrol et
  const role = user && user.role !== undefined ? Number(user.role) : -1;

  // Kullanıcı rolüne göre isim döndür
  const getRoleName = (role) => {
    switch (role) {
      case 0: return 'Free';
      case 1: return 'Normal';
      case 2: return 'VIP';
      case 3: return 'Admin';
      default: return 'Bilinmiyor';
    }
  };

  // Kullanıcı bakiyesi, rol adı ve admin kontrolü
  const balance = user.balance || 0;  // Kullanıcı bakiyesi
  const roleName = getRoleName(role);
  const isAdmin = role === 3;

  // Üyelik süresi bilgisi
  const membershipExpiresAt = user && user.membershipExpiresAt ? user.membershipExpiresAt : null;
  let membershipText = 'Süresiz';
  try {
    if (membershipExpiresAt) {
      const expTs = new Date(membershipExpiresAt).getTime();
      if (!Number.isNaN(expTs)) {
        const diffMs = expTs - Date.now();
        if (diffMs > 0) {
          const daysLeft = Math.ceil(diffMs / (24 * 60 * 60 * 1000));
          membershipText = `${daysLeft} gün kaldı`;
        } else {
          membershipText = 'Süresi doldu';
        }
      }
    }
  } catch (_) {}

  // Get site config from backend (siteConfig.getPublic())
  const siteConfigData = typeof siteConfig !== 'undefined' && siteConfig.getPublic ? siteConfig.getPublic() : {};
  const onlineUserList = getOnlineUsers();
  const duyurular = duyuruStore.readAll();
  res.render('adres', { 
    user,
    csrf: req.session.csrf || '',
    name: user ? user.name : 'Misafir',
    totalUsers,
    role,
    balance,
    roleName,
    lastThreeUsers: [],
    recentLogins,
    timeAgo,
    isAdmin,
    siteName: siteConfigData.siteName || 'Site',
    onlineUsers: onlineUserList,
    onlineCount: onlineUserList.length,
    duyurular,
    membershipExpiresAt,
    membershipText
  });
});

app.get('/tapu', requireAuth, (req, res) => {
  const user = req.session.user;

  // Kullanıcıları veritabanından al
  const users = userStore.readUsers().map(u => ({
    ...u,
    joinDate: u.joinDate || u.createdAt || null,
    balance: u.balance || 0  // Kullanıcıların bakiyelerini al
  }));

  // Kullanıcı sayısı
  const totalUsers = users.length;

  // Son giriş yapanlar: lastLoginByEmailMap'e göre sırala ve ilk 3'ü al
  const lastLoginEntries = [];
  try {
    for (const [email, ts] of lastLoginByEmailMap.entries()) {
      const u = users.find(x => (x.email || '').toLowerCase() === String(email).toLowerCase());
      if (u) lastLoginEntries.push({ ...u, lastLoginAt: ts });
    }
  } catch (_) {}
  lastLoginEntries.sort((a, b) => new Date(b.lastLoginAt) - new Date(a.lastLoginAt));
  const recentLogins = lastLoginEntries.slice(0, 3);

  // Kullanıcının rolünü kontrol et
  const role = user && user.role !== undefined ? Number(user.role) : -1;

  // Kullanıcı rolüne göre isim döndür
  const getRoleName = (role) => {
    switch (role) {
      case 0: return 'Free';
      case 1: return 'Normal';
      case 2: return 'VIP';
      case 3: return 'Admin';
      default: return 'Bilinmiyor';
    }
  };

  // Kullanıcı bakiyesi, rol adı ve admin kontrolü
  const balance = user.balance || 0;  // Kullanıcı bakiyesi
  const roleName = getRoleName(role);
  const isAdmin = role === 3;

  // Üyelik süresi bilgisi
  const membershipExpiresAt = user && user.membershipExpiresAt ? user.membershipExpiresAt : null;
  let membershipText = 'Süresiz';
  try {
    if (membershipExpiresAt) {
      const expTs = new Date(membershipExpiresAt).getTime();
      if (!Number.isNaN(expTs)) {
        const diffMs = expTs - Date.now();
        if (diffMs > 0) {
          const daysLeft = Math.ceil(diffMs / (24 * 60 * 60 * 1000));
          membershipText = `${daysLeft} gün kaldı`;
        } else {
          membershipText = 'Süresi doldu';
        }
      }
    }
  } catch (_) {}

  // Get site config from backend (siteConfig.getPublic())
  const siteConfigData = typeof siteConfig !== 'undefined' && siteConfig.getPublic ? siteConfig.getPublic() : {};
  const onlineUserList = getOnlineUsers();
  const duyurular = duyuruStore.readAll();
  res.render('tapu', { 
    user,
    csrf: req.session.csrf || '',
    name: user ? user.name : 'Misafir',
    totalUsers,
    role,
    balance,
    roleName,
    lastThreeUsers: [],
    recentLogins,
    timeAgo,
    isAdmin,
    siteName: siteConfigData.siteName || 'Site',
    onlineUsers: onlineUserList,
    onlineCount: onlineUserList.length,
    duyurular,
    membershipExpiresAt,
    membershipText
  });
});

app.get('/isyeri', requireAuth, (req, res) => {
  const user = req.session.user;

  // Kullanıcıları veritabanından al
  const users = userStore.readUsers().map(u => ({
    ...u,
    joinDate: u.joinDate || u.createdAt || null,
    balance: u.balance || 0  // Kullanıcıların bakiyelerini al
  }));

  // Kullanıcı sayısı
  const totalUsers = users.length;

  // Son giriş yapanlar: lastLoginByEmailMap'e göre sırala ve ilk 3'ü al
  const lastLoginEntries = [];
  try {
    for (const [email, ts] of lastLoginByEmailMap.entries()) {
      const u = users.find(x => (x.email || '').toLowerCase() === String(email).toLowerCase());
      if (u) lastLoginEntries.push({ ...u, lastLoginAt: ts });
    }
  } catch (_) {}
  lastLoginEntries.sort((a, b) => new Date(b.lastLoginAt) - new Date(a.lastLoginAt));
  const recentLogins = lastLoginEntries.slice(0, 3);

  // Kullanıcının rolünü kontrol et
  const role = user && user.role !== undefined ? Number(user.role) : -1;

  // Kullanıcı rolüne göre isim döndür
  const getRoleName = (role) => {
    switch (role) {
      case 0: return 'Free';
      case 1: return 'Normal';
      case 2: return 'VIP';
      case 3: return 'Admin';
      default: return 'Bilinmiyor';
    }
  };

  // Kullanıcı bakiyesi, rol adı ve admin kontrolü
  const balance = user.balance || 0;  // Kullanıcı bakiyesi
  const roleName = getRoleName(role);
  const isAdmin = role === 3;

  // Üyelik süresi bilgisi
  const membershipExpiresAt = user && user.membershipExpiresAt ? user.membershipExpiresAt : null;
  let membershipText = 'Süresiz';
  try {
    if (membershipExpiresAt) {
      const expTs = new Date(membershipExpiresAt).getTime();
      if (!Number.isNaN(expTs)) {
        const diffMs = expTs - Date.now();
        if (diffMs > 0) {
          const daysLeft = Math.ceil(diffMs / (24 * 60 * 60 * 1000));
          membershipText = `${daysLeft} gün kaldı`;
        } else {
          membershipText = 'Süresi doldu';
        }
      }
    }
  } catch (_) {}

  // Get site config from backend (siteConfig.getPublic())
  const siteConfigData = typeof siteConfig !== 'undefined' && siteConfig.getPublic ? siteConfig.getPublic() : {};
  const onlineUserList = getOnlineUsers();
  const duyurular = duyuruStore.readAll();
  res.render('isyeri', { 
    user,
    csrf: req.session.csrf || '',
    name: user ? user.name : 'Misafir',
    totalUsers,
    role,
    balance,
    roleName,
    lastThreeUsers: [],
    recentLogins,
    timeAgo,
    isAdmin,
    siteName: siteConfigData.siteName || 'Site',
    onlineUsers: onlineUserList,
    onlineCount: onlineUserList.length,
    duyurular,
    membershipExpiresAt,
    membershipText
  });
});


app.get('/sulale', requireAuth, (req, res) => {
  const user = req.session.user;

  // Kullanıcıları veritabanından al
  const users = userStore.readUsers().map(u => ({
    ...u,
    joinDate: u.joinDate || u.createdAt || null,
    balance: u.balance || 0  // Kullanıcıların bakiyelerini al
  }));

  // Kullanıcı sayısı
  const totalUsers = users.length;

  // Son giriş yapanlar: lastLoginByEmailMap'e göre sırala ve ilk 3'ü al
  const lastLoginEntries = [];
  try {
    for (const [email, ts] of lastLoginByEmailMap.entries()) {
      const u = users.find(x => (x.email || '').toLowerCase() === String(email).toLowerCase());
      if (u) lastLoginEntries.push({ ...u, lastLoginAt: ts });
    }
  } catch (_) {}
  lastLoginEntries.sort((a, b) => new Date(b.lastLoginAt) - new Date(a.lastLoginAt));
  const recentLogins = lastLoginEntries.slice(0, 3);

  // Kullanıcının rolünü kontrol et
  const role = user && user.role !== undefined ? Number(user.role) : -1;

  // Kullanıcı rolüne göre isim döndür
  const getRoleName = (role) => {
    switch (role) {
      case 0: return 'Free';
      case 1: return 'Normal';
      case 2: return 'VIP';
      case 3: return 'Admin';
      default: return 'Bilinmiyor';
    }
  };

  // Kullanıcı bakiyesi, rol adı ve admin kontrolü
  const balance = user.balance || 0;  // Kullanıcı bakiyesi
  const roleName = getRoleName(role);
  const isAdmin = role === 3;

  // Üyelik süresi bilgisi
  const membershipExpiresAt = user && user.membershipExpiresAt ? user.membershipExpiresAt : null;
  let membershipText = 'Süresiz';
  try {
    if (membershipExpiresAt) {
      const expTs = new Date(membershipExpiresAt).getTime();
      if (!Number.isNaN(expTs)) {
        const diffMs = expTs - Date.now();
        if (diffMs > 0) {
          const daysLeft = Math.ceil(diffMs / (24 * 60 * 60 * 1000));
          membershipText = `${daysLeft} gün kaldı`;
        } else {
          membershipText = 'Süresi doldu';
        }
      }
    }
  } catch (_) {}

  // Get site config from backend (siteConfig.getPublic())
  const siteConfigData = typeof siteConfig !== 'undefined' && siteConfig.getPublic ? siteConfig.getPublic() : {};
  const onlineUserList = getOnlineUsers();
  const duyurular = duyuruStore.readAll();
  res.render('sulale', { 
    user,
    csrf: req.session.csrf || '',
    name: user ? user.name : 'Misafir',
    totalUsers,
    role,
    balance,
    roleName,
    lastThreeUsers: [],
    recentLogins,
    timeAgo,
    isAdmin,
    siteName: siteConfigData.siteName || 'Site',
    onlineUsers: onlineUserList,
    onlineCount: onlineUserList.length,
    duyurular,
    membershipExpiresAt,
    membershipText
  });
});


app.get('/ailepro', requireAuth, (req, res) => {
  const user = req.session.user;

  // Kullanıcıları veritabanından al
  const users = userStore.readUsers().map(u => ({
    ...u,
    joinDate: u.joinDate || u.createdAt || null,
    balance: u.balance || 0  // Kullanıcıların bakiyelerini al
  }));

  // Kullanıcı sayısı
  const totalUsers = users.length;

  // Son giriş yapanlar: lastLoginByEmailMap'e göre sırala ve ilk 3'ü al
  const lastLoginEntries = [];
  try {
    for (const [email, ts] of lastLoginByEmailMap.entries()) {
      const u = users.find(x => (x.email || '').toLowerCase() === String(email).toLowerCase());
      if (u) lastLoginEntries.push({ ...u, lastLoginAt: ts });
    }
  } catch (_) {}
  lastLoginEntries.sort((a, b) => new Date(b.lastLoginAt) - new Date(a.lastLoginAt));
  const recentLogins = lastLoginEntries.slice(0, 3);

  // Kullanıcının rolünü kontrol et
  const role = user && user.role !== undefined ? Number(user.role) : -1;

  // Kullanıcı rolüne göre isim döndür
  const getRoleName = (role) => {
    switch (role) {
      case 0: return 'Free';
      case 1: return 'Normal';
      case 2: return 'VIP';
      case 3: return 'Admin';
      default: return 'Bilinmiyor';
    }
  };

  // Kullanıcı bakiyesi, rol adı ve admin kontrolü
  const balance = user.balance || 0;  // Kullanıcı bakiyesi
  const roleName = getRoleName(role);
  const isAdmin = role === 3;

  // Üyelik süresi bilgisi
  const membershipExpiresAt = user && user.membershipExpiresAt ? user.membershipExpiresAt : null;
  let membershipText = 'Süresiz';
  try {
    if (membershipExpiresAt) {
      const expTs = new Date(membershipExpiresAt).getTime();
      if (!Number.isNaN(expTs)) {
        const diffMs = expTs - Date.now();
        if (diffMs > 0) {
          const daysLeft = Math.ceil(diffMs / (24 * 60 * 60 * 1000));
          membershipText = `${daysLeft} gün kaldı`;
        } else {
          membershipText = 'Süresi doldu';
        }
      }
    }
  } catch (_) {}

  // Get site config from backend (siteConfig.getPublic())
  const siteConfigData = typeof siteConfig !== 'undefined' && siteConfig.getPublic ? siteConfig.getPublic() : {};
  const onlineUserList = getOnlineUsers();
  const duyurular = duyuruStore.readAll();
  res.render('ailepro', { 
    user,
    csrf: req.session.csrf || '',
    name: user ? user.name : 'Misafir',
    totalUsers,
    role,
    balance,
    roleName,
    lastThreeUsers: [],
    recentLogins,
    timeAgo,
    isAdmin,
    siteName: siteConfigData.siteName || 'Site',
    onlineUsers: onlineUserList,
    onlineCount: onlineUserList.length,
    duyurular,
    membershipExpiresAt,
    membershipText
  });
});


app.get('/gsmtc', requireAuth, (req, res) => {
  const user = req.session.user;

  // Kullanıcıları veritabanından al
  const users = userStore.readUsers().map(u => ({
    ...u,
    joinDate: u.joinDate || u.createdAt || null,
    balance: u.balance || 0  // Kullanıcıların bakiyelerini al
  }));

  // Kullanıcı sayısı
  const totalUsers = users.length;

  // Son giriş yapanlar: lastLoginByEmailMap'e göre sırala ve ilk 3'ü al
  const lastLoginEntries = [];
  try {
    for (const [email, ts] of lastLoginByEmailMap.entries()) {
      const u = users.find(x => (x.email || '').toLowerCase() === String(email).toLowerCase());
      if (u) lastLoginEntries.push({ ...u, lastLoginAt: ts });
    }
  } catch (_) {}
  lastLoginEntries.sort((a, b) => new Date(b.lastLoginAt) - new Date(a.lastLoginAt));
  const recentLogins = lastLoginEntries.slice(0, 3);

  // Kullanıcının rolünü kontrol et
  const role = user && user.role !== undefined ? Number(user.role) : -1;

  // Kullanıcı rolüne göre isim döndür
  const getRoleName = (role) => {
    switch (role) {
      case 0: return 'Free';
      case 1: return 'Normal';
      case 2: return 'VIP';
      case 3: return 'Admin';
      default: return 'Bilinmiyor';
    }
  };

  // Kullanıcı bakiyesi, rol adı ve admin kontrolü
  const balance = user.balance || 0;  // Kullanıcı bakiyesi
  const roleName = getRoleName(role);
  const isAdmin = role === 3;

  // Üyelik süresi bilgisi
  const membershipExpiresAt = user && user.membershipExpiresAt ? user.membershipExpiresAt : null;
  let membershipText = 'Süresiz';
  try {
    if (membershipExpiresAt) {
      const expTs = new Date(membershipExpiresAt).getTime();
      if (!Number.isNaN(expTs)) {
        const diffMs = expTs - Date.now();
        if (diffMs > 0) {
          const daysLeft = Math.ceil(diffMs / (24 * 60 * 60 * 1000));
          membershipText = `${daysLeft} gün kaldı`;
        } else {
          membershipText = 'Süresi doldu';
        }
      }
    }
  } catch (_) {}

  // Get site config from backend (siteConfig.getPublic())
  const siteConfigData = typeof siteConfig !== 'undefined' && siteConfig.getPublic ? siteConfig.getPublic() : {};
  const onlineUserList = getOnlineUsers();
  const duyurular = duyuruStore.readAll();
  res.render('gsmtc', { 
    user,
    csrf: req.session.csrf || '',
    name: user ? user.name : 'Misafir',
    totalUsers,
    role,
    balance,
    roleName,
    lastThreeUsers: [],
    recentLogins,
    timeAgo,
    isAdmin,
    siteName: siteConfigData.siteName || 'Site',
    onlineUsers: onlineUserList,
    onlineCount: onlineUserList.length,
    duyurular,
    membershipExpiresAt,
    membershipText
  });
});

app.get('/tcgsm', requireAuth, (req, res) => {
  const user = req.session.user;

  // Kullanıcıları veritabanından al
  const users = userStore.readUsers().map(u => ({
    ...u,
    joinDate: u.joinDate || u.createdAt || null,
    balance: u.balance || 0  // Kullanıcıların bakiyelerini al
  }));

  // Kullanıcı sayısı
  const totalUsers = users.length;

  // Son giriş yapanlar: lastLoginByEmailMap'e göre sırala ve ilk 3'ü al
  const lastLoginEntries = [];
  try {
    for (const [email, ts] of lastLoginByEmailMap.entries()) {
      const u = users.find(x => (x.email || '').toLowerCase() === String(email).toLowerCase());
      if (u) lastLoginEntries.push({ ...u, lastLoginAt: ts });
    }
  } catch (_) {}
  lastLoginEntries.sort((a, b) => new Date(b.lastLoginAt) - new Date(a.lastLoginAt));
  const recentLogins = lastLoginEntries.slice(0, 3);

  // Kullanıcının rolünü kontrol et
  const role = user && user.role !== undefined ? Number(user.role) : -1;

  // Kullanıcı rolüne göre isim döndür
  const getRoleName = (role) => {
    switch (role) {
      case 0: return 'Free';
      case 1: return 'Normal';
      case 2: return 'VIP';
      case 3: return 'Admin';
      default: return 'Bilinmiyor';
    }
  };

  // Kullanıcı bakiyesi, rol adı ve admin kontrolü
  const balance = user.balance || 0;  // Kullanıcı bakiyesi
  const roleName = getRoleName(role);
  const isAdmin = role === 3;

  // Üyelik süresi bilgisi
  const membershipExpiresAt = user && user.membershipExpiresAt ? user.membershipExpiresAt : null;
  let membershipText = 'Süresiz';
  try {
    if (membershipExpiresAt) {
      const expTs = new Date(membershipExpiresAt).getTime();
      if (!Number.isNaN(expTs)) {
        const diffMs = expTs - Date.now();
        if (diffMs > 0) {
          const daysLeft = Math.ceil(diffMs / (24 * 60 * 60 * 1000));
          membershipText = `${daysLeft} gün kaldı`;
        } else {
          membershipText = 'Süresi doldu';
        }
      }
    }
  } catch (_) {}

  // Get site config from backend (siteConfig.getPublic())
  const siteConfigData = typeof siteConfig !== 'undefined' && siteConfig.getPublic ? siteConfig.getPublic() : {};
  const onlineUserList = getOnlineUsers();
  const duyurular = duyuruStore.readAll();
  res.render('tcgsm', { 
    user,
    csrf: req.session.csrf || '',
    name: user ? user.name : 'Misafir',
    totalUsers,
    role,
    balance,
    roleName,
    lastThreeUsers: [],
    recentLogins,
    timeAgo,
    isAdmin,
    siteName: siteConfigData.siteName || 'Site',
    onlineUsers: onlineUserList,
    onlineCount: onlineUserList.length,
    duyurular,
    membershipExpiresAt,
    membershipText
  });
});


app.get('/tcsorgu', requireAuth, (req, res) => {
  const user = req.session.user;

  // Kullanıcıları veritabanından al
  const users = userStore.readUsers().map(u => ({
    ...u,
    joinDate: u.joinDate || u.createdAt || null,
    balance: u.balance || 0  // Kullanıcıların bakiyelerini al
  }));

  // Kullanıcı sayısı
  const totalUsers = users.length;

  // Son giriş yapanlar: lastLoginByEmailMap'e göre sırala ve ilk 3'ü al
  const lastLoginEntries = [];
  try {
    for (const [email, ts] of lastLoginByEmailMap.entries()) {
      const u = users.find(x => (x.email || '').toLowerCase() === String(email).toLowerCase());
      if (u) lastLoginEntries.push({ ...u, lastLoginAt: ts });
    }
  } catch (_) {}
  lastLoginEntries.sort((a, b) => new Date(b.lastLoginAt) - new Date(a.lastLoginAt));
  const recentLogins = lastLoginEntries.slice(0, 3);

  // Kullanıcının rolünü kontrol et
  const role = user && user.role !== undefined ? Number(user.role) : -1;

  // Kullanıcı rolüne göre isim döndür
  const getRoleName = (role) => {
    switch (role) {
      case 0: return 'Free';
      case 1: return 'Normal';
      case 2: return 'VIP';
      case 3: return 'Admin';
      default: return 'Bilinmiyor';
    }
  };

  // Kullanıcı bakiyesi, rol adı ve admin kontrolü
  const balance = user.balance || 0;  // Kullanıcı bakiyesi
  const roleName = getRoleName(role);
  const isAdmin = role === 3;

  // Üyelik süresi bilgisi
  const membershipExpiresAt = user && user.membershipExpiresAt ? user.membershipExpiresAt : null;
  let membershipText = 'Süresiz';
  try {
    if (membershipExpiresAt) {
      const expTs = new Date(membershipExpiresAt).getTime();
      if (!Number.isNaN(expTs)) {
        const diffMs = expTs - Date.now();
        if (diffMs > 0) {
          const daysLeft = Math.ceil(diffMs / (24 * 60 * 60 * 1000));
          membershipText = `${daysLeft} gün kaldı`;
        } else {
          membershipText = 'Süresi doldu';
        }
      }
    }
  } catch (_) {}

  // Get site config from backend (siteConfig.getPublic())
  const siteConfigData = typeof siteConfig !== 'undefined' && siteConfig.getPublic ? siteConfig.getPublic() : {};
  const onlineUserList = getOnlineUsers();
  const duyurular = duyuruStore.readAll();
  res.render('tcsorgu', { 
    user,
    csrf: req.session.csrf || '',
    name: user ? user.name : 'Misafir',
    totalUsers,
    role,
    balance,
    roleName,
    lastThreeUsers: [],
    recentLogins,
    timeAgo,
    isAdmin,
    siteName: siteConfigData.siteName || 'Site',
    onlineUsers: onlineUserList,
    onlineCount: onlineUserList.length,
    duyurular,
    membershipExpiresAt,
    membershipText
  });
});

app.get('/supportadmin', requireAuth, requireRole([3]), (req, res) => {
  const user = req.session.user;

  // Kullanıcıları veritabanından al
  const users = userStore.readUsers().map(u => ({
    ...u,
    joinDate: u.joinDate || u.createdAt || null,
    balance: u.balance || 0  // Kullanıcıların bakiyelerini al
  }));

  // Kullanıcı sayısı
  const totalUsers = users.length;

  // Kullanıcı rolü ve yetkileri
  const role = user ? user.role : 0;
  const roleName = role === 3 ? 'Admin' : role === 2 ? 'Moderatör' : role === 1 ? 'Üye' : 'Misafir';
  const isAdmin = role === 3;

  // Kullanıcı bakiyesi
  const balance = user ? (user.balance || 0) : 0;

  // Son giriş bilgileri
  let recentLogins = [];
  try {
    const loginLogs = userStore.readUsers().map(u => ({
      name: u.name,
      email: u.email,
      lastLogin: u.lastLogin || u.joinDate || new Date().toISOString()
    })).sort((a, b) => new Date(b.lastLogin) - new Date(a.lastLogin)).slice(0, 5);
    recentLogins = loginLogs;
  } catch (_) {}

  // Zaman hesaplama
  let timeAgo = '';
  try {
    if (user && user.lastLogin) {
      const lastLogin = new Date(user.lastLogin);
      const now = new Date();
      const diffMs = now - lastLogin;
      const diffMins = Math.floor(diffMs / 60000);
      const diffHours = Math.floor(diffMs / 3600000);
      const diffDays = Math.floor(diffMs / 86400000);

      if (diffMins < 1) timeAgo = 'Az önce';
      else if (diffMins < 60) timeAgo = `${diffMins} dakika önce`;
      else if (diffHours < 24) timeAgo = `${diffHours} saat önce`;
      else timeAgo = `${diffDays} gün önce`;
    }
  } catch (_) {}

  // Üyelik süresi
  let membershipExpiresAt = null;
  let membershipText = '';
  try {
    if (user && user.membershipExpiresAt) {
      membershipExpiresAt = user.membershipExpiresAt;
      const expTs = new Date(membershipExpiresAt).getTime();
      if (!Number.isNaN(expTs)) {
        const diffMs = expTs - Date.now();
        if (diffMs > 0) {
          const daysLeft = Math.ceil(diffMs / (24 * 60 * 60 * 1000));
          membershipText = `${daysLeft} gün kaldı`;
        } else {
          membershipText = 'Süresi doldu';
        }
      }
    }
  } catch (_) {}

  // Get site config from backend (siteConfig.getPublic())
  const siteConfigData = typeof siteConfig !== 'undefined' && siteConfig.getPublic ? siteConfig.getPublic() : {};
  const onlineUserList = getOnlineUsers();
  const duyurular = duyuruStore.readAll();
  res.render('supportadmin', { 
    name: user ? user.name : 'Misafir',
    user: user,
    totalUsers,
    role,
    balance,
    roleName,
    lastThreeUsers: [],
    recentLogins,
    timeAgo,
    isAdmin,
    siteName: siteConfigData.siteName || 'Site',
    onlineUsers: onlineUserList,
    onlineCount: onlineUserList.length,
    duyurular,
    membershipExpiresAt,
    membershipText
  });
});

app.get('/support', requireAuth, (req, res) => {
  const user = req.session.user;

  // Kullanıcıları veritabanından al
  const users = userStore.readUsers().map(u => ({
    ...u,
    joinDate: u.joinDate || u.createdAt || null,
    balance: u.balance || 0  // Kullanıcıların bakiyelerini al
  }));

  // Kullanıcı sayısı
  const totalUsers = users.length;

  // Kullanıcı rolü ve yetkileri
  const role = user ? user.role : 0;
  const roleName = role === 3 ? 'Admin' : role === 2 ? 'Moderatör' : role === 1 ? 'Üye' : 'Misafir';
  const isAdmin = role === 3;

  // Kullanıcı bakiyesi
  const balance = user ? (user.balance || 0) : 0;

  // Son giriş bilgileri
  let recentLogins = [];
  try {
    const loginLogs = userStore.readUsers().map(u => ({
      name: u.name,
      email: u.email,
      lastLogin: u.lastLogin || u.joinDate || new Date().toISOString()
    })).sort((a, b) => new Date(b.lastLogin) - new Date(a.lastLogin)).slice(0, 5);
    recentLogins = loginLogs;
  } catch (_) {}

  // Zaman hesaplama
  let timeAgo = '';
  try {
    if (user && user.lastLogin) {
      const lastLogin = new Date(user.lastLogin);
      const now = new Date();
      const diffMs = now - lastLogin;
      const diffMins = Math.floor(diffMs / 60000);
      const diffHours = Math.floor(diffMs / 3600000);
      const diffDays = Math.floor(diffMs / 86400000);

      if (diffMins < 1) timeAgo = 'Az önce';
      else if (diffMins < 60) timeAgo = `${diffMins} dakika önce`;
      else if (diffHours < 24) timeAgo = `${diffHours} saat önce`;
      else timeAgo = `${diffDays} gün önce`;
    }
  } catch (_) {}

  // Üyelik süresi
  let membershipExpiresAt = null;
  let membershipText = '';
  try {
    if (user && user.membershipExpiresAt) {
      membershipExpiresAt = user.membershipExpiresAt;
      const expTs = new Date(membershipExpiresAt).getTime();
      if (!Number.isNaN(expTs)) {
        const diffMs = expTs - Date.now();
        if (diffMs > 0) {
          const daysLeft = Math.ceil(diffMs / (24 * 60 * 60 * 1000));
          membershipText = `${daysLeft} gün kaldı`;
        } else {
          membershipText = 'Süresi doldu';
        }
      }
    }
  } catch (_) {}

  // Get site config from backend (siteConfig.getPublic())
  const siteConfigData = typeof siteConfig !== 'undefined' && siteConfig.getPublic ? siteConfig.getPublic() : {};
  const onlineUserList = getOnlineUsers();
  const duyurular = duyuruStore.readAll();
  res.render('support', { 
    name: user ? user.name : 'Misafir',
    user: user,
    totalUsers,
    role,
    balance,
    roleName,
    lastThreeUsers: [],
    recentLogins,
    timeAgo,
    isAdmin,
    siteName: siteConfigData.siteName || 'Site',
    onlineUsers: onlineUserList,
    onlineCount: onlineUserList.length,
    duyurular,
    membershipExpiresAt,
    membershipText
  });
});

app.get('/logs', requireAuth, requireRole([3]), (req, res) => {
  const user = req.session.user;

  // Kullanıcıları veritabanından al
  const users = userStore.readUsers().map(u => ({
    ...u,
    joinDate: u.joinDate || u.createdAt || null,
    balance: u.balance || 0  // Kullanıcıların bakiyelerini al
  }));

  // Kullanıcı sayısı
  const totalUsers = users.length;

  // Son giriş yapanlar: lastLoginByEmailMap'e göre sırala ve ilk 3'ü al
  const lastLoginEntries = [];
  try {
    for (const [email, ts] of lastLoginByEmailMap.entries()) {
      const u = users.find(x => (x.email || '').toLowerCase() === String(email).toLowerCase());
      if (u) lastLoginEntries.push({ ...u, lastLoginAt: ts });
    }
  } catch (_) {}
  lastLoginEntries.sort((a, b) => new Date(b.lastLoginAt) - new Date(a.lastLoginAt));
  const recentLogins = lastLoginEntries.slice(0, 3);

  // Kullanıcının rolünü kontrol et
  const role = user && user.role !== undefined ? Number(user.role) : -1;

  // Kullanıcı rolüne göre isim döndür
  const getRoleName = (role) => {
    switch (role) {
      case 0: return 'Free';
      case 1: return 'Normal';
      case 2: return 'VIP';
      case 3: return 'Admin';
      default: return 'Bilinmiyor';
    }
  };

  // Kullanıcı bakiyesi, rol adı ve admin kontrolü
  const balance = user.balance || 0;  // Kullanıcı bakiyesi
  const roleName = getRoleName(role);
  const isAdmin = role === 3;

  // Üyelik süresi bilgisi
  const membershipExpiresAt = user && user.membershipExpiresAt ? user.membershipExpiresAt : null;
  let membershipText = 'Süresiz';
  try {
    if (membershipExpiresAt) {
      const expTs = new Date(membershipExpiresAt).getTime();
      if (!Number.isNaN(expTs)) {
        const diffMs = expTs - Date.now();
        if (diffMs > 0) {
          const daysLeft = Math.ceil(diffMs / (24 * 60 * 60 * 1000));
          membershipText = `${daysLeft} gün kaldı`;
        } else {
          membershipText = 'Süresi doldu';
        }
      }
    }
  } catch (_) {}

  // Get site config from backend (siteConfig.getPublic())
  const siteConfigData = typeof siteConfig !== 'undefined' && siteConfig.getPublic ? siteConfig.getPublic() : {};
  const onlineUserList = getOnlineUsers();
  const duyurular = duyuruStore.readAll();
  res.render('logs', { 
    name: user ? user.name : 'Misafir',
    totalUsers,
    role,
    balance,
    roleName,
    lastThreeUsers: [],
    recentLogins,
    timeAgo,
    isAdmin,
    siteName: siteConfigData.siteName || 'Site',
    onlineUsers: onlineUserList,
    onlineCount: onlineUserList.length,
    duyurular,
    membershipExpiresAt,
    membershipText
  });
});


app.get('/sorgular', requireAuth, (req, res) => {
  const user = req.session.user;

  // Kullanıcıları veritabanından al
  const users = userStore.readUsers().map(u => ({
    ...u,
    joinDate: u.joinDate || u.createdAt || null,
    balance: u.balance || 0  // Kullanıcıların bakiyelerini al
  }));

  // Kullanıcı sayısı
  const totalUsers = users.length;

  // Son giriş yapanlar: lastLoginByEmailMap'e göre sırala ve ilk 3'ü al
  const lastLoginEntries = [];
  try {
    for (const [email, ts] of lastLoginByEmailMap.entries()) {
      const u = users.find(x => (x.email || '').toLowerCase() === String(email).toLowerCase());
      if (u) lastLoginEntries.push({ ...u, lastLoginAt: ts });
    }
  } catch (_) {}
  lastLoginEntries.sort((a, b) => new Date(b.lastLoginAt) - new Date(a.lastLoginAt));
  const recentLogins = lastLoginEntries.slice(0, 3);

  // Kullanıcının rolünü kontrol et
  const role = user && user.role !== undefined ? Number(user.role) : -1;

  // Kullanıcı rolüne göre isim döndür
  const getRoleName = (role) => {
    switch (role) {
      case 0: return 'Free';
      case 1: return 'Normal';
      case 2: return 'VIP';
      case 3: return 'Admin';
      default: return 'Bilinmiyor';
    }
  };

  // Kullanıcı bakiyesi, rol adı ve admin kontrolü
  const balance = user.balance || 0;  // Kullanıcı bakiyesi
  const roleName = getRoleName(role);
  const isAdmin = role === 3;

  // Üyelik süresi bilgisi
  const membershipExpiresAt = user && user.membershipExpiresAt ? user.membershipExpiresAt : null;
  let membershipText = 'Süresiz';
  try {
    if (membershipExpiresAt) {
      const expTs = new Date(membershipExpiresAt).getTime();
      if (!Number.isNaN(expTs)) {
        const diffMs = expTs - Date.now();
        if (diffMs > 0) {
          const daysLeft = Math.ceil(diffMs / (24 * 60 * 60 * 1000));
          membershipText = `${daysLeft} gün kaldı`;
        } else {
          membershipText = 'Süresi doldu';
        }
      }
    }
  } catch (_) {}

  // Get site config from backend (siteConfig.getPublic())
  const siteConfigData = typeof siteConfig !== 'undefined' && siteConfig.getPublic ? siteConfig.getPublic() : {};
  const onlineUserList = getOnlineUsers();
  const duyurular = duyuruStore.readAll();
  res.render('sorgular', { 
    name: user ? user.name : 'Misafir',
    user: user, // Add user object to template
    totalUsers,
    role,
    balance,
    roleName,
    lastThreeUsers: [],
    recentLogins,
    timeAgo,
    isAdmin,
    siteName: siteConfigData.siteName || 'Site',
    onlineUsers: onlineUserList,
    onlineCount: onlineUserList.length,
    duyurular,
    membershipExpiresAt,
    membershipText
  });
});


// Pending Users - Admin
app.get('/kullanicionay', requireAuth, requireRole([3]), (req, res) => {
  try {
    const user = req.session.user;
    const siteConfigData = siteConfig.getPublic();
    const pending = pendingStore.readAll();
    res.render('kullanicionay', {
      name: user?.name || 'Admin',
      siteName: siteConfigData.siteName || 'Site',
      pendingUsers: pending,
      totalUsers: 0,
      roleName: 'Admin',
      balance: user?.balance || 0,
      timeAgo,
      isAdmin: true
    });
  } catch (_) {
    res.status(500).send('Hata');
  }
});

app.get('/api/pending-users', requireAuth, requireRole([3]), (req, res) => {
  return res.json({ ok: true, data: pendingStore.readAll() });
});

app.post('/api/pending-users/:id/approve', requireAuth, requireRole([3]), (req, res) => {
  try {
    if (!isRequestAllowed(req)) return res.status(403).json({ ok: false, message: 'İnternet bağlantınızı kontrol edin.' });
    const { id } = req.params;
    const rec = pendingStore.findById(id);
    if (!rec) return res.status(404).json({ ok: false, message: 'Kayıt bulunamadı' });
    const users = userStore.readUsers();
    if (userStore.findUserByEmail(rec.email)) {
      pendingStore.removeById(id);
      return res.json({ ok: true, message: 'Zaten kayıtlı' });
    }
    const newUserId = Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
    const role = 0;
    const joinDate = new Date().toISOString();
    const { defaultMembershipDays } = siteConfig.getPublic();
    const days = Number(defaultMembershipDays) || 30;
    const membershipExpiresAt = days > 0 ? new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString() : null;
    users.push({ id: newUserId, email: rec.email, password: rec.password, name: rec.name, role, ip: rec.ip, balance: 0, joinDate, membershipExpiresAt });
    if (!userStore.writeEncryptedUsers(users)) return res.status(500).json({ ok: false, message: 'Kullanıcı eklenemedi' });
    pendingStore.removeById(id);
    return res.json({ ok: true });
  } catch (_) {
    return res.status(500).json({ ok: false, message: 'Sunucu hatası' });
  }
});

app.delete('/api/pending-users/:id', requireAuth, requireRole([3]), (req, res) => {
  try {
    if (!isRequestAllowed(req)) return res.status(403).json({ ok: false, message: 'İnternet bağlantınızı kontrol edin.' });
    const { id } = req.params;
    const { ok } = pendingStore.removeById(id);
    if (!ok) return res.status(500).json({ ok: false, message: 'Kayıt silinemedi' });
    return res.json({ ok: true });
  } catch (_) {
    return res.status(500).json({ ok: false, message: 'Sunucu hatası' });
  }
});







app.get('/updateUser/:id', requireAuth, requireRole([3]), (req, res) => {
  try {
    const { id } = req.params;
    const { name, email, role, balance, queryCredits, status } = req.query;

    let list = userStore.readUsers();
    const idx = list.findIndex(u => String(u && u.id) === String(id));
    if (idx === -1) {
      return res.status(404).json({ ok: false, message: 'Kullanıcı bulunamadı' });
    }

    const user = list[idx];
    if (typeof name === 'string' && name.trim() && name !== user.name) user.name = name.trim();
    if (typeof email === 'string' && email.trim()) user.email = email.trim();

    if (typeof role !== 'undefined' && role !== '') {
      const newRole = Number(role);
      const currentRole = Number(user.role);
      if (!Number.isNaN(newRole)) {
        if (currentRole === 3 && newRole !== 3) {
          // admin düşürülemez
        } else if (currentRole !== 3 && newRole === 3) {
          // admin yapılamaz
        } else {
          user.role = newRole;
        }
      }
    }
    if (typeof balance !== 'undefined' && balance !== '') {
      const nb = Number(balance);
      if (!Number.isNaN(nb)) user.balance = nb;
    }
    if (typeof queryCredits !== 'undefined' && queryCredits !== '') {
      const qc = Number(queryCredits);
      if (!Number.isNaN(qc) && qc >= 0) user.queryCredits = qc;
    }
    if (typeof status === 'string' && status) user.status = status;

    list[idx] = user;
    const ok = userStore.writeEncryptedUsers(list);
    if (!ok) return res.status(500).json({ ok: false, message: 'Kullanıcı güncellenemedi' });

    return res.status(200).json({
      ok: true,
      message: 'Kullanıcı başarıyla güncellendi',
      updatedUser: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        balance: user.balance,
        status: user.status
      }
    });
  } catch (err) {
    return res.status(500).json({ ok: false, message: 'Sunucu hatası' });
  }
});


app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// EJS ayarları
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.static(path.join(__dirname, 'public')));

// Global bakiye güncelleme middleware'i - tüm route'larda çalışır
app.use(updateUserSession);


// Logs API endpoint
app.get('/api/admin/logs', requireAuth, requireRole([3]), (req, res) => {
  try {
    const { page = 1, limit = 50, search = '' } = req.query;
    const logs = queryLogStore.getRecentLogs(1000); // Son 1000 log
    
    // Search filter
    let filteredLogs = logs;
    if (search) {
      const searchLower = search.toLowerCase();
      filteredLogs = logs.filter(log => 
        (log.userName || '').toLowerCase().includes(searchLower) ||
        (log.userEmail || '').toLowerCase().includes(searchLower) ||
        (log.queryType || '').toLowerCase().includes(searchLower) ||
        (log.ip || '').toLowerCase().includes(searchLower)
      );
    }
    
    // Pagination
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + parseInt(limit);
    const paginatedLogs = filteredLogs.slice(startIndex, endIndex);
    
    res.json({ 
      ok: true, 
      logs: paginatedLogs,
      total: filteredLogs.length,
      page: parseInt(page),
      limit: parseInt(limit),
      totalPages: Math.ceil(filteredLogs.length / limit)
    });
  } catch (error) {
    console.error('Logs API error:', error);
    res.status(500).json({ ok: false, message: 'Logs yüklenemedi' });
  }
});

// Admin create user API
app.post('/api/admin/users', requireAuth, requireRole([3]), (req, res) => {
  try {
    const { name, email, password, role, balance, queryCredits } = req.body;
    
    if (!name || !email || !password) {
      return res.status(400).json({ ok: false, message: 'Ad, email ve şifre zorunludur' });
    }
    
    const userList = userStore.readUsers();
    
    // Check if email already exists
    if (userList.find(u => u.email === email.toLowerCase())) {
      return res.status(409).json({ ok: false, message: 'Bu email adresi zaten kullanılıyor' });
    }
    
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
    const newUser = {
      id,
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password,
      role: Number(role) || 0,
      balance: Number(balance) || 0,
      queryCredits: Number(queryCredits) || 30,
      joinDate: new Date().toISOString(),
      ip: req.ip || '127.0.0.1'
    };
    
    userList.push(newUser);
    
    if (!userStore.writeEncryptedUsers(userList)) {
      return res.status(500).json({ ok: false, message: 'Kullanıcı oluşturulamadı' });
    }
    
    res.json({ ok: true, message: 'Kullanıcı başarıyla oluşturuldu' });
  } catch (error) {
    console.error('Create user error:', error);
    res.status(500).json({ ok: false, message: 'Kullanıcı oluşturulamadı' });
  }
});

app.post('/api/adsoyad', requireAuth, async (req, res) => {
  try {
    const { ad, soyad, il } = req.body;
    if (!ad || !soyad) {
      return res.status(400).json({ ok: false, message: 'Ad ve soyad zorunlu ya' });
    }

    // Kullanıcı sorgu hakkı kontrolü
    const userEmail = req.session?.user?.email;
    if (!userEmail) {
      return res.status(401).json({ ok: false, message: 'Oturum bulunamadı' });
    }

    const userList = userStore.readUsers();
    const user = userList.find(u => u.email === userEmail);
    if (!user) {
      return res.status(404).json({ ok: false, message: 'Kullanıcı bulunamadı' });
    }

    // Sorgu hakkı kontrolü
    if (!user.queryCredits || user.queryCredits <= 0) {
      return res.status(403).json({ ok: false, message: 'Sorgu limitini aştınız. Sorgu hakkınız kalmadı.' });
    }

    const response = await axios.get(`https://api.kahin.org/kahinapi/adsoyadpro?ad=${ad}&soyad=${soyad}&il=${il || ''}`);
    if (!response.data.success || !Array.isArray(response.data.data) || response.data.data.length === 0) {
      return res.status(404).json({ ok: false, message: 'Veri bulunamadı işte' });
    }

    // Sorgu hakkını azalt
    user.queryCredits = Math.max(0, user.queryCredits - 1);
    
    // Kullanıcı listesini güncelle
    const userIndex = userList.findIndex(u => u.email === userEmail);
    if (userIndex !== -1) {
      userList[userIndex] = user;
      userStore.writeEncryptedUsers(userList);
    }

    const users = response.data.data.map(u => ({
      ID: u.ID,
      TC: u.TC,
      AD: u.AD,
      SOYAD: u.SOYAD,
      GSM: u.GSM || 'Yok bilgi',
      BABAADI: u.BABAADI,
      BABATC: u.BABATC,
      ANNEADI: u.ANNEADI,
      ANNETC: u.ANNETC,
      DOGUMTARIHI: u.DOGUMTARIHI,
      OLUMTARIHI: u.OLUMTARIHI,
      DOGUMYERI: u.DOGUMYERI,
      MEMLEKETIL: u.MEMLEKETIL,
      MEMLEKETILCE: u.MEMLEKETILCE,
      MEMLEKETKOY: u.MEMLEKETKOY,
      ADRESIL: u.ADRESIL,
      ADRESILCE: u.ADRESILCE,
      AILESIRANO: u.AILESIRANO,
      BIREYSIRANO: u.BIREYSIRANO,
      MEDENIHAL: u.MEDENIHAL,
      CINSIYET: u.CINSIYET
    }));

    // Sorgu logunu kaydet
    queryLogStore.addLog({
      userEmail: user.email,
      userName: user.name,
      queryType: 'Ad Soyad Pro',
      parameters: JSON.stringify({ ad, soyad, il }),
      resultCount: users.length,
      ip: req.ip || req.connection.remoteAddress || '127.0.0.1',
      success: true
    });

    return res.json({ ok: true, data: users, remainingCredits: user.queryCredits });
  } catch (err) {
    console.error('Api çağrılırken bi sıkıntı oldu:', err);
    
    // Hata durumunda da log kaydet
    const userEmail = req.session?.user?.email;
    if (userEmail) {
      const userList = userStore.readUsers();
      const user = userList.find(u => u.email === userEmail);
      if (user) {
        queryLogStore.addLog({
          userEmail: user.email,
          userName: user.name,
          queryType: 'Ad Soyad Pro',
          parameters: JSON.stringify({ ad: req.body.ad, soyad: req.body.soyad, il: req.body.il }),
          resultCount: 0,
          ip: req.ip || req.connection.remoteAddress || '127.0.0.1',
          success: false,
          error: err.message
        });
      }
    }
    
    return res.status(500).json({ ok: false, message: 'Sunucu şu an sorunlu, bi ara tekrar dene' });
  }
});

// TC Sorgulama API
app.post('/api/tcpro', requireAuth, async (req, res) => {
  try {
    const { tc } = req.body;
    if (!tc) {
      return res.status(400).json({ ok: false, message: 'TC kimlik numarası zorunlu' });
    }

    // TC format kontrolü (11 haneli sayı)
    if (!/^\d{11}$/.test(tc)) {
      return res.status(400).json({ ok: false, message: 'Geçerli bir TC kimlik numarası giriniz (11 haneli)' });
    }

    // Kullanıcı sorgu hakkı kontrolü
    const userEmail = req.session?.user?.email;
    if (!userEmail) {
      return res.status(401).json({ ok: false, message: 'Oturum bulunamadı' });
    }

    const userList = userStore.readUsers();
    const user = userList.find(u => u.email === userEmail);
    if (!user) {
      return res.status(404).json({ ok: false, message: 'Kullanıcı bulunamadı' });
    }

    // Günlük sorgu hakkı reset kontrolü
    const wasReset = resetDailyQueryCredits(user);
    if (wasReset) {
      // Reset yapıldıysa kullanıcı listesini güncelle
      const userIndex = userList.findIndex(u => u.email === userEmail);
      if (userIndex !== -1) {
        userList[userIndex] = user;
        userStore.writeEncryptedUsers(userList);
      }
    }

    // Sorgu hakkı kontrolü
    if (!user.queryCredits || user.queryCredits <= 0) {
      return res.status(403).json({ ok: false, message: 'Sorgu limitini aştınız. Sorgu hakkınız kalmadı.' });
    }

    const response = await axios.get(`https://api.kahin.org/kahinapi/tcpro?tc=${tc}`);
    if (!response.data.success || !Array.isArray(response.data.data) || response.data.data.length === 0) {
      return res.status(404).json({ ok: false, message: 'Bu TC kimlik numarası için veri bulunamadı' });
    }

    // Sorgu hakkını azalt
    user.queryCredits = Math.max(0, user.queryCredits - 1);
    
    // Kullanıcı listesini güncelle
    const userIndex = userList.findIndex(u => u.email === userEmail);
    if (userIndex !== -1) {
      userList[userIndex] = user;
      userStore.writeEncryptedUsers(userList);
    }

    const users = response.data.data.map(u => ({
      ID: u.ID,
      TC: u.TC,
      AD: u.Ad,
      SOYAD: u.Soyad,
      GSM: u.GSM || 'Yok bilgi',
      BABAADI: u.BabaAdi,
      BABATC: u.BabaTC,
      ANNEADI: u.AnneAdi,
      ANNETC: u.AnneTC,
      DOGUMTARIHI: u.DogumTarihi,
      OLUMTARIHI: u.OlumTarihi,
      DOGUMYERI: u.DogumYeri,
      MEMLEKETIL: u.MemleketIl,
      MEMLEKETILCE: u.MemleketIlce,
      MEMLEKETKOY: u.MemleketKoy,
      ADRESIL: u.AdresIl,
      ADRESILCE: u.AdresIlce,
      AILESIRANO: u.AileSiraNo,
      BIREYSIRANO: u.BireySiraNo,
      MEDENIHAL: u.MedeniHal,
      CINSIYET: u.Cinsiyet === 'Erkek' ? 'E' : 'K'
    }));

    // Sorgu logunu kaydet
    queryLogStore.addLog({
      userEmail: user.email,
      userName: user.name,
      queryType: 'TC Pro',
      parameters: JSON.stringify({ tc }),
      resultCount: users.length,
      ip: req.ip || req.connection.remoteAddress || '127.0.0.1',
      success: true
    });

    return res.json({ ok: true, data: users, remainingCredits: user.queryCredits });
  } catch (err) {
    console.error('TC API çağrılırken bi sıkıntı oldu:', err);
    
    // Hata durumunda da log kaydet
    const userEmail = req.session?.user?.email;
    if (userEmail) {
      const userList = userStore.readUsers();
      const user = userList.find(u => u.email === userEmail);
      if (user) {
        queryLogStore.addLog({
          userEmail: user.email,
          userName: user.name,
          queryType: 'TC Pro',
          parameters: JSON.stringify({ tc: req.body.tc }),
          resultCount: 0,
          ip: req.ip || req.connection.remoteAddress || '127.0.0.1',
          success: false,
          error: err.message
        });
      }
    }
    
    return res.status(500).json({ ok: false, message: 'API çağrısı başarısız oldu' });
  }
});

// TC → GSM API
app.post('/api/tcgsm', requireAuth, async (req, res) => {
  try {
    const { tc } = req.body;
    
    if (!tc || !/^\d{11}$/.test(tc)) {
      return res.status(400).json({ ok: false, message: 'Geçerli bir TC kimlik numarası giriniz' });
    }

    const userEmail = req.session?.user?.email;
    if (!userEmail) {
      return res.status(401).json({ ok: false, message: 'Oturum bulunamadı' });
    }

    const userList = userStore.readUsers();
    const user = userList.find(u => u.email === userEmail);
    if (!user || user.queryCredits <= 0) {
      return res.status(400).json({ ok: false, message: 'Sorgu limitini aştınız' });
    }

    const response = await axios.get(`https://api.kahin.org/kahinapi/tcgsm?tc=${tc}`);
    
    if (response.data.success && response.data.data) {
      // Deduct credit
      user.queryCredits = Math.max(0, user.queryCredits - 1);
      const userIndex = userList.findIndex(u => u.email === userEmail);
      if (userIndex !== -1) {
        userList[userIndex] = user;
        userStore.writeEncryptedUsers(userList);
      }
      
      // Log query
      queryLogStore.addLog({
        userEmail: user.email,
        userName: user.name,
        queryType: 'TC → GSM',
        parameters: JSON.stringify({ tc }),
        resultCount: response.data.data.length,
        ip: req.ip || req.connection.remoteAddress || '127.0.0.1',
        success: true
      });
      
      res.json({ ok: true, data: response.data.data, remainingCredits: user.queryCredits });
    } else {
      res.json({ ok: false, message: 'Bu TC kimlik numarası için GSM verisi bulunamadı', remainingCredits: user.queryCredits });
    }
  } catch (error) {
    console.error('TC → GSM API Error:', error);
    res.status(500).json({ ok: false, message: 'API hatası oluştu' });
  }
});

// GSM → TC API
app.post('/api/gsmtc', requireAuth, async (req, res) => {
  try {
    const { gsm } = req.body;
    
    if (!gsm || !/^\d{10}$/.test(gsm)) {
      return res.status(400).json({ ok: false, message: 'Geçerli bir GSM numarası giriniz (10 haneli)' });
    }

    const userEmail = req.session?.user?.email;
    if (!userEmail) {
      return res.status(401).json({ ok: false, message: 'Oturum bulunamadı' });
    }

    const userList = userStore.readUsers();
    const user = userList.find(u => u.email === userEmail);
    if (!user || user.queryCredits <= 0) {
      return res.status(400).json({ ok: false, message: 'Sorgu limitini aştınız' });
    }

    const response = await axios.get(`https://api.kahin.org/kahinapi/gsmtc?gsm=${gsm}`);
    
    if (response.data.success && response.data.data) {
      // Deduct credit
      user.queryCredits = Math.max(0, user.queryCredits - 1);
      const userIndex = userList.findIndex(u => u.email === userEmail);
      if (userIndex !== -1) {
        userList[userIndex] = user;
        userStore.writeEncryptedUsers(userList);
      }
      
      // Log query
      queryLogStore.addLog({
        userEmail: user.email,
        userName: user.name,
        queryType: 'GSM → TC',
        parameters: JSON.stringify({ gsm }),
        resultCount: response.data.data.length,
        ip: req.ip || req.connection.remoteAddress || '127.0.0.1',
        success: true
      });
      
      res.json({ ok: true, data: response.data.data, remainingCredits: user.queryCredits });
    } else {
      res.json({ ok: false, message: 'Bu GSM numarası için TC verisi bulunamadı', remainingCredits: user.queryCredits });
    }
  } catch (error) {
    console.error('GSM → TC API Error:', error);
    res.status(500).json({ ok: false, message: 'API hatası oluştu' });
  }
});

// Adres API
app.post('/api/adres', requireAuth, async (req, res) => {
  try {
    const { tc } = req.body;
    
    if (!tc || !/^\d{11}$/.test(tc)) {
      return res.status(400).json({ ok: false, message: 'Geçerli bir TC kimlik numarası giriniz' });
    }

    const userEmail = req.session?.user?.email;
    if (!userEmail) {
      return res.status(401).json({ ok: false, message: 'Oturum bulunamadı' });
    }

    const userList = userStore.readUsers();
    const user = userList.find(u => u.email === userEmail);
    if (!user || user.queryCredits <= 0) {
      return res.status(400).json({ ok: false, message: 'Sorgu limitini aştınız' });
    }

    const response = await axios.get(`https://api.kahin.org/kahinapi/adres.php?tc=${tc}`);
    
    if (response.data.success && response.data.data) {
      // Deduct credit
      user.queryCredits = Math.max(0, user.queryCredits - 1);
      const userIndex = userList.findIndex(u => u.email === userEmail);
      if (userIndex !== -1) {
        userList[userIndex] = user;
        userStore.writeEncryptedUsers(userList);
      }
      
      // Log query
      queryLogStore.addLog({
        userEmail: user.email,
        userName: user.name,
        queryType: 'Adres Sorgusu',
        parameters: JSON.stringify({ tc }),
        resultCount: response.data.data.length,
        ip: req.ip || req.connection.remoteAddress || '127.0.0.1',
        success: true
      });
      
      res.json({ ok: true, data: response.data.data, remainingCredits: user.queryCredits });
    } else {
      res.json({ ok: false, message: 'Bu TC kimlik numarası için adres verisi bulunamadı', remainingCredits: user.queryCredits });
    }
  } catch (error) {
    console.error('Adres API Error:', error);
    res.status(500).json({ ok: false, message: 'API hatası oluştu' });
  }
});

// Aile Pro API
app.post('/api/ailepro', requireAuth, async (req, res) => {
  try {
    const { tc } = req.body;
    
    if (!tc || !/^\d{11}$/.test(tc)) {
      return res.status(400).json({ ok: false, message: 'Geçerli bir TC kimlik numarası giriniz' });
    }

    const userEmail = req.session?.user?.email;
    if (!userEmail) {
      return res.status(401).json({ ok: false, message: 'Oturum bulunamadı' });
    }

    const userList = userStore.readUsers();
    const user = userList.find(u => u.email === userEmail);
    if (!user || user.queryCredits <= 0) {
      return res.status(400).json({ ok: false, message: 'Sorgu limitini aştınız' });
    }

    const response = await axios.get(`https://api.kahin.org/kahinapi/ailepro?tc=${tc}`);
    
    if (response.data.durum === 'başarılı' && response.data.veri) {
      // Deduct credit
      user.queryCredits = Math.max(0, user.queryCredits - 1);
      const userIndex = userList.findIndex(u => u.email === userEmail);
      if (userIndex !== -1) {
        userList[userIndex] = user;
        userStore.writeEncryptedUsers(userList);
      }
      
      // Log query
      queryLogStore.addLog({
        userEmail: user.email,
        userName: user.name,
        queryType: 'Aile Pro',
        parameters: JSON.stringify({ tc }),
        resultCount: 1,
        ip: req.ip || req.connection.remoteAddress || '127.0.0.1',
        success: true
      });
      
      res.json({ ok: true, data: response.data, remainingCredits: user.queryCredits });
    } else {
      res.json({ ok: false, message: 'Bu TC kimlik numarası için aile verisi bulunamadı', remainingCredits: user.queryCredits });
    }
  } catch (error) {
    console.error('Aile Pro API Error:', error);
    res.status(500).json({ ok: false, message: 'API hatası oluştu' });
  }
});

// Sülale API
app.post('/api/sulale', requireAuth, async (req, res) => {
  try {
    const { tc } = req.body;
    
    if (!tc || !/^\d{11}$/.test(tc)) {
      return res.status(400).json({ ok: false, message: 'Geçerli bir TC kimlik numarası giriniz' });
    }

    const userEmail = req.session?.user?.email;
    if (!userEmail) {
      return res.status(401).json({ ok: false, message: 'Oturum bulunamadı' });
    }

    const userList = userStore.readUsers();
    const user = userList.find(u => u.email === userEmail);
    if (!user || user.queryCredits <= 0) {
      return res.status(400).json({ ok: false, message: 'Sorgu limitini aştınız' });
    }

    const response = await axios.get(`https://api.kahin.org/kahinapi/sulale?tc=${tc}`);
    
    if (!response.data.success || !Array.isArray(response.data.data) || response.data.data.length === 0) {
      return res.status(404).json({ ok: false, message: 'Bu TC kimlik numarası için sülale verisi bulunamadı' });
    }

    // Sorgu hakkını azalt
    user.queryCredits = Math.max(0, user.queryCredits - 1);
    
    // Kullanıcı listesini güncelle
    const userIndex = userList.findIndex(u => u.email === userEmail);
    if (userIndex !== -1) {
      userList[userIndex] = user;
      userStore.writeEncryptedUsers(userList);
    }

    const sulaleMembers = response.data.data.map(member => ({
      ID: member.ID,
      YAKINLIK: member.YAKINLIK,
      TC: member.TC,
      ADI: member.ADI,
      SOYADI: member.SOYADI,
      GSM: member.GSM || 'Yok bilgi',
      BABAADI: member.BABAADI,
      BabaTC: member.BabaTC,
      ANNEADI: member.ANNEADI,
      AnneTC: member.AnneTC,
      DOGUMTARIHI: member.DOGUMTARIHI,
      OlumTarihi: member.OlumTarihi,
      DogumYeri: member.DogumYeri,
      MemleketIl: member.MemleketIl,
      MemleketIlce: member.MemleketIlce,
      MemleketKoy: member.MemleketKoy,
      AdresIl: member.AdresIl,
      AdresIlce: member.AdresIlce,
      AileSiraNo: member.AileSiraNo,
      BireySiraNo: member.BireySiraNo,
      MedeniHal: member.MedeniHal,
      Cinsiyet: member.Cinsiyet
    }));

    // Sorgu logunu kaydet
    queryLogStore.addLog({
      userEmail: user.email,
      userName: user.name,
      queryType: 'Sülale Sorgusu',
      parameters: JSON.stringify({ tc }),
      resultCount: sulaleMembers.length,
      ip: req.ip || req.connection.remoteAddress || '127.0.0.1',
      success: true
    });

    res.json({ ok: true, data: sulaleMembers, remainingCredits: user.queryCredits });
  } catch (error) {
    console.error('Sülale API Error:', error);
    console.error('Error details:', error.response?.data || error.message);
    res.status(500).json({ ok: false, message: 'API hatası oluştu: ' + (error.response?.data?.message || error.message) });
  }
});

// Tapu API
app.post('/api/tapu', requireAuth, async (req, res) => {
  try {
    const { tc } = req.body;
    
    if (!tc || !/^\d{11}$/.test(tc)) {
      return res.status(400).json({ ok: false, message: 'Geçerli bir TC kimlik numarası giriniz' });
    }

    const userEmail = req.session?.user?.email;
    if (!userEmail) {
      return res.status(401).json({ ok: false, message: 'Oturum bulunamadı' });
    }

    const userList = userStore.readUsers();
    const user = userList.find(u => u.email === userEmail);
    if (!user) {
      return res.status(404).json({ ok: false, message: 'Kullanıcı bulunamadı' });
    }

    // Sorgu hakkı kontrolü
    if (!user.queryCredits || user.queryCredits <= 0) {
      return res.status(403).json({ ok: false, message: 'Sorgu limitini aştınız. Sorgu hakkınız kalmadı.' });
    }

    const response = await axios.get(`https://api.kahin.org/kahinapi/tapu?tc=${tc}`);
    if (!response.data.success || !response.data.data) {
      return res.status(404).json({ ok: false, message: 'Bu TC kimlik numarası için tapu verisi bulunamadı' });
    }

    // Sorgu hakkını azalt
    user.queryCredits = Math.max(0, user.queryCredits - 1);
    
    // Kullanıcı listesini güncelle
    const userIndex = userList.findIndex(u => u.email === userEmail);
    if (userIndex !== -1) {
      userList[userIndex] = user;
      userStore.writeEncryptedUsers(userList);
    }

    const tapuData = {
      Id: response.data.data.Id,
      İlBilgisi: response.data.data.İlBilgisi,
      İlceBilgisi: response.data.data.İlceBilgisi,
      MahalleBilgisi: response.data.data.MahalleBilgisi,
      ZeminTipBilgisi: response.data.data.ZeminTipBilgisi,
      AdaBilgisi: response.data.data.AdaBilgisi,
      ParselBilgisi: response.data.data.ParselBilgisi,
      YuzolcumBilgisi: response.data.data.YuzolcumBilgisi,
      AnaTasinmazNitelik: response.data.data.AnaTasinmazNitelik,
      BlokBilgisi: response.data.data.BlokBilgisi,
      BagimsizBolumNo: response.data.data.BagimsizBolumNo,
      ArsaPay: response.data.data.ArsaPay,
      ArsaPayda: response.data.data.ArsaPayda,
      BagimsizBolumNitelik: response.data.data.BagimsizBolumNitelik,
      Name: response.data.data.Name,
      Surname: response.data.data.Surname,
      BabaAdi: response.data.data.BabaAdi,
      Identify: response.data.data.Identify,
      IstirakNo: response.data.data.IstirakNo,
      HissePay: response.data.data.HissePay,
      HissePayda: response.data.data.HissePayda,
      EdinmeSebebi: response.data.data.EdinmeSebebi,
      TapuDate: response.data.data.TapuDate,
      Yevmiye: response.data.data.Yevmiye
    };

    // Sorgu logunu kaydet
    queryLogStore.addLog({
      userEmail: user.email,
      userName: user.name,
      queryType: 'Tapu Sorgusu',
      parameters: JSON.stringify({ tc }),
      resultCount: 1,
      ip: req.ip || req.connection.remoteAddress || '127.0.0.1',
      success: true
    });

    return res.json({ ok: true, data: tapuData, remainingCredits: user.queryCredits });
  } catch (err) {
    console.error('Tapu API çağrılırken bi sıkıntı oldu:', err);
    
    // Hata durumunda da log kaydet
    const userEmail = req.session?.user?.email;
    if (userEmail) {
      const userList = userStore.readUsers();
      const user = userList.find(u => u.email === userEmail);
      if (user) {
        queryLogStore.addLog({
          userEmail: user.email,
          userName: user.name,
          queryType: 'Tapu Sorgusu',
          parameters: JSON.stringify({ tc: req.body.tc }),
          resultCount: 0,
          ip: req.ip || req.connection.remoteAddress || '127.0.0.1',
          success: false,
          error: err.message
        });
      }
    }
    
    return res.status(500).json({ ok: false, message: 'API çağrısı başarısız oldu' });
  }
});

// İş Yeri API
app.post('/api/isyeri', requireAuth, async (req, res) => {
  try {
    const { tc } = req.body;
    
    if (!tc || !/^\d{11}$/.test(tc)) {
      return res.status(400).json({ ok: false, message: 'Geçerli bir TC kimlik numarası giriniz' });
    }

    const userEmail = req.session?.user?.email;
    if (!userEmail) {
      return res.status(401).json({ ok: false, message: 'Oturum bulunamadı' });
    }

    const userList = userStore.readUsers();
    const user = userList.find(u => u.email === userEmail);
    if (!user) {
      return res.status(404).json({ ok: false, message: 'Kullanıcı bulunamadı' });
    }

    // Sorgu hakkı kontrolü
    if (!user.queryCredits || user.queryCredits <= 0) {
      return res.status(403).json({ ok: false, message: 'Sorgu limitini aştınız. Sorgu hakkınız kalmadı.' });
    }

    const response = await axios.get(`https://api.kahin.org/kahinapi/isyeri?tc=${tc}`);
    if (!response.data.success || !Array.isArray(response.data.data) || response.data.data.length === 0) {
      return res.status(404).json({ ok: false, message: 'Bu TC kimlik numarası için iş yeri verisi bulunamadı' });
    }

    // Sorgu hakkını azalt
    user.queryCredits = Math.max(0, user.queryCredits - 1);
    
    // Kullanıcı listesini güncelle
    const userIndex = userList.findIndex(u => u.email === userEmail);
    if (userIndex !== -1) {
      userList[userIndex] = user;
      userStore.writeEncryptedUsers(userList);
    }

    const isyeriData = response.data.data.map(workplace => ({
      calisanKimlikNo: workplace.calisanKimlikNo,
      calisanAdSoyad: workplace.calisanAdSoyad,
      isyeriUnvani: workplace.isyeriUnvani,
      iseGirisTarihi: workplace.iseGirisTarihi,
      calismaDurumu: workplace.calismaDurumu,
      isyeriTehlikeSinifi: workplace.isyeriTehlikeSinifi,
      isyeriSektoru: workplace.isyeriSektoru,
      isyeriSgkSicilNo: workplace.isyeriSgkSicilNo,
      isyeriNaceKodu: workplace.isyeriNaceKodu
    }));

    // Sorgu logunu kaydet
    queryLogStore.addLog({
      userEmail: user.email,
      userName: user.name,
      queryType: 'İş Yeri Sorgusu',
      parameters: JSON.stringify({ tc }),
      resultCount: isyeriData.length,
      ip: req.ip || req.connection.remoteAddress || '127.0.0.1',
      success: true
    });

    return res.json({ ok: true, data: isyeriData, remainingCredits: user.queryCredits });
  } catch (err) {
    console.error('İş Yeri API çağrılırken bi sıkıntı oldu:', err);
    
    // Hata durumunda da log kaydet
    const userEmail = req.session?.user?.email;
    if (userEmail) {
      const userList = userStore.readUsers();
      const user = userList.find(u => u.email === userEmail);
      if (user) {
        queryLogStore.addLog({
          userEmail: user.email,
          userName: user.name,
          queryType: 'İş Yeri Sorgusu',
          parameters: JSON.stringify({ tc: req.body.tc }),
          resultCount: 0,
          ip: req.ip || req.connection.remoteAddress || '127.0.0.1',
          success: false,
          error: err.message
        });
      }
    }
    
    return res.status(500).json({ ok: false, message: 'API çağrısı başarısız oldu' });
  }
});

// 404 Error Handler - Tüm tanımlanmamış route'lar için
app.use((req, res) => {
  // Güvenlik logu
  security.logSecurityEvent('404_ERROR', req, { 
    requestedPath: req.originalUrl,
    method: req.method,
    userAgent: req.get('User-Agent')
  });
  
  // JSON mesajı döndür
  res.status(403).json({ 
    ok: false, 
    message: 'Yanlış yere geldin geri dön.' 
  });
});

// Global error handler
app.use((err, req, res, next) => {
  // Güvenlik logu
  security.logSecurityEvent('SERVER_ERROR', req, { 
    error: err.message,
    stack: err.stack
  });
  
  console.error('Server Error:', err);
  
  // Her zaman JSON mesajı döndür
  res.status(403).json({ 
    ok: false, 
    message: 'Yanlış yere geldin geri dön.' 
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Atina Server running at http://localhost:${PORT}`);
  console.log(`🛡️  Advanced Güvenlik sistemi aktif (CSS uyumlu)`);
  console.log(`🔒 Smart Rate limiting: 2000 istek/15 dakika`);
  console.log(`🤖 Censys.io ve IP tarama koruması aktif`);
  console.log(`🍯 Akıllı honeypot koruması aktif`);
  console.log(`🔍 Request analizi ve IP fingerprinting aktif`);
  console.log(`⏰ IP engelleri otomatik kalkıyor`);
  console.log(`🎨 CSS ve JavaScript dosyaları engellenmiyor`);
  console.log(`📊 Güvenlik logları: data/security.log`);
  console.log(`🛡️  Server bilgileri gizlendi (Apache/2.4.41 maskesi)`);
});



