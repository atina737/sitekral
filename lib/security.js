const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Güvenlik log dosyası
const securityLogPath = path.join(__dirname, '../data/security.log');

// Rate limiting için memory store
const rateLimitStore = new Map();
const suspiciousIPs = new Set();
const blockedIPs = new Map(); // IP -> timestamp
const bruteForceStore = new Map(); // IP -> { attempts, lastAttempt }

// Güvenlik log fonksiyonu
function logSecurityEvent(type, req, details = {}) {
    const timestamp = new Date().toISOString();
    const ip = req.ip || req.connection.remoteAddress || req.socket.remoteAddress;
    const userAgent = req.get('User-Agent') || 'Unknown';
    const url = req.originalUrl || req.url;
    
    const logEntry = {
        timestamp,
        type,
        ip,
        userAgent,
        url,
        details
    };
    
    // Log dosyasına yaz
    try {
        fs.appendFileSync(securityLogPath, JSON.stringify(logEntry) + '\n');
    } catch (err) {
        console.error('Security log yazılamadı:', err);
    }
    
    // Console'a da yaz
    console.log(`🚨 [${type}] ${ip} - ${url} - ${userAgent.substring(0, 50)}`);
}

// Smart Rate Limiting (F5 spam protection)
function rateLimit(maxRequests = 1000, windowMs = 15 * 60 * 1000) {
    return (req, res, next) => {
        const ip = req.ip || req.connection.remoteAddress;
        const now = Date.now();
        const windowStart = now - windowMs;
        const url = req.originalUrl || req.url;
        
        // Very generous limits - only block obvious abuse
        let requestLimit = maxRequests;
        if (url.includes('/api/')) {
            requestLimit = 800; // API requests
        } else if (url.includes('/login') || url.includes('/register')) {
            requestLimit = 100; // Auth requests - more generous
        }
        
        if (!rateLimitStore.has(ip)) {
            rateLimitStore.set(ip, []);
        }
        
        const requests = rateLimitStore.get(ip);
        const validRequests = requests.filter(time => time > windowStart);
        
        // Only block extreme rapid-fire (20+ requests in 5 seconds)
        const recentRequests = validRequests.filter(time => now - time < 5000);
        if (recentRequests.length > 20) {
            logSecurityEvent('RAPID_FIRE_DETECTED', req, { 
                recentRequests: recentRequests.length,
                url 
            });
            
            // Don't add to suspicious IPs immediately
            return res.status(429).json({ 
                ok: false, 
                message: 'Çok hızlı istek gönderiyorsunuz. Lütfen yavaşlayın.',
                retryAfter: 5
            });
        }
        
        if (validRequests.length >= requestLimit) {
            logSecurityEvent('RATE_LIMIT_EXCEEDED', req, { 
                requestCount: validRequests.length,
                maxRequests: requestLimit,
                url 
            });
            
            suspiciousIPs.add(ip);
            return res.status(429).json({ 
                ok: false, 
                message: 'İstek limitiniz aşıldı. Lütfen bekleyin.',
                retryAfter: Math.ceil(windowMs / 1000)
            });
        }
        
        validRequests.push(now);
        rateLimitStore.set(ip, validRequests);
        next();
    };
}

// Advanced Bot Detection & IP Protection
function botDetection(req, res, next) {
    const userAgent = req.get('User-Agent') || '';
    const ip = req.ip || req.connection.remoteAddress;
    const referer = req.get('Referer') || '';
    const host = req.get('Host') || '';
    
    // Advanced bot patterns
    const botPatterns = [
        /bot/i, /crawler/i, /spider/i, /scraper/i, /curl/i, /wget/i,
        /python/i, /java/i, /php/i, /perl/i, /ruby/i, /go-http/i,
        /postman/i, /insomnia/i, /httpie/i, /requests/i, /scrapy/i,
        /selenium/i, /phantom/i, /headless/i, /automation/i
    ];
    
    // Security scanner patterns
    const scannerPatterns = [
        /sqlmap/i, /nikto/i, /nmap/i, /masscan/i, /zap/i, /burp/i,
        /havij/i, /sqlninja/i, /pangolin/i, /acunetix/i, /nessus/i,
        /openvas/i, /retire\.js/i, /snyk/i, /veracode/i, /checkmarx/i
    ];
    
    // Censys.io and similar services
    const censysPatterns = [
        /censys/i, /shodan/i, /zoomeye/i, /binaryedge/i, /fofa/i,
        /search\.censys\.io/i, /censys\.io/i, /shodan\.io/i,
        /zoomeye\.org/i, /binaryedge\.io/i, /fofa\.so/i
    ];
    
    // Cloud provider patterns (VDS protection)
    const cloudPatterns = [
        /amazonaws/i, /googlecloud/i, /azure/i, /digitalocean/i,
        /linode/i, /vultr/i, /ovh/i, /hetzner/i, /contabo/i,
        /aws/i, /gcp/i, /cloudflare/i, /fastly/i
    ];
    
    const isBot = botPatterns.some(pattern => pattern.test(userAgent));
    const isScanner = scannerPatterns.some(pattern => pattern.test(userAgent));
    const isCensys = censysPatterns.some(pattern => pattern.test(userAgent + ' ' + referer));
    const isCloud = cloudPatterns.some(pattern => pattern.test(userAgent + ' ' + host));
    
    // Only block obvious threats (Censys.io, malicious tools)
    if (isCensys || (isScanner && (userAgent.includes('sqlmap') || userAgent.includes('nikto')))) {
        logSecurityEvent('THREAT_DETECTED', req, { 
            userAgent, 
            referer,
            host,
            isCensys,
            isScanner
        });
        
        blockedIPs.set(ip, Date.now()); // Temporary block with timestamp
        return res.status(403).json({ 
            ok: false, 
            message: 'Erişim reddedildi.' 
        });
    }
    
    next();
}

// XSS Protection
function xssProtection(req, res, next) {
    const checkXSS = (obj) => {
        if (typeof obj === 'string') {
            const xssPatterns = [
                /<script[^>]*>.*?<\/script>/gi,
                /javascript:/gi,
                /on\w+\s*=/gi,
                /<iframe[^>]*>.*?<\/iframe>/gi,
                /<object[^>]*>.*?<\/object>/gi,
                /<embed[^>]*>.*?<\/embed>/gi,
                /<link[^>]*>.*?<\/link>/gi,
                /<meta[^>]*>.*?<\/meta>/gi
            ];
            
            return xssPatterns.some(pattern => pattern.test(obj));
        }
        
        if (typeof obj === 'object' && obj !== null) {
            return Object.values(obj).some(checkXSS);
        }
        
        return false;
    };
    
    if (checkXSS(req.body) || checkXSS(req.query) || checkXSS(req.params)) {
        logSecurityEvent('XSS_ATTEMPT', req, { 
            body: req.body, 
            query: req.query, 
            params: req.params 
        });
        
        return res.status(400).json({ 
            ok: false, 
            message: 'Güvenlik ihlali tespit edildi.' 
        });
    }
    
    next();
}

// SQL Injection Protection
function sqlInjectionProtection(req, res, next) {
    const sqlPatterns = [
        /('|(\\')|(;)|(\\)|(\|)|(\*)|(%)|(\+)|(\-)|(\()|(\))|(\[)|(\])|(\{)|(\})|(\^)|(\$)|(\?)|(\!)|(\~)|(\`)|(\@)|(\#)|(\&)|(\=)|(\<)|(\>)|(\|)|(\\)|(\/)|(\:)|(\;)|(\")|(\')|(\x00)|(\x1a)|(\x0d)|(\x0a)|(\x0b)|(\x0c)|(\x0e)|(\x0f)|(\x10)|(\x11)|(\x12)|(\x13)|(\x14)|(\x15)|(\x16)|(\x17)|(\x18)|(\x19)|(\x1b)|(\x1c)|(\x1d)|(\x1e)|(\x1f))/i,
        /union\s+select/i,
        /select\s+.*\s+from/i,
        /insert\s+into/i,
        /update\s+.*\s+set/i,
        /delete\s+from/i,
        /drop\s+table/i,
        /create\s+table/i,
        /alter\s+table/i,
        /exec\s*\(/i,
        /execute\s*\(/i,
        /sp_/i,
        /xp_/i,
        /0x[0-9a-f]+/i
    ];
    
    const checkSQL = (obj) => {
        if (typeof obj === 'string') {
            return sqlPatterns.some(pattern => pattern.test(obj));
        }
        
        if (typeof obj === 'object' && obj !== null) {
            return Object.values(obj).some(checkSQL);
        }
        
        return false;
    };
    
    if (checkSQL(req.body) || checkSQL(req.query) || checkSQL(req.params)) {
        logSecurityEvent('SQL_INJECTION_ATTEMPT', req, { 
            body: req.body, 
            query: req.query, 
            params: req.params 
        });
        
        return res.status(400).json({ 
            ok: false, 
            message: 'Güvenlik ihlali tespit edildi.' 
        });
    }
    
    next();
}

// IP blocking check
function ipBlocking(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress;
    
    // Localhost IP'lerini engelleme
    if (ip === '::1' || ip === '127.0.0.1' || ip === 'localhost') {
        return next(); // Localhost'u geç
    }
    
    // Check if IP is temporarily blocked (5 minutes)
    if (blockedIPs.has(ip)) {
        const blockTime = blockedIPs.get(ip);
        const now = Date.now();
        
        // Remove block after 5 minutes
        if (now - blockTime > 5 * 60 * 1000) {
            blockedIPs.delete(ip);
        } else {
            logSecurityEvent('BLOCKED_IP_ACCESS', req);
            return res.status(403).json({ 
                ok: false, 
                message: 'IP adresiniz geçici olarak engellenmiştir. 5 dakika sonra tekrar deneyin.' 
            });
        }
    }
    
    next();
}

// Minimal Security Headers - User Friendly
function securityHeaders(req, res, next) {
    // Only essential headers - no CSP blocking
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    
    // Hide server information (fake Apache)
    res.setHeader('Server', 'Apache/2.4.41 (Ubuntu)');
    res.setHeader('X-Powered-By', 'PHP/7.4.3');
    
    next();
}

// Request logging
function requestLogging(req, res, next) {
    const start = Date.now();
    
    res.on('finish', () => {
        const duration = Date.now() - start;
        const ip = req.ip || req.connection.remoteAddress;
        
        if (res.statusCode >= 400) {
            logSecurityEvent('HTTP_ERROR', req, { 
                statusCode: res.statusCode, 
                duration 
            });
        }
        
        // Suspicious activity detection
        if (duration > 10000) { // 10 saniyeden uzun süren istekler
            logSecurityEvent('SLOW_REQUEST', req, { duration });
        }
    });
    
    next();
}

// Cleanup old rate limit data
setInterval(() => {
    const now = Date.now();
    const maxAge = 60 * 60 * 1000; // 1 saat
    
    for (const [ip, requests] of rateLimitStore.entries()) {
        const validRequests = requests.filter(time => now - time < maxAge);
        if (validRequests.length === 0) {
            rateLimitStore.delete(ip);
        } else {
            rateLimitStore.set(ip, validRequests);
        }
    }
}, 5 * 60 * 1000); // Her 5 dakikada bir temizle

// Honeypot Protection
function honeypotProtection(req, res, next) {
    const suspiciousPaths = [
        '/admin', '/wp-admin', '/administrator', '/phpmyadmin', '/mysql',
        '/.env', '/config', '/backup', '/test', '/debug', '/api/v1',
        '/robots.txt', '/sitemap.xml', '/.git', '/.svn', '/.htaccess'
    ];
    
    const url = req.originalUrl || req.url;
    const isSuspiciousPath = suspiciousPaths.some(path => url.toLowerCase().includes(path));
    
    if (isSuspiciousPath) {
        logSecurityEvent('HONEYPOT_TRIGGERED', req, { url });
        blockedIPs.set(req.ip || req.connection.remoteAddress, Date.now()); // Temporary block
        return res.status(404).json({ 
            ok: false, 
            message: 'Sayfa bulunamadı.' 
        });
    }
    
    next();
}

// Advanced IP Analysis
function ipAnalysis(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('User-Agent') || '';
    
    // Check for suspicious IP patterns
    const suspiciousIPPatterns = [
        /^10\./, /^172\.(1[6-9]|2[0-9]|3[0-1])\./, /^192\.168\./, // Private IPs
        /^127\./, /^::1$/, /^fe80:/, // Localhost
        /^169\.254\./ // Link-local
    ];
    
    const isSuspiciousIP = suspiciousIPPatterns.some(pattern => pattern.test(ip));
    
    if (isSuspiciousIP && !userAgent.includes('Mozilla')) {
        logSecurityEvent('SUSPICIOUS_IP_DETECTED', req, { ip, userAgent });
        suspiciousIPs.add(ip);
    }
    
    next();
}

// Request Fingerprinting
function requestFingerprinting(req, res, next) {
    const fingerprint = {
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent') || '',
        acceptLanguage: req.get('Accept-Language') || '',
        acceptEncoding: req.get('Accept-Encoding') || '',
        connection: req.get('Connection') || '',
        method: req.method,
        url: req.originalUrl || req.url
    };
    
    // Store fingerprint for analysis
    req.securityFingerprint = fingerprint;
    
    next();
}

// Clear all blocked IPs (for admin use)
function clearBlockedIPs() {
    blockedIPs.clear();
    console.log('🔄 Tüm engellenmiş IP\'ler temizlendi');
}

// Clear localhost from blocked IPs
function clearLocalhost() {
    blockedIPs.delete('::1');
    blockedIPs.delete('127.0.0.1');
    blockedIPs.delete('localhost');
    console.log('🔄 Localhost IP\'leri temizlendi');
}

// Clear specific IP
function clearIP(ip) {
    blockedIPs.delete(ip);
    console.log(`🔄 IP ${ip} engeli kaldırıldı`);
}

// Brute Force Koruması
function bruteForceProtection(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress;
    const username = req.body.username || req.body.email;
    const now = Date.now();
    const windowMs = 15 * 60 * 1000; // 15 dakika
    const maxAttempts = 5; // Maksimum deneme sayısı
    
    // IP bazlı deneme sayısı
    if (!bruteForceStore.has(ip)) {
        bruteForceStore.set(ip, { attempts: 0, lastAttempt: now });
    }
    
    const ipData = bruteForceStore.get(ip);
    
    // Süre dolmuşsa sıfırla
    if (now - ipData.lastAttempt > windowMs) {
        ipData.attempts = 0;
    }
    
    // Deneme sayısı limiti aşılmışsa engelle
    if (ipData.attempts >= maxAttempts) {
        logSecurityEvent('BRUTE_FORCE_BLOCKED', req, { ip, attempts: ipData.attempts });
        return res.status(429).json({ 
            ok: false, 
            message: 'Çok fazla başarısız deneme. 15 dakika sonra tekrar deneyin.' 
        });
    }
    
    // Başarısız deneme sayısını artır
    ipData.attempts++;
    ipData.lastAttempt = now;
    
    next();
}

// Akıllı Bot Tespiti (Görünmez Captcha)
function smartBotDetection(req, res, next) {
    const userAgent = req.get('User-Agent') || '';
    const acceptLanguage = req.get('Accept-Language') || '';
    const acceptEncoding = req.get('Accept-Encoding') || '';
    const connection = req.get('Connection') || '';
    const ip = req.ip || req.connection.remoteAddress;
    
    // Bot tespit puanı
    let botScore = 0;
    
    // 1. User-Agent analizi
    if (!userAgent || userAgent.length < 10) botScore += 30;
    if (userAgent.length > 500) botScore += 20;
    if (/^[A-Za-z0-9\s\-\.]+$/.test(userAgent) && userAgent.length < 20) botScore += 25;
    
    // 2. Header eksiklikleri
    if (!acceptLanguage) botScore += 20;
    if (!acceptEncoding) botScore += 15;
    if (!connection) botScore += 10;
    
    // 3. Bot pattern'leri
    if (/bot|crawler|spider|scraper|curl|wget|python|java|go-http/i.test(userAgent)) {
        if (!/googlebot|bingbot|slurp|facebook|twitter/i.test(userAgent)) {
            botScore += 40;
        }
    }
    
    // 4. Honeypot tuzakları (gizli alanlar)
    if (req.body.honeypot || req.body.website || req.body.url) {
        botScore += 100; // Kesin bot
    }
    
    // 5. Timing analizi (çok hızlı form gönderimi)
    const now = Date.now();
    if (!req.session.lastFormTime) {
        req.session.lastFormTime = now;
    } else {
        const timeDiff = now - req.session.lastFormTime;
        if (timeDiff < 2000) { // 2 saniyeden az
            botScore += 30;
        }
    }
    req.session.lastFormTime = now;
    
    // 6. Mouse movement ve keyboard events (JavaScript ile kontrol edilecek)
    if (req.body.mouseEvents === '0' || req.body.keyboardEvents === '0') {
        botScore += 25;
    }
    
    // Bot skoru 50'den fazlaysa engelle
    if (botScore >= 50) {
        logSecurityEvent('SMART_BOT_DETECTED', req, { 
            botScore,
            userAgent,
            acceptLanguage,
            acceptEncoding,
            ip
        });
        
        // Geçici engelleme (10 dakika)
        blockedIPs.set(ip, Date.now());
        
        return res.status(403).json({ 
            ok: false, 
            message: 'Erişim reddedildi.' 
        });
    }
    
    next();
}

// Advanced IP Hiding & Censys Protection
function advancedIPProtection(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress;
    
    // Localhost IP'lerini engelleme
    if (ip === '::1' || ip === '127.0.0.1' || ip === 'localhost') {
        return next(); // Localhost'u geç
    }
    
    const userAgent = req.get('User-Agent') || '';
    const referer = req.get('Referer') || '';
    const host = req.get('Host') || '';
    
    // Censys.io ve benzeri IP tarama servisleri
    const censysPatterns = [
        /censys\.io/i, /search\.censys\.io/i, /api\.censys\.io/i,
        /shodan\.io/i, /api\.shodan\.io/i, /shodan\.net/i,
        /zoomeye\.org/i, /api\.zoomeye\.org/i,
        /binaryedge\.io/i, /api\.binaryedge\.io/i,
        /fofa\.so/i, /quake\.360\.cn/i,
        /virustotal\.com/i, /api\.virustotal\.com/i,
        /securitytrails\.com/i, /api\.securitytrails\.com/i,
        /threatcrowd\.org/i, /api\.threatcrowd\.org/i
    ];
    
    // Cloud provider ve VDS tespiti
    const cloudPatterns = [
        /amazonaws/i, /aws\.amazon/i, /ec2\.amazon/i,
        /googlecloud/i, /gcp\.google/i, /cloud\.google/i,
        /azure\.microsoft/i, /microsoft\.azure/i,
        /digitalocean/i, /do\.digitalocean/i,
        /linode/i, /vultr/i, /ovh/i, /hetzner/i,
        /contabo/i, /scaleway/i, /lightsail/i
    ];
    
    // Bot ve scanner tespiti
    const botPatterns = [
        /censys/i, /shodan/i, /zoomeye/i, /binaryedge/i,
        /nmap/i, /masscan/i, /zmap/i, /unicornscan/i,
        /sqlmap/i, /nikto/i, /havij/i, /acunetix/i,
        /burp/i, /zap/i, /w3af/i, /nessus/i,
        /openvas/i, /retire\.js/i, /snyk/i
    ];
    
    const isCensys = censysPatterns.some(pattern => 
        pattern.test(userAgent + ' ' + referer + ' ' + host)
    );
    
    const isCloud = cloudPatterns.some(pattern => 
        pattern.test(userAgent + ' ' + referer + ' ' + host)
    );
    
    const isBot = botPatterns.some(pattern => 
        pattern.test(userAgent + ' ' + referer)
    );
    
    // Sadece gerçek tehditleri engelle
    if (isCensys || (isCloud && isBot)) {
        logSecurityEvent('IP_SCANNER_DETECTED', req, { 
            userAgent, 
            referer,
            host,
            isCensys,
            isCloud,
            isBot
        });
        
        // Geçici engelleme (10 dakika)
        blockedIPs.set(ip, Date.now());
        
        return res.status(403).json({ 
            ok: false, 
            message: 'Erişim reddedildi.' 
        });
    }
    
    next();
}

// Smart Rate Limiting (CSS friendly)
function smartRateLimit(maxRequests = 2000, windowMs = 15 * 60 * 1000) {
    const requests = new Map();
    
    return (req, res, next) => {
        const ip = req.ip || req.connection.remoteAddress;
        const now = Date.now();
        const windowStart = now - windowMs;
        const url = req.originalUrl || req.url;
        
        // Clean old entries
        if (requests.has(ip)) {
            const userRequests = requests.get(ip).filter(time => time > windowStart);
            requests.set(ip, userRequests);
        }
        
        const userRequests = requests.get(ip) || [];
        
        // Very generous limits - only block extreme abuse
        let limit = maxRequests;
        if (url.includes('/api/')) {
            limit = 1500; // API requests
        } else if (url.includes('login') || url.includes('register')) {
            limit = 200; // Auth requests
        } else if (url.includes('.css') || url.includes('.js') || url.includes('.png') || url.includes('.jpg')) {
            limit = 5000; // Static files - very generous
        }
        
        // Only block if way over limit (extreme abuse)
        if (userRequests.length >= limit) {
            logSecurityEvent('RATE_LIMIT_EXCEEDED', req, { 
                ip, 
                requestCount: userRequests.length,
                limit,
                url
            });
            
            return res.status(429).json({ 
                ok: false, 
                message: 'İstek limitiniz aşıldı. Lütfen daha sonra tekrar deneyin.' 
            });
        }
        
        // Add current request
        userRequests.push(now);
        requests.set(ip, userRequests);
        
        next();
    };
}

// Advanced Request Analysis
function requestAnalysis(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('User-Agent') || '';
    const referer = req.get('Referer') || '';
    const acceptLanguage = req.get('Accept-Language') || '';
    const acceptEncoding = req.get('Accept-Encoding') || '';
    
    // Suspicious request patterns
    const suspiciousPatterns = [
        // Missing common headers (bots often don't send these)
        !acceptLanguage,
        !acceptEncoding,
        
        // Suspicious user agents
        userAgent.length < 10,
        userAgent.length > 500,
        /^[A-Za-z0-9\s\-\.]+$/.test(userAgent) && userAgent.length < 20,
        
        // Common bot patterns
        /bot/i.test(userAgent) && !/googlebot|bingbot|slurp/i.test(userAgent),
        /crawler/i.test(userAgent) && !/googlebot|bingbot|slurp/i.test(userAgent),
        /spider/i.test(userAgent) && !/googlebot|bingbot|slurp/i.test(userAgent)
    ];
    
    const suspiciousCount = suspiciousPatterns.filter(Boolean).length;
    
    // Only flag if multiple suspicious patterns
    if (suspiciousCount >= 3) {
        logSecurityEvent('SUSPICIOUS_REQUEST', req, { 
            suspiciousCount,
            userAgent,
            acceptLanguage,
            acceptEncoding
        });
        
        // Don't block, just log
    }
    
    next();
}

// Honeypot Protection (CSS friendly)
function smartHoneypot(req, res, next) {
    const url = req.originalUrl || req.url;
    const ip = req.ip || req.connection.remoteAddress;
    
    // Localhost IP'lerini engelleme
    if (ip === '::1' || ip === '127.0.0.1' || ip === 'localhost') {
        return next(); // Localhost'u geç
    }
    
    // Only block obvious malicious paths
    const maliciousPaths = [
        '/admin', '/wp-admin', '/administrator', '/phpmyadmin',
        '/.env', '/config', '/backup', '/.git', '/.svn',
        '/robots.txt', '/sitemap.xml', '/.htaccess',
        '/api/v1', '/api/v2', '/api/v3',
        '/test', '/debug', '/dev', '/staging'
    ];
    
    const isMalicious = maliciousPaths.some(path => 
        url.toLowerCase().includes(path.toLowerCase())
    );
    
    if (isMalicious) {
        logSecurityEvent('HONEYPOT_TRIGGERED', req, { url });
        
        // Geçici engelleme (5 dakika)
        blockedIPs.set(ip, Date.now());
        
        return res.status(404).json({ 
            ok: false, 
            message: 'Sayfa bulunamadı.' 
        });
    }
    
    next();
}

// IP Fingerprinting Protection
function ipFingerprinting(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress;
    
    // Localhost IP'lerini engelleme
    if (ip === '::1' || ip === '127.0.0.1' || ip === 'localhost') {
        return next(); // Localhost'u geç
    }
    
    // Check for suspicious IP patterns
    const suspiciousIPPatterns = [
        // Private IPs (shouldn't access from outside)
        /^10\./, /^172\.(1[6-9]|2[0-9]|3[0-1])\./, /^192\.168\./,
        // Link-local
        /^169\.254\./
    ];
    
    const isSuspiciousIP = suspiciousIPPatterns.some(pattern => pattern.test(ip));
    
    if (isSuspiciousIP) {
        const userAgent = req.get('User-Agent') || '';
        
        // Only block if it's clearly a bot/scanner
        if (!userAgent.includes('Mozilla') && !userAgent.includes('Chrome') && !userAgent.includes('Firefox')) {
            logSecurityEvent('SUSPICIOUS_IP_DETECTED', req, { ip, userAgent });
            
            // Geçici engelleme (5 dakika)
            blockedIPs.set(ip, Date.now());
            
            return res.status(403).json({ 
                ok: false, 
                message: 'Erişim reddedildi.' 
            });
        }
    }
    
    next();
}

module.exports = {
    // Original functions
    rateLimit,
    botDetection,
    xssProtection,
    sqlInjectionProtection,
    ipBlocking,
    securityHeaders,
    requestLogging,
    honeypotProtection,
    ipAnalysis,
    requestFingerprinting,
    logSecurityEvent,
    clearBlockedIPs,
    clearIP,
    clearLocalhost,
    suspiciousIPs,
    blockedIPs,
    
    // New advanced functions
    advancedIPProtection,
    smartRateLimit,
    requestAnalysis,
    smartHoneypot,
    ipFingerprinting,
    bruteForceProtection,
    smartBotDetection
};
