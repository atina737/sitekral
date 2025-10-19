const fs = require('fs');
const path = require('path');

const configPath = path.join(__dirname, '../data/s.json');

function readConfig() {
    try {
        const raw = fs.readFileSync(configPath, 'utf8');
        return JSON.parse(raw);
    } catch (err) {
        return { siteName: 'Site', registerAutoApprove: false, defaultMembershipDays: 30 };
    }
}

function writeConfig(data) {
    try {
        fs.writeFileSync(configPath, JSON.stringify(data, null, 2), 'utf8');
        return true;
    } catch (err) {
        return false;
    }
}

module.exports = {
    getPublic() {
        const cfg = readConfig();
        let changed = false;
        if (typeof cfg.defaultMembershipDays === 'undefined') { cfg.defaultMembershipDays = 30; changed = true; }
        if (typeof cfg.registerAutoApprove === 'undefined') { cfg.registerAutoApprove = false; changed = true; }
        if (typeof cfg.siteName !== 'string') { cfg.siteName = 'Site'; changed = true; }
        if (typeof cfg.defaultQueryCredits === 'undefined') { cfg.defaultQueryCredits = 30; changed = true; }
        if (typeof cfg.dailyQueryCredits === 'undefined') { cfg.dailyQueryCredits = 10; changed = true; }
        if (changed) writeConfig(cfg);
        return {
            siteName: cfg.siteName,
            registerAutoApprove: cfg.registerAutoApprove,
            defaultMembershipDays: Number(cfg.defaultMembershipDays) || 30,
            defaultQueryCredits: Number(cfg.defaultQueryCredits) || 30,
            dailyQueryCredits: Number(cfg.dailyQueryCredits) || 10
        };
    },
    update({ siteName, registerAutoApprove, defaultMembershipDays, defaultQueryCredits, dailyQueryCredits }) {
        const current = readConfig();
        if (typeof siteName !== 'undefined') current.siteName = siteName;
        if (typeof registerAutoApprove !== 'undefined') current.registerAutoApprove = registerAutoApprove;
        if (typeof defaultMembershipDays !== 'undefined') {
            const n = Number(defaultMembershipDays);
            if (Number.isFinite(n) && n >= 0 && n <= 3650) current.defaultMembershipDays = Math.floor(n);
        }
        if (typeof defaultQueryCredits !== 'undefined') {
            const n = Number(defaultQueryCredits);
            if (Number.isFinite(n) && n >= 0 && n <= 1000) current.defaultQueryCredits = Math.floor(n);
        }
        if (typeof dailyQueryCredits !== 'undefined') {
            const n = Number(dailyQueryCredits);
            if (Number.isFinite(n) && n >= 1 && n <= 1000) current.dailyQueryCredits = Math.floor(n);
        }
        return writeConfig(current);
    }
};
