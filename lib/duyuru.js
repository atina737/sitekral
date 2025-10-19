const fs = require('fs');
const path = require('path');

const filePath = path.join(__dirname, '../data/duyurular.json');

function readAll() {
    try {
        if (!fs.existsSync(filePath)) return [];
        const raw = fs.readFileSync(filePath, 'utf8');
        return JSON.parse(raw);
    } catch (err) {
        return [];
    }
}

function writeAll(list) {
    try {
        fs.writeFileSync(filePath, JSON.stringify(list, null, 2), 'utf8');
        return true;
    } catch (err) {
        return false;
    }
}

function addDuyuru({ title, type, icon, text, active, admin }) {
    const list = readAll();
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
    list.unshift({ id, title, type, icon: icon || 'ti-bell', text: text || '', active, admin, date: new Date().toISOString(), createdAt: new Date().toISOString() });
    return writeAll(list);
}

function removeDuyuru(id) {
    const list = readAll().filter(d => d.id !== id);
    return writeAll(list);
}

function updateDuyuru(id, { title, type, icon, text, active, admin }) {
    const list = readAll();
    const idx = list.findIndex(d => d.id === id);
    if (idx === -1) return false;
    list[idx] = {
        ...list[idx],
        title,
        type,
        icon,
        text,
        active,
        admin,
        date: new Date().toISOString(),
        createdAt: list[idx].createdAt || new Date().toISOString()
    };
    return writeAll(list);
}

module.exports = {
    readAll,
    addDuyuru,
    removeDuyuru,
    updateDuyuru
};
