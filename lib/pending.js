const fs = require('fs');
const path = require('path');

const PENDING_FILE = path.join(__dirname, '..', 'data', 'pending-users.json');

function safeRead() {
  try {
    const raw = fs.readFileSync(PENDING_FILE, 'utf8');
    const data = JSON.parse(raw);
    return Array.isArray(data) ? data : [];
  } catch (_) {
    return [];
  }
}

function safeWrite(arr) {
  try {
    fs.writeFileSync(PENDING_FILE, JSON.stringify(arr, null, 2), 'utf8');
    return true;
  } catch (_) {
    return false;
  }
}

function readAll() {
  return safeRead();
}

function add(user) {
  const list = safeRead();
  list.push(user);
  return safeWrite(list);
}

function removeById(id) {
  const list = safeRead();
  const next = list.filter(u => String(u && u.id) !== String(id));
  const ok = safeWrite(next);
  return { ok, removed: list.length - next.length };
}

function findById(id) {
  const list = safeRead();
  return list.find(u => String(u && u.id) === String(id)) || null;
}

function findByEmail(email) {
  const list = safeRead();
  const e = String(email || '').toLowerCase();
  return list.find(u => String(u && u.email || '').toLowerCase() === e) || null;
}

module.exports = { PENDING_FILE, readAll, add, removeById, findById, findByEmail };


