const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class QueryLogStore {
    constructor() {
        this.logsFile = path.join(__dirname, '..', 'data', 'query-logs.json');
        this.ensureLogsFile();
    }

    ensureLogsFile() {
        if (!fs.existsSync(this.logsFile)) {
            fs.writeFileSync(this.logsFile, JSON.stringify([]));
        }
    }

    readLogs() {
        try {
            const data = fs.readFileSync(this.logsFile, 'utf8');
            return JSON.parse(data);
        } catch (error) {
            console.error('Logs okuma hatası:', error);
            return [];
        }
    }

    writeLogs(logs) {
        try {
            fs.writeFileSync(this.logsFile, JSON.stringify(logs, null, 2));
            return true;
        } catch (error) {
            console.error('Logs yazma hatası:', error);
            return false;
        }
    }

    addLog(logData) {
        const logs = this.readLogs();
        const newLog = {
            id: crypto.randomUUID(),
            ...logData,
            createdAt: new Date().toISOString()
        };
        
        logs.unshift(newLog); // En yeni logları başa ekle
        
        // Maksimum 1000 log tut (performans için)
        if (logs.length > 1000) {
            logs.splice(1000);
        }
        
        return this.writeLogs(logs);
    }

    getLogsByUser(userEmail, limit = 50) {
        const logs = this.readLogs();
        return logs
            .filter(log => log.userEmail === userEmail)
            .slice(0, limit);
    }

    getRecentLogs(limit = 100) {
        const logs = this.readLogs();
        return logs.slice(0, limit);
    }

    deleteLog(logId) {
        const logs = this.readLogs();
        const filteredLogs = logs.filter(log => log.id !== logId);
        return this.writeLogs(filteredLogs);
    }

    clearOldLogs(daysOld = 30) {
        const logs = this.readLogs();
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - daysOld);
        
        const filteredLogs = logs.filter(log => {
            const logDate = new Date(log.createdAt);
            return logDate > cutoffDate;
        });
        
        return this.writeLogs(filteredLogs);
    }
}

module.exports = new QueryLogStore();
