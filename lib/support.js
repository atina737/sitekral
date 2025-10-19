const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SUPPORT_FILE = path.join(__dirname, '..', 'data', 'support-tickets.json');

class SupportStore {
  constructor() {
    this.ensureFileExists();
  }

  ensureFileExists() {
    if (!fs.existsSync(SUPPORT_FILE)) {
      fs.writeFileSync(SUPPORT_FILE, JSON.stringify([], null, 2));
    }
  }

  readTickets() {
    try {
      const data = fs.readFileSync(SUPPORT_FILE, 'utf8');
      return JSON.parse(data);
    } catch (error) {
      console.error('Support tickets okunamadı:', error);
      return [];
    }
  }

  writeTickets(tickets) {
    try {
      fs.writeFileSync(SUPPORT_FILE, JSON.stringify(tickets, null, 2));
      return true;
    } catch (error) {
      console.error('Support tickets yazılamadı:', error);
      return false;
    }
  }

  addTicket(ticketData) {
    const tickets = this.readTickets();
    const newTicket = {
      id: 'TKT-' + Date.now() + '-' + crypto.randomBytes(3).toString('hex').toUpperCase(),
      ...ticketData,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      replies: []
    };
    
    tickets.unshift(newTicket);
    this.writeTickets(tickets);
    return newTicket;
  }

  updateTicket(ticketId, updateData) {
    const tickets = this.readTickets();
    const ticketIndex = tickets.findIndex(t => t.id === ticketId);
    
    if (ticketIndex === -1) {
      return false;
    }

    tickets[ticketIndex] = {
      ...tickets[ticketIndex],
      ...updateData,
      updatedAt: new Date().toISOString()
    };

    return this.writeTickets(tickets);
  }

  addReply(ticketId, replyData) {
    const tickets = this.readTickets();
    const ticketIndex = tickets.findIndex(t => t.id === ticketId);
    
    if (ticketIndex === -1) {
      return false;
    }

    const newReply = {
      id: crypto.randomUUID(),
      ...replyData,
      createdAt: new Date().toISOString()
    };

    tickets[ticketIndex].replies.push(newReply);
    tickets[ticketIndex].updatedAt = new Date().toISOString();
    
    // Eğer admin cevap veriyorsa, durumu "answered" yap
    if (replyData.userRole === 'Admin') {
      tickets[ticketIndex].status = 'answered';
    }

    return this.writeTickets(tickets);
  }

  deleteTicket(ticketId) {
    const tickets = this.readTickets();
    const filteredTickets = tickets.filter(t => t.id !== ticketId);
    return this.writeTickets(filteredTickets);
  }

  getTicketById(ticketId) {
    const tickets = this.readTickets();
    return tickets.find(t => t.id === ticketId);
  }

  getTicketsByUser(userEmail) {
    const tickets = this.readTickets();
    return tickets.filter(t => t.userEmail === userEmail);
  }

  getAllTickets() {
    return this.readTickets();
  }

  getTicketStats() {
    const tickets = this.readTickets();
    return {
      total: tickets.length,
      open: tickets.filter(t => t.status === 'open').length,
      answered: tickets.filter(t => t.status === 'answered').length,
      inProgress: tickets.filter(t => t.status === 'in-progress').length,
      closed: tickets.filter(t => t.status === 'closed').length
    };
  }
}

module.exports = new SupportStore();
