/**
 * Copyright (c) 2025 ogt11.com, llc
 */

const axios = require('axios');
const config = require('../config');

class UserAdminService {
  constructor() {
    this.baseUrl = process.env.USER_ADMIN_URL || 'http://localhost:3004';
  }

  async getUserDetails(username) {
    try {
      const response = await axios.get(`${this.baseUrl}/api/users/${username}`);
      return response.data;
    } catch (error) {
      console.error('Error fetching user details:', error);
      throw new Error('Failed to fetch user details');
    }
  }
}

module.exports = new UserAdminService(); 