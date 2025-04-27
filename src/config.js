/**
 * Copyright (c) 2025 ogt11.com, llc
 */

const rootConfig = require('../../config');

module.exports = {
  port: rootConfig.SERVICE_PORTS['cert-create'],
  baseUrl: rootConfig.BASE_URL,
  serviceUrl: rootConfig.certCreateUrl,
  userAdminUrl: rootConfig.userAdminUrl,
  
  // Certificate settings
  certConfig: {
    validityDays: process.env.CERT_VALIDITY_DAYS || 365,
    keySize: process.env.CERT_KEY_SIZE || 2048,
    country: process.env.CERT_COUNTRY || 'US',
    state: process.env.CERT_STATE || 'California',
    locality: process.env.CERT_LOCALITY || 'San Francisco',
    organization: process.env.CERT_ORGANIZATION || 'OGT11 Inc',
    organizationalUnit: process.env.CERT_ORG_UNIT || 'IT'
  }
}; 