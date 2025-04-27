/**
 * Copyright (c) 2025 ogt11.com, llc
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Generate a version string that includes timestamp and hash
function generateVersion() {
    const timestamp = new Date().toISOString().replace(/[^0-9]/g, '');
    const randomBytes = crypto.randomBytes(4).toString('hex');
    return `cert-create-${timestamp}-${randomBytes}`;
}

// Write version to file and export it
const version = generateVersion();
fs.writeFileSync(path.join(__dirname, 'current-version.txt'), version);

module.exports = version; 