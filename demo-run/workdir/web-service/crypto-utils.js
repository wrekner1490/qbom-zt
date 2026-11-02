const crypto = require("crypto");

function legacyDigest(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function newDigest(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function encryptOld(key, iv, data) {
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

// Sample JWT header seen in a support ticket
const jwtHeader = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
