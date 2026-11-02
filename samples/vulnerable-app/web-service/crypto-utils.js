const crypto = require("crypto");

function legacyDigest(data) {
  return crypto.createHash("md5").update(data).digest("hex");
}

function newDigest(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function encryptOld(key, iv, data) {
  const cipher = crypto.createCipheriv("des-ede3-cbc", key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

// Sample JWT header seen in a support ticket
const jwtHeader = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
