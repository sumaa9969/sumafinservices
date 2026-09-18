function sanitizeName(str) {
  if (!str) return '';
  return String(str).trim().replace(/[<>]/g, '').slice(0, 100);
}

function sanitizeText(str, max = 255) {
  if (!str) return '';
  return String(str).trim().replace(/[<>]/g, '').slice(0, max);
}

module.exports = { sanitizeName, sanitizeText };
