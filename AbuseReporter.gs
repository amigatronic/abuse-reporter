/**
 * ============================================================
 * ABUSE REPORTER - v1.2.0
 * ============================================================
 */

// ============================================================
// CONFIG - Edit these
// ============================================================
var MAX_THREADS_PER_RUN = 30;
var MAX_PER_PROVIDER = 3;
var TRUSTED_SENDER_DOMAINS = [];
var KNOWN_TRAP_ABUSE_DOMAINS = [];
var USE_ARF_ATTACHMENT = false;
var ENABLE_SHEET_LOG = false;
var LOG_SHEET_ID = "";
var DOGET_SECRET_PROPERTY = "ABUSE_REPORTER_SECRET";
var CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000;
var CACHE_PROPERTY_KEY = "ABUSE_LOOKUP_CACHE_V1";
var CACHE_MAX_ENTRIES = 150;
var RDAP_BOOTSTRAP = null;
var PERSISTENT_CACHE = {};
var CACHE_DIRTY = false; // Flag to avoid unnecessary PropertiesService writes

// ============================================================
// MAIN LOOP
// ============================================================
function processAndSendAbuseReports() {
  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(5000);
  } catch (e) {
    Logger.log("Could not acquire lock (another run may be in progress). Aborting.");
    return;
  }
  try {
    runAbuseReportPass();
  } finally {
    lock.releaseLock();
  }
}

function runAbuseReportPass() {
  var threads = GmailApp.search("in:spam", 0, MAX_THREADS_PER_RUN);
  if (threads.length === 0) {
    Logger.log("No emails found in spam.");
    return;
  }
  PERSISTENT_CACHE = loadPersistentCache();
  var myPublicIp = getMyPublicIp();
  if (myPublicIp) {
    Logger.log("Current execution public IP: " + myPublicIp);
  }
  var sentToProvider = {};
  var reviewLabel = getOrCreateLabel("Abuse/NeedsReview");
  var fpLabel = getOrCreateLabel("Abuse/LikelyFalsePositive");
  
  for (var i = 0; i < threads.length; i++) {
    var messages = threads[i].getMessages();
    for (var j = 0; j < messages.length; j++) {
      try {
        processOneMessage(threads[i], messages[j], myPublicIp, sentToProvider, reviewLabel, fpLabel);
      } catch (msgErr) {
        Logger.log("--> ERROR processing message, skipped | " + msgErr.toString());
      }
    }
  }
  savePersistentCache(PERSISTENT_CACHE);
}

function processOneMessage(thread, message, myPublicIp, sentToProvider, reviewLabel, fpLabel) {
  var rawContent = message.getRawContent();
  var rawHeader = unfoldHeaders(rawContent.split(/\r?\n\r?\n/)[0]);
  var bodyText = getMessageBodyText(message);
  var subject = message.getSubject();
  
  // Use decoded From for accurate analysis, keep raw for fallback
  var fromDecoded = message.getFrom(); 
  var fromRawMatch = rawHeader.match(/^From:[^\n]*/mi);
  var fromRaw = fromRawMatch ? fromRawMatch[0].replace(/^From:\s*/i, "") : "";
  
  var evalResult = evaluateMessage(rawHeader, bodyText, subject, fromDecoded, fromRaw);
  logToSheet([new Date(), evalResult.category, evalResult.score, subject, fromDecoded]);
  
  if (evalResult.category === "likely-false-positive") {
    thread.addLabel(fpLabel);
    Logger.log("--> LIKELY FALSE POSITIVE | msgId=" + message.getId() + " | " + evalResult.reasons.join("; "));
    return;
  }
  
  var result = analyzeAbuseHeader(rawHeader, bodyText, message, myPublicIp);
  if (result.ip && myPublicIp && result.ip === myPublicIp) {
    Logger.log("--> SKIPPED: extracted IP matches current execution IP | msgId=" + message.getId());
    return;
  }
  
  if (!result.abuseEmails || result.abuseEmails.length === 0) {
    Logger.log("--> NO ABUSE ADDRESS FOUND | msgId=" + message.getId() + " | Provider: " + result.provider + " | IP: " + (result.ip || "N/A"));
    return;
  }
  
  var abuseRecipient = result.abuseEmails[0];
  if (!/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(abuseRecipient)) {
    Logger.log("--> INVALID ABUSE EMAIL | msgId=" + message.getId() + " | " + abuseRecipient);
    return;
  }
  
  if (!isSafeAbuseTarget(result.ip, result.abuseEmails, evalResult.fromDomain)) {
    thread.addLabel(reviewLabel);
    Logger.log("--> ANTI-SELF-REPORT CHECK FAILED | msgId=" + message.getId() + " | IP: " + result.ip + " | Abuse: " + abuseRecipient);
    return;
  }
  
  var providerKey = result.provider || abuseRecipient;
  sentToProvider[providerKey] = (sentToProvider[providerKey] || 0) + 1;
  if (sentToProvider[providerKey] > MAX_PER_PROVIDER) {
    Logger.log("--> PER-PROVIDER LIMIT REACHED | msgId=" + message.getId() + " | " + providerKey);
    return;
  }
  
  // Build email payload
  var subjectPrefix = evalResult.category === "phishing" ? "PHISHING Notice" : "SPAM Notice";
  var emailBody = "Dear Network Abuse Department,\n";
  if (evalResult.category === "phishing") {
    emailBody += "WARNING: This email appears to be a PHISHING attempt.\nIndicators: " + evalResult.reasons.join(", ") + "\n";
  }
  emailBody += "Reporting spam/abusive activity from your network.\nSource IP: " + result.ip + "\nForward type: " + (result.forwardType || "direct") + "\nOriginal Subject: " + subject + "\nFull headers attached.\nRegards,\nAutomated Abuse Reporter";
  
  var sendOptions = {
    attachments: [Utilities.newBlob(rawHeader + "\n" + bodyText, "text/plain", "abuse_report_header.txt")],
    name: "Abuse Reporter",
    headers: { "Auto-Submitted": "auto-generated", "X-Abuse-Report": "true" }
  };
  
  if (USE_ARF_ATTACHMENT) {
    var arfBlob = buildArfBlob(result, evalResult, subject, rawHeader);
    if (arfBlob) sendOptions.attachments.push(arfBlob);
  }

  // Attempt to send with retry BEFORE trashing
  var success = sendEmailWithRetry(abuseRecipient, subjectPrefix, emailBody, sendOptions, 3);
  
  if (success) {
    message.moveToTrash();
    Logger.log("--> REPORT SENT | msgId=" + message.getId() + " to=" + abuseRecipient + " provider=" + result.provider + " ip=" + result.ip + " score=" + evalResult.score + " | MESSAGE TRASHED");
  } else {
    thread.addLabel(reviewLabel);
    Logger.log("--> SEND FAILED after retries | msgId=" + message.getId() + " to=" + abuseRecipient + " | Email KEPT in spam for manual review.");
  }
}

// Helper to send email with retry, returns true only on success
function sendEmailWithRetry(to, subject, body, options, maxRetries) {
  maxRetries = maxRetries || 3;
  var attempt = 0;
  while (attempt < maxRetries) {
    try {
      GmailApp.sendEmail(to, subject, body, options);
      return true;
    } catch (e) {
      Logger.log("sendEmail attempt " + (attempt + 1) + " failed: " + e.toString());
      Utilities.sleep(Math.pow(2, attempt) * 1000);
      attempt++;
    }
  }
  return false;
}

// ============================================================
// SHARED STATE HELPERS
// ============================================================
function getMyPublicIp() {
  var res = fetchWithRetry("https://api.ipify.org?format=json", { muteHttpExceptions: true }, 2);
  if (res && res.getResponseCode() === 200) {
    try { return JSON.parse(res.getContentText()).ip; } catch (e) {}
  }
  return null;
}

function doGet(e) {
  var expected = PropertiesService.getScriptProperties().getProperty(DOGET_SECRET_PROPERTY);
  var provided = e && e.parameter ? e.parameter.token : null;
  if (!expected) return HtmlService.createHtmlOutput("Web trigger disabled: no secret set in Script Properties.");
  if (!provided || provided !== expected) return HtmlService.createHtmlOutput("Unauthorized.");
  try {
    processAndSendAbuseReports();
    return HtmlService.createHtmlOutput('<html><body style="font-family: Arial; padding: 20px;"><h2>Execution completed</h2><p>Check the logs for details.</p></body></html>');
  } catch (err) {
    return HtmlService.createHtmlOutput('<html><body style="font-family: Arial; padding: 20px;"><h2>Error: ' + err.message + '</h2></body></html>');
  }
}

function unfoldHeaders(headerText) {
  return String(headerText || "").replace(/\r?\n[ \t]+/g, " ");
}

function getMessageBodyText(message) {
  var body = message.getPlainBody();
  if (body && body.trim() !== "") return body;
  var html = message.getBody();
  if (!html) return "";
  return html.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "")
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "")
    .replace(/<br\s*\/?>/gi, "\n").replace(/<\/p>/gi, "\n")
    .replace(/<[^>]+>/g, "").replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">");
}

function getOrCreateLabel(name) {
  var label = GmailApp.getUserLabelByName(name);
  return label || GmailApp.createLabel(name);
}

function logToSheet(row) {
  if (!ENABLE_SHEET_LOG || !LOG_SHEET_ID) return;
  try {
    SpreadsheetApp.openById(LOG_SHEET_ID).getSheets()[0].appendRow(row);
  } catch (e) {
    Logger.log("Sheet logging failed: " + e.toString());
  }
}

// ============================================================
// PERSISTENT LOOKUP CACHE
// ============================================================
function loadPersistentCache() {
  try {
    var raw = PropertiesService.getScriptProperties().getProperty(CACHE_PROPERTY_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch (e) { return {}; }
}

function savePersistentCache(cache) {
  if (!CACHE_DIRTY) return; // Skip write if cache was not modified
  try {
    var keys = Object.keys(cache);
    if (keys.length > CACHE_MAX_ENTRIES) {
      keys.sort(function(a, b) { return cache[a].ts - cache[b].ts; });
      keys.slice(0, keys.length - CACHE_MAX_ENTRIES).forEach(function(k) { delete cache[k]; });
    }
    PropertiesService.getScriptProperties().setProperty(CACHE_PROPERTY_KEY, JSON.stringify(cache));
    CACHE_DIRTY = false; // Reset flag after successful save
  } catch (e) {
    Logger.log("Could not persist lookup cache: " + e.toString());
  }
}

function getCachedAbuseEmails(ip, cache) {
  var entry = cache[ip];
  if (!entry || (Date.now() - entry.ts > CACHE_TTL_MS)) return null;
  return entry.emails;
}

function setCachedAbuseEmails(ip, emails, cache) {
  cache[ip] = { emails: emails, ts: Date.now() };
  CACHE_DIRTY = true;
}

// ============================================================
// DIRECT VS FORWARDED EMAIL DETECTION
// ============================================================
function analyzeAbuseHeader(headerText, bodyText, message, myPublicIp) {
  if ((!headerText || headerText.trim() === "") && (!bodyText || bodyText.trim() === "")) {
    return { provider: "N/A", ip: null, abuseEmails: [], forwardType: "n/a" };
  }
  var subject = message ? message.getSubject() : "";
  var fwd = message ? detectForwardType(message, subject) : { type: "direct", raw: null };
  var ip = null;
  var combinedText;
  
  if (fwd.type === "attachment" && fwd.raw) {
    var rawParts = fwd.raw.split(/\r?\n\r?\n/);
    var origHeader = unfoldHeaders(rawParts[0]);
    var origBody = rawParts.slice(1).join("\n");
    ip = extractIpFromHeader(origHeader) || extractIpFromHeader(origBody);
    combinedText = origHeader + "\n" + origBody;
  } else {
    var inlineBlock = extractInlineForwardedHeaderBlock(bodyText);
    if (inlineBlock) {
      fwd.type = "inline";
      ip = extractIpFromHeader(bodyText);
      if (!ip || ip === myPublicIp) {
        var headerIp = extractIpFromHeader(headerText);
        if (headerIp && headerIp !== myPublicIp) ip = headerIp;
      }
    } else {
      ip = extractIpFromHeader(headerText);
      if (!ip || (myPublicIp && ip === myPublicIp)) {
        var bodyIp = extractIpFromHeader(bodyText);
        if (bodyIp && bodyIp !== myPublicIp) ip = bodyIp;
      }
    }
    combinedText = headerText + "\n" + (bodyText || "");
  }
  
  if (!ip) return { provider: "Source IP not found", ip: null, abuseEmails: [], forwardType: fwd.type };
  
  var providerData = getAbuseFromIp(ip, combinedText);
  providerData.ip = ip;
  providerData.forwardType = fwd.type;
  return providerData;
}

function detectForwardType(message, subject) {
  var attRaw = extractForwardedAttachmentRaw(message);
  if (attRaw) return { type: "attachment", raw: attRaw };
  var subjPrefix = /^\s*(fwd|fw|i|rif)\s*:/i.test(subject || "");
  return { type: subjPrefix ? "maybe-inline" : "direct", raw: null };
}

function extractForwardedAttachmentRaw(message) {
  try {
    var atts = message.getAttachments({ includeInlineImages: false, includeAttachments: true });
    for (var i = 0; i < atts.length; i++) {
      if ((atts[i].getContentType() || "").toLowerCase().indexOf("message/rfc822") !== -1) {
        return atts[i].getDataAsString();
      }
    }
  } catch (e) { Logger.log("Error reading attachments: " + e.toString()); }
  return null;
}

function extractInlineForwardedHeaderBlock(bodyText) {
  if (!bodyText) return null;
  var markerRegex = /(?:-{2,}\s*(?:Forwarded message|Messaggio inoltrato)\s*-{2,}|-{2,}\s*Original Message\s*-{2,}|-{2,}\s*Messaggio originale\s*-{2,})/i;
  var m = markerRegex.exec(bodyText);
  if (!m) return null;
  var afterMarker = bodyText.slice(m.index + m[0].length);
  var lines = afterMarker.split(/\r?\n/);
  var headerLines = [];
  var headerFieldRegex = /^(From|Date|Subject|To|Cc|Sent|Da|Data|Oggetto|A|Inviato)\s*:/i;
  for (var i = 0; i < lines.length && headerLines.length < 40; i++) {
    var line = lines[i];
    if (line.trim() === "" && headerLines.length > 0) break;
    if (headerFieldRegex.test(line) || (headerLines.length > 0 && /^\s/.test(line))) {
      headerLines.push(line);
    } else if (headerLines.length === 0) {
      continue;
    } else {
      break;
    }
  }
  return headerLines.length > 0 ? headerLines.join("\n") : null;
}

// ============================================================
// IP EXTRACTION
// ============================================================
function extractIpFromHeader(textToScan) {
  if (!textToScan) return null;
  var text = unfoldHeaders(textToScan);
  var regIp4 = "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b";
  var regIp6 = "(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))";
  var regIp = "(?:" + regIp4 + "|" + regIp6 + ")";
  var lines = text.split("\n");
  
  for (var i = lines.length - 1; i >= 0; i--) {
    if (/Received:/i.test(lines[i])) {
      // Priority A: IP inside square brackets (RFC standard)
      var bracketMatch = lines[i].match(/\[([^\]]+)\]/);
      if (bracketMatch && isValidIpFormat(bracketMatch[1])) {
        var cleaned = cleanIp(bracketMatch[1]);
        if (!isExcludedIp(cleaned)) return cleaned;
      }
      // Priority B: client-ip=...
      var clientIpMatch = lines[i].match(/client-ip=([^\s;]+)/i);
      if (clientIpMatch && isValidIpFormat(clientIpMatch[1])) {
        var cleaned2 = cleanIp(clientIpMatch[1]);
        if (!isExcludedIp(cleaned2)) return cleaned2;
      }
      // Priority C: Any valid IP in the line, preferring the LAST one
      var matches = lines[i].match(new RegExp(regIp, "gi"));
      if (matches) {
        for (var k = matches.length - 1; k >= 0; k--) {
          if (isValidIpFormat(matches[k])) {
            var cleaned3 = cleanIp(matches[k]);
            if (!isExcludedIp(cleaned3)) return cleaned3;
          }
        }
      }
    }
  }
  
  var matchOrig = text.match(new RegExp("X-Originating-IP:\\s*\\[?(" + regIp + ")\\]?", "i"));
  if (matchOrig && matchOrig[1] && isValidIpFormat(matchOrig[1])) {
    var ipClean = cleanIp(matchOrig[1]);
    if (!isExcludedIp(ipClean)) return ipClean;
  }
  
  var allIps = text.match(new RegExp(regIp, "gi"));
  if (allIps) {
    for (var j = allIps.length - 1; j >= 0; j--) {
      if (isValidIpFormat(allIps[j])) {
        var ipAny = cleanIp(allIps[j]);
        if (!isExcludedIp(ipAny)) return ipAny;
      }
    }
  }
  return null;
}

function isValidIpFormat(str) {
  if (!str) return false;
  if (str.indexOf(".") !== -1) {
    var parts = str.split(".");
    if (parts.length !== 4) return false;
    for (var i = 0; i < 4; i++) {
      var num = Number(parts[i]);
      if (isNaN(num) || num < 0 || num > 255 || (parts[i].length > 1 && parts[i].startsWith("0"))) return false;
    }
    return true;
  }
  if (str.indexOf(":") !== -1) {
    var hexParts = str.split(":");
    if (hexParts.length < 3) return false;
    if (hexParts.length === 3) {
      var p0 = parseInt(hexParts[0], 10), p1 = parseInt(hexParts[1], 10), p2 = parseInt(hexParts[2], 10);
      if (!isNaN(p0) && !isNaN(p1) && !isNaN(p2) && p0 < 24 && p1 < 60 && p2 < 60) return false; // Likely time format
    }
    return true;
  }
  return false;
}

function cleanIp(ip) {
  if (!ip) return "";
  return String(ip).replace(/[\[\]\(\)\'\"]/g, "").replace(/%.*$/, "").trim();
}

function isExcludedIp(ip) {
  if (!ip) return true;
  var lowerIp = ip.toLowerCase();
  if (lowerIp.indexOf("::ffff:") === 0) return isExcludedIp(lowerIp.substring(7)); // Handle IPv4-mapped IPv6
  if (lowerIp === "127.0.0.1" || lowerIp === "::1" || lowerIp === "0:0:0:0:0:0:0:1") return true;
  if (lowerIp.indexOf("10.") === 0 || lowerIp.indexOf("192.168.") === 0 || lowerIp.indexOf("127.") === 0) return true;
  if (lowerIp.indexOf("172.") === 0) {
    var parts = lowerIp.split(".");
    if (parts.length >= 2) { var second = parseInt(parts[1], 10); if (second >= 16 && second <= 31) return true; }
  }
  if (lowerIp.indexOf("fe80:") === 0 || lowerIp.indexOf("fc00:") === 0 || lowerIp.indexOf("fd00:") === 0 || lowerIp.indexOf("2002:") === 0) return true;
  if (lowerIp.indexOf("209.85.") === 0 || lowerIp.indexOf("195.130.225.") === 0 || lowerIp.indexOf("37.163.") === 0) return true;
  return false;
}

// ============================================================
// PHISHING / SPAM / FALSE POSITIVE CLASSIFICATION
// ============================================================
function evaluateMessage(headerText, bodyText, subject, fromDecoded, fromRaw) {
  var reasons = [];
  var score = 0;
  var signalCategories = {};
  headerText = unfoldHeaders(headerText);
  var bodyLower = (bodyText || "").toLowerCase();
  
  // Extract domain from decoded From for accurate analysis
  var fromMatch = fromDecoded && fromDecoded.match(/"?([^"<]*)"?\s*<([^>]+)>/);
  var displayName = fromMatch ? fromMatch[1].trim() : (fromDecoded || "").trim();
  var fromEmail = (fromMatch ? fromMatch[2] : (fromDecoded || "")).trim().toLowerCase();
  var fromDomain = (fromEmail.split("@")[1] || "").toLowerCase();
  
  if (fromDomain && TRUSTED_SENDER_DOMAINS.indexOf(fromDomain) !== -1) {
    return { category: "likely-false-positive", score: 0, reasons: ["Sender domain is in TRUSTED_SENDER_DOMAINS whitelist"], fromDomain: fromDomain };
  }
  
  // Obfuscation Detection: Spammers use Base64/QP to hide homoglyphs or bypass filters
  if (/=\?(?:utf-8|iso-8859-1|windows-1252)\?[bq]\?/i.test(subject) || /=\?(?:utf-8|iso-8859-1|windows-1252)\?[bq]\?/i.test(fromDecoded)) {
    score += 2;
    signalCategories.structural = true;
    reasons.push("Obfuscated Base64/Quoted-Printable encoding in From/Subject");
  }
  
  // Authentication signals
  var authResults = headerText.match(/Authentication-Results:[^\n]*/gi) || [];
  var receivedSpf = headerText.match(/Received-SPF:[^\n]*/gi) || [];
  var allAuthLines = authResults.concat(receivedSpf).join(" ").toLowerCase();
  var spfFail = /spf=(fail|softfail)/.test(allAuthLines);
  var dkimFail = /dkim=fail/.test(allAuthLines);
  var dmarcFail = /dmarc=fail/.test(allAuthLines);
  
  if (spfFail || dkimFail || dmarcFail) {
    score += 3;
    signalCategories.auth = true;
    reasons.push("Authentication failed (" + [spfFail && "SPF", dkimFail && "DKIM", dmarcFail && "DMARC"].filter(Boolean).join("/") + ")");
  }
  
  // Display name impersonating a brand/institution
  var brandNames = ["paypal", "amazon", "poste", "posteitaliane", "intesa", "unicredit", "microsoft", "google", "apple", "netflix", "dhl", "fedex", "ups", "agenzia delle entrate", "inps", "aruba", "bancoposta"];
  brandNames.forEach(function(brand) {
    if (displayName.toLowerCase().indexOf(brand) !== -1 && fromDomain.indexOf(brand) === -1) {
      score += 3;
      signalCategories.brand = true;
      reasons.push("Display name imitates '" + brand + "' but real domain is '" + fromDomain + "'");
    }
  });
  
  // Reply-To different from From
  var replyToMatch = headerText.match(/Reply-To:\s*.*?<?([^\s<>]+@[^\s<>]+)>?/i);
  if (replyToMatch) {
    var replyDomain = (replyToMatch[1].split("@")[1] || "").toLowerCase();
    if (replyDomain && fromDomain && replyDomain !== fromDomain) {
      score += 2;
      signalCategories.replyto = true;
      reasons.push("Reply-To (" + replyDomain + ") differs from From (" + fromDomain + ")");
    }
  }
  
  // Keywords: weak signal, capped contribution
  var highRiskKeywords = ["verify your account", "account suspended", "account locked", "urgent action required", "confirm your identity", "welcome bonus", "free spins", "exclusive bonus"];
  var mediumRiskKeywords = ["password", "bank", "credit card", "iban", "casino", "slots", "125%", "upto", "up to"];
  var hrHits = highRiskKeywords.filter(function(k) { return bodyLower.indexOf(k) !== -1; });
  var mrHits = mediumRiskKeywords.filter(function(k) { return bodyLower.indexOf(k) !== -1; });
  
  if (hrHits.length > 0 || mrHits.length > 0) {
    score += 1;
    signalCategories.keywords = true;
    if (hrHits.length > 0) reasons.push("High-risk phrases: " + hrHits.join(", "));
    if (mrHits.length > 0) reasons.push("Sensitive terms: " + mrHits.join(", "));
  }
  
  // Universal Classifieds Bot Detection (works for any user, any item)
  var isFreeProvider = /(gmail|yahoo|outlook|hotmail|icloud|aol)\.com$/.test(fromDomain);
  var isBurnerEmail = /^[a-z]{6,}[0-9]{2,}@/.test(fromEmail);
  var genericQueryRegex = /\b(available|still have|pick up|interested|noch zu haben|verfügbar|abholen|interesse|disponibile|ritiro|interessato|ancora|encore disponible|récupérer)\b/i;
  var hasGenericQuery = genericQueryRegex.test(subject + " " + bodyLower);
  var isVeryShortBody = bodyText && bodyText.replace(/\s/g, '').length < 150;

  if (isFreeProvider && isBurnerEmail && hasGenericQuery) {
    score += 4;
    signalCategories.structural = true;
    reasons.push("Matched universal classifieds bot pattern (burner email + generic short query)");
    if (isVeryShortBody) {
      score += 1;
      reasons.push("Suspiciously short message body typical of automated templates");
    }
  }
  
  // Punycode/IDN detection
  if (/xn--/i.test(fromDomain)) {
    score += 3;
    signalCategories.structural = true;
    reasons.push("Punycode/IDN sender domain: " + fromDomain);
  }
  var punycodeLinks = (bodyText || "").match(/https?:\/\/[^\s"'<>]*xn--[^\s"'<>]*/gi);
  if (punycodeLinks && punycodeLinks.length > 0) {
    score += 3;
    signalCategories.structural = true;
    reasons.push("Punycode/IDN link(s) in body");
  }
  
  // Homoglyph mixing detection on decoded display name
  var hasLatin = /[a-z]/i;
  var hasCyrillicOrGreek = /[\u0400-\u04FF\u0370-\u03FF]/;
  if (fromDomain && hasLatin.test(fromDomain) && hasCyrillicOrGreek.test(fromDomain)) {
    score += 3;
    signalCategories.structural = true;
    reasons.push("Mixed Latin/Cyrillic-Greek characters in sender domain (homoglyph attack)");
  }
  if (displayName && hasLatin.test(displayName) && hasCyrillicOrGreek.test(displayName)) {
    score += 3;
    signalCategories.structural = true;
    reasons.push("Mixed Latin/Cyrillic-Greek characters in display name");
  }
  
  // Urgency patterns
  if (bodyText) {
    var exclamationRuns = bodyText.match(/!{2,}/g) || [];
    var capsWords = bodyText.match(/\b[A-Z]{4,}\b/g) || [];
    if (exclamationRuns.length >= 2 || capsWords.length >= 5) {
      score += 1;
      signalCategories.structural = true;
      reasons.push("Excessive urgency punctuation or ALL-CAPS shouting");
    }
  }
  
  // Suspicious links
  if (bodyText && /https?:\/\/\d{1,3}(\.\d{1,3}){3}/.test(bodyText)) {
    score += 2;
    signalCategories.links = true;
    reasons.push("Direct link to an IP address");
  }
  if (bodyText && /https?:\/\/[a-z0-9-]+\.(tk|ml|ga|cf|gq|top|xyz|click|zip|country|kim)\b/i.test(bodyText)) {
    score += 2;
    signalCategories.links = true;
    reasons.push("Link on a high-abuse TLD");
  }
  
  var hrefTextMismatch = /href\s*=\s*["']https?:\/\/([^"'\/]+)[^"']*["'][^>]*>\s*(?:https?:\/\/)?([a-z0-9.-]+\.[a-z]{2,})/gi;
  var mismatchMatch;
  while ((mismatchMatch = hrefTextMismatch.exec(bodyText || "")) !== null) {
    var hrefDomain = mismatchMatch[1].toLowerCase();
    var visibleDomain = mismatchMatch[2].toLowerCase();
    if (hrefDomain !== visibleDomain && hrefDomain.indexOf(visibleDomain) === -1) {
      score += 3;
      signalCategories.links = true;
      reasons.push("Masked link: text '" + visibleDomain + "' points to '" + hrefDomain + "'");
      break;
    }
  }
  
  // --- CRITICAL SAFEGUARD ---
  // If score is 0, there are absolutely no risk signals. It must be a false positive.
  // Never report an email with a score of 0.
  if (score === 0) {
    return { category: "likely-false-positive", score: 0, reasons: ["No risk signals detected (score 0)"], fromDomain: fromDomain };
  }
  
  // Classification
  var categoryCount = Object.keys(signalCategories).length;
  var category = (score >= 7 && categoryCount >= 2) ? "phishing" : "spam";
  
  return { category: category, score: score, reasons: reasons, fromDomain: fromDomain };
}


function isSafeAbuseTarget(ip, abuseEmails, senderDomain) {
  if (!ip || !abuseEmails || abuseEmails.length === 0) return false;
  if (isExcludedIp(ip)) return false;
  
  var trapMatch = abuseEmails.some(function(email) {
    var domain = email.split("@")[1];
    return domain && KNOWN_TRAP_ABUSE_DOMAINS.indexOf(domain) !== -1;
  });
  if (trapMatch) return false;
  
  var suspicious = abuseEmails.every(function(email) {
    var domain = email.split("@")[1];
    return domain && senderDomain && (domain === senderDomain || domain.endsWith("." + senderDomain));
  });
  if (suspicious) return false;
  
  return true;
}

// ============================================================
// OPTIONAL: ARF (RFC 5965) FEEDBACK-REPORT ATTACHMENT
// ============================================================
function buildArfBlob(result, evalResult, subject, rawHeader) {
  try {
    var arrivalDate = new Date().toUTCString();
    var arf = "Feedback-Type: " + (evalResult.category === "phishing" ? "phishing" : "abuse") + "\n" +
              "User-Agent: AppsScriptAbuseReporter/1.0\nVersion: 1\n" +
              "Original-Mail-From: " + (rawHeader.match(/^From:[^\n]*/mi) || [""])[0].replace(/^From:\s*/i, "") + "\n" +
              "Source-IP: " + result.ip + "\nArrival-Date: " + arrivalDate + "\n" +
              "Reported-Domain: " + evalResult.fromDomain + "\nOriginal-Subject: " + subject + "\n";
    return Utilities.newBlob(arf, "text/plain", "feedback-report.txt");
  } catch (e) {
    Logger.log("Could not build ARF blob: " + e.toString());
    return null;
1.1.2
  }
}

// ============================================================
// NETWORK HELPER: RETRY WITH BACKOFF
// ============================================================
function fetchWithRetry(url, options, maxRetries) {
  maxRetries = maxRetries || 3;
  var attempt = 0;
  var lastError = null;
  var fetchOptions = options || { muteHttpExceptions: true, followRedirects: true };
  if (!fetchOptions.timeout) fetchOptions.timeout = 30000; // Enforce 30s timeout
  
  while (attempt < maxRetries) {
    try {
      var res = UrlFetchApp.fetch(url, fetchOptions);
      var code = res.getResponseCode();
      if (code === 200) return res;
      if (code === 429 || code >= 500) {
        Utilities.sleep(Math.pow(2, attempt) * 1000);
        attempt++;
        continue;
      }
      Logger.log("HTTP " + code + " (no retry) | " + url);
      return res;
    } catch (e) {
      lastError = e;
      Utilities.sleep(Math.pow(2, attempt) * 1000);
      attempt++;
    }
  }
  Logger.log("fetchWithRetry: giving up after " + maxRetries + " attempts | " + url + (lastError ? " | " + lastError.toString() : ""));
  return null;
}

// ============================================================
// ABUSE CONTACT LOOKUP (RDAP / RIPE / ARIN)
// ============================================================
function getAbuseFromIp(ipAddress, combinedText) {
  var infoApi = queryIpApi(ipAddress);
  var providerName = infoApi.org || infoApi.isp || "Unknown";
  var abuseEmails = extractAbuseFromHeader(combinedText);
  if (abuseEmails.length > 0) return { provider: providerName + " (Header)", abuseEmails: abuseEmails };
  
  var cached = getCachedAbuseEmails(ipAddress, PERSISTENT_CACHE);
  if (cached) return { provider: providerName, abuseEmails: cached };
  
  abuseEmails = searchAbuseFromIp(ipAddress);
  setCachedAbuseEmails(ipAddress, abuseEmails, PERSISTENT_CACHE);
  return { provider: providerName, abuseEmails: abuseEmails };
}

function searchAbuseFromIp(ipAddress) {
  var emails = [];
  if (isIPv4(ipAddress)) {
    var base = getRdapBaseUrl(ipAddress);
    if (base) {
      emails = fetchRdapAndExtract(base.replace(/\/+$/, "") + "/ip/" + encodeURIComponent(ipAddress));
      if (emails.length > 0) return emails;
    }
  }
  var fallbackUrls = [
    "https://rdap.org/ip/" + encodeURIComponent(ipAddress),
    "https://rdap.arin.net/registry/ip/" + encodeURIComponent(ipAddress),
    "https://rdap.db.ripe.net/ip/" + encodeURIComponent(ipAddress),
    "https://rdap.apnic.net/ip/" + encodeURIComponent(ipAddress),
    "https://rdap.lacnic.net/rdap/ip/" + encodeURIComponent(ipAddress),
    "https://rdap.afrinic.net/rdap/ip/" + encodeURIComponent(ipAddress)
  ];
  for (var i = 0; i < fallbackUrls.length; i++) {
    emails = fetchRdapAndExtract(fallbackUrls[i]);
    if (emails.length > 0) return emails;
    Utilities.sleep(250);
  }
  if (isIPv4(ipAddress)) {
    emails = searchRipe(ipAddress);
    if (emails.length > 0) return emails;
    emails = searchArin(ipAddress);
  }
  return emails;
}

var RDAP_BOOTSTRAP_V6 = null;
function getRdapBaseUrl(ip) {
  var isV6 = ip.indexOf(":") !== -1;
  var bootstrapUrl = isV6 ? "https://data.iana.org/rdap/ipv6.json" : "https://data.iana.org/rdap/ipv4.json";
  if (isV6) {
    if (RDAP_BOOTSTRAP_V6 === null) RDAP_BOOTSTRAP_V6 = loadRdapBootstrap(bootstrapUrl);
    return lookupRdapUrl(ip, RDAP_BOOTSTRAP_V6, true);
  } else {
    if (RDAP_BOOTSTRAP === null) RDAP_BOOTSTRAP = loadRdapBootstrap(bootstrapUrl);
    return lookupRdapUrl(ip, RDAP_BOOTSTRAP, false);
  }
}

function loadRdapBootstrap(url) {
  var res = fetchWithRetry(url, { muteHttpExceptions: true, followRedirects: true }, 2);
  if (res && res.getResponseCode() === 200) {
    try { return JSON.parse(res.getContentText()); } catch (e) { Logger.log("RDAP Bootstrap parse error: " + e.toString()); }
  }
  return false;
}

function lookupRdapUrl(ip, bootstrapData, isV6) {
  if (!bootstrapData || !bootstrapData.services) return null;
  var bestUrl = null, bestMask = -1;
  bootstrapData.services.forEach(function(service) {
    var prefixes = service[1] || [], urls = service[2] || [];
    if (!urls.length) return;
    prefixes.forEach(function(prefix) {
      var parts = prefix.split("/");
      if (parts.length < 2) return;
      var mask = parseInt(parts[1], 10);
      if (!isV6) {
        var ipLong = ipToLong(ip);
        var maskBits = mask === 0 ? 0 : ((~0 << (32 - mask)) >>> 0);
        var netLong = ipToLong(parts[0]);
        if (((ipLong & maskBits) >>> 0) === ((netLong & maskBits) >>> 0) && mask > bestMask) {
          bestMask = mask; bestUrl = urls[0];
        }
      } else {
        var prefixNorm = parts[0].toLowerCase(), ipNorm = ip.toLowerCase();
        if ((ipNorm === prefixNorm || ipNorm.startsWith(prefixNorm + ":")) && mask > bestMask) {
          bestMask = mask; bestUrl = urls[0];
        }
      }
    });
  });
  return bestUrl;
}

function ipToLong(ip) {
  var parts = ip.split(".");
  if (parts.length !== 4) return 0;
  var long = 0;
  for (var i = 0; i < 4; i++) long = long * 256 + parseInt(parts[i], 10);
  return long >>> 0;
}

function isIPv4(ip) { return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip); }

function fetchRdapAndExtract(url) {
  var options = { muteHttpExceptions: true, followRedirects: true, headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AbuseReporter/1.0" } };
  var res = fetchWithRetry(url, options, 3);
  if (!res) return [];
  var code = res.getResponseCode(), text = res.getContentText();
  if (code !== 200) { Logger.log("RDAP HTTP " + code + " | " + url); return []; }
  
  var emails = [];
  if (text && text.trim().charAt(0) === "{") {
    try {
      var data = JSON.parse(text), visited = new WeakSet();
      emails = findEmailsInRdap(data, ["abuse"], visited);
      if (emails.length === 0) {
        visited = new WeakSet();
        emails = findEmailsInRdap(data, ["noc", "technical", "administrative", "registrant", "abuse-c"], visited);
      }
    } catch (e) {}
  }
  if (emails.length === 0) emails = extractEmailsFromText(text, true);
  if (emails.length === 0) emails = extractEmailsFromText(text, false);
  return filterValidEmails(emails);
}

function findEmailsInRdap(obj, targetRoles, visitedSet) {
  var emails = [];
  if (!obj || typeof obj !== "object" || visitedSet.has(obj)) return emails;
  visitedSet.add(obj);
  var entities = obj.entities;
  if (entities && !Array.isArray(entities)) entities = [entities];
  if (Array.isArray(entities)) {
    entities.forEach(function(entity) {
      var roles = entity.roles || [];
      if (!Array.isArray(roles)) roles = [roles];
      var roleMatch = roles.some(function(role) { return targetRoles.indexOf(String(role).toLowerCase()) !== -1; });
      if (roleMatch && entity.vcardArray) emails = emails.concat(extractEmailFromVcard(entity.vcardArray));
      emails = emails.concat(findEmailsInRdap(entity, targetRoles, visitedSet));
    });
  }
  if (obj.vcardArray) emails = emails.concat(extractEmailFromVcard(obj.vcardArray));
  return emails;
}

function extractEmailFromVcard(vcardArray) {
  var emails = [];
  if (!Array.isArray(vcardArray) || vcardArray.length < 2) return emails;
  var props = vcardArray[1];
  if (!Array.isArray(props)) return emails;
  props.forEach(function(prop) {
    if (Array.isArray(prop) && prop.length >= 4) {
      var name = String(prop[0]).toLowerCase();
      if (name.indexOf("email") !== -1 || name.indexOf("abuse") !== -1) {
        var val = prop[prop.length - 1];
        if (typeof val === "string" && val.indexOf("@") !== -1) emails.push(val.replace(/^mailto:/i, ""));
      }
    }
  });
  return emails;
}

function extractEmailsFromText(text, onlyAbuse) {
  if (!text) return [];
  var matches = String(text).match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [];
  if (onlyAbuse) matches = matches.filter(function(e) { return e.toLowerCase().indexOf("abuse") !== -1; });
  return filterValidEmails(matches);
}

function filterValidEmails(emails) {
  var out = [];
  (emails || []).forEach(function(email) {
    email = String(email).toLowerCase().trim().replace(/^mailto:/i, "");
    if (/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/.test(email) && !isBlockedEmail(email)) out.push(email);
  });
  return removeDuplicates(out);
}

function isBlockedEmail(email) {
  var blocked = ["@example.", "@iana.org", "@icann.org", "@ripe.net", "@arin.net", "@apnic.net", "@lacnic.net", "@afrinic.net", "@ietf.org", "@localhost"];
  for (var i = 0; i < blocked.length; i++) if (email.indexOf(blocked[i]) !== -1) return true;
  return false;
}

function searchRipe(ipAddress) {
  var url = "https://rest.db.ripe.net/search.json?query-string=" + encodeURIComponent(ipAddress) + "&source=ripe";
  var res = fetchWithRetry(url, { muteHttpExceptions: true, followRedirects: true }, 3);
  if (!res || res.getResponseCode() !== 200) return [];
  var text = res.getContentText(), data = safeParse(text);
  var emails = extractRipeAbuseMailboxes(data);
  if (emails.length > 0) return filterValidEmails(emails);
  emails = extractEmailsFromText(text, true);
  if (emails.length > 0) return filterValidEmails(emails);
  
  var handles = extractRipeAbuseHandles(data);
  for (var i = 0; i < handles.length && i < 5; i++) {
    var urlHandle = "https://rest.db.ripe.net/search.json?query-string=" + encodeURIComponent(handles[i]) + "&source=ripe";
    var resHandle = fetchWithRetry(urlHandle, { muteHttpExceptions: true, followRedirects: true }, 3);
    if (!resHandle || resHandle.getResponseCode() !== 200) continue;
    var textHandle = resHandle.getContentText(), dataHandle = safeParse(textHandle);
    emails = extractRipeAbuseMailboxes(dataHandle);
    if (emails.length > 0) return filterValidEmails(emails);
    emails = extractEmailsFromText(textHandle, true);
    if (emails.length > 0) return filterValidEmails(emails);
    Utilities.sleep(250);
  }
  return [];
}

function safeParse(text) { try { return JSON.parse(text); } catch (e) { return null; } }
function extractRipeAbuseMailboxes(data) { return findNamedAttributeValues(data, "abuse-mailbox", new WeakSet()); }
function extractRipeAbuseHandles(data) { return removeDuplicates(findNamedAttributeValues(data, "abuse-c", new WeakSet())); }

function findNamedAttributeValues(obj, attrName, visitedSet) {
  var values = [];
  if (!obj || typeof obj !== "object" || visitedSet.has(obj)) return values;
  visitedSet.add(obj);
  if (Array.isArray(obj)) {
    obj.forEach(function(item) { values = values.concat(findNamedAttributeValues(item, attrName, visitedSet)); });
    return values;
  }
  if (obj[attrName] && typeof obj[attrName] === "string") values.push(obj[attrName]);
  if (obj.name === attrName && typeof obj.value === "string") values.push(obj.value);
  for (var key in obj) { if (obj.hasOwnProperty(key)) values = values.concat(findNamedAttributeValues(obj[key], attrName, visitedSet)); }
  return values;
}

function searchArin(ipAddress) {
  var urls = ["https://whois.arin.net/rest/ip/" + encodeURIComponent(ipAddress) + ".json", "https://whois.arin.net/rest/ip/" + encodeURIComponent(ipAddress) + "/pocs.json"];
  for (var i = 0; i < urls.length; i++) {
    var res = fetchWithRetry(urls[i], { muteHttpExceptions: true, followRedirects: true }, 3);
    if (!res || res.getResponseCode() !== 200) continue;
    var text = res.getContentText();
    var emails = extractEmailsFromText(text, true);
    if (emails.length > 0) return filterValidEmails(emails);
    var pocLinks = text.match(/https:\/\/whois\.arin\.net\/rest\/poc\/[^"<>]+/gi) || [];
    for (var j = 0; j < pocLinks.length && j < 5; j++) {
      var link = pocLinks[j];
      if (link.indexOf(".json") === -1) link += ".json";
      var pocRes = fetchWithRetry(link, { muteHttpExceptions: true, followRedirects: true }, 3);
      if (!pocRes || pocRes.getResponseCode() !== 200) continue;
      emails = extractEmailsFromText(pocRes.getContentText(), true);
      if (emails.length > 0) return filterValidEmails(emails);
      Utilities.sleep(200);
    }
    Utilities.sleep(200);
  }
  return [];
}

function extractAbuseFromHeader(textToScan) {
  var emails = [];
  var abuseHeaderLines = String(textToScan).match(/(?:X-Report-Abuse|X-Abuse-Contact|X-Complaints-To|X-Abuse|Abuse-Contact|Report-Abuse|X-Abuse-Info):[^\n]*/gi) || [];
  abuseHeaderLines.forEach(function(line) {
    var lineEmails = line.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [];
    emails = emails.concat(lineEmails);
  });
  var genericAbuse = String(textToScan).match(/\babuse@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/gi) || [];
  emails = emails.concat(genericAbuse);
  return filterValidEmails(emails);
}

function queryIpApi(ipAddress) {
  var url1 = "https://ipwho.is/" + ipAddress;
  var res1 = fetchWithRetry(url1, { muteHttpExceptions: true }, 2);
  if (res1 && res1.getResponseCode() === 200) {
    try {
      var data = JSON.parse(res1.getContentText());
      if (data.success) return { org: (data.connection && data.connection.org) ? data.connection.org : "Unknown", isp: data.isp || "Unknown" };
    } catch (e) {}
  }
  var url2 = "http://ip-api.com/json/" + ipAddress;
  var res2 = fetchWithRetry(url2, { muteHttpExceptions: true }, 2);
  if (res2 && res2.getResponseCode() === 200) {
    try { return JSON.parse(res2.getContentText()); } catch (e) {}
  }
  return {};
}

function removeDuplicates(arr) { return arr.filter(function(item, pos) { return arr.indexOf(item) === pos; }); }
