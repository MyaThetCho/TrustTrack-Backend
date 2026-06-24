import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import axios from "axios";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// -----------------------------
// URL normalization
// -----------------------------


function isValidUrlInput(input) {
  const value = input.trim();

  // reject empty or single words like "apple", "bank", "hello"
  if (!value || value.includes(" ")) {
    return false;
  }

  // remove protocol if exists
  const withoutProtocol = value.replace(/^https?:\/\//i, "");

  // get only domain part before slash
  const domainPart = withoutProtocol.split("/")[0];

  // must contain at least one dot
  if (!domainPart.includes(".")) {
    return false;
  }

  // basic domain format check
  const domainRegex =
    /^(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$/;

  return domainRegex.test(domainPart);
}



function normalizeUrl(input) {
  try {
    let raw = input.trim();

    if (!/^https?:\/\//i.test(raw)) {
      raw = "https://" + raw;
    }

    const parsed = new URL(raw);
    const protocol = parsed.protocol.toLowerCase();
    const hostname = parsed.hostname.toLowerCase().replace(/^www\./, "");

    let pathname = parsed.pathname || "";
    pathname = pathname.replace(/\/+$/, "");

    if (pathname === "") {
      return `${protocol}//${hostname}`;
    }

    return `${protocol}//${hostname}${pathname}`;
  } catch {
    return input.trim().toLowerCase();
  }
}

function getDomain(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return null;
  }
}

// -----------------------------
// Typosquatting helpers
// -----------------------------
const protectedBrands = [
  { brand: "paypal", domains: ["paypal.com"] },
  { brand: "google", domains: ["google.com"] },
  { brand: "facebook", domains: ["facebook.com"] },
  { brand: "microsoft", domains: ["microsoft.com"] },
  { brand: "apple", domains: ["apple.com"] },
  { brand: "amazon", domains: ["amazon.com"] },
  { brand: "kbz", domains: ["kbzbank.com", "kpay.com.mm"] },
  { brand: "aya", domains: ["ayabank.com"] },
  { brand: "cb", domains: ["cbbank.com.mm"] },
  { brand: "wavepay", domains: ["wavepay.com.mm"] }
];

function getRootDomain(domain) {
  if (!domain) return "";
  const parts = domain.toLowerCase().split(".");
  if (parts.length <= 2) return parts[0];
  return parts[parts.length - 2];
}

function normalizeLookalike(text) {
  return text
    .toLowerCase()
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/3/g, "e")
    .replace(/5/g, "s")
    .replace(/@/g, "a")
    .replace(/\$/g, "s");
}

function levenshteinDistance(a, b) {
  const matrix = [];

  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }

  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }

  return matrix[b.length][a.length];
}

function checkTyposquatting(domain) {
  const reasons = [];
  let score = 0;

  if (!domain) {
    return { score, reasons };
  }

  const cleanDomain = domain.toLowerCase().replace(/^www\./, "");
  const root = getRootDomain(cleanDomain);
  const normalizedRoot = normalizeLookalike(root);

  for (const item of protectedBrands) {
    const isOfficialDomain = item.domains.includes(cleanDomain);

    if (isOfficialDomain) {
      continue;
    }

    const protectedBrand = item.brand;
    const normalizedBrand = normalizeLookalike(protectedBrand);
    const distance = levenshteinDistance(normalizedRoot, normalizedBrand);

    if (
      normalizedRoot === normalizedBrand ||
      distance === 1 ||
      root.includes(protectedBrand) ||
      normalizedRoot.includes(normalizedBrand)
    ) {
      score += 35;
      reasons.push(
        `Possible typosquatting or brand impersonation: looks similar to ${protectedBrand}`
      );
    }
  }

  return { score, reasons };
}

// -----------------------------
// Heuristic analysis
// -----------------------------
function analyzeUrl(url, domain) {
  const words = [
    "login",
    "verify",
    "bank",
    "otp",
    "password",
    "wallet",
    "free",
    "bonus",
    "gift",
    "claim",
    "reward",
    "win",
    "prize",
    "security",
    "update",
    "account"
  ];

  let score = 0;
  let reasons = [];

  words.forEach((word) => {
    if (url.includes(word)) {
      score += 10;
      reasons.push(`Contains suspicious keyword: ${word}`);
    }
  });

  if (!url.startsWith("https://")) {
    score += 20;
    reasons.push("No HTTPS");
  }

  if (url.length > 80) {
    score += 10;
    reasons.push("Very long URL");
  }

  if (url.includes("@")) {
    score += 20;
    reasons.push("Contains @ symbol");
  }

  const typoResult = checkTyposquatting(domain);
  score += typoResult.score;
  reasons = [...reasons, ...typoResult.reasons];

  return { score, reasons };
}

// -----------------------------
// Google Safe Browsing
// -----------------------------
async function checkGoogleSafeBrowsing(url) {
  const key = process.env.GOOGLE_SAFE_BROWSING_KEY;

  if (!key) {
    return {
      checked: false,
      match: false,
      reason: "Google Safe Browsing API key not configured"
    };
  }

  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${key}`;

  const body = {
    client: {
      clientId: "trusttrack",
      clientVersion: "1.0.0"
    },
    threatInfo: {
      threatTypes: [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION"
      ],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }]
    }
  };

  try {
    const response = await axios.post(endpoint, body);

    if (response.data.matches) {
      return {
        checked: true,
        match: true,
        reason: "Matched Google Safe Browsing unsafe list",
        raw: response.data
      };
    }

    return {
      checked: true,
      match: false,
      reason: "No match in Google Safe Browsing",
      raw: response.data
    };
  } catch (error) {
    return {
      checked: true,
      match: false,
      reason: "Google Safe Browsing check failed",
      error: error.message
    };
  }
}



async function checkPhishTank(url) {
  const endpoint = "https://checkurl.phishtank.com/checkurl/";

  const formData = new URLSearchParams();
  formData.append("url", url);
  formData.append("format", "json");

  if (process.env.PHISHTANK_APP_KEY) {
    formData.append("app_key", process.env.PHISHTANK_APP_KEY);
  }

  try {
    const response = await axios.post(endpoint, formData, {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "phishtank/trusttrack"
      }
    });

    const result = response.data?.results;

    const isRealPhishing =
      result?.in_database === true &&
      result?.verified === true &&
      result?.valid === true;

    return {
      checked: true,
      match: isRealPhishing,
      in_database: result?.in_database === true,
      verified: result?.verified === true,
      valid: result?.valid === true,
      reason: isRealPhishing
        ? "Matched verified valid PhishTank phishing database"
        : "No verified valid phishing match in PhishTank",
      raw: result
    };

  } catch (error) {
    return {
      checked: false,
      match: false,
      verified: false,
      valid: false,
      reason: "PhishTank check failed",
      error: error.message
    };
  }
}



// -----------------------------
// Final decision
// -----------------------------
function finalDecision(googleResult, phishTankResult, heuristicResult) {
  if (googleResult.match) {
    return {
      status: "dangerous",
      trust_level: "red",
      confidence: 95,
      description: "This URL is listed as unsafe by Google Safe Browsing.",
      reason: googleResult.reason,
      recommendation:
        "Do not open this link. Do not enter passwords, OTP, banking information, or personal data."
    };
  }

  if (phishTankResult.match && phishTankResult.verified && phishTankResult.valid) {
  return {
    status: "dangerous",
    trust_level: "red",
    confidence: 96,
    description: "This URL is listed as a verified phishing site by PhishTank.",
    reason: phishTankResult.reason,
    recommendation:
      "Do not open this link. Do not enter passwords, OTP, banking information, or personal data."
  };
}

  if (heuristicResult.score >= 60) {
    return {
      status: "dangerous",
      trust_level: "red",
      confidence: 90,
      description:
        "This URL appears dangerous based on phishing and impersonation indicators.",
      reason: heuristicResult.reasons.join(", "),
      recommendation:
        "Do not open this site. Use the official website by typing the address manually."
    };
  }

  if (heuristicResult.score >= 30) {
    return {
      status: "suspicious",
      trust_level: "yellow",
      confidence: 75,
      description: "This URL has suspicious indicators.",
      reason: heuristicResult.reasons.join(", "),
      recommendation:
        "Do not enter sensitive information. Verify the source carefully before proceeding."
    };
  }

  return {
    status: "safe",
    trust_level: "green",
    confidence: 85,
    description: "No major scam indicators were detected.",
    reason: googleResult.checked
      ? "No Google Safe Browsing match and no major suspicious pattern."
      : "No major suspicious pattern.",
    recommendation: "Continue with normal caution."
  };
}

// -----------------------------
// Routes
// -----------------------------
app.get("/health", (req, res) => {
  res.json({ status: "ok", project: "TrustTrack Backend" });
});

app.get("/news", async (req, res) => {
  const { data, error } = await supabase
    .from("news")
    .select("*")
    .order("created_at", { ascending: false });

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get("/results", async (req, res) => {
  const { data, error } = await supabase
    .from("scans")
    .select("*")
    .order("created_at", { ascending: false })
    .limit(50);

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});





async function resolveRedirects(url) {
  try {
    const response = await axios.get(url, {
      maxRedirects: 5,
      timeout: 8000,
      validateStatus: () => true
    });

    const finalUrl =
      response.request?.res?.responseUrl || url;

    return {
      checked: true,
      original_url: url,
      final_url: finalUrl,
      redirected: finalUrl !== url
    };
  } catch (error) {
    return {
      checked: false,
      original_url: url,
      final_url: url,
      redirected: false,
      error: error.message
    };
  }
}









app.post("/scan", async (req, res) => {
  try {
    const { input_value } = req.body;

    if (!input_value) {
      return res.status(400).json({ error: "input_value is required" });
    }

    if (!isValidUrlInput(input_value)) {
      return res.status(400).json({
        error: "Invalid URL. Please enter a valid website link, for example: google.com or https://google.com"
      });
    }

    const normalized_url = normalizeUrl(input_value);
    const domain = getDomain(normalized_url);
    const display_value = domain || normalized_url;

    const redirectResult = await resolveRedirects(normalized_url);
    const scanUrl = redirectResult.final_url || normalized_url;
    const scanDomain = getDomain(scanUrl);

    const googleResult = await checkGoogleSafeBrowsing(scanUrl);
    const phishTankResult = await checkPhishTank(scanUrl);
    const heuristicResult = analyzeUrl(scanUrl, scanDomain);
    const result = finalDecision(googleResult, phishTankResult, heuristicResult);

    const { data, error } = await supabase
      .from("scans")
      .insert({
        input_type: "link",
        input_value,
        normalized_url,
        domain,
        display_value,
        trust_level: result.trust_level,
        status: result.status,
        confidence: result.confidence,
        description: result.description,
        reason: result.reason,
        recommendation: result.recommendation,
        redirect_result: redirectResult,
        google_safe_browsing_result: googleResult,
        phishtank_result: phishTankResult,
        heuristic_result: heuristicResult,
        source: "website",
        is_public: true
      })
      .select()
      .single();

    if (error) throw error;

    res.json({
      id: data.id,
      input_value: data.input_value,
      normalized_url: data.normalized_url,
      domain: data.domain,
      display_value: data.display_value,
      trust_level: data.trust_level,
      status: data.status,
      confidence: data.confidence,
      description: data.description,
      reason: data.reason,
      recommendation: data.recommendation,
      redirect_result: data.redirect_result,
      google_safe_browsing_result: data.google_safe_browsing_result,
      phishtank_result: data.phishtank_result,
      heuristic_result: data.heuristic_result,
      created_at: data.created_at
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/flag", async (req, res) => {
  const { input_value, reason, reporter } = req.body;

  if (!input_value) {
    return res.status(400).json({ error: "input_value is required" });
  }

  const { data, error } = await supabase
    .from("flags")
    .insert({
      input_value,
      reason,
      reporter,
      status: "pending"
    })
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});




// Get all pending user reports for admin
app.get("/admin/flags", async (req, res) => {
  const { data, error } = await supabase
    .from("flags")
    .select("*")
    .order("created_at", { ascending: false });

  if (error) return res.status(500).json({ error: error.message });

  res.json(data);
});

// Approve a user report
app.patch("/admin/flags/:id/approve", async (req, res) => {
  const { id } = req.params;
  const { reviewed_by, admin_note } = req.body;

  const { data, error } = await supabase
    .from("flags")
    .update({
      status: "approved",
      approved_at: new Date().toISOString(),
      reviewed_by: reviewed_by || "admin",
      admin_note: admin_note || null
    })
    .eq("id", id)
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });

  res.json(data);
});

// Reject a user report
app.patch("/admin/flags/:id/reject", async (req, res) => {
  const { id } = req.params;
  const { reviewed_by, admin_note } = req.body;

  const { data, error } = await supabase
    .from("flags")
    .update({
      status: "rejected",
      reviewed_by: reviewed_by || "admin",
      admin_note: admin_note || null
    })
    .eq("id", id)
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });

  res.json(data);
});






async function sendTelegramMessage(chatId, text) {
  const token = process.env.TELEGRAM_BOT_TOKEN;

  if (!token) {
    console.log("Telegram token missing");
    return;
  }

  await axios.post(`https://api.telegram.org/bot${token}/sendMessage`, {
    chat_id: chatId,
    text,
    parse_mode: "Markdown"
  });
}

app.post("/telegram/webhook", async (req, res) => {
  try {
    const message = req.body.message;
    const chatId = message?.chat?.id;
    const text = message?.text?.trim();

    if (!chatId) {
      return res.sendStatus(200);
    }

    if (!text || text === "/start") {
      await sendTelegramMessage(
        chatId,
        "👋 Welcome to *TrustTrack*.\n\nSend me a suspicious link and I will check it for scams, phishing, QR redirects, and brand impersonation.\n\nExample:\n`paypa1.com`"
      );
      return res.sendStatus(200);
    }

    if (text === "/help") {
      await sendTelegramMessage(
        chatId,
        "🔍 *How to use TrustTrack Bot*\n\n1. Send any website link\n2. I will analyze it\n3. You will receive a trust report\n\nExample:\n`google.com`\n`paypa1.com`\n`free-bank-login-bonus.com`"
      );
      return res.sendStatus(200);
    }

    if (!isValidUrlInput(text)) {
      await sendTelegramMessage(
        chatId,
        "⚠️ Please send a valid website link.\n\nExample:\n`google.com` or `https://google.com`"
      );
      return res.sendStatus(200);
    }

    const normalized_url = normalizeUrl(text);
    const redirectResult = await resolveRedirects(normalized_url);
    const scanUrl = redirectResult.final_url || normalized_url;
    const domain = getDomain(scanUrl);
    const display_value = domain || scanUrl;

    const googleResult = await checkGoogleSafeBrowsing(scanUrl);
    const phishTankResult = await checkPhishTank(scanUrl);
    const heuristicResult = analyzeUrl(scanUrl, domain);
    const result = finalDecision(googleResult, phishTankResult, heuristicResult);

    await supabase.from("scans").insert({
      input_type: "telegram",
      input_value: text,
      normalized_url: scanUrl,
      domain,
      display_value,
      trust_level: result.trust_level,
      status: result.status,
      confidence: result.confidence,
      description: result.description,
      reason: result.reason,
      recommendation: result.recommendation,
      google_safe_browsing_result: googleResult,
      phishtank_result: phishTankResult,
      heuristic_result: heuristicResult,
      redirect_result: redirectResult,
      source: "telegram",
      is_public: true
    });

    const trustEmoji =
      result.trust_level === "green"
        ? "🟢"
        : result.trust_level === "yellow"
        ? "🟡"
        : "🔴";

    const statusEmoji =
      result.status === "dangerous"
        ? "🔴"
        : result.status === "suspicious"
        ? "🟡"
        : "🟢";

        const reply =
        `${statusEmoji} *TrustTrack Report*

        🌐 *URL*
        ${display_value}

        🛡️ *Status*
        ${result.status.toUpperCase()}

        📋 *Reason*
        ${result.reason}

        💡 *Recommendation*
        ${result.recommendation}

        🔎 *Detection Sources*
        Google Safe Browsing: ${googleResult.match ? "⚠️ Match" : "✅ No Match"}
        PhishTank: ${phishTankResult.match ? "⚠️ Match" : "✅ No Match"}
        Typo Detection: ${
          heuristicResult.reasons.some(r =>
            r.toLowerCase().includes("typosquatting") ||
            r.toLowerCase().includes("impersonation")
          )
            ? "⚠️ Detected"
            : "✅ No Match"
        }`;

    await sendTelegramMessage(chatId, reply);

    res.sendStatus(200);
  } catch (error) {
    console.error("Telegram webhook error:", error.message);
    res.sendStatus(200);
  }
});






app.listen(PORT, () => {
  console.log(`TrustTrack backend running on port ${PORT}`);
});