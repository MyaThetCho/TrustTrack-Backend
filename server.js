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

function normalizeUrl(input) {
  let url = input.trim();
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "https://" + url;
  }
  return url.toLowerCase();
}

function getDomain(url) {
  try {
    return new URL(url).hostname.replace("www.", "");
  } catch {
    return null;
  }
}

function analyzeUrl(url) {
  const words = ["login", "verify", "bank", "otp", "password", "wallet", "free", "bonus", "gift", "claim", "reward", "win", "prize"];
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

  return { score, reasons };
}

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

function finalDecision(googleResult, heuristicResult) {
  if (googleResult.match) {
    return {
      status: "dangerous",
      trust_level: "red",
      confidence: 95,
      description: "This URL is listed as unsafe by Google Safe Browsing.",
      reason: googleResult.reason,
      recommendation: "Do not open this link. Do not enter passwords, OTP, banking information, or personal data."
    };
  }

  if (heuristicResult.score >= 40) {
    return {
      status: "dangerous",
      trust_level: "red",
      confidence: 90,
      description: "This URL appears dangerous based on suspicious patterns.",
      reason: heuristicResult.reasons.join(", "),
      recommendation: "Avoid opening this link. Verify the source using an official website."
    };
  }

  if (heuristicResult.score >= 20) {
    return {
      status: "suspicious",
      trust_level: "yellow",
      confidence: 70,
      description: "This URL has suspicious indicators.",
      reason: heuristicResult.reasons.join(", "),
      recommendation: "Do not enter sensitive information. Check the source carefully."
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

app.post("/scan", async (req, res) => {
  try {
    const { input_value } = req.body;

    if (!input_value) {
      return res.status(400).json({ error: "input_value is required" });
    }

    const normalized_url = normalizeUrl(input_value);
    const domain = getDomain(normalized_url);
    const display_value = domain || normalized_url;

    const googleResult = await checkGoogleSafeBrowsing(normalized_url);
    const heuristicResult = analyzeUrl(normalized_url);
    const result = finalDecision(googleResult, heuristicResult);

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
        google_safe_browsing_result: googleResult,
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
      google_safe_browsing_result: data.google_safe_browsing_result,
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

app.listen(PORT, () => {
  console.log(`TrustTrack backend running on port ${PORT}`);
});