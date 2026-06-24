import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

// ---------------------------
// Supabase Connection
// ---------------------------

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// ---------------------------
// Health Check
// ---------------------------

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    project: "TrustTrack Backend"
  });
});

// ---------------------------
// Test Supabase Connection
// ---------------------------

app.get("/supabase-test", async (req, res) => {
  try {

    const { data, error } = await supabase
      .from("news")
      .select("*")
      .limit(5);

    if (error) throw error;

    res.json({
      success: true,
      records: data
    });

  } catch (err) {

    res.status(500).json({
      success: false,
      error: err.message
    });

  }
});

// ---------------------------
// Get News
// ---------------------------

app.get("/news", async (req, res) => {
  try {

    const { data, error } = await supabase
      .from("news")
      .select("*")
      .order("created_at", { ascending: false });

    if (error) throw error;

    res.json(data);

  } catch (err) {

    res.status(500).json({
      error: err.message
    });

  }
});

// ---------------------------
// Get Scan Results
// ---------------------------

app.get("/results", async (req, res) => {
  try {

    const { data, error } = await supabase
      .from("scans")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(50);

    if (error) throw error;

    res.json(data);

  } catch (err) {

    res.status(500).json({
      error: err.message
    });

  }
});

// ---------------------------
// Scam Detection Logic
// ---------------------------

function analyzeUrl(url) {

  const suspiciousWords = [
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
    "prize"
  ];

  let score = 0;
  let reasons = [];

  suspiciousWords.forEach(word => {

    if (url.toLowerCase().includes(word)) {

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

  if (score >= 40) {

    return {
      status: "dangerous",
      trust_level: "red",
      confidence: 90,
      description: "This URL appears dangerous.",
      reason: reasons.join(", "),
      recommendation:
        "Do not open this link or provide personal information."
    };

  }

  if (score >= 20) {

    return {
      status: "suspicious",
      trust_level: "yellow",
      confidence: 70,
      description: "This URL appears suspicious.",
      reason: reasons.join(", "),
      recommendation:
        "Verify the source before proceeding."
    };

  }

  return {
    status: "safe",
    trust_level: "green",
    confidence: 90,
    description: "No major suspicious indicators detected.",
    reason: "No major suspicious indicators found.",
    recommendation:
      "Continue with normal caution."
  };

}

// ---------------------------
// Scan URL
// ---------------------------

app.post("/scan", async (req, res) => {

  try {

    const { input_value } = req.body;

    if (!input_value) {

      return res.status(400).json({
        error: "input_value is required"
      });

    }

    const result = analyzeUrl(input_value);

    const { data, error } = await supabase
      .from("scans")
      .insert({
        input_type: "link",
        input_value,
        trust_level: result.trust_level,
        status: result.status,
        confidence: result.confidence,
        description: result.description,
        reason: result.reason,
        recommendation: result.recommendation,
        source: "website"
      })
      .select()
      .single();

    if (error) throw error;

    res.json(data);

  } catch (err) {

    res.status(500).json({
      error: err.message
    });

  }

});

// ---------------------------
// Start Server
// ---------------------------

app.listen(PORT, () => {
  console.log(`TrustTrack backend running on port ${PORT}`);
});