import express from "express";
import cors from "cors";
import crypto from "crypto";
import fetch from "node-fetch";
import admin from "firebase-admin";

// 1) Firebase Admin (on Cloud Run, default service account works)
admin.initializeApp();

const app = express();

// 2) CORS — lock to your domains
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",")
  : ["https://skatecityng.com", "https://www.skatecityng.com", "https://skatecity-ng.web.app"];

app.use(cors({
  origin: allowedOrigins,
  methods: ["POST", "GET", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: false
}));

// JSON parser for normal routes
app.use(express.json());

// 3) Helper: verify Firebase ID token
async function verifyIdToken(req) {
  const authHeader = req.headers.authorization || "";
  const idToken = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!idToken) throw new Error("Missing token");
  return admin.auth().verifyIdToken(idToken);
}

// (Optional) compute/validate amount on server using your product DB
function validateAmount(amountFromClient) {
  // TODO: replace with real validation
  if (!Number.isInteger(amountFromClient) || amountFromClient <= 0) {
    throw new Error("Invalid amount");
  }
  return amountFromClient;
}

// 4) Initialize Paystack transaction
app.post("/", async (req, res) => {
  try {
    await verifyIdToken(req);

    const { email, amount, callback_url } = req.body || {};
    if (!email || !amount) return res.status(400).json({ status: false, message: "Missing email/amount" });

    const verifiedAmount = validateAmount(amount);

    const secret = process.env.PAYSTACK_SECRET_KEY; // set in Cloud Run
    if (!secret) return res.status(500).json({ status: false, message: "Missing server Paystack secret key" });

    const resp = await fetch("https://api.paystack.co/transaction/initialize", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${secret}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email,
        amount: verifiedAmount,
        callback_url,
        currency: "NGN",
      }),
    });

    const data = await resp.json();
    if (!data?.status) {
      return res.status(502).json({ status: false, message: "Paystack init failed", data });
    }

    return res.json({ status: true, data: data.data }); // { authorization_url, reference, ... }
  } catch (err) {
    console.error(err);
    const code = /token|auth/i.test(err.message) ? 401 : 400;
    return res.status(code).json({ status: false, message: err.message || "Request failed" });
  }
});

// 5) Webhook — must read raw body to verify signature
app.post("/webhook/paystack",
  express.raw({ type: "*/*" }),
  (req, res) => {
    try {
      const signature = req.headers["x-paystack-signature"];
      const secret = process.env.PAYSTACK_SECRET_KEY;
      if (!secret) return res.status(500).end();

      const hash = crypto.createHmac("sha512", secret).update(req.body).digest("hex");
      if (hash !== signature) return res.status(401).end();

      const event = JSON.parse(req.body.toString("utf8"));

      if (event?.event === "charge.success") {
        const { reference, amount, currency, customer } = event.data;
        // TODO: look up pending order by reference, verify amount/currency,
        // then mark order paid / fulfill.
        console.log("PAYSTACK SUCCESS", { reference, amount, currency, email: customer?.email });
      }

      return res.sendStatus(200);
    } catch (e) {
      console.error("Webhook error", e);
      return res.sendStatus(400);
    }
  }
);

// 6) Health check
app.get("/health", (_, res) => res.send("ok"));

const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`Server listening on port ${port}`));