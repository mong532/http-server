import crypto from "crypto";
import { MongoClient } from "mongodb";

/**
 * OxaPay webhook receiver (Vercel Serverless Function).
 *
 * - Validates `HMAC` header (sha512) using `OXAPAY_MERCHANT_API_KEY`.
 * - On status "Paid", grants the role via Discord REST API.
 *
 * Required env vars (set in Vercel Project Settings):
 * - OXAPAY_MERCHANT_API_KEY
 * - DISCORD_TOKEN   (bot token)
 * - MONGODB_URI     (Atlas connection string)
 * - MONGODB_DB_NAME (optional; default goffup_bot)
 */

export const config = {
  api: {
    bodyParser: false, // we need RAW body for HMAC validation
  },
};

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    let data = Buffer.alloc(0);
    req.on("data", (chunk) => {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      data = Buffer.concat([data, buf]);
      if (data.length > 1_000_000) {
        reject(new Error("Payload too large"));
        req.destroy();
      }
    });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

function safeJsonParse(buf) {
  try {
    return JSON.parse(buf.toString("utf8"));
  } catch {
    return null;
  }
}

function verifyHmac(rawBuf, hmacHeader, secret) {
  const got = String(hmacHeader || "").trim().toLowerCase();
  if (!got) return false;
  const expected = crypto.createHmac("sha512", secret).update(rawBuf).digest("hex").toLowerCase();
  return expected === got;
}

function parseOrderId(orderId) {
  // Must match bot format: premium_<guildId>_<userId>_<roleId>_<ts>
  const m = String(orderId || "").match(/^premium_(\d{5,})_(\d{5,})_(\d{5,})_(\d+)$/);
  if (!m) return null;
  return { guildId: m[1], userId: m[2], roleId: m[3], ts: Number(m[4]) };
}

async function discordAddRole({ token, guildId, userId, roleId }) {
  const url = `https://discord.com/api/v10/guilds/${guildId}/members/${userId}/roles/${roleId}`;
  const res = await fetch(url, {
    method: "PUT",
    headers: {
      Authorization: `Bot ${token}`,
      "Content-Type": "application/json",
    },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Discord role add failed: HTTP ${res.status} ${text}`.slice(0, 500));
  }
}

let mongoClient = null;
let mongoConnecting = null;

async function getMongo() {
  const uri = process.env.MONGODB_URI || "";
  if (!uri) return null;
  if (mongoClient) return mongoClient;
  if (mongoConnecting) return mongoConnecting;
  mongoConnecting = new MongoClient(uri)
    .connect()
    .then((c) => {
      mongoClient = c;
      return c;
    })
    .finally(() => {
      mongoConnecting = null;
    });
  return mongoConnecting;
}

async function upsertInvoice({ trackId, orderId, status, payload, parsed }) {
  const c = await getMongo();
  if (!c) return;
  const dbName = process.env.MONGODB_DB_NAME || "goffup_bot";
  const col = c.db(dbName).collection("premium_invoices");
  await col.createIndex({ trackId: 1 }, { unique: true }).catch(() => null);
  await col.updateOne(
    { trackId: String(trackId || "") },
    {
      $setOnInsert: {
        trackId: String(trackId || ""),
        orderId: String(orderId || ""),
        guildId: parsed?.guildId || null,
        userId: parsed?.userId || null,
        roleId: parsed?.roleId || null,
        createdAt: new Date(),
      },
      $set: {
        status: String(status || "unknown"),
        updatedAt: new Date(),
        lastWebhook: payload || null,
      },
    },
    { upsert: true }
  );
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.status(405).send("Method Not Allowed");
    return;
  }

  const merchantKey = process.env.OXAPAY_MERCHANT_API_KEY || "";
  const botToken = process.env.DISCORD_TOKEN || "";
  if (!merchantKey || !botToken) {
    res.status(500).send("Missing env");
    return;
  }

  let raw;
  try {
    raw = await readRawBody(req);
  } catch (e) {
    res.status(413).send(e?.message || "Too large");
    return;
  }

  const hmacHeader = req.headers["hmac"];
  if (!verifyHmac(raw, hmacHeader, merchantKey)) {
    res.status(400).send("Invalid HMAC");
    return;
  }

  const data = safeJsonParse(raw);
  if (!data) {
    res.status(400).send("Invalid JSON");
    return;
  }

  const status = String(data.status || "").trim().toLowerCase();
  const orderId = String(data.order_id || "").trim();
  const trackId = String(data.track_id || "").trim();
  const parsed = parseOrderId(orderId);

  // Record webhook to Mongo (best-effort).
  try {
    if (trackId) {
      await upsertInvoice({ trackId, orderId, status, payload: data, parsed });
    }
  } catch (e) {
    console.error("[oxapay] mongo upsert failed:", e);
  }

  // Always acknowledge with 200 "ok" (OxaPay retries otherwise).
  // We still do best-effort processing before replying.
  if (status === "paid") {
    if (parsed) {
      try {
        await discordAddRole({
          token: botToken,
          guildId: parsed.guildId,
          userId: parsed.userId,
          roleId: parsed.roleId,
        });
      } catch (e) {
        // Still return ok so OxaPay doesn't spam retries; logs will show failures in Vercel.
        console.error("[oxapay] role grant failed:", e);
      }
    }
  }

  res.status(200).send("ok");
}

