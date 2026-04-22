import crypto from "crypto";
import { MongoClient } from "mongodb";

/**
 * OxaPay webhook receiver (Vercel Serverless Function).
 *
 * - Validates `HMAC` header (sha512) using `OXAPAY_MERCHANT_API_KEY`.
 * - On status "Paid", loads invoice from Mongo by `track_id`, grants role, creates premium ticket channel.
 *
 * Invoice rows are created by the bot with guildId, userId, roleId, ticketCategoryId, staffRoleIds.
 */

export const config = {
  api: {
    bodyParser: false,
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

function decodeSnowflake36(v) {
  try {
    const chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let out = 0n;
    for (const ch of String(v || "").toUpperCase()) {
      const idx = chars.indexOf(ch);
      if (idx < 0) return "";
      out = out * 36n + BigInt(idx);
    }
    return out.toString(10);
  } catch {
    return "";
  }
}

function parseOrderId(orderId) {
  const m = String(orderId || "").trim().match(/^premium_([A-Z0-9]+)_([A-Z0-9]+)_([A-Z0-9]+)$/);
  if (!m) return null;
  const guildId = decodeSnowflake36(m[1]);
  const userId = decodeSnowflake36(m[2]);
  if (!guildId || !userId) return null;
  return { guildId, userId };
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

async function discordGetBotUserId(token) {
  const res = await fetch("https://discord.com/api/v10/users/@me", {
    headers: { Authorization: `Bot ${token}` },
  });
  if (!res.ok) {
    const t = await res.text().catch(() => "");
    throw new Error(`Discord @me failed: HTTP ${res.status} ${t}`.slice(0, 300));
  }
  const j = await res.json();
  return String(j.id);
}

async function discordListGuildChannels(token, guildId) {
  const res = await fetch(`https://discord.com/api/v10/guilds/${guildId}/channels`, {
    headers: { Authorization: `Bot ${token}` },
  });
  if (!res.ok) return [];
  return res.json();
}

async function discordCreatePremiumChannel({ token, guildId, categoryId, userId, staffRoleIds, botUserId }) {
  const VIEW = 1024;
  const SEND = 2048;
  const ATTACH = 32768;
  const READ_HISTORY = 65536;
  const MANAGE_CH = 16;
  const userAllow = VIEW + SEND + ATTACH + READ_HISTORY;
  const botAllow = VIEW + SEND + MANAGE_CH + READ_HISTORY;
  const staffAllow = VIEW + SEND + READ_HISTORY;

  const overwrites = [
    { id: guildId, type: 0, deny: String(VIEW) },
    { id: userId, type: 1, allow: String(userAllow) },
    { id: botUserId, type: 1, allow: String(botAllow) },
  ];
  for (const rid of staffRoleIds || []) {
    if (!rid) continue;
    overwrites.push({ id: String(rid), type: 0, allow: String(staffAllow) });
  }

  const name = `premium-${userId}`.toLowerCase().slice(0, 100);
  const res = await fetch(`https://discord.com/api/v10/guilds/${guildId}/channels`, {
    method: "POST",
    headers: {
      Authorization: `Bot ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      name,
      type: 0,
      parent_id: categoryId,
      topic: `Premium · ${userId}`,
      permission_overwrites: overwrites,
    }),
  });
  if (!res.ok) {
    const t = await res.text().catch(() => "");
    throw new Error(`Discord create channel failed: HTTP ${res.status} ${t}`.slice(0, 400));
  }
  return res.json();
}

async function discordSendMessage(token, channelId, content) {
  await fetch(`https://discord.com/api/v10/channels/${channelId}/messages`, {
    method: "POST",
    headers: {
      Authorization: `Bot ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ content }),
  });
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
        createdAt: new Date(),
      },
      $set: {
        status: String(status || "unknown"),
        ...(parsed?.guildId ? { guildId: String(parsed.guildId) } : {}),
        ...(parsed?.userId ? { userId: String(parsed.userId) } : {}),
        updatedAt: new Date(),
        lastWebhook: payload || null,
      },
    },
    { upsert: true }
  );
}

function candidateDbNames() {
  const set = new Set();
  const envDb = String(process.env.MONGODB_DB_NAME || "").trim();
  if (envDb) set.add(envDb);
  set.add("gopuff_bot");
  set.add("goffup_bot");
  return [...set];
}

async function loadInvoice(trackId) {
  const c = await getMongo();
  if (!c) return null;
  const tid = String(trackId || "");
  for (const dbName of candidateDbNames()) {
    const doc = await c.db(dbName).collection("premium_invoices").findOne({ trackId: tid });
    if (doc) return { ...doc, _dbName: dbName };
  }
  return null;
}

/**
 * Update user role snapshot used by admin dashboard.
 * We store a simple role entry so UI can immediately show premium status.
 */
async function upsertPremiumMemberRoleSnapshot({ guildId, userId, roleId }) {
  const c = await getMongo();
  if (!c || !guildId || !userId) return;
  const dbName = process.env.MONGODB_DB_NAME || "goffup_bot";
  const col = c.db(dbName).collection("guild_member_joins");
  const now = new Date();
  await col.createIndex({ guildId: 1, userId: 1 }, { unique: true }).catch(() => null);
  await col.updateOne(
    { guildId: String(guildId), userId: String(userId) },
    {
      $set: {
        guildId: String(guildId),
        userId: String(userId),
        roles: roleId ? [{ id: String(roleId), name: "premium members" }] : [],
        updatedAt: now,
      },
      $setOnInsert: {
        createdAt: now,
        joinedAt: now,
        username: null,
        globalName: null,
        displayName: null,
        accountCreatedAt: null,
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

  try {
    if (trackId) {
      await upsertInvoice({ trackId, orderId, status, payload: data, parsed });
    }
  } catch (e) {
    console.error("[oxapay] mongo upsert failed:", e);
  }

  if (status === "paid" && trackId) {
    try {
      const doc = await loadInvoice(trackId);
      const guildId = doc?.guildId ? String(doc.guildId) : parsed?.guildId || "";
      const userId = doc?.userId ? String(doc.userId) : parsed?.userId || "";
      const roleId = doc?.roleId ? String(doc.roleId) : "";
      const categoryId = doc?.ticketCategoryId ? String(doc.ticketCategoryId) : "";
      const staffRoleIds = Array.isArray(doc?.staffRoleIds) ? doc.staffRoleIds.map(String) : [];

      console.log(
        `[oxapay] paid trackId=${trackId} db=${doc?._dbName || "n/a"} guildId=${guildId || "-"} userId=${userId || "-"} roleId=${roleId || "-"} categoryId=${categoryId || "-"}`
      );

      if (!guildId || !userId) {
        console.warn(
          `[oxapay] paid webhook missing guild/user mapping for trackId=${trackId}. Ensure premium_invoices row exists in Mongo with guildId/userId.`
        );
      }

      if (guildId && userId && roleId) {
        await discordAddRole({ token: botToken, guildId, userId, roleId });
        await upsertPremiumMemberRoleSnapshot({ guildId, userId, roleId }).catch(() => null);
      }

      if (guildId && userId && categoryId) {
        const botUserId = await discordGetBotUserId(botToken);
        const channels = await discordListGuildChannels(botToken, guildId);
        const wantName = `premium-${userId}`.toLowerCase();
        const existing = channels.find(
          (ch) => ch.type === 0 && String(ch.parent_id || "") === categoryId && String(ch.name || "") === wantName
        );

        const dashboardHint = "Use **`/gopuff`** in the server to open the main dashboard.";
        if (existing?.id) {
          await discordSendMessage(
            botToken,
            existing.id,
            `<@${userId}>\n**Premium payment confirmed.** ${dashboardHint}`
          );
        } else {
          const created = await discordCreatePremiumChannel({
            token: botToken,
            guildId,
            categoryId,
            userId,
            staffRoleIds,
            botUserId,
          });
          const mention = staffRoleIds.length ? `${staffRoleIds.map((id) => `<@&${id}>`).join(" ")} ` : "";
          if (created?.id) {
            await discordSendMessage(
              botToken,
              created.id,
              `<@${userId}> ${mention}\n**Premium payment confirmed.** This is your private premium channel.\n${dashboardHint}`
            );
          }
        }
      }
    } catch (e) {
      console.error("[oxapay] paid fulfillment failed:", e);
    }
  }

  res.status(200).send("ok");
}
