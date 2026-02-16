import OTPAuth from "otpauth";

function json(res, status, body){
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(body));
}

async function readJson(req){
  return await new Promise((resolve, reject) => {
    let data = "";
    req.on("data", chunk => (data += chunk));
    req.on("end", () => {
      try { resolve(data ? JSON.parse(data) : {}); }
      catch (e) { reject(e); }
    });
  });
}

export default async function handler(req, res) {
  // Preflight (CORS)
  if (req.method === "OPTIONS") return json(res, 200, { ok: true });

  if (req.method !== "POST") return json(res, 405, { error: "Method not allowed" });

  const secret = process.env.OTP_SECRET;
  if (!secret) return json(res, 500, { error: "Missing OTP_SECRET" });

  let body;
  try{
    body = await readJson(req);
  }catch{
    return json(res, 400, { valid: false, error: "Invalid JSON" });
  }

  const code = String(body.code || "").trim();
  if (!/^\d{6}$/.test(code)) return json(res, 200, { valid: false });

  const period = 300;     // 5 minutes
  const gracePrev = 60;   // previous code valid only first 60 seconds of new window

  const totp = new OTPAuth.TOTP({
    issuer: "XIME",
    label: "GateOTP",
    algorithm: "SHA1",
    digits: 6,
    period,
    secret: OTPAuth.Secret.fromBase32(secret)
  });

  const now = Date.now();
  const epochSec = Math.floor(now / 1000);
  const secondsIntoWindow = epochSec % period;

  // Generate current + previous window codes safely by shifting timestamp
  const currentCode = totp.generate({ timestamp: now });
  if (code === currentCode) return json(res, 200, { valid: true, mode: "current" });

  // Only accept previous window if within first 60 seconds
  if (secondsIntoWindow <= gracePrev) {
    const prevCode = totp.generate({ timestamp: now - (period * 1000) });
    if (code === prevCode) return json(res, 200, { valid: true, mode: "previous_grace" });
  }

  return json(res, 200, { valid: false });
}
