import OTPAuth from "otpauth";

function json(res, status, body){
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(body));
}

export default function handler(req, res) {
  // Preflight (CORS)
  if (req.method === "OPTIONS") return json(res, 200, { ok: true });

  if (req.method !== "GET") return json(res, 405, { error: "Method not allowed" });

  const secret = process.env.OTP_SECRET;
  if (!secret) return json(res, 500, { error: "Missing OTP_SECRET" });

  // 5 min = 300 seconds step
  const period = 300;

  const totp = new OTPAuth.TOTP({
    issuer: "XIME",
    label: "GateOTP",
    algorithm: "SHA1",
    digits: 6,
    period,
    secret: OTPAuth.Secret.fromBase32(secret)
  });

  const now = Date.now();
  const code = totp.generate({ timestamp: now });

  // remaining seconds in current 5-min window
  const epochSec = Math.floor(now / 1000);
  const remainingSeconds = period - (epochSec % period);

  return json(res, 200, {
    code,
    validForSeconds: period,
    remainingSeconds
  });
}
