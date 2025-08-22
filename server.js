import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

const app = express();
app.use(helmet());
app.use(express.json({ limit: "50kb" }));
app.use(rateLimit({ windowMs: 60_000, max: 30 }));

const SENSITIVE = [/^authorization$/i, /^cookie$/i, /^x-.*token$/i];

function parsePowerShell(ps) {
  const methodMatch = ps.match(/-Method\s+['"]?(\w+)['"]?/i);
  const uriMatch = ps.match(/-Uri\s+['"]([^'"]+)['"]/i);
  const bodyMatch = ps.match(/-Body\s+(@'([\s\S]*?)'@|['"]([\s\S]*?)['"])/i);

  // Headers hash: @{ "Key" = "Val"; 'Key2' = 'Val2' }
  const headersBlock = ps.match(/-Headers\s+@{([\s\S]*?)}/i);
  const headers = {};
  if (headersBlock) {
    const entries = headersBlock[1].match(/(['"])(.+?)\1\s*=\s*(['"])([\s\S]*?)\3/g) || [];
    for (const line of entries) {
      const m = line.match(/(['"])(.+?)\1\s*=\s*(['"])([\s\S]*?)\3/);
      if (!m) continue;
      const key = m[2].trim();
      const val = m[4].trim();
      const isSecret = SENSITIVE.some(rx => rx.test(key)) ||
        /roblosecurity/i.test(key) || /roblosecurity/i.test(val) ||
        /token/i.test(key) || /token/i.test(val);
      headers[key] = isSecret ? "[REDACTED]" : val;
    }
  }

  const secretDetected =
    /roblosecurity/i.test(ps) || /authorization/i.test(ps) || /cookie/i.test(ps) || /token/i.test(ps);

  return {
    method: methodMatch?.[1] || "GET",
    url: uriMatch?.[1] || "",
    body: bodyMatch?.[2] || bodyMatch?.[3] || "",
    headers,
    secretDetected
  };
}

app.post("/convert", (req, res) => {
  const { powershell } = req.body || {};
  if (!powershell || typeof powershell !== "string") {
    return res.status(400).json({ error: "powershell text required" });
  }
  const parsed = parsePowerShell(powershell);
  if (parsed.secretDetected) {
    parsed.notice = "Sensitive data detected and redacted. Do not share secrets.";
  }
  res.json(parsed);
});

app.listen(process.env.PORT || 8080, () => {
  console.log("API listening");
});
