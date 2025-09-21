const express = require("express");
const multer = require("multer");
const fs = require("fs");
const cors = require("cors");
const path = require("path");
const { OpenAI } = require("openai");
require("dotenv").config();
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args)); 
async function fetchWithTimeout(url, opts = {}, ms = 20000) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: ac.signal });
  } finally {
    clearTimeout(t);
  }
}

const cookieParser = require("cookie-parser");


const app = express();


app.use(cookieParser());

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));


app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});


app.use((req, res, next) => {
  if (req.path.startsWith('/api') || req.path === '/analyze' || req.path === '/hf-classify') {
    res.setHeader('Cache-Control', 'no-store, max-age=0');
    res.setHeader('CDN-Cache-Control', 'no-store');
    res.setHeader('Vercel-CDN-Cache-Control', 'no-store');
  }
  next();
});

const admin = require("firebase-admin");


let svc = null;


if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  try { svc = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT); }
  catch (e) { console.warn("[boot] Bad FIREBASE_SERVICE_ACCOUNT JSON"); }
}


if (!svc) {
  try { svc = require(path.join(__dirname, "serviceAccount.json")); }
  catch { }
}


if (!admin.apps.length) {
  if (svc && svc.project_id) {
    admin.initializeApp({ credential: admin.credential.cert(svc) });
  } else {

    admin.initializeApp({ credential: admin.credential.applicationDefault() });
  }
}




async function verifyRecaptcha(req, res, next) {
  try {
    const token =
      req.body?.['g-recaptcha-response'] ||
      req.headers['x-recaptcha-token'] ||
      req.query?.token;

    if (!token) {
      return res.status(400).json({ ok:false, error:'Captcha requerido' });
    }

    const params = new URLSearchParams({
      secret: process.env.RECAPTCHA_SECRET || '',
      response: token,
      remoteip: req.ip,
    });

    const r = await fetchWithTimeout(
      'https://www.google.com/recaptcha/api/siteverify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: params
      },
      10000
    );

    const data = await r.json();


    const allowed = new Set([
      'localhost','127.0.0.1',
      'epidermyx.com','www.epidermyx.com',

    ]);

    if (!data.success || (data.hostname && !allowed.has(data.hostname))) {
      console.warn('[reCAPTCHA] fail', { hostname: data.hostname, errors: data['error-codes'] });
      return res.status(403).json({ ok:false, error:'Captcha inválido' });
    }

    next();
  } catch (e) {
    console.error('[reCAPTCHA] error', e);
    res.status(502).json({ ok:false, error:'Captcha verification error' });
  }
}

const SESSION_LOGIN_PATHS  = ["/sessionLogin",  "/api/sessionLogin"];
const SESSION_SIGNUP_PATHS = ["/sessionSignup", "/api/sessionSignup"];
const SESSION_LOGOUT_PATHS = ["/sessionLogout", "/api/sessionLogout"];
const WHOAMI_PATHS         = ["/whoami",        "/api/whoami"];




app.post(SESSION_LOGIN_PATHS, express.json(), async (req, res) => {
  try {
    const idToken = req.body?.idToken;
    if (!idToken) {
      return res.status(400).json({ ok: false, error: "Missing idToken" });
    }


    await admin.auth().verifyIdToken(idToken);

    const expiresIn = 5 * 24 * 60 * 60 * 1000; 
    const cookie = await admin.auth().createSessionCookie(idToken, { expiresIn });

    res.cookie("__session", cookie, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      path: "/",
      maxAge: expiresIn
    });

    return res.json({ ok: true });
  } catch (err) {
    console.error("[/sessionLogin] ERROR:", err);
    return res.status(401).json({ ok: false, error: "Session creation failed" });
  }
});


app.post(SESSION_SIGNUP_PATHS, express.json(), verifyRecaptcha, async (req, res) => {
  try {
    const idToken = req.body?.idToken;
    if (!idToken) return res.status(400).json({ ok:false, error:"Missing idToken" });

    const expiresIn = 5 * 24 * 60 * 60 * 1000;
    const cookie = await admin.auth().createSessionCookie(idToken, { expiresIn });
    res.cookie("__session", cookie, {
      httpOnly: true, sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      path: "/", maxAge: expiresIn
    });
    return res.json({ ok:true });
  } catch (err) {
    console.error("[/sessionSignup] ERROR:", err);
    return res.status(401).json({ ok:false, error:"Session creation failed" });
  }
});


app.post(SESSION_LOGOUT_PATHS, (_req,res)=>{ res.clearCookie("__session"); res.json({ok:true}); });
app.get(WHOAMI_PATHS, authRequired, (req,res)=> res.json({ ok:true, uid:req.user.uid, email:req.user.email || null }));

//login

app.post(SESSION_LOGOUT_PATHS, (_req, res) => {
  res.clearCookie("__session");
  res.json({ ok:true });
});

async function authRequired(req, res, next) {
  const raw = req.cookies?.__session;
  if (!raw) {
    console.warn("[authRequired] no __session cookie");
    return res.status(401).json({ ok:false, error:"Login required" });
  }
  try {
    const decoded = await admin.auth().verifySessionCookie(raw, true);
    req.user = decoded;
    return next();
  } catch (e) {
    console.warn("[authRequired] invalid session:", e?.code || e?.message || e);
    return res.status(401).json({ ok:false, error:"Invalid session" });
  }
}

const USAGE_FILE = path.join(__dirname, "usage.json");
const isServerless = !!process.env.VERCEL;
let USAGE_MEM = {}; 

function readUsage() {
  if (isServerless) return USAGE_MEM;
  try { return JSON.parse(fs.readFileSync(USAGE_FILE, "utf8")); }
  catch { return {}; }
}

function writeUsage(obj) {
  if (isServerless) { USAGE_MEM = obj; return; }
  fs.writeFileSync(USAGE_FILE, JSON.stringify(obj));
}

function usageLimiter({ daily = 3, monthly = 90 } = {}) {
  return (req, res, next) => {
    const uid = req.user.uid;
    const usage = readUsage();
    const u = usage[uid] || { daily:{}, monthly:{} };

    const today = new Date().toISOString().slice(0,10); 
    const month = today.slice(0,7);                      

    const d = u.daily[today] || 0;
    const m = u.monthly[month] || 0;
    if (d >= daily)   return res.status(429).json({ ok:false, error:`Daily limit ${daily} reached` });
    if (m >= monthly) return res.status(429).json({ ok:false, error:`Monthly limit ${monthly} reached` });

 
    u.daily[today] = d + 1;
    u.monthly[month] = m + 1;
    usage[uid] = u;
    writeUsage(usage);

    next();
  };
}
app.get("/me/usage", authRequired, (req, res) => {
  const usage = readUsage();
  const u = usage[req.user.uid] || { daily:{}, monthly:{} };
  const today = new Date().toISOString().slice(0,10);
  const month = today.slice(0,7);
  res.json({
    ok:true,
    today: u.daily[today] || 0,
    month: u.monthly[month] || 0,
    limits: { daily:5, monthly:100 }
  });
});


async function callSpacePredict(spaceUrl, imageBuffer, { filename = "image.jpg", mime = "image/jpeg" } = {}) {
  const url = (spaceUrl || "").replace(/\/+$/, ""); 
  if (!url) throw new Error("SPACE_URL missing");


  async function postMultipart(fullUrl, fieldName) {
    const boundary = '----spaceForm_' + Math.random().toString(16).slice(2);
    const body = Buffer.concat([
      Buffer.from(
        `--${boundary}\r\n` +
        `Content-Disposition: form-data; name="${fieldName}"; filename="${filename}"\r\n` +
        `Content-Type: ${mime}\r\n\r\n`
      ),
      imageBuffer,
      Buffer.from(`\r\n--${boundary}--\r\n`)
    ]);

    const resp = await fetchWithTimeout(fullUrl, {
      method: 'POST',
      headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
      body
    }, 20000);

    const text = await resp.text();
    if (!resp.ok) throw new Error(`${resp.status} ${resp.statusText}: ${text.slice(0,400)}`);
    try { return JSON.parse(text); } catch { return text; }
  }

  try { await fetchWithTimeout(url, { method: "GET" }, 8000); } catch {}

 
  try {
    return await postMultipart(`${url}/predict`, "imagen");
  } catch (e1) {

    try {
      return await postMultipart(`${url}/predict`, "file");
    } catch (e2) {
      
      try {
        const base64 = imageBuffer.toString("base64");
        const resp = await fetchWithTimeout(`${url}/api/predict`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ data: [`data:${mime};base64,${base64}`] })
        }, 20000);

        const text = await resp.text();
        if (!resp.ok) throw new Error(`${resp.status} ${resp.statusText}: ${text.slice(0,400)}`);
        try { return JSON.parse(text); } catch { return text; }
      } catch (e3) {

        const model = process.env.HF_MODEL_SLUG || "lightningpal/epiderm2";
        const out = await hfImageClassify(model, imageBuffer);
        return { model, predictions: out };
      }
    }
  }
}




const allow = new Set([
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'http://localhost:2001',       
  'http://127.0.0.1:2001',
  'https://epidermyx.com',        
  'https://www.epidermyx.com'
]);

app.use((req, res, next) => {
  res.setHeader('Vary', 'Origin');
  next();
});

app.use(cors({
  origin: (origin, callback) => {
    
    if (!origin) return callback(null, true);

    
    if (allow.has(origin) || /\.vercel\.app$/i.test(origin)) {
      return callback(null, true);
    }

    return callback(null, false);
  },
  credentials: true
}));







app.use(express.static(path.join(__dirname, "public")));

app.get('/api/ping', (req, res) => res.json({ ok: true, where: 'server', path: req.path }));
app.post('/api/ping', (req, res) => res.json({ ok: true, where: 'server', method: 'POST', path: req.path }));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 }, 
  fileFilter: (req, file, cb) => {
    
    if (!/^image\/(png|jpe?g|webp|gif)$/i.test(file.mimetype)) {
      return cb(new Error('Only image files (png/jpg/webp/gif) are allowed'));
    }
    cb(null, true);
  }
});


const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

const { HttpsProxyAgent } = require('https-proxy-agent');
const proxyUrl   = process.env.HTTPS_PROXY || process.env.HTTP_PROXY;
const proxyAgent = proxyUrl ? new HttpsProxyAgent(proxyUrl) : undefined;

async function hfImageClassify(model, imageBuffer, { maxRetries = 2, retryDelayMs = 1500 } = {}) {
  const url = `https://api-inference.huggingface.co/models/${model}`;

  const headers = {
    "Content-Type": "application/octet-stream",
    "Accept": "application/json",
    "X-Wait-For-Model": "true",
  };
  const tok = (process.env.HF_TOKEN || "").trim();
  if (tok.startsWith("hf_")) headers.Authorization = `Bearer ${tok}`;

  let attempt = 0;
  while (true) {
    const resp = await fetchWithTimeout(url, {
  method: "POST",
  headers,
  body: imageBuffer,
  ...(proxyAgent && { agent: proxyAgent }),
}, 20000);


    if (resp.status === 503 && attempt < maxRetries) {
      const ra = parseInt(resp.headers.get("retry-after") || "", 10);
      const delay = Number.isFinite(ra) ? ra * 1000 : retryDelayMs;
      await new Promise(r => setTimeout(r, delay));
      attempt++;
      continue;
    }

    const text = await resp.text();
    if (!resp.ok) {
      const err = new Error(`HF ${resp.status}: ${text || "Unknown error"}`);
      err.status = resp.status;
      throw err;
    }
    try { return JSON.parse(text); } catch { return text; }
  }
}



// --- Routes ---

// EpiDerm-1 
const ANALYZE_PATHS = ["/analyze", "/api/analyze"]; 
app.post(ANALYZE_PATHS, authRequired, usageLimiter({ daily: 3, monthly: 90 }), upload.single("imagen"), async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: "No image uploaded." });
      }

      const base64Image = req.file.buffer.toString("base64");
      const mime = req.file.mimetype || "image/jpeg"; 

      const response = await openai.chat.completions.create({
        model: "gpt-4o",
        messages: [
          {
            role: "user",
            content: [
              {
                type: "text",
                text:
                  "Eres un dermatólogo que responde de muy clara manera a sus pacientes de acuerdo a lo que solicitan. Genera un diagnóstico en base a tus propios conocimientos, lo más certero posible. Recuerda siempre terminar recomendando la atención de un dermatólogo. En caso de que o la imágen y el texto, o solo la imágen (en caso de no haber texto) o solo el texto (en caso de no haber imágen) tengan relación con la dermatología, responde. Si la imágen y el texto parecen no ser conslutas dermatológicas, no respondas, y al contrario, solicita que el usuario haga una consulta dermatológica, o que explicitice su consulta. Si el texto tiene una ligera relación con que identifiques la imágen, igual intenta responder, siempre y cuando la imágen se asimile a una patología de la piel. No digas que no eres capaz de diagnosticar, solo que tu diagnóstico no puede reemplazar al de un médico o recomienda visitar a un médico. Además, recuerda responder en html, o sea, si quieres responder en negrita, utiliza <strong>, si vas a hacer una lista con números, <li>, etc, menos etiquetas como <html>. Recuerda de que es posible que un diagnóstico no sea maligno, sino que la patología presente es benigna o inexistente. Dentro de lo posible, indica otro diagnóstico que se podría asimilar o confundir con el que ya diste. Resume tus respuestas y no ocupes un lenguaje tan técnico."
              },
              {
                type: "image_url",
                image_url: { url: `data:${mime};base64,${base64Image}` }
              }
            ]
          }
        ]
      });

      return res.json({ result: response.choices?.[0]?.message?.content ?? "" });
    } catch (err) {
      console.error(err);
      return res.status(500).json({ error: "Error al procesar la imagen" });
    }
    
  }
);


const HF_PATHS = ["/hf-classify", "/api/hf-classify"];
app.post(HF_PATHS, upload.single("imagen"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ ok: false, error: "No se subió ninguna imagen." });
    }

    const imageBuffer = req.file.buffer;  
    const spaceUrl = process.env.SPACE_URL || "https://lightningpal-epiderm.hf.space";

    const out = await callSpacePredict(spaceUrl, imageBuffer);

    const predictions = Array.isArray(out?.predictions)
  ? out.predictions
  : Array.isArray(out)
  ? out
  : [];

return res.json({
  ok: true,
  model: `${out?.model || process.env.HF_MODEL_SLUG || 'unknown'} (Space/HF)`,
  predictions
});

  } catch (err) {
    console.error("Error en /hf-classify (Space proxy):", err);
    return res.status(502).json({ ok: false, error: err?.message || "No se pudo clasificar la imagen." });
  }
});






//hhtft
app.get("/hf-sanity", async (_req, res) => {
  const slug = "lightningpal/epiderm2";         
  const r = await fetch(`https://huggingface.co/api/models/${slug}`, {
    headers: (process.env.HF_TOKEN?.startsWith("hf_"))
      ? { Authorization: `Bearer ${process.env.HF_TOKEN}` } : {}
  });
  const text = await r.text();
  let meta = {};
  try { meta = JSON.parse(text); } catch {}

  const files = (meta.siblings || []).map(s => s.rfilename || s);
  const hasWeights = files.some(f => /(?:model\.safetensors|pytorch_model\.bin)$/i.test(f));
  const hasConfig  = files.includes("config.json");
  const hasProc    = files.some(f => /(preprocessor_config\.json|image_processor\.json|feature_extraction\.json)$/i.test(f));
  const isModelRepo = (meta.cardData || meta.pipeline_tag || meta.library_name || files.length) ? true : false;

  res.json({
    http_status: r.status,
    slug,
    isModelRepo,
    private_or_gated: !!(meta.private || meta.gated),
    pipeline_tag: meta.pipeline_tag || null,
    library_name: meta.library_name || null,
    files_present: { hasWeights, hasConfig, hasProcessor: hasProc },
    note: "Serverless inference needs a *Model* repo with: weights + config.json + preprocessor/image_processor json. Private/gated requires a token."
  });
});


app.get( WHOAMI_PATHS, authRequired, (req, res) =>
  res.json({ ok: true, uid: req.user.uid, email: req.user.email || null })
);



app.use((err, req, res, _next) => {
  console.error('[ERROR]', err);
  const code = err.status || 500;
  res.status(code).json({ error: err.message || 'Server error' });
});



app.get(/.*/, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});


// --- Start server ---
const PORT = process.env.PORT || 3000;

if (process.env.VERCEL) {
  module.exports = app; 
} else {
  app.listen(PORT, () => console.log('Server listening on ' + PORT));
}

