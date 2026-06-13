/**
 * server.js — MQTT → WebSocket Bridge + Face Recognition + Fingerprint + DB
 */
require("dotenv").config();
const nodemailer = require('nodemailer');
const express    = require("express");
const http       = require("http");
const WebSocket  = require("ws");
const mqtt       = require("mqtt");
const path       = require("path");
const fs         = require("fs");
const multer     = require("multer");
const cors       = require('cors');
const bcrypt     = require('bcrypt');
const fetch      = require('node-fetch'); // Đã chuyển sang kiểu require truyền thống

const MQTT_BROKER           = "mqtts://e539507d822e4b348dc6f0af2600bd01.s1.eu.hivemq.cloud:8883";
const MQTT_USER             = "ketsat";
const MQTT_PASS             = "Ket123456";
const TOPIC_PHOTO           = "safe1/cam";
const TOPIC_LOGS            = "safe1/log";
const TOPIC_CMD             = "safe1/cmd";
const TOPIC_FINGER_CMD      = "safe1/fingercmd";
const TOPIC_FINGER_STATUS   = "safe1/fingerstatus";
const TOPIC_FACE_RESULT     = "safe1/faceresult"; 
const WS_PORT               = process.env.PORT || 3000;

const FACE_SERVICE_URL      = process.env.FACE_SERVICE_URL || "https://smart-safe.onrender.com/recognize";
const FACE_RELOAD_URL       = process.env.FACE_RELOAD_URL || "https://smart-safe.onrender.com/reload";
const FACE_EXTRACT_URL      = FACE_SERVICE_URL.replace("/recognize", "/extract_vector"); 
const RECOGNIZE_COOLDOWN    = 3000;

const { createClient } = require('@supabase/supabase-js');
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com', port: 465, secure: true, 
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    tls: { rejectUnauthorized: false }
});

const DATA_FACE_DIR = path.join(__dirname, "data_face");
if (!fs.existsSync(DATA_FACE_DIR)) fs.mkdirSync(DATA_FACE_DIR, { recursive: true });

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/")) cb(null, true);
    else cb(new Error("Chỉ chấp nhận file ảnh"), false);
  }
});

const app = express();
app.use(cors());
const server = http.createServer(app);

app.use(express.static(path.join(__dirname)));
app.use(express.json({ limit: "10mb" }));
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

// --- CÁC API AUTH (Đã giữ nguyên logic) ---
app.post('/api/auth/register', upload.single('photo'), async (req, res) => {
    try {
        const { full_name, email, password, fingerprint_id } = req.body;
        const b64Image = req.file ? req.file.buffer.toString("base64") : null;
        let faceVector = null;
        if (b64Image) {
            const extractRes = await fetch(FACE_EXTRACT_URL, {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ image: b64Image }),
            });
            const extractData = await extractRes.json();
            if (extractData.success) faceVector = extractData.vector;
        }
        const password_hash = await bcrypt.hash(password, 10);
        const { data: newUser } = await supabase.from('accounts').insert([{ full_name, email, password_hash, fingerprint_id: parseInt(fingerprint_id), face_vector: faceVector }]).select().single();
        res.json({ success: true, user: newUser });
    } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const { data: user } = await supabase.from('accounts').select('*').eq('email', email).single();
        if (user && await bcrypt.compare(password, user.password_hash)) {
            delete user.password_hash;
            res.json({ success: true, user });
        } else res.status(401).json({ success: false, error: "Sai thông tin" });
    } catch (err) { res.status(500).json({ success: false, error: "Lỗi" }); }
});

// --- PHẦN XỬ LÝ NHẬN DIỆN CỐT LÕI ---
const wss = new WebSocket.Server({ server });
let wsClients = new Set();
let lastRecognizeTime = 0;

async function runRecognition(b64Image, timestamp) {
    try {
      const res = await fetch(FACE_SERVICE_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ image: b64Image }),
      });
      const result = await res.json();
      wsClients.forEach(ws => ws.send(JSON.stringify({ type: "recognition_result", ...result })));
      if (result.recognized) publishUnlock(result.name);
    } catch (err) { console.error("AI Error:", err); }
}

function publishUnlock(name) {
    mqttClient.publish(TOPIC_CMD, JSON.stringify({ cmd: "UNLOCK", name }));
}

const mqttClient = mqtt.connect(MQTT_BROKER, { username: MQTT_USER, password: MQTT_PASS, rejectUnauthorized: false });

mqttClient.on("message", async (topic, payload) => {
    if (topic === TOPIC_PHOTO) {
        const b64 = payload.toString("base64");
        if (Date.now() - lastRecognizeTime >= RECOGNIZE_COOLDOWN) {
            lastRecognizeTime = Date.now();
            await runRecognition(b64, new Date().toISOString());
        }
    }
});

server.listen(WS_PORT, () => console.log(`🚀 Server running on port ${WS_PORT}`));
