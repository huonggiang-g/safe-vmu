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
const fetch      = require('node-fetch');

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

const upload = multer({ storage: multer.memoryStorage() });
const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" }));
const server = http.createServer(app);

// --- 7 API AUTH ---
app.post('/api/auth/register', upload.single('photo'), async (req, res) => {
    try {
        const { full_name, email, password, fingerprint_id } = req.body;
        const b64 = req.file ? req.file.buffer.toString("base64") : null;
        let vector = null;
        if (b64) {
            const r = await fetch(FACE_EXTRACT_URL, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ image: b64 }) });
            const d = await r.json();
            if (d.success) vector = d.vector;
        }
        const hash = await bcrypt.hash(password, 10);
        await supabase.from('accounts').insert([{ full_name, email, password_hash: hash, fingerprint_id: parseInt(fingerprint_id), face_vector: vector }]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const { data: user } = await supabase.from('accounts').select('*').eq('email', email).single();
    if (user && await bcrypt.compare(password, user.password_hash)) { delete user.password_hash; res.json({ success: true, user }); }
    else res.status(401).json({ error: "Sai" });
});

app.post('/api/auth/update-profile', async (req, res) => {
    try { await supabase.from('accounts').update({ full_name: req.body.full_name }).eq('id', req.body.user_id); res.json({ success: true }); }
    catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/update-face', upload.single('photo'), async (req, res) => {
    try {
        const b64 = req.file.buffer.toString("base64");
        const r = await fetch(FACE_EXTRACT_URL, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ image: b64 }) });
        const d = await r.json();
        await supabase.from('accounts').update({ face_vector: d.vector }).eq('id', req.body.user_id);
        res.json({ success: true });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/forgot-password', async (req, res) => {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await supabase.from('accounts').update({ otp_code: otp }).eq('email', req.body.email);
    res.json({ success: true });
});

app.post('/api/auth/reset-password', async (req, res) => {
    const hash = await bcrypt.hash(req.body.new_password, 10);
    await supabase.from('accounts').update({ password_hash: hash }).eq('email', req.body.email);
    res.json({ success: true });
});

// --- MQTT & WEBSOCKET CORE ---
const wss = new WebSocket.Server({ server });
let wsClients = new Set();
const mqttClient = mqtt.connect(MQTT_BROKER, { username: MQTT_USER, password: MQTT_PASS, rejectUnauthorized: false });

mqttClient.on("message", async (topic, payload) => {
    if (topic === TOPIC_PHOTO) {
        const b64 = payload.toString("base64");
        wsClients.forEach(ws => ws.send(JSON.stringify({ type: "photo", data: b64 })));
        await runRecognition(b64);
    }
});

async function runRecognition(b64) {
    try {
        const res = await fetch(FACE_SERVICE_URL, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ image: b64 }) });
        const result = await res.json();
        if (result.recognized) mqttClient.publish(TOPIC_CMD, JSON.stringify({ cmd: "UNLOCK", name: result.name }));
    } catch(e) { console.error(e); }
}

wss.on("connection", (ws) => { wsClients.add(ws); ws.on("close", () => wsClients.delete(ws)); });
server.listen(WS_PORT, () => console.log(`Server online port ${WS_PORT}`));
