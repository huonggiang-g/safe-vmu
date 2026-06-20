require("dotenv").config();
const nodemailer = require('nodemailer');
const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const mqtt = require("mqtt");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const cors = require('cors');
const bcrypt = require('bcrypt');
const fetch = require('node-fetch');

const MQTT_BROKER          = "mqtts://e539507d822e4b348dc6f0af2600bd01.s1.eu.hivemq.cloud:8883";
const MQTT_USER            = "ketsat";
const MQTT_PASS            = "Ket123456";
const TOPIC_PHOTO          = "safe1/cam";
const TOPIC_LOGS           = "safe1/log";
const TOPIC_CMD            = "safe1/cmd";
const TOPIC_FINGER_CMD     = "safe1/fingercmd";
const TOPIC_FINGER_STATUS  = "safe1/fingerstatus";
const TOPIC_FACE_RESULT    = "safe1/faceresult";
const WS_PORT              = process.env.PORT || 3000;

// URL AI Services
const SMART_SAFE_URL    = "https://smart-safe.onrender.com/recognize";
const AI_LIGHT_URL      = process.env.AI_LIGHT_URL || "http://localhost:5001/extract_vector";
const RECOGNIZE_COOLDOWN = 5000;

// Cấu hình Mail (nodemailer - giữ lại làm fallback)
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    tls: { rejectUnauthorized: false }
});

const { createClient } = require('@supabase/supabase-js');
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

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

// ==========================================
// CÁC API AUTH
// ==========================================

app.post('/api/auth/register', upload.single('photo'), async (req, res) => {
    try {
        const { full_name, email, password, fingerprint_id } = req.body;
        if (!full_name || !email || !password) return res.status(400).json({ success: false, error: "Thiếu thông tin" });

        let faceVector = null;
        if (req.file) {
            const b64Image = req.file.buffer.toString("base64");
            const extractRes = await fetch(AI_LIGHT_URL, {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ image: b64Image }),
            });
            const extractData = await extractRes.json();
            if (extractData.embedding) faceVector = extractData.embedding;
            else throw new Error("AI không nhận diện được khuôn mặt.");
        }

        const password_hash = await bcrypt.hash(password, 10);
        const { data: newUser, error: insertError } = await supabase
            .from('accounts')
            .insert([{ full_name, email, password_hash, face_vector: faceVector }]).select().single();
        if (insertError) throw insertError;
        res.json({ success: true, message: "Đăng ký thành công!", user: newUser });
    } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ success: false, error: "Vui lòng nhập Email và Mật khẩu" });

        const { data: user, error: userError } = await supabase
            .from('accounts').select('id, full_name, email, password_hash, role, fingerprint_id').eq('email', email).single();

        if (userError || !user) return res.status(401).json({ success: false, error: "Email hoặc mật khẩu sai" });

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) return res.status(401).json({ success: false, error: "Email hoặc mật khẩu sai" });

        delete user.password_hash;
        res.json({ success: true, message: "Đăng nhập thành công!", user: user, roles: {} });
    } catch (err) { res.status(500).json({ success: false, error: "Lỗi máy chủ" }); }
});

app.post('/api/auth/update-profile', async (req, res) => {
    try {
        const { user_id, full_name, new_password, fingerprint_id } = req.body;
        if (!user_id || !full_name) return res.status(400).json({ success: false, error: "Thiếu thông tin" });

        let updateData = { full_name: full_name };
        if (fingerprint_id !== undefined && fingerprint_id !== null) updateData.fingerprint_id = parseInt(fingerprint_id);

        if (new_password && new_password.trim() !== "") {
            if (new_password.length < 8) return res.status(400).json({ success: false, error: "Mật khẩu < 8 ký tự" });
            updateData.password_hash = await bcrypt.hash(new_password, 10);
        }

        const { data: updatedUser, error: updateError } = await supabase
            .from('accounts').update(updateData).eq('id', user_id)
            .select('id, full_name, email, role, fingerprint_id').single();

        if (updateError) throw updateError;
        res.json({ success: true, message: "Cập nhật hồ sơ thành công!", user: updatedUser });
    } catch (err) { res.status(500).json({ success: false, error: "Lỗi máy chủ khi cập nhật" }); }
});

app.post('/api/auth/update-face', upload.single('photo'), async (req, res) => {
    try {
        const user_id = req.body.user_id;
        if (!user_id || !req.file) return res.status(400).json({ success: false, error: "Thiếu thông tin hoặc ảnh" });

        const b64Image = req.file.buffer.toString("base64");

        const resSmart = await fetch(SMART_SAFE_URL, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ image: b64Image }),
        });
        const dataSmart = await resSmart.json();
        if (dataSmart.status !== "ok") throw new Error("Không phát hiện khuôn mặt thật hoặc ảnh giả mạo.");

        const resAi = await fetch(AI_LIGHT_URL, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ image: dataSmart.face }),
        });
        const dataAi = await resAi.json();
        if (!dataAi.embedding) throw new Error("Không trích xuất được vector khuôn mặt.");

        const { error: updateError } = await supabase
            .from('accounts').update({ face_vector: dataAi.embedding }).eq('id', user_id);
        if (updateError) throw updateError;

        const personDir = path.join(DATA_FACE_DIR, `user_${user_id}`);
        if (!fs.existsSync(personDir)) fs.mkdirSync(personDir, { recursive: true });
        fs.writeFileSync(path.join(personDir, `${Date.now()}.jpg`), req.file.buffer);

        res.json({ success: true, message: "Đã cập nhật dữ liệu khuôn mặt thành công!" });
    } catch (err) { res.status(500).json({ success: false, error: err.message || "Lỗi máy chủ" }); }
});

// ==========================================
// API MAIL & PASSWORD
// ==========================================

app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ success: false, error: "Vui lòng nhập Email" });

        const { data: user } = await supabase.from('accounts').select('id, full_name').eq('email', email).single();
        if (!user) return res.status(404).json({ success: false, error: "Email không tồn tại" });

        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date();
        expiresAt.setMinutes(expiresAt.getMinutes() + 5);

        await supabase.from('accounts').update({ otp_code: otpCode, otp_expires_at: expiresAt.toISOString() }).eq('id', user.id);

        const html = `<h3>Xin chào ${user.full_name},</h3><p>Mã xác thực của bạn là: <b>${otpCode}</b>. Mã này hết hạn sau 5 phút.</p>`;
        await sendEmail(email, "Mã OTP Đặt Lại Mật Khẩu", html);

        res.json({ success: true, message: "Mã OTP đã được gửi!" });
    } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { email, otp, new_password } = req.body;
        const { data: user } = await supabase.from('accounts').select('id, otp_code, otp_expires_at').eq('email', email).single();

        if (!user || String(user.otp_code).trim() !== String(otp).trim())
            return res.status(400).json({ success: false, error: "Mã OTP không chính xác" });
        if (new Date() > new Date(user.otp_expires_at))
            return res.status(400).json({ success: false, error: "Mã OTP đã hết hạn." });

        const new_password_hash = await bcrypt.hash(new_password, 10);
        await supabase.from('accounts').update({
            password_hash: new_password_hash,
            otp_code: null,
            otp_expires_at: null
        }).eq('id', user.id);

        res.json({ success: true, message: "Đặt lại mật khẩu thành công!" });
    } catch (err) { res.status(500).json({ success: false, error: "Lỗi hệ thống" }); }
});

// ==========================================
// CÁC API HISTORY & SAFE
// ==========================================

app.post('/api/history/view', async (req, res) => {
    try {
        const { user_id, safe_id } = req.body;

        const { data: safeData } = await supabase
            .from('safes').select('id').eq('serial_number', safe_id).single();
        if (!safeData) return res.status(404).json({ success: false, message: "Két sắt không tồn tại" });

        const realSafeId = safeData.id;

        const { data: member, error: memberError } = await supabase
            .from('safe_members').select('role')
            .eq('safe_id', realSafeId).eq('user_id', user_id).single();
        if (memberError || !member)
            return res.status(403).json({ success: false, message: "Bạn không có quyền truy cập két này" });

        let query = supabase
            .from('unlock_logs')
            .select('*, accounts(full_name), safes(serial_number)')
            .eq('safe_id', realSafeId)
            .order('attempted_at', { ascending: false });

        if (member.role === 'user') query = query.eq('actor_id', user_id);

        const { data: logs, error } = await query;
        if (error) throw error;
        res.json({ success: true, logs: logs });
    } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.get('/api/safe/my-role', async (req, res) => {
    try {
        const { safe_id } = req.query;
        const user_id = req.headers['x-user-id'];
        if (!safe_id || !user_id) return res.status(400).json({ error: "Thiếu thông tin xác thực" });

        const { data: safeData } = await supabase
            .from('safes').select('id').eq('serial_number', safe_id).single();
        if (!safeData) return res.status(404).json({ error: "Két sắt không tồn tại" });

        const { data: member } = await supabase
            .from('safe_members').select('role')
            .eq('safe_id', safeData.id).eq('user_id', user_id).maybeSingle();

        res.json({ role: member ? member.role : null });
    } catch (err) {
        console.error("LỖI API my-role:", err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/safe/members', async (req, res) => {
    try {
        const { safe_id } = req.query;

        const { data: safeData } = await supabase.from('safes').select('id').eq('serial_number', safe_id).single();
        if (!safeData) return res.status(404).json({ error: "Két không tồn tại" });

        const { data: members, error } = await supabase
            .from('safe_members').select('user_id, role, accounts(full_name)').eq('safe_id', safeData.id);

        if (error) throw error;
        res.json({ members });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/safe/add-member', async (req, res) => {
    try {
        const { safe_id, email, role } = req.body;

        const { data: userData } = await supabase.from('accounts').select('id').eq('email', email).single();
        if (!userData) return res.status(404).json({ error: "Không tìm thấy người dùng có email này" });

        const { data: safeData } = await supabase.from('safes').select('id').eq('serial_number', safe_id).single();

        const { error } = await supabase.from('safe_members').insert({
            safe_id: safeData.id,
            user_id: userData.id,
            role: role || 'user'
        });

        if (error) return res.status(400).json({ error: "Người dùng này đã tồn tại trong két" });
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/safe/transfer-owner', async (req, res) => {
    try {
        const { safe_id, new_owner_id, current_owner_id } = req.body;
        const { data: safeData } = await supabase.from('safes').select('id').eq('serial_number', safe_id).single();

        await supabase.from('safe_members').update({ role: 'user' }).eq('safe_id', safeData.id).eq('user_id', current_owner_id);
        await supabase.from('safe_members').update({ role: 'owner' }).eq('safe_id', safeData.id).eq('user_id', new_owner_id);

        res.json({ success: true, message: "Đã nhượng quyền thành công!" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/safe/join-by-code', async (req, res) => {
    try {
        const { user_id, serial_number, invite_code } = req.body;

        const { data: safe } = await supabase.from('safes').select('id').eq('serial_number', serial_number).single();
        if (!safe) return res.status(404).json({ error: "Không tìm thấy két sắt" });

        const { data: invite } = await supabase
            .from('safe_invitations').select('*')
            .eq('safe_id', safe.id).eq('invite_code', invite_code).eq('is_used', false).single();
        if (!invite) return res.status(400).json({ error: "Mã không hợp lệ hoặc đã được sử dụng" });

        await supabase.from('safe_members').insert({ safe_id: safe.id, user_id: user_id, role: invite.role });
        await supabase.from('safe_invitations').update({ is_used: true }).eq('id', invite.id);

        res.json({ success: true, message: `Tham gia két ${serial_number} thành công với quyền ${invite.role}!` });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ==========================================
// LOGIC AI
// ==========================================

async function runRecognition(b64Image, timestamp) {
    if (!b64Image || b64Image.length < 1000) return;
    const cleanBase64 = b64Image.includes(',') ? b64Image.split(',')[1] : b64Image;

    broadcast({ type: "recognizing", timestamp });

    try {
        const resSmart = await fetch(SMART_SAFE_URL, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ image: cleanBase64 }),
        });
        const dataSmart = await resSmart.json();
        if (dataSmart.status !== "ok") return;

        const inputVector = await getVectorFromHuggingFace(dataSmart.face);
        const bestMatch = await compareWithDatabase(inputVector);

        if (bestMatch.recognized) {
            publishUnlock(bestMatch.name);
            mqttClient.publish(TOPIC_FACE_RESULT, JSON.stringify({
                result: "ok", name: bestMatch.name, timestamp
            }), { qos: 1 });
        }
    } catch (err) { console.error("LỖI ĐIỀU PHỐI:", err.message); }
}

async function getVectorFromHuggingFace(b64FaceImage) {
    const response = await fetch("https://api-inference.huggingface.co/models/michaelfeil/bbr-face-embedding", {
        method: "POST",
        headers: {
            "Authorization": `Bearer ${process.env.HUGGING_FACE_TOKEN}`,
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ inputs: b64FaceImage }),
    });
    if (!response.ok) throw new Error("Lỗi API HuggingFace");
    const data = await response.json();
    return data[0];
}

async function compareWithDatabase(inputVector) {
    const { data: users } = await supabase.from('accounts').select('full_name, face_vector');
    let bestName = "Unknown";
    let minDistance = 0.4;

    if (!users) return { recognized: false };
    for (const user of users) {
        if (!user.face_vector) continue;
        let dot = 0, ma = 0, mb = 0;
        for (let i = 0; i < 512; i++) {
            dot += inputVector[i] * user.face_vector[i];
            ma  += inputVector[i] * inputVector[i];
            mb  += user.face_vector[i] * user.face_vector[i];
        }
        const dist = 1 - (dot / (Math.sqrt(ma) * Math.sqrt(mb)));
        if (dist < minDistance) { minDistance = dist; bestName = user.full_name; }
    }
    return { recognized: bestName !== "Unknown", name: bestName };
}

// ==========================================
// HÀM GỬI EMAIL (Resend API)
// ==========================================

async function sendEmail(toEmail, subject, content) {
    try {
        const response = await fetch("https://api.resend.com/emails", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${process.env.RESEND_API_KEY || "re_MY6LzVMu_Ne1LVHiGYxq8pQDTgnXvnSLZ"}`
            },
            body: JSON.stringify({
                from: "onboarding@resend.dev",
                to: [toEmail],
                subject: subject,
                html: content
            })
        });
        const result = await response.json();
        console.log("Resend response:", result);
    } catch (err) { console.error("Lỗi gửi mail:", err); }
}

// ==========================================
// WEBSOCKET SERVER
// ==========================================

const wss = new WebSocket.Server({ server });
let wsClients         = new Set();
let mqttConnected     = false;
let lastRecognizeTime = 0;

wss.on("connection", (ws, req) => {
    wsClients.add(ws);
    ws.send(JSON.stringify({ type: "status", connected: mqttConnected, clients: wsClients.size }));

    ws.on("close", () => wsClients.delete(ws));

    ws.on("message", async (data) => {
        try {
            const msg = JSON.parse(data);

            if (msg.type === "manual_unlock") {
                publishUnlock("MANUAL");
            } else if (msg.type === "finger_enroll") {
                const { data: accounts } = await supabase.from('accounts').select('fingerprint_id');
                let nextId = 1;
                if (accounts && accounts.length > 0) {
                    let maxId = 0;
                    accounts.forEach(acc => {
                        if (acc.fingerprint_id !== null && acc.fingerprint_id > maxId) maxId = acc.fingerprint_id;
                    });
                    nextId = maxId + 1;
                }
                if (nextId > 127) nextId = 1;

                const name = msg.name || `User_${nextId}`;
                mqttClient.publish(TOPIC_FINGER_CMD, JSON.stringify({ cmd: "enroll", id: nextId, name }), { qos: 1 });
                console.log(`[FINGER] Ra lệnh lấy vân tay mới ID = ${nextId}`);
            }
        } catch (err) { console.error("Lỗi xử lý WS:", err); }
    });
});

function broadcast(data) {
    const str = typeof data === "string" ? data : JSON.stringify(data);
    wsClients.forEach(ws => { if (ws.readyState === WebSocket.OPEN) ws.send(str); });
}

function publishUnlock(name) {
    mqttClient.publish(TOPIC_CMD, JSON.stringify({ cmd: "UNLOCK", name, timestamp: new Date().toISOString() }), { qos: 1 });
}

// ==========================================
// MQTT CLIENT
// ==========================================

const mqttClient = mqtt.connect(MQTT_BROKER, {
    username: MQTT_USER,
    password: MQTT_PASS,
    rejectUnauthorized: false,
    clientId: "server_bridge_" + Math.random().toString(16).slice(2, 8),
    keepalive: 30,
    reconnectPeriod: 3000,
});

mqttClient.on("connect", () => {
    mqttConnected = true;
    mqttClient.subscribe([TOPIC_PHOTO, TOPIC_LOGS, TOPIC_FINGER_STATUS, TOPIC_CMD], { qos: 1 });
    broadcast({ type: "status", connected: true, clients: wsClients.size });
    console.log("✅ MQTT connected");
});

mqttClient.on("disconnect", () => {
    mqttConnected = false;
    broadcast({ type: "status", connected: false });
});

mqttClient.on("message", async (topic, payload) => {
    if (topic === TOPIC_PHOTO) {
        const size = payload.length;
        const ts   = new Date().toISOString();
        const b64  = payload.toString("base64");
        broadcast({ type: "photo", data: b64, size, timestamp: ts });
        const now = Date.now();
        if (now - lastRecognizeTime >= RECOGNIZE_COOLDOWN) {
            lastRecognizeTime = now;
            await runRecognition(b64, ts);
        }
    } else if (topic === TOPIC_CMD) {
        try {
            const data = JSON.parse(payload.toString());
            if (data.cmd === "UNLOCK_REQUEST") {
                const ts = new Date().toISOString();
                try {
                    await supabase.from('unlock_history').insert([{
                        safe_id:   data.safe_id || "SAFE_VMU_01",
                        reason:    data.reason  || "unknown",
                        method:    data.reason && data.reason.includes("Mat") ? "face" : "fingerprint",
                        timestamp: ts,
                        source:    "device"
                    }]);
                } catch (e) {}
                const unlockPayload = JSON.stringify({ cmd: "UNLOCK", reason: data.reason, timestamp: ts });
                mqttClient.publish(TOPIC_CMD, unlockPayload, { qos: 1 });
                broadcast({ type: "unlock_sent", reason: data.reason, timestamp: ts, source: "device" });
            } else if (data.cmd === "UNLOCK") {
                broadcast({ type: "unlock_sent", name: data.name, timestamp: data.timestamp, source: "server" });
            }
        } catch (e) {}
    } else if (topic === TOPIC_FINGER_STATUS) {
        try {
            const data = JSON.parse(payload.toString());
            broadcast({ type: "finger_status", ...data });
        } catch {}
    } else if (topic === TOPIC_LOGS) {
        try {
            const log = JSON.parse(payload.toString());
            broadcast({ type: "log", ...log, timestamp: new Date().toISOString() });
        } catch {}
    }
});

server.listen(WS_PORT, () => console.log(`🚀 Server running on port ${WS_PORT}`));
