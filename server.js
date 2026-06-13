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

const MQTT_BROKER         = "mqtts://e539507d822e4b348dc6f0af2600bd01.s1.eu.hivemq.cloud:8883";
const MQTT_USER           = "ketsat";
const MQTT_PASS           = "Ket123456";
const TOPIC_PHOTO         = "safe1/cam";
const TOPIC_LOGS          = "safe1/log";
const TOPIC_CMD           = "safe1/cmd";
const TOPIC_FINGER_CMD    = "safe1/fingercmd";
const TOPIC_FINGER_STATUS = "safe1/fingerstatus";
const TOPIC_FACE_RESULT   = "safe1/faceresult"; 
const WS_PORT             = process.env.PORT || 3000;

// URL AI Model (Ngrok)
const FACE_SERVICE_URL    = process.env.FACE_SERVICE_URL || "http://localhost:5001/recognize";
const FACE_RELOAD_URL     = process.env.FACE_RELOAD_URL || "http://localhost:5001/reload";
const FACE_EXTRACT_URL    = FACE_SERVICE_URL.replace("/recognize", "/extract_vector"); 
const RECOGNIZE_COOLDOWN  = 3000;

// Supabase
const { createClient } = require('@supabase/supabase-js');
const SUPABASE_URL = process.env.SUPABASE_URL; 
const SUPABASE_KEY = process.env.SUPABASE_KEY; 

if (!SUPABASE_URL || !SUPABASE_KEY) {
    console.error("LỖI: Chưa cấu hình SUPABASE_URL hoặc SUPABASE_KEY");
    process.exit(1);
}
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

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

(async () => {
  const fetch = (await import("node-fetch")).default;
  console.log("[INIT] ✅ node-fetch đã sẵn sàng");

  const app    = express();
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
          if (password.length < 8) return res.status(400).json({ success: false, error: "Mật khẩu < 8 ký tự" });

          const { data: existingUser } = await supabase.from('accounts').select('id').eq('email', email).maybeSingle();
          if (existingUser) return res.status(409).json({ success: false, error: "Email đã tồn tại" });

          let faceVector = null;
          if (req.file) {
              const b64Image = req.file.buffer.toString("base64");
              const extractRes = await fetch(FACE_EXTRACT_URL, {
                  method: "POST", headers: { "Content-Type": "application/json", "ngrok-skip-browser-warning": "true" },
                  body: JSON.stringify({ image: b64Image }),
              });
              const extractData = await extractRes.json();
              if (extractData.success) faceVector = extractData.vector;
              else throw new Error("AI không nhận diện được khuôn mặt.");
          }

          const password_hash = await bcrypt.hash(password, 10);
          const fpIdParsed = parseInt(fingerprint_id);
          const finalFingerprintId = isNaN(fpIdParsed) ? null : fpIdParsed;

          const { data: newUser, error: insertError } = await supabase
              .from('accounts')
              .insert([{ 
                  full_name, email, password_hash, role: 'user',
                  fingerprint_id: finalFingerprintId, 
                  face_vector: faceVector
              }]).select('id, full_name, email, role').single();

          if (insertError) throw insertError;

          if (req.file) {
              const personDir = path.join(DATA_FACE_DIR, `user_${newUser.id}`);
              if (!fs.existsSync(personDir)) fs.mkdirSync(personDir, { recursive: true });
              fs.writeFileSync(path.join(personDir, `${Date.now()}.jpg`), req.file.buffer);
              try { await fetch(FACE_RELOAD_URL, { method: "POST", headers: { "ngrok-skip-browser-warning": "true" }}); } catch(e) {}
          }
          res.json({ success: true, message: "Đăng ký thành công!", user: newUser });
      } catch (err) {
          res.status(500).json({ success: false, error: err.message || "Lỗi máy chủ" });
      }
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
          if (fingerprint_id !== undefined && fingerprint_id !== null) {
              updateData.fingerprint_id = parseInt(fingerprint_id);
          }

          if (new_password && new_password.trim() !== "") {
              if (new_password.length < 8) return res.status(400).json({ success: false, error: "Mật khẩu < 8 ký tự" });
              updateData.password_hash = await bcrypt.hash(new_password, 10);
          }

          const { data: updatedUser, error: updateError } = await supabase
              .from('accounts').update(updateData).eq('id', user_id)
              .select('id, full_name, email, role, fingerprint_id').single();

          if (updateError) throw updateError;
          res.json({ success: true, message: "Cập nhật hồ sơ thành công!", user: updatedUser });
      } catch (err) {
          res.status(500).json({ success: false, error: "Lỗi máy chủ khi cập nhật" });
      }
  });

  app.post('/api/auth/update-face', upload.single('photo'), async (req, res) => {
      try {
          const user_id = req.body.user_id;
          if (!user_id || !req.file) return res.status(400).json({ success: false, error: "Thiếu thông tin hoặc ảnh" });

          const b64Image = req.file.buffer.toString("base64");
          const extractRes = await fetch(FACE_EXTRACT_URL, {
              method: "POST", headers: { "Content-Type": "application/json", "ngrok-skip-browser-warning": "true" },
              body: JSON.stringify({ image: b64Image }),
          });
          const extractData = await extractRes.json();
          if (!extractData.success) throw new Error("Không nhận diện được khuôn mặt.");

          const { error: updateError } = await supabase.from('accounts').update({ face_vector: extractData.vector }).eq('id', user_id);
          if (updateError) throw updateError;

          const personDir = path.join(DATA_FACE_DIR, `user_${user_id}`);
          if (!fs.existsSync(personDir)) fs.mkdirSync(personDir, { recursive: true });
          fs.writeFileSync(path.join(personDir, `${Date.now()}.jpg`), req.file.buffer);

          try { await fetch(FACE_RELOAD_URL, { method: "POST", headers: { "ngrok-skip-browser-warning": "true" } }); } catch(e) {}
          res.json({ success: true, message: "Đã cập nhật dữ liệu khuôn mặt thành công!" });
      } catch (err) {
          res.status(500).json({ success: false, error: err.message || "Lỗi máy chủ" });
      }
  });
    // ==========================================
  // API: QUÊN MẬT KHẨU (GỬI MÃ OTP)
  // ==========================================
  app.post('/api/auth/forgot-password', async (req, res) => {
      try {
          const { email } = req.body;
          if (!email) return res.status(400).json({ success: false, error: "Vui lòng nhập Email" });

          const { data: user } = await supabase.from('accounts').select('id, full_name').eq('email', email).single();
          if (!user) return res.status(404).json({ success: false, error: "Email không tồn tại trong hệ thống" });

          const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
          const expiresAt = new Date();
          expiresAt.setMinutes(expiresAt.getMinutes() + 5);

          const { error: updateError } = await supabase
              .from('accounts').update({ otp_code: otpCode, otp_expires_at: expiresAt.toISOString() }).eq('id', user.id);

          if (updateError) throw updateError;

          const mailOptions = {
              from: `"Hệ thống SAFE VMU" <${process.env.EMAIL_USER}>`,
              to: email,
              subject: "Mã OTP Đặt Lại Mật Khẩu",
              html: `
                  <h3>Xin chào ${user.full_name},</h3>
                  <p>Bạn (hoặc ai đó) vừa yêu cầu đặt lại mật khẩu. Dưới đây là mã xác thực OTP của bạn:</p>
                  <h2 style="color: #00e5ff; background: #0c1018; padding: 12px; display: inline-block; border-radius: 4px; letter-spacing: 5px;">${otpCode}</h2>
                  <p>Mã này sẽ hết hạn sau <strong>5 phút</strong>.</p>
                  <p>Nếu bạn không yêu cầu, vui lòng phớt lờ email này để bảo vệ tài khoản.</p>
              `
          };

          await transporter.sendMail(mailOptions);
          res.json({ success: true, message: "Mã OTP đã được gửi đến email của bạn!" });

      } catch (err) { res.status(500).json({ success: false, error: "Lỗi hệ thống khi gửi email" }); }
  });

  // ==========================================
  // API: ĐẶT LẠI MẬT KHẨU TÀI KHOẢN
  // ==========================================
  app.post('/api/auth/reset-password', async (req, res) => {
      try {
          const { email, otp, new_password } = req.body;
          if (!email || !otp || !new_password) return res.status(400).json({ success: false, error: "Vui lòng nhập đủ thông tin" });

          const { data: user } = await supabase
              .from('accounts').select('id, otp_code, otp_expires_at').eq('email', email).single();

          if (!user || user.otp_code !== String(otp)) return res.status(400).json({ success: false, error: "Mã OTP không chính xác" });
          if (new Date() > new Date(user.otp_expires_at)) return res.status(400).json({ success: false, error: "Mã OTP đã hết hạn. Vui lòng yêu cầu lại." });

          const saltRounds = 10;
          const new_password_hash = await bcrypt.hash(new_password, saltRounds);

          const { error: updateError } = await supabase
              .from('accounts').update({ password_hash: new_password_hash, otp_code: null, otp_expires_at: null }).eq('id', user.id);

          if (updateError) throw updateError;
          res.json({ success: true, message: "Đặt lại mật khẩu thành công! Bạn có thể đăng nhập ngay." });

      } catch (err) { res.status(500).json({ success: false, error: "Lỗi máy chủ" }); }
  });
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
    ws.on("close", () => { wsClients.delete(ws); });
    
    ws.on("message", async (data) => {
      try {
        const msg = JSON.parse(data);
        if (msg.type === "manual_unlock") publishUnlock("MANUAL");
        else if (msg.type === "reload_faces") reloadFaces();
        else if (msg.type === "finger_enroll") {
          
          const { data: accounts, error: dbErr } = await supabase.from('accounts').select('fingerprint_id');
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

  // ==========================================
  // MQTT CLIENT
  // ==========================================
  const mqttClient = mqtt.connect(MQTT_BROKER, {
    username: MQTT_USER, password: MQTT_PASS,
    rejectUnauthorized: false,
    clientId: "server_bridge_" + Math.random().toString(16).slice(2, 8),
    keepalive: 30, reconnectPeriod: 3000,
  });

  mqttClient.on("connect", () => {
    mqttConnected = true;
    mqttClient.subscribe([TOPIC_PHOTO, TOPIC_LOGS, TOPIC_FINGER_STATUS, TOPIC_CMD], { qos: 1 });
    broadcast({ type: "status", connected: true, clients: wsClients.size });
  });

  mqttClient.on("disconnect", () => {
    mqttConnected = false;
    broadcast({ type: "status", connected: false });
  });

  mqttClient.on("message", async (topic, payload) => {
    if (topic === TOPIC_PHOTO) {
      const size = payload.length;
      const ts   = new Date().toISOString();
      const b64 = payload.toString("base64");
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

  async function runRecognition(b64Image, timestamp) {
    broadcast({ type: "recognizing", timestamp });
    try {
      const res = await fetch(FACE_SERVICE_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json", "ngrok-skip-browser-warning": "true" },
        body: JSON.stringify({ image: b64Image }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const result = await res.json();
      broadcast({ type: "recognition_result", ...result, timestamp });

      if (result.recognized) {
        publishUnlock(result.name);
        mqttClient.publish(TOPIC_FACE_RESULT, JSON.stringify({ result: "ok", name: result.name, confidence: parseFloat((result.confidence * 100).toFixed(1)), timestamp }), { qos: 1 });
      } else if (result.detected) {
        mqttClient.publish(TOPIC_FACE_RESULT, JSON.stringify({ result: "fail", name: "Unknown", timestamp }), { qos: 1 });
      } else {
        mqttClient.publish(TOPIC_FACE_RESULT, JSON.stringify({ result: "noface", timestamp }), { qos: 1 });
      }
    } catch (err) {
      broadcast({ type: "face_service_error", error: err.message, timestamp });
    }
  }

  function publishUnlock(name) {
    const payload = JSON.stringify({ cmd: "UNLOCK", name, timestamp: new Date().toISOString() });
    mqttClient.publish(TOPIC_CMD, payload, { qos: 1 }, (err) => {
      if (!err) broadcast({ type: "unlock_sent", name, timestamp: new Date().toISOString() });
    });
  }

  async function reloadFaces() {
    try {
      const res  = await fetch(FACE_RELOAD_URL, { method: "POST", headers: { "ngrok-skip-browser-warning": "true" } });
      const data = await res.json();
      broadcast({ type: "faces_reloaded", count: data.count, names: data.names });
    } catch (err) {}
  }

  server.listen(WS_PORT, () => {
    console.log(`\n──────────────────────────────────────────────────`);
    console.log(`🚀 Server: http://localhost:${WS_PORT}`);
    console.log(`📡 WebSocket: ws://localhost:${WS_PORT}`);
    console.log(`──────────────────────────────────────────────────\n`);
  });
})();
