/**
 * server.js — MQTT → WebSocket Bridge + Face Recognition + Face Enrollment + OTP
 */
const nodemailer = require('nodemailer');
require("dotenv").config();

const express   = require("express");
const http      = require("http");
const WebSocket = require("ws");
const mqtt      = require("mqtt");
const path      = require("path");
const fs        = require("fs");
const multer    = require("multer");
const cors = require('cors');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

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

// URL Của AI Model (Sử dụng Ngrok)
const FACE_SERVICE_URL    = process.env.FACE_SERVICE_URL || "http://localhost:5001/recognize";
const FACE_RELOAD_URL     = process.env.FACE_RELOAD_URL || "http://localhost:5001/reload";
// Tự động suy ra đường dẫn extract vector từ URL recognize
const FACE_EXTRACT_URL    = FACE_SERVICE_URL.replace("/recognize", "/extract_vector"); 
const RECOGNIZE_COOLDOWN  = 3000;

const { createClient } = require('@supabase/supabase-js');
const SUPABASE_URL = process.env.SUPABASE_URL; 
const SUPABASE_KEY = process.env.SUPABASE_KEY; 

if (!SUPABASE_URL || !SUPABASE_KEY) {
    console.error("LỖI: Chưa cấu hình SUPABASE_URL hoặc SUPABASE_KEY trong file .env");
    process.exit(1);
}
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true, 
    auth: {
        user: process.env.EMAIL_USER, 
        pass: process.env.EMAIL_PASS
    },
    tls: {
        rejectUnauthorized: false 
    }
});

// ── Thư mục lưu ảnh khuôn mặt mẫu ──
const DATA_FACE_DIR = path.join(__dirname, "data_face");
if (!fs.existsSync(DATA_FACE_DIR)) fs.mkdirSync(DATA_FACE_DIR, { recursive: true });

// ── Fingerprint DB ──
const FINGER_DB_FILE = path.join(__dirname, "finger_db.json");
let fingerDB = {};
try {
  if (fs.existsSync(FINGER_DB_FILE)) {
    fingerDB = JSON.parse(fs.readFileSync(FINGER_DB_FILE, "utf8"));
    console.log(`[FINGER] 📂 Đã load ${Object.keys(fingerDB).length} vân tay`);
  }
} catch(e) { console.error("[FINGER] ❌ Load DB lỗi:", e.message); }

function saveFingerDB() {
  try { fs.writeFileSync(FINGER_DB_FILE, JSON.stringify(fingerDB, null, 2)); }
  catch(e) { console.error("[FINGER] ❌ Lưu DB lỗi:", e.message); }
}

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
  // API: ĐĂNG KÝ TÀI KHOẢN CƠ BẢN
  // ==========================================
  app.post('/api/auth/register', async (req, res) => {
      try {
          const { full_name, email, password } = req.body;

          if (!full_name || !email || !password) {
              return res.status(400).json({ success: false, error: "Vui lòng nhập đủ Họ tên, Email và Mật khẩu" });
          }

          if (password.length < 8) {
              return res.status(400).json({ success: false, error: "Mật khẩu phải có ít nhất 8 ký tự" });
          }

          // Kiểm tra xem Email đã tồn tại chưa
          const { data: existingUser } = await supabase
              .from('accounts')
              .select('id')
              .eq('email', email)
              .maybeSingle();

          if (existingUser) {
              return res.status(409).json({ success: false, error: "Email này đã được sử dụng" });
          }

          // Mã hóa mật khẩu
          const saltRounds = 10;
          const password_hash = await bcrypt.hash(password, saltRounds);

          // Tạo tài khoản (Chưa có face và vân tay)
          const { data: newUser, error: insertError } = await supabase
              .from('accounts')
              .insert([{ 
                  full_name: full_name, 
                  email: email, 
                  password_hash: password_hash, 
                  role: 'user' 
              }])
              .select('id, full_name, email, role')
              .single();

          if (insertError) throw insertError;

          res.json({ success: true, message: "Đăng ký thành công! Vui lòng đăng nhập.", user: newUser });

      } catch (err) {
          console.error("Lỗi đăng ký:", err);
          res.status(500).json({ success: false, error: "Lỗi máy chủ khi đăng ký" });
      }
  });
  // ==========================================
  // API: ĐĂNG NHẬP
  // ==========================================
  app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ success: false, error: "Vui lòng nhập Email và Mật khẩu" });

        const { data: user, error: userError } = await supabase
            .from('accounts').select('id, full_name, email, password_hash, role').eq('email', email).single();

        if (userError || !user) return res.status(401).json({ success: false, error: "Email hoặc mật khẩu không chính xác" });

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) return res.status(401).json({ success: false, error: "Email hoặc mật khẩu không chính xác" });

        const { data: ownedSafes } = await supabase
            .from('safe_ownership').select('safe_id').eq('account_id', user.id).eq('is_active', true);
        const { data: sharedSafes } = await supabase
            .from('safe_access').select('safe_id, access_level').eq('user_id', user.id);

        delete user.password_hash;
        res.json({
            success: true, message: "Đăng nhập thành công!", user: user,
            roles: {
                owner_of: ownedSafes ? ownedSafes.map(s => s.safe_id) : [],
                user_of: sharedSafes ? sharedSafes.map(s => s.safe_id) : []
            }
        });
    } catch (err) { res.status(500).json({ success: false, error: "Lỗi máy chủ" }); }
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
  // API: CẬP NHẬT THÔNG TIN TÀI KHOẢN (PROFILE)
  // ==========================================
  app.post('/api/auth/update-profile', async (req, res) => {
      try {
          const { user_id, full_name, new_password, fingerprint_id } = req.body;

          if (!user_id || !full_name) {
              return res.status(400).json({ success: false, error: "Thiếu thông tin bắt buộc" });
          }

          let updateData = { full_name: full_name };
          
          // NẾU CÓ DỮ LIỆU VÂN TAY MỚI GỬI LÊN THÌ LƯU VÀO
          if (fingerprint_id !== undefined) {
              updateData.fingerprint_id = fingerprint_id;
          }

          if (new_password && new_password.trim() !== "") {
              if (new_password.length < 8) return res.status(400).json({ success: false, error: "Mật khẩu mới phải >= 8 ký tự" });
              const saltRounds = 10;
              updateData.password_hash = await bcrypt.hash(new_password, saltRounds);
          }

          const { data: updatedUser, error: updateError } = await supabase
              .from('accounts')
              .update(updateData)
              .eq('id', user_id)
              .select('id, full_name, email, role, fingerprint_id')
              .single();

          if (updateError) throw updateError;
          res.json({ success: true, message: "Cập nhật hồ sơ thành công!", user: updatedUser });

      } catch (err) {
          res.status(500).json({ success: false, error: "Lỗi máy chủ khi cập nhật" });
      }
  });
    // ==========================================
  // API: CẬP NHẬT LẠI KHUÔN MẶT (CHỤP LẠI)
  // ==========================================
  app.post('/api/auth/update-face', upload.single('photo'), async (req, res) => {
      try {
          const user_id = req.body.user_id;
          if (!user_id || !req.file) {
              return res.status(400).json({ success: false, error: "Thiếu thông tin hoặc ảnh" });
          }

          console.log(`[FACE] Đang trích xuất Vector mới cho user ID: ${user_id}...`);
          const b64Image = req.file.buffer.toString("base64");
          
          // Gọi AI lấy Vector mới
          const extractRes = await fetch(FACE_EXTRACT_URL, {
              method: "POST",
              headers: { "Content-Type": "application/json", "ngrok-skip-browser-warning": "true" },
              body: JSON.stringify({ image: b64Image }),
          });
          const extractData = await extractRes.json();
          
          if (!extractData.success) {
              throw new Error("Không nhận diện được khuôn mặt. Vui lòng chụp rõ hơn.");
          }

          // Lưu Vector mới vào Supabase
          const { error: updateError } = await supabase
              .from('accounts')
              .update({ face_vector: extractData.vector })
              .eq('id', user_id);

          if (updateError) throw updateError;

          // Lưu file ảnh dự phòng
          const personDir = path.join(DATA_FACE_DIR, `user_${user_id}`);
          if (!fs.existsSync(personDir)) fs.mkdirSync(personDir, { recursive: true });
          fs.writeFileSync(path.join(personDir, `${Date.now()}.jpg`), req.file.buffer);

          // Cập nhật lại bộ nhớ AI ngầm
          try { await fetch(FACE_RELOAD_URL, { method: "POST", headers: { "ngrok-skip-browser-warning": "true" } }); } catch(e) {}

          res.json({ success: true, message: "Đã cập nhật dữ liệu khuôn mặt thành công!" });

      } catch (err) {
          console.error("Lỗi cập nhật khuôn mặt:", err);
          res.status(500).json({ success: false, error: err.message || "Lỗi máy chủ" });
      }
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

  // ── REST API: Đăng ký khuôn mặt mới (FIXED) ──
  app.post("/api/register-owner", upload.single("photo"), async (req, res) => {
    try {
      const name = (req.body.name || "").trim();
      const email = (req.body.email || "").trim();
      const fingerprint_id = parseInt(req.body.fingerprint_id);
      const safe_id = req.body.safe_id || "safe_001"; 

      if (!name) return res.status(400).json({ error: "Thiếu tên người dùng" });
      if (!req.file) return res.status(400).json({ error: "Thiếu ảnh khuôn mặt" });

      const b64Image = req.file.buffer.toString("base64");

      console.log(`[FACE] Đang trích xuất Vector khuôn mặt cho ${name} qua URL: ${FACE_EXTRACT_URL}...`);
      let faceVector = null;
      
      try {
        // Đã sửa thành FACE_EXTRACT_URL thay vì localhost và thêm header vượt ngrok
        const extractRes = await fetch(FACE_EXTRACT_URL, {
          method: "POST",
          headers: { 
              "Content-Type": "application/json",
              "ngrok-skip-browser-warning": "true" 
          },
          body: JSON.stringify({ image: b64Image }),
        });
        
        const extractData = await extractRes.json();
        
        if (extractData.success) {
          faceVector = extractData.vector;
          console.log(`[FACE] ✅ Đã lấy được Vector (${faceVector.length} chiều)`);
        } else {
          throw new Error(extractData.error);
        }
      } catch (err) {
        console.error("[FACE] ❌ Lỗi trích xuất Vector:", err.message);
        return res.status(400).json({ error: err.message || "Lỗi AI xử lý khuôn mặt (Có thể Python đang offline)" });
      }

      console.log(`[SUPABASE] Đang lưu Database cho: ${name}`);
      const { data: newAccount, error: accountError } = await supabase
        .from('accounts')
        .insert([{ 
            full_name: name, email: email || null,
            fingerprint_id: isNaN(fingerprint_id) ? null : fingerprint_id, face_vector: faceVector 
        }]).select().single();

      if (accountError) throw new Error("Lỗi lưu Account: " + accountError.message);

      const { error: ownershipError } = await supabase
        .from('safe_ownership').insert([{ safe_id: safe_id, account_id: newAccount.id, role: 'owner' }]);

      if (ownershipError) throw new Error("Lỗi cấp quyền: " + ownershipError.message);

      const personDir = path.join(DATA_FACE_DIR, name.replace(/\s+/g, "_").toLowerCase());
      if (!fs.existsSync(personDir)) fs.mkdirSync(personDir, { recursive: true });
      fs.writeFileSync(path.join(personDir, `${Date.now()}.jpg`), req.file.buffer);

      return res.json({ success: true, message: `Đã đăng ký chủ két "${name}" và lưu Vector thành công!`, });

    } catch (err) { return res.status(500).json({ error: err.message }); }
  });

  // ==========================================
  // API: LỊCH SỬ MỞ KHÓA
  // ==========================================
  app.get("/api/unlock-history", async (req, res) => {
    try {
      const safe_id = req.query.safe_id || "SAFE_VMU_01";
      const limit   = parseInt(req.query.limit) || 50;
      const { data, error } = await supabase
        .from('unlock_history')
        .select('*')
        .eq('safe_id', safe_id)
        .order('timestamp', { ascending: false })
        .limit(limit);
      if (error) throw error;
      res.json({ success: true, history: data, total: data.length });
    } catch (err) { res.status(500).json({ success: false, error: err.message }); }
  });

  app.get("/api/face-list", (req, res) => {
    try {
      const people = [];
      if (fs.existsSync(DATA_FACE_DIR)) {
        for (const entry of fs.readdirSync(DATA_FACE_DIR, { withFileTypes: true })) {
          if (entry.isDirectory()) {
            const dir   = path.join(DATA_FACE_DIR, entry.name);
            const files = fs.readdirSync(dir).filter(f => /\.(jpg|jpeg|png|webp)$/i.test(f));
            people.push({ folder: entry.name, name: entry.name.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase()), photos: files.length });
          }
        }
      }
      res.json({ people, total: people.length });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.delete("/api/face/:folder", async (req, res) => {
    try {
      const folder    = req.params.folder;
      const personDir = path.join(DATA_FACE_DIR, folder);
      if (!fs.existsSync(personDir)) return res.status(404).json({ error: "Không tìm thấy" });

      fs.rmSync(personDir, { recursive: true, force: true });
      console.log(`[ENROLL] 🗑️ Đã xóa: ${personDir}`);

      try {
        const reloadRes = await fetch(FACE_RELOAD_URL, { 
            method: "POST", headers: { "ngrok-skip-browser-warning": "true" } 
        });
        const reloadResult = await reloadRes.json();
        broadcast({ type: "faces_reloaded", count: reloadResult.people, names: reloadResult.names });
      } catch (err) { console.error("[ENROLL] ⚠️ Reload lỗi:", err.message); }

      broadcast({ type: "face_deleted", folder, timestamp: new Date().toISOString() });
      res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ── WebSocket ──
  const wss = new WebSocket.Server({ server });
  let wsClients         = new Set();
  let mqttConnected     = false;
  let lastRecognizeTime = 0;

  wss.on("connection", (ws, req) => {
    wsClients.add(ws);
    console.log(`[WS] Client kết nối: ${req.socket.remoteAddress} | Tổng: ${wsClients.size}`);
    ws.send(JSON.stringify({ type: "status", connected: mqttConnected, clients: wsClients.size }));
    ws.on("close", () => { wsClients.delete(ws); });
    
    // Đổi thành async để gọi được Database
    ws.on("message", async (data) => {
      try {
        const msg = JSON.parse(data);
        if (msg.type === "manual_unlock") publishUnlock("MANUAL");
        else if (msg.type === "reload_faces") reloadFaces();
        else if (msg.type === "finger_enroll") {
          
          // 1. TÌM ID VÂN TAY LỚN NHẤT TRONG SUPABASE ĐỂ KHÔNG BỊ GHI ĐÈ
          const { data: accounts } = await supabase
              .from('accounts')
              .select('fingerprint_id')
              .not('fingerprint_id', 'is', null)
              .order('fingerprint_id', { ascending: false })
              .limit(1);
              
          let nextId = 1;
          if (accounts && accounts.length > 0 && accounts[0].fingerprint_id) {
              nextId = accounts[0].fingerprint_id + 1;
          }
          if (nextId > 127) nextId = 1; // AS608 chỉ lưu tối đa 127 vân tay

          const name = msg.name || `User_${nextId}`;
          mqttClient.publish(TOPIC_FINGER_CMD, JSON.stringify({ cmd: "enroll", id: nextId, name }), { qos: 1 });
          console.log(`[FINGER] 📤 Đã ra lệnh lấy vân tay mới với ID = ${nextId}`);
          
        } else if (msg.type === "finger_delete") {
          mqttClient.publish(TOPIC_FINGER_CMD, JSON.stringify({ cmd: "delete", id: msg.id }), { qos: 1 });
        }
      } catch (err) {
          console.error("Lỗi xử lý WS:", err);
      }
    });
  });
  function broadcast(data) {
    const str = typeof data === "string" ? data : JSON.stringify(data);
    wsClients.forEach(ws => { if (ws.readyState === WebSocket.OPEN) ws.send(str); });
  }

  // ── MQTT ──
  const mqttClient = mqtt.connect(MQTT_BROKER, {
    username: MQTT_USER, password: MQTT_PASS,
    rejectUnauthorized: false,
    clientId: "server_bridge_" + Math.random().toString(16).slice(2, 8),
    keepalive: 30, reconnectPeriod: 3000,
  });

  mqttClient.on("connect", () => {
    mqttConnected = true;
    console.log("[MQTT] ✅ Đã kết nối HiveMQ");
    mqttClient.subscribe([TOPIC_PHOTO, TOPIC_LOGS, TOPIC_FINGER_STATUS, TOPIC_CMD], { qos: 1 });
    broadcast({ type: "status", connected: true, clients: wsClients.size });
  });

  mqttClient.on("disconnect", () => {
    mqttConnected = false;
    broadcast({ type: "status", connected: false });
  });

  mqttClient.on("error", err => console.error("[MQTT] ❌", err.message));

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
      // Nhận UNLOCK_REQUEST từ thiết bị → lưu lịch sử → publish lại UNLOCK
      try {
        const data = JSON.parse(payload.toString());
        console.log(`[CMD] 📩 Nhận từ safe1/cmd:`, data);

        if (data.cmd === "UNLOCK_REQUEST") {
          const ts = new Date().toISOString();
          console.log(`[UNLOCK] ✅ Yêu cầu mở khóa từ thiết bị: ${data.safe_id}, lý do: ${data.reason}`);

          // Lưu lịch sử mở khóa vào Supabase
          try {
            await supabase.from('unlock_history').insert([{
              safe_id:   data.safe_id || "SAFE_VMU_01",
              reason:    data.reason  || "unknown",
              method:    data.reason && data.reason.includes("Mat") ? "face" : "fingerprint",
              timestamp: ts,
              source:    "device"
            }]);
            console.log(`[SUPABASE] ✅ Đã lưu lịch sử mở khóa`);
          } catch (dbErr) {
            console.error("[SUPABASE] ❌ Lưu lịch sử lỗi:", dbErr.message);
          }

          // Publish lại lệnh UNLOCK để thiết bị mở relay
          const unlockPayload = JSON.stringify({ cmd: "UNLOCK", reason: data.reason, timestamp: ts });
          mqttClient.publish(TOPIC_CMD, unlockPayload, { qos: 1 });
          broadcast({ type: "unlock_sent", reason: data.reason, timestamp: ts, source: "device" });

        } else if (data.cmd === "UNLOCK") {
          // Lệnh UNLOCK do server tự publish (manual hoặc face recognition)
          // Chỉ broadcast cho dashboard, thiết bị tự xử lý
          broadcast({ type: "unlock_sent", name: data.name, timestamp: data.timestamp, source: "server" });
        }
      } catch (e) { /* payload không phải JSON, bỏ qua */ }
    } else if (topic === TOPIC_FINGER_STATUS) {
      try {
        const data = JSON.parse(payload.toString());
        if (data.event === "enroll_ok" && data.id !== undefined) {
          fingerDB[data.id] = { name: data.name || `User_${data.id}`, enrolledAt: new Date().toISOString() };
          saveFingerDB();
          broadcast({ type: "finger_status", ...data, db: fingerDB });
        } else if (data.event === "delete_ok" && data.id !== undefined) {
          delete fingerDB[data.id];
          saveFingerDB();
          broadcast({ type: "finger_status", ...data, db: fingerDB });
        } else { broadcast({ type: "finger_status", ...data }); }
      } catch {}
    } else if (topic === TOPIC_LOGS) {
      try {
        const log = JSON.parse(payload.toString());
        broadcast({ type: "log", ...log, timestamp: new Date().toISOString() });
      } catch {}
    }
  });

  // ── Face Recognition (FIXED NGROK HEADER) ──
  async function runRecognition(b64Image, timestamp) {
    console.log("[FACE] 🔍 Gửi ảnh đến face_service qua URL:", FACE_SERVICE_URL);
    broadcast({ type: "recognizing", timestamp });
    try {
      const res = await fetch(FACE_SERVICE_URL, {
        method: "POST",
        headers: { 
            "Content-Type": "application/json",
            "ngrok-skip-browser-warning": "true" // Vượt cảnh báo Ngrok
        },
        body: JSON.stringify({ image: b64Image }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const result = await res.json();
      console.log(`[FACE] Kết quả:`, result);
      broadcast({ type: "recognition_result", ...result, timestamp });

      if (result.recognized) {
        publishUnlock(result.name);
        const facePayload = JSON.stringify({ result: "ok", name: result.name, confidence: parseFloat((result.confidence * 100).toFixed(1)), timestamp });
        mqttClient.publish(TOPIC_FACE_RESULT, facePayload, { qos: 1 });
      } else if (result.detected) {
        const facePayload = JSON.stringify({ result: "fail", name: "Unknown", timestamp });
        mqttClient.publish(TOPIC_FACE_RESULT, facePayload, { qos: 1 });
      } else {
        const facePayload = JSON.stringify({ result: "noface", timestamp });
        mqttClient.publish(TOPIC_FACE_RESULT, facePayload, { qos: 1 });
      }
    } catch (err) {
      console.error("[FACE] ❌ Lỗi gọi face_service:", err.message);
      broadcast({ type: "face_service_error", error: err.message, timestamp });
    }
  }

  function getNextFingerId() {
    const ids = Object.keys(fingerDB).map(Number);
    for (let i = 1; i <= 127; i++) { if (!ids.includes(i)) return i; }
    return 1;
  }

  function publishUnlock(name) {
    const payload = JSON.stringify({ cmd: "UNLOCK", name, timestamp: new Date().toISOString() });
    mqttClient.publish(TOPIC_CMD, payload, { qos: 1 }, (err) => {
      if (err) console.error("[MQTT] ❌ Gửi unlock thất bại:", err.message);
      else broadcast({ type: "unlock_sent", name, timestamp: new Date().toISOString() });
    });
  }

  async function reloadFaces() {
    try {
      const res  = await fetch(FACE_RELOAD_URL, { method: "POST", headers: { "ngrok-skip-browser-warning": "true" } });
      const data = await res.json();
      broadcast({ type: "faces_reloaded", count: data.count, names: data.names });
    } catch (err) { console.error("[FACE] ❌ Reload lỗi:", err.message); }
  }

  server.listen(WS_PORT, () => {
    console.log(`\n${"─".repeat(50)}`);
    console.log(`🚀 Server: http://localhost:${WS_PORT}`);
    console.log(`📡 WebSocket: ws://localhost:${WS_PORT}`);
    console.log(`🔍 Face service: ${FACE_SERVICE_URL}`);
    console.log(`🔓 Unlock topic: ${TOPIC_CMD}`);
    console.log(`${"─".repeat(50)}\n`);
  });
})();
