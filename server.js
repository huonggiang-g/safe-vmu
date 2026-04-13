/**
 * server.js — MQTT → WebSocket Bridge + Face Recognition + Face Enrollment
 */
require("dotenv").config();

const express   = require("express");
const http      = require("http");
const WebSocket = require("ws");
const mqtt      = require("mqtt");
const path      = require("path");
const fs        = require("fs");
const multer    = require("multer");

const MQTT_BROKER         = "mqtts://e539507d822e4b348dc6f0af2600bd01.s1.eu.hivemq.cloud:8883";
const MQTT_USER           = "ketsat";
const MQTT_PASS           = "Ket123456";
const TOPIC_PHOTO         = "safe1/cam";
const TOPIC_LOGS          = "safe1/log";
const TOPIC_CMD           = "safe1/cmd";
const TOPIC_FINGER_CMD    = "safe1/fingercmd";
const TOPIC_FINGER_STATUS = "safe1/fingerstatus";
const TOPIC_FACE_RESULT   = "safe1/faceresult";   // ← Topic mới: gửi kết quả nhận diện khuôn mặt
const WS_PORT             = process.env.PORT || 3000;
const FACE_SERVICE_URL    = process.env.FACE_SERVICE_URL || "http://localhost:5001/recognize";
const FACE_RELOAD_URL     = process.env.FACE_RELOAD_URL || "http://localhost:5001/reload";
const RECOGNIZE_COOLDOWN  = 3000;

// ── Thư mục lưu ảnh khuôn mặt mẫu (phải khớp với KNOWN_FACES_DIR trong face_service.py) ──
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

// ── Multer: nhận ảnh upload từ browser ──
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
  const server = http.createServer(app);

  app.use(express.static(path.join(__dirname)));
  app.use(express.json({ limit: "10mb" }));
  app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

  // ── REST API: Đăng ký khuôn mặt mới ──
  app.post("/api/register-owner", upload.single("photo"), async (req, res) => {
    try {
      const name = (req.body.name || "").trim();
      const email = (req.body.email || "").trim();
      const fingerprint_id = parseInt(req.body.fingerprint_id);
      const safe_id = req.body.safe_id || "safe_001"; 

      if (!name) return res.status(400).json({ error: "Thiếu tên người dùng" });
      if (!req.file) return res.status(400).json({ error: "Thiếu ảnh khuôn mặt" });

      // Chuyển ảnh file sang Base64 để gửi cho Python
      const b64Image = req.file.buffer.toString("base64");

      // ----------------------------------------------------
      // 1. GỌI PYTHON ĐỂ LẤY FACE VECTOR
      // ----------------------------------------------------
      console.log(`[FACE] Đang trích xuất Vector khuôn mặt cho ${name}...`);
      let faceVector = null;
      
      try {
        // Đảm bảo port 5001 khớp với port Flask của bạn
        const extractRes = await fetch("http://localhost:5001/extract_vector", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ image: b64Image }),
        });
        
        const extractData = await extractRes.json();
        
        if (extractData.success) {
          faceVector = extractData.vector; // Đây là một mảng: [0.012, -0.453, 1.23, ...]
          console.log(`[FACE] ✅ Đã lấy được Vector (${faceVector.length} chiều)`);
        } else {
          throw new Error(extractData.error);
        }
      } catch (err) {
        console.error("[FACE] ❌ Lỗi trích xuất Vector:", err.message);
        return res.status(400).json({ error: err.message || "Lỗi AI xử lý khuôn mặt" });
      }

      // ----------------------------------------------------
      // 2. LƯU LÊN SUPABASE VỚI ĐẦY ĐỦ VECTOR
      // ----------------------------------------------------
      console.log(`[SUPABASE] Đang lưu Database cho: ${name}`);
      
      const { data: newAccount, error: accountError } = await supabase
        .from('accounts')
        .insert([{ 
            full_name: name, 
            email: email || null,
            fingerprint_id: isNaN(fingerprint_id) ? null : fingerprint_id,
            face_vector: faceVector // <--- TRUYỀN MẢNG VECTOR VÀO ĐÂY LÀ XONG!
        }])
        .select()
        .single();

      if (accountError) throw new Error("Lỗi lưu Account: " + accountError.message);

      const { error: ownershipError } = await supabase
        .from('safe_ownership')
        .insert([{ 
            safe_id: safe_id,
            account_id: newAccount.id,
            role: 'owner'
        }]);

      if (ownershipError) throw new Error("Lỗi cấp quyền: " + ownershipError.message);

      console.log(`[SUPABASE] ✅ Đã đăng ký thành công (ID: ${newAccount.id})`);

      // ----------------------------------------------------
      // 3. (Tùy chọn) Lưu dự phòng ảnh cục bộ
      // ----------------------------------------------------
      const personDir = path.join(DATA_FACE_DIR, name.replace(/\s+/g, "_").toLowerCase());
      if (!fs.existsSync(personDir)) fs.mkdirSync(personDir, { recursive: true });
      fs.writeFileSync(path.join(personDir, `${Date.now()}.jpg`), req.file.buffer);

      return res.json({
        success: true,
        message: `Đã đăng ký chủ két "${name}" và lưu Vector thành công!`,
      });

    } catch (err) {
      console.error("[API] ❌ Lỗi đăng ký:", err.message);
      return res.status(500).json({ error: err.message });
    }
  });

  // REST API: Lấy danh sách khuôn mặt đã đăng ký
  app.get("/api/face-list", (req, res) => {
    try {
      const people = [];
      if (fs.existsSync(DATA_FACE_DIR)) {
        for (const entry of fs.readdirSync(DATA_FACE_DIR, { withFileTypes: true })) {
          if (entry.isDirectory()) {
            const dir   = path.join(DATA_FACE_DIR, entry.name);
            const files = fs.readdirSync(dir).filter(f => /\.(jpg|jpeg|png|webp)$/i.test(f));
            people.push({
              folder: entry.name,
              name: entry.name.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase()),
              photos: files.length
            });
          }
        }
      }
      res.json({ people, total: people.length });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // REST API: Xóa khuôn mặt
  app.delete("/api/face/:folder", async (req, res) => {
    try {
      const folder    = req.params.folder;
      const personDir = path.join(DATA_FACE_DIR, folder);
      if (!fs.existsSync(personDir)) return res.status(404).json({ error: "Không tìm thấy" });

      fs.rmSync(personDir, { recursive: true, force: true });
      console.log(`[ENROLL] 🗑️ Đã xóa: ${personDir}`);

      try {
        const reloadRes = await fetch(FACE_RELOAD_URL, { method: "POST" });
        const reloadResult = await reloadRes.json();
        broadcast({ type: "faces_reloaded", count: reloadResult.people, names: reloadResult.names });
      } catch (err) {
        console.error("[ENROLL] ⚠️ Reload lỗi:", err.message);
      }

      broadcast({ type: "face_deleted", folder, timestamp: new Date().toISOString() });
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
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
    ws.on("message", (data) => {
      try {
        const msg = JSON.parse(data);
        if (msg.type === "manual_unlock") publishUnlock("MANUAL");
        else if (msg.type === "reload_faces") reloadFaces();
        else if (msg.type === "finger_enroll") {
          const id   = msg.id || getNextFingerId();
          const name = msg.name || `User_${id}`;
          mqttClient.publish(TOPIC_FINGER_CMD,
            JSON.stringify({ cmd: "enroll", id, name }), { qos: 1 });
          console.log(`[FINGER] 📤 Gửi lệnh enroll id=${id} name=${name}`);
        } else if (msg.type === "finger_delete") {
          mqttClient.publish(TOPIC_FINGER_CMD,
            JSON.stringify({ cmd: "delete", id: msg.id }), { qos: 1 });
          console.log(`[FINGER] 🗑️ Gửi lệnh xóa id=${msg.id}`);
        } else if (msg.type === "finger_list") {
          ws.send(JSON.stringify({ type: "finger_list", db: fingerDB }));
        }
      } catch {}
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
    mqttClient.subscribe([TOPIC_PHOTO, TOPIC_LOGS, TOPIC_FINGER_STATUS], { qos: 1 });
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
      console.log(`[MQTT] 📸 Nhận ảnh: ${size} bytes`);
      const b64 = payload.toString("base64");
      broadcast({ type: "photo", data: b64, size, timestamp: ts });
      const now = Date.now();
      if (now - lastRecognizeTime >= RECOGNIZE_COOLDOWN) {
        lastRecognizeTime = now;
        await runRecognition(b64, ts);
      }
    } else if (topic === TOPIC_FINGER_STATUS) {
      try {
        const data = JSON.parse(payload.toString());
        console.log(`[FINGER] 📩 Status:`, data);
        if (data.event === "enroll_ok" && data.id !== undefined) {
          fingerDB[data.id] = { name: data.name || `User_${data.id}`, enrolledAt: new Date().toISOString() };
          saveFingerDB();
          broadcast({ type: "finger_status", ...data, db: fingerDB });
        } else if (data.event === "delete_ok" && data.id !== undefined) {
          delete fingerDB[data.id];
          saveFingerDB();
          console.log(`[FINGER] 🗑️ Đã xóa ID=${data.id} khỏi DB`);
          broadcast({ type: "finger_status", ...data, db: fingerDB });
        } else {
          broadcast({ type: "finger_status", ...data });
        }
      } catch {}
    } else if (topic === TOPIC_LOGS) {
      try {
        const log = JSON.parse(payload.toString());
        broadcast({ type: "log", ...log, timestamp: new Date().toISOString() });
      } catch {}
    }
  });

  // ── Face Recognition ──
  async function runRecognition(b64Image, timestamp) {
    console.log("[FACE] 🔍 Gửi ảnh đến face_service...");
    broadcast({ type: "recognizing", timestamp });
    try {
      const res = await fetch(FACE_SERVICE_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ image: b64Image }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const result = await res.json();
      console.log(`[FACE] Kết quả:`, result);
      broadcast({ type: "recognition_result", ...result, timestamp });

      if (result.recognized) {
        // ── Nhận diện thành công ──
        console.log(`[FACE] ✅ NHẬN DIỆN: ${result.name} (${(result.confidence*100).toFixed(1)}%)`);
        publishUnlock(result.name);

        // Publish kết quả lên topic mới để S3 nhận và hiển thị LCD
        const facePayload = JSON.stringify({
          result: "ok",
          name: result.name,
          confidence: parseFloat((result.confidence * 100).toFixed(1)),
          timestamp
        });
        mqttClient.publish(TOPIC_FACE_RESULT, facePayload, { qos: 1 });
        console.log(`[FACE] 📤 Publish faceresult: ${facePayload}`);

      } else if (result.detected) {
        // ── Phát hiện mặt nhưng không nhận ra ──
        console.log(`[FACE] ❌ Khuôn mặt lạ — KHÔNG mở khóa`);

        const facePayload = JSON.stringify({
          result: "fail",
          name: "Unknown",
          timestamp
        });
        mqttClient.publish(TOPIC_FACE_RESULT, facePayload, { qos: 1 });
        console.log(`[FACE] 📤 Publish faceresult: ${facePayload}`);

      } else {
        // ── Không phát hiện mặt nào ──
        const facePayload = JSON.stringify({
          result: "noface",
          timestamp
        });
        mqttClient.publish(TOPIC_FACE_RESULT, facePayload, { qos: 1 });
        console.log(`[FACE] 📤 Publish faceresult (no face): ${facePayload}`);
      }

    } catch (err) {
      console.error("[FACE] ❌ Lỗi gọi face_service:", err.message);
      broadcast({ type: "face_service_error", error: err.message, timestamp });
    }
  }

  function getNextFingerId() {
    const ids = Object.keys(fingerDB).map(Number);
    for (let i = 1; i <= 127; i++) {
      if (!ids.includes(i)) return i;
    }
    return 1;
  }

  function publishUnlock(name) {
    const payload = JSON.stringify({ cmd: "UNLOCK", name, timestamp: new Date().toISOString() });
    mqttClient.publish(TOPIC_CMD, payload, { qos: 1 }, (err) => {
      if (err) console.error("[MQTT] ❌ Gửi unlock thất bại:", err.message);
      else {
        console.log(`[MQTT] 🔓 Đã gửi UNLOCK cho: ${name}`);
        broadcast({ type: "unlock_sent", name, timestamp: new Date().toISOString() });
      }
    });
  }

  async function reloadFaces() {
    try {
      const res  = await fetch(FACE_RELOAD_URL, { method: "POST" });
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
    console.log(`📸 Enroll API: POST /api/enroll-face`);
    console.log(`👤 Face result topic: ${TOPIC_FACE_RESULT}`);
    console.log(`${"─".repeat(50)}\n`);
  });

})();
