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
const fetch      = require('node-fetch'); // Đảm bảo dùng node-fetch@2

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

const app    = express();
app.use(cors());
const server = http.createServer(app);
app.use(express.static(path.join(__dirname)));
app.use(express.json({ limit: "10mb" }));

// --- MQTT & WEBSOCKET CORE ---
const wss = new WebSocket.Server({ server });
let wsClients = new Set();
let lastRecognizeTime = 0;

const mqttClient = mqtt.connect(MQTT_BROKER, {
    username: MQTT_USER, password: MQTT_PASS,
    rejectUnauthorized: false,
    clientId: "server_bridge_" + Math.random().toString(16).slice(2, 8)
});

mqttClient.on("connect", () => {
    mqttClient.subscribe([TOPIC_PHOTO, TOPIC_LOGS, TOPIC_FINGER_STATUS, TOPIC_CMD]);
});

mqttClient.on("message", async (topic, payload) => {
    if (topic === TOPIC_PHOTO) {
        const b64 = payload.toString("base64");
        wsClients.forEach(ws => ws.send(JSON.stringify({ type: "photo", data: b64 })));
        if (Date.now() - lastRecognizeTime >= RECOGNIZE_COOLDOWN) {
            lastRecognizeTime = Date.now();
            await runRecognition(b64);
        }
    } else {
        // Chuyển tiếp các tin nhắn khác sang WebSocket
        wsClients.forEach(ws => ws.send(JSON.stringify({ type: "mqtt", topic, data: payload.toString() })));
    }
});

async function runRecognition(b64Image) {
    try {
      const res = await fetch(FACE_SERVICE_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ image: b64Image }),
      });
      const result = await res.json();
      wsClients.forEach(ws => ws.send(JSON.stringify({ type: "recognition_result", ...result })));
      if (result.recognized) {
          mqttClient.publish(TOPIC_CMD, JSON.stringify({ cmd: "UNLOCK", name: result.name }));
      }
    } catch (err) { console.error("AI Error:", err); }
}

wss.on("connection", (ws) => {
    wsClients.add(ws);
    ws.on("close", () => wsClients.delete(ws));
});

server.listen(WS_PORT, () => console.log(`Server online tại port ${WS_PORT}`));
