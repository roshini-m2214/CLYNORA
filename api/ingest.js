// POST /api/ingest   (called by the ESP32 over WiFi)
//
// Headers:  x-api-key: <device key>
// Body:     { "deviceId": "ESP32-CLY-05", "hr": 78, "spo2": 97, "temp": 36.8,
//             "fw": "1.0.0", "rssi": -61, "battery": 84 }      <- last 3 optional
//
// Writes one row per vital into the existing `vitals` table, in exactly the
// shape the frontend already reads:
//   patient_id, recorded_at_ms, vital_type ('hr'|'spo2'|'temp'), value, source

const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

// Service-role key bypasses RLS. It lives ONLY in Vercel env vars, never in frontend code.
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false } }
);

// Reject physically impossible values so a loose wire can't create fake alerts.
const LIMITS = { hr: [20, 250], spo2: [50, 100], temp: [25, 45] };

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const safeEqual = (a, b) => {
  const A = Buffer.from(String(a)), B = Buffer.from(String(b));
  return A.length === B.length && crypto.timingSafeEqual(A, B);
};

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Use POST' });
  }

  const apiKey = req.headers['x-api-key'];
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const deviceId = typeof body.deviceId === 'string' ? body.deviceId.trim() : '';

  if (!apiKey || !deviceId) {
    return res.status(401).json({ error: 'Missing device credentials' });
  }

  try {
    // 1. Authenticate the device
    const { data: dev, error: devErr } = await supabase
      .from('device_keys')
      .select('key_hash, enabled')
      .eq('device_id', deviceId)
      .maybeSingle();
    if (devErr) throw devErr;

    // Same response for "unknown device" and "wrong key" so IDs can't be probed.
    if (!dev || !dev.enabled || !safeEqual(dev.key_hash, sha256(apiKey))) {
      return res.status(401).json({ error: 'Invalid device credentials' });
    }

    // 2. Heartbeat (so the Device Fleet page can show last ping / signal / firmware)
    const heartbeat = { last_seen_at: new Date().toISOString() };
    if (typeof body.fw === 'string') heartbeat.firmware = body.fw.slice(0, 32);
    if (Number.isInteger(body.rssi) && body.rssi >= -120 && body.rssi <= 0) heartbeat.rssi = body.rssi;
    if (Number.isInteger(body.battery) && body.battery >= 0 && body.battery <= 100) heartbeat.battery = body.battery;
    await supabase.from('device_keys').update(heartbeat).eq('device_id', deviceId);

    // 3. Which patient wears this device? (patients.device_id, already in your table)
    const { data: patient, error: patErr } = await supabase
      .from('patients')
      .select('id')
      .eq('device_id', deviceId)
      .or('is_active.is.null,is_active.eq.true')
      .order('id', { ascending: false })
      .limit(1)
      .maybeSingle();
    if (patErr) throw patErr;
    if (!patient) {
      return res.status(409).json({ error: 'Device is not assigned to an active patient' });
    }

    // 4. Validate and build rows
    const now = Date.now();
    const rows = [];
    for (const [key, [lo, hi]] of Object.entries(LIMITS)) {
      const v = body[key];
      if (typeof v === 'number' && Number.isFinite(v) && v >= lo && v <= hi) {
        rows.push({
          patient_id: patient.id,
          recorded_at_ms: now,
          vital_type: key,
          value: v,
          source: 'device'           // frontend labels 'device' as "ESP32 Wearable"
        });
      }
    }
    if (rows.length === 0) {
      return res.status(400).json({ error: 'No valid hr / spo2 / temp values in payload' });
    }

    // 5. Save
    const { error: insErr } = await supabase.from('vitals').insert(rows);
    if (insErr) throw insErr;

    return res.status(201).json({ ok: true, saved: rows.length, patientId: patient.id });
  } catch (err) {
    console.error('ingest failed:', err);
    return res.status(500).json({ error: 'Server error' });
  }
};
