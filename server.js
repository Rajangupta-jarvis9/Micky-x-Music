const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());

// ── Supabase ─────────────────────────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ── Rate limiting ─────────────────────────────────────────────────────────────
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 20,
  message: { error: 'Too many requests' }
});
app.use('/api/', limiter);

// ── Key generator ─────────────────────────────────────────────────────────────
function generateKey(plan = 'basic') {
  const prefix = plan === 'pro' ? 'LIA-PRO' : 'LIA-BSC';
  const random = crypto.randomBytes(8).toString('hex').toUpperCase();
  // Format: LIA-PRO-XXXX-XXXX-XXXX
  const parts = random.match(/.{1,4}/g).join('-');
  return `${prefix}-${parts}`;
}

// ── POST /api/generate ────────────────────────────────────────────────────────
// Admin only — generate new key
app.post('/api/generate', async (req, res) => {
  const adminSecret = req.headers['x-admin-secret'];
  if (adminSecret !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const {
    plan = 'basic',
    expires_days = 30,
    email = null
  } = req.body;

  const key = generateKey(plan);
  const expires_at = expires_days > 0
    ? new Date(Date.now() + expires_days * 24 * 60 * 60 * 1000).toISOString()
    : null;

  const { data, error } = await supabase
    .from('license_keys')
    .insert({
      key,
      plan,
      email,
      active: true,
      blocked: false,
      expires_at,
      created_at: new Date().toISOString(),
      device_id: null,
      last_check: null,
    })
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });

  res.json({ key: data.key, plan: data.plan, expires_at: data.expires_at });
});

// ── POST /api/activate ────────────────────────────────────────────────────────
// App calls this when user enters key first time
app.post('/api/activate', async (req, res) => {
  const { key, device } = req.body;

  if (!key || !device) {
    return res.status(400).json({ error: 'Missing key or device' });
  }

  const { data, error } = await supabase
    .from('license_keys')
    .select('*')
    .eq('key', key.trim().toUpperCase())
    .single();

  if (error || !data) {
    return res.status(404).json({ active: false, error: 'Key not found' });
  }

  if (data.blocked) {
    return res.json({ active: false, error: 'Key blocked' });
  }

  if (data.expires_at && new Date(data.expires_at) < new Date()) {
    return res.json({ active: false, error: 'Key expired' });
  }

  // Bind key to this device (first activation)
  if (!data.device_id) {
    await supabase
      .from('license_keys')
      .update({ device_id: device, last_check: new Date().toISOString() })
      .eq('key', key.trim().toUpperCase());
  } else if (data.device_id !== device) {
    // Already activated on another device
    return res.json({ active: false, error: 'Key already used on another device' });
  }

  res.json({
    active: true,
    plan: data.plan,
    expires_at: data.expires_at ? new Date(data.expires_at).getTime() : 0,
  });
});

// ── POST /api/check ───────────────────────────────────────────────────────────
// App calls every 3 hours to verify key still valid
app.post('/api/check', async (req, res) => {
  const { key, device } = req.body;

  if (!key || !device) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  const { data, error } = await supabase
    .from('license_keys')
    .select('active, plan, expires_at, blocked, device_id')
    .eq('key', key.trim().toUpperCase())
    .single();

  if (error || !data) {
    return res.json({ active: false });
  }

  if (data.blocked) return res.json({ active: false, blocked: true });
  if (data.device_id && data.device_id !== device) {
    return res.json({ active: false, error: 'Device mismatch' });
  }
  if (data.expires_at && new Date(data.expires_at) < new Date()) {
    return res.json({ active: false, error: 'Expired' });
  }

  // Update last check time
  await supabase
    .from('license_keys')
    .update({ last_check: new Date().toISOString() })
    .eq('key', key.trim().toUpperCase());

  res.json({
    active: data.active,
    plan: data.plan,
    expires_at: data.expires_at ? new Date(data.expires_at).getTime() : 0,
  });
});

// ── POST /api/revoke ──────────────────────────────────────────────────────────
// Admin — block a key
app.post('/api/revoke', async (req, res) => {
  const adminSecret = req.headers['x-admin-secret'];
  if (adminSecret !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { key } = req.body;
  const { error } = await supabase
    .from('license_keys')
    .update({ blocked: true, active: false })
    .eq('key', key.trim().toUpperCase());

  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ── GET /api/stats ────────────────────────────────────────────────────────────
// Admin — total keys, active users
app.get('/api/stats', async (req, res) => {
  const adminSecret = req.headers['x-admin-secret'];
  if (adminSecret !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { count: total } = await supabase
    .from('license_keys')
    .select('*', { count: 'exact', head: true });

  const { count: active } = await supabase
    .from('license_keys')
    .select('*', { count: 'exact', head: true })
    .eq('active', true)
    .eq('blocked', false);

  const { count: blocked } = await supabase
    .from('license_keys')
    .select('*', { count: 'exact', head: true })
    .eq('blocked', true);

  res.json({ total, active, blocked });
});

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status: 'ok', service: 'LiaAI License' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`License server running on ${PORT}`));
