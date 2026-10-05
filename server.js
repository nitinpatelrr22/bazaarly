require('dotenv').config();
const express = require('express'), mongoose = require('mongoose'), bcrypt = require('bcryptjs'),
  jwt = require('jsonwebtoken'), helmet = require('helmet'), rateLimit = require('express-rate-limit'), path = require('path');
const crypto = require('crypto');
const { User, Product, Order, Otp } = require('./models');
const { MONGO_URI, JWT_SECRET, ADMIN_EMAIL, ADMIN_PASSWORD, PORT = 3000 } = process.env;
const { TWILIO_SID, TWILIO_TOKEN, TWILIO_FROM, COUNTRY_CODE = '+91', NODE_ENV } = process.env;
const { RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET, RAZORPAY_WEBHOOK_SECRET } = process.env;
if (!MONGO_URI || !JWT_SECRET || !ADMIN_PASSWORD) { console.error('Set MONGO_URI, JWT_SECRET and ADMIN_PASSWORD in .env'); process.exit(1); }

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '4mb', verify: (req, res, buf) => { req.rawBody = buf; } }));

const wrap = f => (req, res, next) => f(req, res, next).catch(next);
const bad = (res, m, c = 400) => res.status(c).json({ error: m });
const sign = u => jwt.sign({ id: u.id }, JWT_SECRET, { expiresIn: '7d' });
const emailOk = e => /^\S+@\S+\.\S+$/.test(e);
const auth = (...roles) => wrap(async (req, res, next) => {
  let p; try { p = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), JWT_SECRET); } catch { return bad(res, 'Please log in again', 401); }
  const u = await User.findById(p.id);
  if (!u) return bad(res, 'Please log in again', 401);
  if (u.passwordChangedAt && p.iat < Math.floor(+u.passwordChangedAt / 1000)) return bad(res, 'Please log in again', 401);   // password was reset
  if (roles.length && !roles.includes(u.role)) return bad(res, 'Not allowed', 403);
  req.user = u; next();
});

// JSON shapes used by the web page
const shopJ = u => ({ id: u.id, name: u.name, shop: u.shopName, email: u.email });
const prodJ = p => ({ id: p.id, sid: p.shopkeeper.id, shop: p.shopkeeper.shopName, name: p.name, desc: p.description, mrp: p.mrp, price: p.price, stock: p.stock, imgs: p.images });
const ordJ = (o, sid) => ({
  id: o.id, customer: o.customerName, email: o.email, phone: o.phone, address: o.address, status: o.status, pay: o.payment && o.payment.status,
  placedAt: +o.createdAt, expiresAt: +o.expiresAt, cancelledAt: o.cancelledAt ? +o.cancelledAt : null,
  items: o.items.filter(i => !sid || String(i.shopkeeper) === sid).map(i => ({ pid: String(i.product), sid: String(i.shopkeeper), name: i.name, price: i.price, q: i.qty }))
});

// ---- Auth ----
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30 });
app.post('/api/auth/admin', limiter, wrap(async (req, res) => {
  const u = await User.findOne({ role: 'admin' }).select('+password');
  if (!u || !(await bcrypt.compare(String(req.body.password || ''), u.password))) return bad(res, 'Wrong admin password', 401);
  res.json({ token: sign(u), name: u.name });
}));
app.post('/api/auth/shop', limiter, wrap(async (req, res) => {
  const u = await User.findOne({ role: 'shopkeeper', email: String(req.body.email || '').toLowerCase() }).select('+password');
  if (!u || !(await bcrypt.compare(String(req.body.password || ''), u.password))) return bad(res, 'Email or password is incorrect', 401);
  res.json({ token: sign(u), id: u.id, name: u.name });
}));
// Customer login: mobile number + OTP
const smsReady = !!(TWILIO_SID && TWILIO_TOKEN && TWILIO_FROM);
const hashOtp = (phone, otp) => crypto.createHmac('sha256', JWT_SECRET).update(phone + ':' + otp).digest('hex');
async function sendSms(phone, text) {   // swap this function to use MSG91, Fast2SMS etc.
  const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${TWILIO_SID}/Messages.json`, {
    method: 'POST',
    headers: { Authorization: 'Basic ' + Buffer.from(TWILIO_SID + ':' + TWILIO_TOKEN).toString('base64'), 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ To: COUNTRY_CODE + phone, From: TWILIO_FROM, Body: text })
  });
  if (!r.ok) throw new Error('SMS failed with status ' + r.status);
}
app.post('/api/auth/otp/request', limiter, wrap(async (req, res) => {
  const phone = String(req.body.phone || '').trim();
  if (!/^\d{10}$/.test(phone)) return bad(res, 'Enter a valid 10 digit mobile number');
  if (!smsReady && NODE_ENV === 'production') return bad(res, 'SMS is not set up yet', 503);
  const last = await Otp.findOne({ phone });
  if (last && Date.now() - +last.createdAt < 30000) return bad(res, 'Please wait 30 seconds before asking for a new OTP', 429);
  const otp = String(crypto.randomInt(100000, 1000000));
  await Otp.deleteMany({ phone });
  await Otp.create({ phone, hash: hashOtp(phone, otp), expiresAt: new Date(Date.now() + 5 * 60 * 1000) });
  if (smsReady) { await sendSms(phone, `Your Bazaarly OTP is ${otp}. It is valid for 5 minutes.`); return res.json({ sent: true }); }
  console.log(`[test mode] OTP for ${phone}: ${otp}`);
  res.json({ sent: true, devOtp: otp });   // only when SMS is not configured and NODE_ENV is not production
}));
app.post('/api/auth/otp/verify', limiter, wrap(async (req, res) => {
  const phone = String(req.body.phone || '').trim(), otp = String(req.body.otp || '').trim(), name = String(req.body.name || '').trim();
  const rec = await Otp.findOne({ phone });
  if (!rec || rec.expiresAt < new Date()) return bad(res, 'OTP expired. Please ask for a new one');
  if (rec.attempts >= 5) { await rec.deleteOne(); return bad(res, 'Too many wrong tries. Ask for a new OTP', 429); }
  const x = Buffer.from(hashOtp(phone, otp)), y = Buffer.from(rec.hash);
  if (!(x.length === y.length && crypto.timingSafeEqual(x, y))) { rec.attempts++; await rec.save(); return bad(res, 'Wrong OTP', 401); }
  await rec.deleteOne();
  let u = await User.findOne({ phone });
  if (!u) { if (!name) return bad(res, 'Enter your name'); u = await User.create({ name, phone, role: 'customer' }); }
  res.json({ token: sign(u), id: u.id, name: u.name, phone: u.phone });
}));

// ---- Admin: manage shopkeepers ----
const adm = auth('admin');
app.get('/api/admin/shops', adm, wrap(async (req, res) => res.json((await User.find({ role: 'shopkeeper' }).sort('-createdAt')).map(shopJ))));
app.post('/api/admin/shops', adm, wrap(async (req, res) => {
  const name = String(req.body.name || '').trim(), shop = String(req.body.shop || '').trim(),
    email = String(req.body.email || '').trim().toLowerCase(), pw = String(req.body.pw || '');
  if (!name || !shop || !emailOk(email) || pw.length < 6) return bad(res, 'Fill all fields. The password needs at least 6 characters');
  if (await User.exists({ email })) return bad(res, 'That email is already registered', 409);
  const u = await User.create({ name, email, shopName: shop, role: 'shopkeeper', password: await bcrypt.hash(pw, 12), createdBy: req.user.id });
  res.status(201).json(shopJ(u));
}));
app.patch('/api/admin/shops/:id', adm, wrap(async (req, res) => {   // change shop name, shopkeeper name or password
  const name = String(req.body.name || '').trim(), shop = String(req.body.shop || '').trim(), pw = String(req.body.pw || '');
  if (!name || !shop || (pw && pw.length < 6)) return bad(res, 'Name and shop name are required. A new password needs at least 6 characters');
  const upd = { name, shopName: shop };
  if (pw) { upd.password = await bcrypt.hash(pw, 12); upd.passwordChangedAt = new Date(); }
  const u = await User.findOneAndUpdate({ _id: req.params.id, role: 'shopkeeper' }, upd, { new: true });
  if (!u) return bad(res, 'Shopkeeper not found', 404);
  res.json(shopJ(u));
}));
app.delete('/api/admin/shops/:id', adm, wrap(async (req, res) => {
  const u = await User.findOneAndDelete({ _id: req.params.id, role: 'shopkeeper' });
  if (u) await Product.deleteMany({ shopkeeper: u.id });
  res.json({ ok: true });
}));

// ---- Products ----
const cleanImgs = a => Array.isArray(a) ? a.filter(x => typeof x === 'string' && /^data:image\/(jpeg|png|webp);base64,/.test(x) && x.length < 600000).slice(0, 5) : [];
function prodBody(b) {
  const name = String(b.name || '').trim(), description = String(b.desc || '').trim(),
    mrp = Math.round(+b.mrp), price = Math.round(+b.price), stock = Math.round(+b.stock);
  if (!name || !description || !(mrp > 0) || !(price >= 1) || !(stock >= 0)) return { err: 'Fill all product fields with valid numbers' };
  if (price > mrp) return { err: 'Selling price cannot be more than MRP' };
  return { v: { name, description, mrp, price, stock, images: cleanImgs(b.imgs) } };
}
const shopOnly = auth('shopkeeper');
app.get('/api/products', wrap(async (req, res) =>
  res.json((await Product.find().populate('shopkeeper', 'shopName').sort('-createdAt')).filter(p => p.shopkeeper).map(prodJ))));
app.post('/api/products', shopOnly, wrap(async (req, res) => {
  const { err, v } = prodBody(req.body); if (err) return bad(res, err);
  const p = await Product.create({ ...v, shopkeeper: req.user.id }); res.status(201).json({ id: p.id });
}));
app.put('/api/products/:id', shopOnly, wrap(async (req, res) => {
  const { err, v } = prodBody(req.body); if (err) return bad(res, err);
  const p = await Product.findOneAndUpdate({ _id: req.params.id, shopkeeper: req.user.id }, v, { new: true, runValidators: true }); // owner only
  if (!p) return bad(res, 'Product not found', 404); res.json({ id: p.id });
}));
app.delete('/api/products/:id', shopOnly, wrap(async (req, res) => {
  await Product.deleteOne({ _id: req.params.id, shopkeeper: req.user.id }); res.json({ ok: true });
}));

// ---- Orders (24 hour cancel window is enforced here, on the server) ----
app.post('/api/orders', auth('customer'), wrap(async (req, res) => {
  const b = req.body, qty = Math.round(+b.qty), name = String(b.name || '').trim(), phone = String(b.phone || '').trim(), address = String(b.address || '').trim();
  if (!name || !/^\d{10}$/.test(phone) || address.length < 5 || !(qty >= 1)) return bad(res, 'Enter your name, a 10 digit phone number, address and quantity');
  if (!rzpReady && NODE_ENV === 'production') return bad(res, 'Online payment is not set up yet', 503);
  const p = await Product.findOneAndUpdate({ _id: b.productId, stock: { $gte: qty } }, { $inc: { stock: -qty } }, { new: true }); // reserve stock atomically
  if (!p) return bad(res, 'Not enough stock for that quantity', 409);
  const amount = p.price * qty;
  const o = await Order.create({
    customer: req.user.id, customerName: name, phone, address, amount,
    items: [{ product: p.id, shopkeeper: p.shopkeeper, name: p.name, price: p.price, qty }]
  });
  if (!rzpReady) {   // local test mode: no real payment
    o.status = 'confirmed'; o.expiresAt = new Date(Date.now() + 24 * 3600 * 1000); o.payment.status = 'test'; await o.save();
    return res.status(201).json({ test: true, order: ordJ(o) });
  }
  try {
    const rz = await rzp('POST', '/orders', { amount: amount * 100, currency: 'INR', receipt: o.id, notes: { orderId: o.id } });
    o.payment.rzpOrderId = rz.id; await o.save();
    res.status(201).json({ orderId: o.id, key: RAZORPAY_KEY_ID, rzpOrderId: rz.id, amount: amount * 100, name, phone });
  } catch (e) {
    console.error(e.message);
    await Order.updateOne({ _id: o.id }, { status: 'failed' }); await Product.updateOne({ _id: p.id }, { $inc: { stock: qty } });
    bad(res, 'Could not start the payment. Please try again', 502);
  }
}));
app.get('/api/orders', auth(), wrap(async (req, res) => {
  const u = req.user, q = u.role === 'admin' ? {} : u.role === 'shopkeeper' ? { 'items.shopkeeper': u.id } : { customer: u.id };
  res.json((await Order.find({ ...q, status: { $in: ['confirmed', 'cancelled'] } }).sort('-createdAt')).map(o => ordJ(o, u.role === 'shopkeeper' ? u.id : null)));
}));
app.post('/api/orders/:id/cancel', auth('customer'), wrap(async (req, res) => {
  const o = await Order.findOneAndUpdate(
    { _id: req.params.id, customer: req.user.id, status: 'confirmed', expiresAt: { $gt: new Date() } },
    { status: 'cancelled', cancelledAt: new Date() }, { new: true });
  if (!o) return bad(res, 'This order can no longer be cancelled', 409);
  for (const i of o.items) await Product.updateOne({ _id: i.product }, { $inc: { stock: i.qty } });
  if (o.payment && o.payment.status === 'paid') {   // cancelled inside 24 hours: refund the payment
    try { await rzp('POST', `/payments/${o.payment.paymentId}/refund`, { amount: o.amount * 100 }); o.payment.status = 'refunded'; }
    catch (e) { console.error(e.message); o.payment.status = 'refund_failed'; }
    await o.save();
  }
  res.json(ordJ(o));
}));

// ---- Razorpay payments ----
const rzpReady = !!(RAZORPAY_KEY_ID && RAZORPAY_KEY_SECRET);
async function rzp(method, p, body) {
  const resp = await fetch('https://api.razorpay.com/v1' + p, {
    method, headers: { Authorization: 'Basic ' + Buffer.from(RAZORPAY_KEY_ID + ':' + RAZORPAY_KEY_SECRET).toString('base64'), 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined
  });
  const d = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error('Razorpay ' + resp.status + ': ' + ((d.error && d.error.description) || ''));
  return d;
}
const safeEq = (a, b) => { a = Buffer.from(String(a)); b = Buffer.from(String(b)); return a.length === b.length && crypto.timingSafeEqual(a, b); };
// Marks the order paid and starts the 24 hour cancel window. Used by both the page callback and the webhook.
async function confirmPaid(rzpOrderId, paymentId) {
  const o = await Order.findOneAndUpdate({ 'payment.rzpOrderId': rzpOrderId, status: 'pending_payment' },
    { status: 'confirmed', expiresAt: new Date(Date.now() + 24 * 3600 * 1000), 'payment.status': 'paid', 'payment.paymentId': paymentId, 'payment.paidAt': new Date() }, { new: true });
  if (o) return o;
  const ex = await Order.findOne({ 'payment.rzpOrderId': rzpOrderId });
  if (ex && ex.status === 'failed' && ex.payment.status === 'pending') {   // money arrived after the stock reservation was released
    try { await rzp('POST', `/payments/${paymentId}/refund`, { amount: ex.amount * 100 }); ex.payment.status = 'refunded'; } catch (e) { ex.payment.status = 'refund_failed'; }
    ex.payment.paymentId = paymentId; await ex.save();
  }
  return null;
}
app.post('/api/orders/:id/verify', auth('customer'), wrap(async (req, res) => {
  if (!rzpReady) return bad(res, 'Payments are not enabled');
  const { razorpay_payment_id: pid, razorpay_order_id: oid, razorpay_signature: sig } = req.body;
  const o0 = await Order.findOne({ _id: req.params.id, customer: req.user.id, 'payment.rzpOrderId': String(oid) });
  if (!o0) return bad(res, 'Order not found', 404);
  const expect = crypto.createHmac('sha256', RAZORPAY_KEY_SECRET).update(oid + '|' + pid).digest('hex');
  if (!safeEq(expect, sig || '')) return bad(res, 'Payment could not be verified');
  const o = (await confirmPaid(oid, pid)) || (await Order.findById(o0.id));
  if (o.status !== 'confirmed' && o.status !== 'cancelled') return bad(res, 'Payment arrived after the order expired. It will be refunded', 409);
  res.json(ordJ(o));
}));
app.post('/api/orders/:id/abandon', auth('customer'), wrap(async (req, res) => {   // customer closed the payment window
  const o = await Order.findOneAndUpdate({ _id: req.params.id, customer: req.user.id, status: 'pending_payment' }, { status: 'failed' });
  if (o) for (const i of o.items) await Product.updateOne({ _id: i.product }, { $inc: { stock: i.qty } });
  res.json({ ok: true });
}));
app.post('/api/payments/webhook', wrap(async (req, res) => {   // Razorpay calls this even if the customer closes the page
  if (!RAZORPAY_WEBHOOK_SECRET || !req.rawBody) return res.sendStatus(404);
  const expect = crypto.createHmac('sha256', RAZORPAY_WEBHOOK_SECRET).update(req.rawBody).digest('hex');
  if (!safeEq(expect, req.headers['x-razorpay-signature'] || '')) return res.sendStatus(400);
  const pay = req.body.payload && req.body.payload.payment && req.body.payload.payment.entity;
  if (req.body.event === 'payment.captured' && pay) await confirmPaid(pay.order_id, pay.id);
  res.sendStatus(200);
}));

app.use(express.static(path.join(__dirname, 'public')));
app.use('/api', (req, res) => bad(res, 'Not found', 404));
app.use((err, req, res, next) => {
  console.error(err);
  const c = err.name === 'CastError' || err.name === 'ValidationError' ? 400 : 500;
  res.status(c).json({ error: c === 400 ? 'Invalid request' : 'Something went wrong' });
});

mongoose.connect(MONGO_URI).then(async () => {
  if (!(await User.exists({ role: 'admin' })))
    await User.create({ name: 'Admin', email: (ADMIN_EMAIL || 'admin@example.com').toLowerCase(), role: 'admin', password: await bcrypt.hash(ADMIN_PASSWORD, 12) });
  app.listen(PORT, () => console.log('Running on port ' + PORT));
  setInterval(async () => {   // release stock held by payments that were never completed (30 minutes)
    try {
      const old = await Order.find({ status: 'pending_payment', createdAt: { $lt: new Date(Date.now() - 30 * 60 * 1000) } });
      for (const o of old) {
        const x = await Order.findOneAndUpdate({ _id: o._id, status: 'pending_payment' }, { status: 'failed' });
        if (x) for (const i of x.items) await Product.updateOne({ _id: i.product }, { $inc: { stock: i.qty } });
      }
    } catch (e) { console.error(e.message); }
  }, 5 * 60 * 1000);
}).catch(e => { console.error('MongoDB connection failed:', e.message); process.exit(1); });
