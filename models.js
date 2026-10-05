const mongoose = require('mongoose');
const { Schema } = mongoose;

const User = mongoose.model('User', new Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: function () { return this.role !== 'customer'; }, unique: true, sparse: true, lowercase: true, trim: true },
  phone: { type: String, unique: true, sparse: true },  // customers log in with phone + OTP
  password: { type: String, select: false },            // bcrypt hash (admin + shopkeeper only)
  role: { type: String, enum: ['admin', 'shopkeeper', 'customer'], required: true, index: true },
  shopName: String,
  passwordChangedAt: Date,
  createdBy: { type: Schema.Types.ObjectId, ref: 'User' }
}, { timestamps: true }));

const Product = mongoose.model('Product', new Schema({
  shopkeeper: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  name: { type: String, required: true, trim: true, maxlength: 150 },
  description: { type: String, required: true, maxlength: 2000 },
  mrp: { type: Number, required: true, min: 1 },
  price: { type: Number, required: true, min: 0 },
  stock: { type: Number, required: true, min: 0 },
  images: [String]
}, { timestamps: true }));

const Order = mongoose.model('Order', new Schema({
  customer: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  customerName: String, email: String, phone: String, address: String,
  items: [{
    product: { type: Schema.Types.ObjectId, ref: 'Product' },
    shopkeeper: { type: Schema.Types.ObjectId, ref: 'User', index: true },
    name: String, price: Number, qty: Number
  }],
  amount: { type: Number, required: true },              // total in rupees
  status: { type: String, enum: ['pending_payment', 'confirmed', 'cancelled', 'failed'], default: 'pending_payment', index: true },
  payment: {
    rzpOrderId: { type: String, index: true },
    paymentId: String,
    status: { type: String, enum: ['pending', 'paid', 'test', 'refunded', 'refund_failed'], default: 'pending' },
    paidAt: Date
  },
  expiresAt: Date,                                       // payment time + 24 hours (cancel window)
  cancelledAt: Date
}, { timestamps: true }));

const Otp = mongoose.model('Otp', new Schema({
  phone: { type: String, required: true, index: true },
  hash: { type: String, required: true },                 // HMAC of the OTP, never the OTP itself
  attempts: { type: Number, default: 0 },
  expiresAt: { type: Date, required: true, index: { expires: 0 } }   // auto-deleted after expiry
}, { timestamps: true }));

module.exports = { User, Product, Order, Otp };
