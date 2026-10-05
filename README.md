# Bazaarly - multi-vendor store (Node, Express, MongoDB)

## Run on your computer
1. Install Node 18+ and create a free MongoDB Atlas database (copy its connection string).
2. `cp .env.example .env` and fill in MONGO_URI, JWT_SECRET, ADMIN_PASSWORD.
3. `npm install` then `npm start`, and open http://localhost:3000

The admin account is created automatically on the first start from ADMIN_EMAIL / ADMIN_PASSWORD.
Log in as Admin with that password, add shopkeepers, and give them the email and temporary password.

## Put it online (Render)
1. Push this folder to a GitHub repository.
2. On render.com create a Web Service from the repo. Build command: `npm install`. Start command: `npm start`.
3. Add the same environment variables (MONGO_URI, JWT_SECRET, ADMIN_EMAIL, ADMIN_PASSWORD).
4. In MongoDB Atlas, allow network access from Render (Network Access > add 0.0.0.0/0 for a start).

## Customer login (mobile OTP)
Customers log in with their mobile number and a 6 digit OTP (valid 5 minutes, 5 tries).
- Local testing: leave the TWILIO_* values empty. The OTP is shown on the login screen and printed in the server log.
- Online: set NODE_ENV=production and fill TWILIO_SID, TWILIO_TOKEN, TWILIO_FROM. Without SMS settings, OTP login is switched off in production on purpose.
- To use another SMS service (MSG91, Fast2SMS...), only change the `sendSms` function in server.js.

## Online payment (Razorpay)
Customer pays on Razorpay's checkout window. The order is confirmed only after the payment signature is verified on the server, and the 24 hour cancel window starts from that moment. Cancelling inside 24 hours refunds the payment automatically.
1. Create a Razorpay account and copy the **test** Key ID and Key Secret first (they start with `rzp_test_`). Put them in `.env`.
2. In the Razorpay dashboard add a webhook: URL `https://YOUR-DOMAIN/api/payments/webhook`, event `payment.captured`, and choose a secret. Put that secret in RAZORPAY_WEBHOOK_SECRET. Keep payment capture on automatic.
3. Test with test mode. When ready for real money, complete Razorpay KYC and switch to the live keys.
- Without Razorpay keys, local testing places orders directly (marked "Test order"). In production, orders are refused until payment is set up.
- All money lands in one Razorpay account (yours). Paying shopkeepers their share is manual for now; Razorpay Route can split payments automatically later.
- Selling price must now be at least Rs 1, because Razorpay does not accept zero amounts.
