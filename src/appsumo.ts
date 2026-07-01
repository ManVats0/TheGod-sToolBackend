const express = require('express');
const crypto = require('crypto');
const router = express.Router();

// You'll get the REAL api key after AppSumo approves your listing.
// Store it in Railway env vars, never hardcode it.
const APPSUMO_API_KEY = process.env.APPSUMO_API_KEY;

// Optional but recommended: verify the request actually came from AppSumo
function verifySignature(req) {
  const signature = req.headers['x-appsumo-signature'];
  const timestamp = req.headers['x-appsumo-timestamp'];
  if (!signature || !timestamp) return false;

  const payload = timestamp + JSON.stringify(req.body);
  const expected = crypto
    .createHmac('sha256', APPSUMO_API_KEY)
    .update(payload)
    .digest('hex');

  return expected === signature;
}

// WEBHOOK — AppSumo pings this on purchase/activate/upgrade/downgrade/deactivate
router.post('/v2/webhooks', async (req, res) => {
  const { license_key, event, license_status, tier, prev_license_key, test } = req.body;

  console.log('AppSumo webhook:', event, license_key);

  if (!test) {
    try {
      // TODO: replace with your actual DB logic (Mongo model)
      // Example pattern:
      switch (event) {
        case 'purchase':
          // create placeholder license record, no user attached yet
          // await License.create({ license_key, tier, status: 'inactive' });
          break;
        case 'activate':
          // mark license active — user completes this via OAuth redirect
          // await License.updateOne({ license_key }, { status: 'active', tier });
          break;
        case 'upgrade':
        case 'downgrade':
          // find by prev_license_key, replace key + tier
          // await License.updateOne({ license_key: prev_license_key }, { license_key, tier });
          break;
        case 'deactivate':
          // revoke access
          // await License.updateOne({ license_key }, { status: 'deactivated' });
          break;
      }
    } catch (err) {
      console.error('AppSumo webhook DB error:', err);
      // still return success — don't let AppSumo retry-storm you over a DB hiccup
    }
  }

  res.status(200).json({ event, success: true });
});

// OAUTH REDIRECT — AppSumo sends the customer here after purchase
router.get('/v2/redirect-url', (req, res) => {
  const { code } = req.query;

  if (!code) {
    // AppSumo's validation check — no code, just confirm the endpoint is alive
    return res.status(200).json({ success: true });
  }

  // TODO: real flow — exchange `code` for access_token, then fetch license_key
  // For now, redirect user to a page in your app that finishes account linking
  res.redirect(`https://thegodstool.com/appsumo-activate?code=${code}`);
});

module.exports = router;
