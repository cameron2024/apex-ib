# Apex IB — iOS App Setup Runbook

Everything in `ios-wrapper/` and the updated `animations.js` / `sidebar.js` /
`server.js` is ready. This doc is the part that has to happen on your Mac —
Capacitor's native build step needs Xcode, which I can't run remotely.

## 0. Prerequisites (one-time)
- A Mac with Xcode installed (free, via the App Store). You need an actual
  Mac for this — there's no way around it for iOS builds.
- Apple Developer Program enrollment — $99/year, at developer.apple.com.
  Takes Apple a few hours to a day to approve.
- Node.js installed (you already have this for the server).
- CocoaPods: `sudo gem install cocoapods`

## 1. Get the wrapper project onto your Mac
Drop the `ios-wrapper/` folder I built into your repo (or its own repo,
either works — it doesn't need to live next to server.js). Then:

```bash
cd ios-wrapper
npm install
npx cap add ios
```

This generates an `ios/` folder with a real Xcode project inside it.

## 2. Open it in Xcode and configure signing
```bash
npx cap open ios
```
In Xcode: select the project → Signing & Capabilities → choose your Apple
Developer team. Xcode will auto-provision a signing certificate.

Also in Xcode: Signing & Capabilities → "+" → add **In-App Purchase**
capability (this is what lets the app talk to StoreKit at all).

## 3. Create your products in App Store Connect
At appstoreconnect.apple.com → your app → Monetization → Subscriptions.
Create a subscription group (e.g. "Apex IB Plans") with these products,
matching the IDs already wired into the code:

| Product ID | Maps to | Price |
|---|---|---|
| `pro_monthly` | Pro | $19.99/mo |
| `pro_weekly` | Pro | $4.99/wk (if you keep the weekly toggle) |
| `pass_monthly` | Recruiting Pass | $39.99/mo |
| `pass_weekly` | Recruiting Pass | weekly equivalent |

(If you want different product IDs, just update `RC_PRODUCT_TO_PLAN` in
server.js and `APEX_RC_PRODUCT_MAP` in animations.js to match — they have to
agree across all three: App Store Connect, RevenueCat, and your code.)

## 4. Set up RevenueCat (free up to $2.5k/mo tracked revenue, then 1%)
1. Sign up at revenuecat.com, create a project.
2. Connect your App Store Connect account (Project Settings → Apple App
   Store) — RevenueCat needs an App Store Connect API key, which you
   generate in App Store Connect → Users and Access → Keys.
3. Import the 4 products you created in step 3.
4. Create two **Entitlements**: `pro` and `pass`, and attach the matching
   products to each.
5. Create an **Offering** called `default` with both products available as
   packages — this is what `Purchases.getOfferings()` reads in the app.
6. Grab your **public iOS API key** (Project Settings → API Keys) and paste
   it into the two `YOUR_REVENUECAT_PUBLIC_IOS_API_KEY` placeholders — one
   in `animations.js` (`apexNativePurchase`), one in `sidebar.js`
   (`_apexConfigureNativeIAP`).
7. Set up the webhook: Project Settings → Integrations → Webhooks. URL is
   `https://apex-ib-production.up.railway.app/api/webhooks/revenuecat`.
   Set an Authorization header value (any random secret string) and put
   that same string in Railway's environment variables as
   `REVENUECAT_WEBHOOK_AUTH`.

## 5. Sync and rebuild whenever you change the wrapper or config
```bash
npx cap sync ios
```
Run this after any `npm install` of a new plugin or change to
`capacitor.config.ts`. You do **not** need to do this for normal app
changes — those live on Railway and the app just loads them live.

## 6. Test on a real device (simulators can't do IAP)
Plug in an iPhone, select it as the run target in Xcode, hit Run. To test
purchases without real money, create a **Sandbox Tester** account in App
Store Connect (Users and Access → Sandbox Testers) and sign into it on the
test device under Settings → App Store → Sandbox Account.

## 7. Submit for review
Back in Xcode: Product → Archive → Distribute App → App Store Connect.
Then in App Store Connect: fill out the listing (screenshots, description,
privacy policy URL — you'll need one if you don't already), submit for
review.

Expect 1-3 days for the first review. Common rejection reasons to avoid:
- Missing privacy policy URL.
- "Sign in with Apple" requirement — if your app supports any other social
  login (it currently doesn't, just email/password, so you're fine).
- IAP not actually working when reviewers test it — make sure the sandbox
  tester flow works end-to-end before submitting.

## What you do NOT need to do
- No need to touch your existing Stripe integration — it stays exactly as
  is for web users.
- No need to rebuild or duplicate any HTML — the app loads your live site.
- No need to manage subscription renewals/cancellations by hand — Apple +
  RevenueCat handle billing, your webhook just reflects the result.
