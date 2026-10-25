# UtilityCare AI — Full-stack V2

A role-aware utility billing portal with an Express backend, persistent SQLite database, Google Identity Services sign-in, role-scoped bill/tenant APIs, optional OpenAI assistant responses, and Razorpay Standard Checkout integration. Without Razorpay credentials, checkout runs in a clearly-labelled local demo mode. No live payments are possible in demo mode.

## Requirements

- Node.js 20+ (LTS recommended)
- npm
- A Google Cloud OAuth Web client for Google sign-in
- Optional Razorpay account with **Test Mode** API keys
- Optional OpenAI API key for LLM-based assistant responses

## Run locally on Windows / VS Code

1. Extract the ZIP.
2. In VS Code choose **File → Open Folder** and open the folder that contains `package.json` (the project root).
3. Copy `.env.example` to `.env`.
4. Install packages and start:

```powershell
npm install
npm start
```

5. Open http://localhost:3000.

Do not run `npm start` from the parent Downloads folder. `package.json` must be in the terminal's current directory. Check with `Get-ChildItem package.json`.

## Configure Google sign-in

1. Open https://console.cloud.google.com/apis/credentials and create/select a project.
2. Create an OAuth client ID of type **Web application**.
3. Add `http://localhost:3000` to **Authorized JavaScript origins**. This implementation uses Google Identity Services and verifies the ID token on the backend; it does not use the OAuth authorization-code redirect flow, so no callback URI is needed for this setup.
4. Copy the client ID into `.env` as `GOOGLE_CLIENT_ID=...`.
5. Set `STAFF_EMAILS` to a comma-separated allowlist of staff emails. Staff roles are server-authorized, not chosen by the browser.
6. Restart `npm start` and sign in.

Role rules:
- Staff: Google email must be included in `STAFF_EMAILS`.
- Landlord: first Google sign-in can create a landlord account by selecting the landlord entry option.
- Tenant: a landlord must first create the tenant invitation record; tenant must sign in with the exact registered Google email. The client cannot self-assign staff or tenant roles.

Google docs: https://developers.google.com/identity/sign-in/web/backend-auth

## Configure Razorpay test checkout

1. Create/sign in to your Razorpay account at https://dashboard.razorpay.com/.
2. Switch the dashboard to **Test Mode** before creating keys.
3. Open **Account & Settings → API Keys** (dashboard wording may change) and generate a test key pair. Copy the **Key ID** and **Key Secret** once shown.
4. In the project's `.env`, set `RAZORPAY_KEY_ID=rzp_test_...` and `RAZORPAY_KEY_SECRET=...`. Never use `rzp_live_...` for this test project and never put the secret in frontend code.
5. Restart the server. The app creates payment orders on the backend, launches Razorpay Checkout, verifies the checkout signature on the backend and fetches provider status before marking a bill paid. Landlords and tenants can pay only bills returned by their role-scoped bill API; staff can view payment history and use **Refresh from Razorpay** to reconcile known pending attempts.
6. Optional webhook setup: the app must be reachable at a public HTTPS URL for Razorpay to deliver webhooks. In Dashboard → Webhooks, add `https://YOUR_PUBLIC_HOST/api/payments/webhook`, set a strong webhook secret, and copy the same value to `RAZORPAY_WEBHOOK_SECRET`. Subscribe to `payment.captured`, `payment.failed`, and `order.paid` if available for your account. Localhost alone is not reachable by Razorpay.
7. Test with Razorpay's test payment methods and confirm that captured status updates the bill and payment history. Do not treat a browser success callback as final proof. Never use live keys until you have production deployment, webhook verification and reconciliation tested.

Official docs: https://razorpay.com/docs/payments/payment-gateway/web-integration/standard/checkout/

If Razorpay keys are absent, the UI switches to local simulated outcomes (`success`, `failed`, `reversed`). These are stored as **demo simulation** and never claimed to be a bank/provider confirmation. Never use live keys for a demo or school project. Review the official docs before going live: https://razorpay.com/docs/payments/payment-gateway/web-integration/standard/checkout/

## Database

SQLite is stored persistently in `data/utilitycare.sqlite`; session data is stored in `data/sessions.sqlite`. Tables cover users, meters, tenant links, bills, payments, complaints, outages and audit events. Back up the `data` directory. The supplied `.env.example` enables `DEMO_MODE=true` for local evaluation, so the demo buttons and synthetic sample accounts work immediately. Set `DEMO_MODE=false` outside local development. Demo seed happens only when the users table is empty.

Demo accounts are intentionally unavailable unless `DEMO_MODE=true`:
- `staff@demo.local`
- `landlord@demo.local`
- `tenant@demo.local`

These are selected via the demo buttons; they are not real Google identities. Do not enable demo mode in production.

## OpenAI-powered voice + chat assistant

1. Create an API key in the OpenAI API platform: https://platform.openai.com/api-keys. API billing/access is separate from a ChatGPT subscription.
2. Copy `.env.example` to `.env` and set `OPENAI_API_KEY=...` (never paste the key into browser JavaScript, HTML, GitHub, or a public screenshot).
3. Optionally set `OPENAI_MODEL=gpt-4.1-mini` to a model available to your API project.
4. Restart `npm start`. The assistant sends the signed-in role's server-filtered context to the model. Without the key it uses role-specific database-backed fallback responses.
5. Voice input/output uses browser speech recognition and speech synthesis (Chrome/Edge support varies by OS and permissions). Allow microphone access. This build sends the recognized text to the backend; it does not upload raw microphone recordings to OpenAI.
6. Test all roles separately. Staff assistant topics are operations, complaint counts, outage verification and payment reconciliation; landlords get their own meters/tenants/bills; tenants get only their assigned meter, permitted bills, own payments and own complaints.

Security note: the model is not the authorization boundary. Backend route guards and SQL filters must enforce access even if a user asks the model to ignore its instructions. Keep API keys server-side and review logs/privacy before public deployment.

## Role permissions and important behavior

- Staff can see service-wide bills/payment records, manage complaint/outage status in Operations, review illustrative energy slabs, and monitor a schematic outage grid. The separate Complaints & Outages page is hidden from staff navigation. Staff assistant suggestions focus on operations, reports and reconciliation.
- Landlords can manage their own meters and invited tenant assignments; tenant list and bills are filtered to the signed-in landlord.
- Each tenant account is assigned one meter in this version. A landlord can create multiple meter connections and assign each to a tenant. Tenant bill queries enforce `billing_month >= start_month` on the server, not just the UI. The same invited email must be used for Google sign-in.
- Bill totals are computed on the server and payment order amounts are sourced from the stored bill, never from a client-supplied amount.
- Duplicate payment attempts are guarded while a previous attempt is in a processing state.
- Payment status values distinguish initiated, debit confirmed, credit reconciled, failed and reversed; demo outcomes are labelled separately from provider-backed payments.

## Scripts

```powershell
npm test
npm start
```

## Before public production deployment

This is a robust development foundation, not a compliance-certified utility billing platform. Before public launch:

- Deploy behind HTTPS and set `NODE_ENV=production`, a strong `SESSION_SECRET`, and secure cookie settings.
- Use managed PostgreSQL for multi-instance/production workloads or carefully manage SQLite backups and single-instance limits.
- Configure real email invitations, account recovery and tenant verification.
- Configure Razorpay webhooks, capture policy, idempotency, refunds and reconciliation; test with test keys first.
- Add CSRF protection suitable for your session architecture, stricter per-route rate limits, monitoring, backup/restore drills and security review.
- Configure staff provisioning and offboarding, audit retention, privacy notices and consent.
- Add Hindi assistant prompts/voice selection only after testing language-specific speech recognition and spoken replies.
- Do not store card details, CVVs, OTPs or payment credentials.

The website is not intended to expose health-related priority-load records; if such a feature is added, treat it as sensitive data and implement explicit, minimal access controls.

## Self-service bill reproduction and usage anomaly review

Landlord and tenant accounts have a **Bill calculator & anomalies** section. Select an accessible meter and bill period, upload a clear meter photo, and OCR runs in the browser through Tesseract.js (CDN). OCR is only a suggestion: verify both readings manually. The calculator reproduces usage charges by progressive synthetic slab, fixed charge, tax, bill arrears and adjustment, then compares the total with the selected system bill. This build uses the illustrative rates shown in the UI (first 100 kWh at ₹3.20, additional kWh at ₹5.10, ₹100 fixed charge and 5% tax); these are not official utility rates.

The anomaly review ranks possible explanations without assigning blame: estimate/catch-up or unusually high usage relative to available prior bills, slab threshold effects, seasonal and household changes, and lower-confidence leak/meter-fault checks. It is a heuristic, not a meter diagnosis, and works best when several prior bills are available.

## Payment attempts that are cancelled or abandoned

Closing Razorpay checkout without a payment reference marks that attempt **Abandoned** and restores the bill to **Unpaid**, so the customer can retry. A payment with a provider payment reference is never automatically abandoned; it must be checked against Razorpay first. Users can use **Resolve status** in payment history. Staff can use **Resolve stale attempts** for Razorpay attempts with no payment reference older than two minutes, then **Refresh from Razorpay** for attempts that do have provider references. A captured payment is marked paid; a failed/abandoned attempt leaves the bill unpaid. Never retry while a provider-backed attempt remains unresolved.

## Voice output

The voice assistant includes **Stop speech** to cancel the current spoken answer immediately.


## Added hard-mode payment and reminder flows

### Payment reconciliation and duplicate-payment guard
- A bank debit is not treated as a confirmed utility credit. Razorpay capture/webhook/provider refresh remains the evidence for credit reconciliation.
- Use **Resolve status** on the payment history after checkout if the payment is not confirmed. If it remains unresolved after the waiting window, UtilityCare creates a **Payment reconciliation** complaint for the signed-in landlord/tenant and keeps the bill locked as pending.
- Starting a second payment is blocked while that complaint is open. Staff reviews the order ID, provider payment ID, receipt, timestamps and provider refresh result in the reconciliation queue.
- Staff must explicitly mark the complaint **Resolved** or **Closed** before another attempt is allowed. If the provider later confirms capture, the bill is marked paid and the payment complaint is auto-resolved. Never use the demo flow as evidence of a real bank credit.

### Gmail API reminders
The staff **Bills & payments → Unpaid bill reminders** panel filters unpaid bills by age and sends live emails with one click. The upcoming filter uses the current month and the immediately preceding month (age <= 1); the overdue filter uses bills aged 2 or more months. The exact subjects are:
- `Remainder - Upcoming Bill due date is near`
- `Bill Due date exceeded !! Please Clear your Pending dues immediately`

Tenant emails include only that tenant's assigned meter. Each landlord receives a summary for all unpaid bills across their associated meters. Sending requires Gmail API OAuth credentials; no email is sent until configured.

1. In Google Cloud Console, enable **Gmail API** for a project and create OAuth 2.0 credentials.
2. Grant the OAuth account the `https://www.googleapis.com/auth/gmail.send` scope and obtain an offline refresh token for the Gmail mailbox that should send messages. The sender address must belong to that mailbox.
3. Add these to `.env` (never commit the file): `GMAIL_CLIENT_ID`, `GMAIL_CLIENT_SECRET`, `GMAIL_REFRESH_TOKEN`, `GMAIL_SENDER_EMAIL`.
4. Restart with `npm start`. The staff reminder panel reports whether Gmail is configured. Test first with addresses you control.

### Meter-photo OCR and lower readings
OCR now preprocesses the photo (grayscale/contrast, enlarged) and prioritizes plausible digit strings based on the previous reading rather than blindly choosing the largest number. Verify every extracted value. If the current reading is lower than the previous reading, the calculator asks whether this is a genuine meter rollover or an OCR/entry error; rollover math is only applied after confirmation. Confirm the meter's display capacity with the utility—this prompt does not independently prove rollover.
# Utility-Care-AI
