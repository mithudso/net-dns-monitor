# Net DNS Monitor storefront

The Worker serves the product page, the public Free archive, and private paid orders at https://netdnsmonitor.com/. Cloudflare stores archives in a private R2 bucket and order state in D1. Each order pins the purchased archive. Use a new archive filename for every release and keep previously purchased artifacts available.

## Local checks

Run `node --test storefront/worker.test.mjs` from the repository root using Node.js 24 or newer. The tests exercise the application with SQLite and simulated provider responses. They cover the free download, both Managed Payments purchase categories, the hosted form’s origin checks, signed completion events and replay, and access denial before payment or after reversal.

## Release and deployment

1. Build the Free and Premium ZIP archives with `scripts/build_direct_release.py`. Verify both archives on Apple silicon and retain their SHA-256 digests. Upload each to the matching `free/` or `premium/` prefix in `netdnsmonitor-downloads`. Leave both public R2 access methods disabled. Set `FREE_RELEASE` and `PREMIUM_RELEASE` in `wrangler.jsonc` to their exact object keys.
2. Apply the D1 migrations with `npx --yes wrangler@4.164.0 d1 migrations apply netdnsmonitor-orders --remote` from this directory. Deploy with `npx --yes wrangler@4.164.0 deploy` from the same directory. Configure payment secrets through the Cloudflare dashboard or Wrangler secret input. Keep secret values out of Git and command arguments.
3. Download Free from the live storefront and compare its SHA-256 with the release digest. Verify that an unknown order key and direct GET to the Premium route do not serve the archive. Add the Apple listing URL only after the public store lookup finds the shipped app.

## Stripe Managed Payments

Stripe is the merchant of record for Premium storefront purchases and handles tax on those transactions. The two Stripe products deliver the same archive at $29 USD one time. `ndm_premium_personal` uses tax code `txcd_10202001`. `ndm_premium_business` uses `txcd_10202003`. The customer picks the intended use before Checkout. Each product’s one-time `default_price` supplies `STRIPE_PERSONAL_PRICE_ID` or `STRIPE_BUSINESS_PRICE_ID`.

- Activate Managed Payments for the merchant in Stripe. Configure `STRIPE_SECRET_KEY` as a Worker secret from the Stripe Dashboard. The restricted key needs Checkout Sessions read/write and Payment Intents read. The Stripe-hosted form uses no publishable key.
- Configure `STRIPE_WEBHOOK_SECRET` for `https://netdnsmonitor.com/webhooks/stripe`. Subscribe to snapshot events `checkout.session.completed`, `checkout.session.async_payment_succeeded`, `charge.refunded`, and `charge.dispute.created`. Checkout uses API version `2026-02-25.preview` from the integration blueprint. The signed Checkout Session must match the stored order, price and category, payment mode and amount, and identify Stripe's tax liability before the Worker delivers the archive.
- Test both purchase options in an isolated sandbox, with its own D1 and R2 state. Set `BILLING_MODE=test`, set `STORE_URL` to the sandbox storefront, use sandbox price IDs, and configure test credentials for the Worker and Stripe CLI forwarding. Test actual hosted payment with sample addresses and Stripe's test card. Verify the webhook updates the order before the browser completes its return.
- Set `STRIPE_CHECKOUT_ENABLED=true` after verification. Check that a live Checkout Session is for the correct product, amount, and Managed Payments account. Stripe presents Apple Pay and Cash App Pay to eligible buyers. Buyers enter their card data on Stripe’s hosted page.

The signed webhook persists payment state independently of the buyer’s return. The private order page can also check Stripe if the webhook is still in flight. The database retains the Checkout Session ID, Price, Payment Intent, and Stripe Customer ID when one is returned. It stores the customer's private order key as a hash. For buyer support, verify the provider receipt and match the order reference before recovering access.
