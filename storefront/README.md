# Net DNS Monitor storefront

The Worker serves the product page, the public Free archive, and private paid orders at https://netdnsmonitor.com/. Cloudflare stores archives in a private R2 bucket and order state in D1. Each order pins the purchased archive. Use a new archive filename for every release and keep previously purchased artifacts available.

## Local checks

Run `node --test storefront/worker.test.mjs` from the repository root using Node.js 24 or newer. The tests exercise the application with SQLite and simulated provider responses. They cover the free download, access denial before payment, webhook validation and replay, reversals, and PayPal capture.

## Release and deployment

1. Build the Free and Premium ZIP archives with `scripts/build_direct_release.py`. Verify both archives on Apple silicon and retain their SHA-256 digests. Upload each to the matching `free/` or `premium/` prefix in `netdnsmonitor-downloads`. Leave both public R2 access methods disabled. Set `FREE_RELEASE` and `PREMIUM_RELEASE` in `wrangler.jsonc` to their exact object keys.
2. Apply the D1 migration with `npx --yes wrangler@4.164.0 d1 migrations apply netdnsmonitor-orders --remote` from this directory. Deploy with `npx --yes wrangler@4.164.0 deploy` from the same directory. Configure payment secrets through the Cloudflare dashboard or Wrangler secret input. Keep secret values out of Git and command arguments.
3. Download Free from the live storefront and compare its SHA-256 with the release digest. Verify that an unknown order key and direct GET to the Premium route do not serve the archive. Add the Apple listing URL only after the public store lookup finds the shipped app.

## Payment configuration

- **Stripe** requires the `STRIPE_PRICE_ID` of an active one-time USD price equal to `PREMIUM_CENTS`. Add a `STRIPE_API_KEY` restricted to the necessary Checkout Sessions and Payment Intents operations and set `STRIPE_WEBHOOK_SECRET` for `https://netdnsmonitor.com/webhooks/stripe`. Subscribe to `checkout.session.completed`, `checkout.session.async_payment_succeeded`, `charge.refunded`, and `charge.dispute.created`. Enable Apple Pay and Cash App Pay in Stripe where the merchant account and customer are eligible. Hosted Checkout displays the available methods. Set `STRIPE_AUTOMATIC_TAX` only after the seller confirms tax configuration and registrations.
- **PayPal and Venmo** require a separate PayPal Business REST app. Set `PAYPAL_CLIENT_ID` and `PAYPAL_CLIENT_SECRET` as Worker secrets. Verify the PayPal payment flow before setting `ENABLE_PAYPAL`; set `ENABLE_VENMO` only when the account is enabled for Venmo and the merchant has confirmed PayPal tax handling. The PayPal buttons are disabled when Stripe automatic tax is enabled because the PayPal path does not calculate tax.
- **Sandbox checks** belong on an isolated deployment with its own D1 database and test credentials. Set `BILLING_MODE` to `test`, use the sandbox price and webhook, and use the sandbox domain as `STORE_URL`. Check a successful buyer return, an abandoned order, and a replayed webhook. Enable the live methods only after verifying the corresponding account and payment configuration.

A buyer returns to a private order URL. Stripe webhooks persist payment state independently of that return. The browser can also check Stripe directly if the webhook is still in flight. The PayPal return asks the buyer to confirm capture. Download requires a paid order and the private order key. The key is stored as a hash. For buyer support, verify the provider receipt and match the order reference before helping a buyer recover access.
