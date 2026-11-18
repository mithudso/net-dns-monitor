import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { readFile } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { handler } from "./worker.mjs";

const origin = "https://netdnsmonitor.com";
const free = "free/Net-DNS-Monitor-Free-1.0.zip";
const premium = "premium/Net-DNS-Monitor-Premium-1.0.zip";
const release = new Map([[free, "free archive"], [premium, "premium archive"]]);
const index = await readFile(new URL("./public/index.html", import.meta.url), "utf8");
const migration = await readFile(new URL("./migrations/0001_orders.sql", import.meta.url), "utf8");

function setup(t, simulation) {
  const db = new DatabaseSync(":memory:");
  t.after(() => db.close());
  db.exec(migration);
  const prepare = (query) => ({
    bind: (...params) => ({
      first: () => db.prepare(query).get(...params),
      run: () => db.prepare(query).run(...params),
    }),
  });
  const env = {
    ORDERS: { prepare, batch: (statements) => statements.map((statement) => statement.run()) },
    RELEASES: {
      head: (key) => release.has(key) ? { size: release.get(key).length, httpEtag: '"test"' } : null,
      get: (key) => release.has(key) ? { size: release.get(key).length, httpEtag: '"test"', body: release.get(key) } : null,
    },
    ASSETS: { fetch: () => new Response(index) },
    STORE_URL: origin,
    FREE_RELEASE: free,
    PREMIUM_RELEASE: premium,
    PREMIUM_CENTS: "2900",
    STRIPE_PRICE_ID: "price_example",
    STRIPE_API_KEY: "rk_test_example",
    STRIPE_WEBHOOK_SECRET: "whsec_example",
    BILLING_MODE: "test",
  };
  const fetch = handler(async (url, options) => {
    const result = await simulation(url, options);
    return Response.json(result);
  });
  const hit = (path, init) => fetch(new Request(new URL(path, origin), init), env);
  const post = (path, body, headers = {}) => hit(path, {
    method: "POST", body: new URLSearchParams(body), headers: { Origin: origin, ...headers },
  });
  const event = (type, object, seconds = Math.floor(Date.now() / 1000)) => {
    const content = JSON.stringify({ type, data: { object }, livemode: false });
    const mac = createHmac("sha256", env.STRIPE_WEBHOOK_SECRET).update(`${seconds}.${content}`).digest("hex");
    return hit("/webhooks/stripe", { method: "POST", body: content, headers: { "Stripe-Signature": `t=${seconds},v1=${mac}` } });
  };
  return { env, hit, post, event };
}

test("free delivery works and unavailable checkout is hidden", async (t) => {
  const { env, hit, post } = setup(t, () => assert.fail("Payment call should be disabled"));
  env.STRIPE_API_KEY = undefined;
  const page = await (await hit("/")).text();
  assert.match(page, /href="\/download\/free"/);
  assert.doesNotMatch(page, /Buy with Stripe/);
  const file = await hit("/download/free");
  assert.match(file.headers.get("Content-Disposition"), /Net-DNS-Monitor-Free/);
  assert.equal(await file.text(), "free archive");
  assert.equal((await hit("/download/free", { method: "HEAD" })).headers.get("Content-Length"), "12");
  assert.equal((await hit("/download/premium")).status, 405);
  assert.equal((await post("/download/premium", { key: "0".repeat(64) })).status, 403);
  assert.equal((await post("/checkout", { provider: "stripe" }, { Origin: "https://other.example" })).status, 403);
  assert.equal((await post("/checkout", { provider: "stripe" })).status, 503);
});

test("Stripe only delivers a paid, correlated order and rejects a reversed payment", async (t) => {
  let callback;
  let reference;
  let paymentStatus = "unpaid";
  const session = () => ({
    object: "checkout.session", id: "cs_test_order", amount_subtotal: 2900, status: "complete",
    payment_status: paymentStatus, client_reference_id: reference, livemode: false,
    mode: "payment", currency: "usd", metadata: { sku: "net-dns-monitor-premium" },
    payment_intent: "pi_example",
  });
  const { hit, post, event } = setup(t, (url, opts) => {
    if (opts.method === "POST") {
      assert.equal(opts.body.get("line_items[0][price]"), "price_example");
      assert.equal(opts.body.get("payment_method_types"), null);
      callback = new URL(opts.body.get("success_url"));
      reference = opts.body.get("client_reference_id");
      return { ...session(), url: "https://checkout.stripe.com/example" };
    }
    assert.match(url, /checkout\/sessions\/cs_test_order$/);
    return session();
  });

  const start = await post("/checkout", { provider: "stripe" });
  assert.equal(start.status, 303);
  const orderPath = callback.pathname + callback.search;
  const key = callback.searchParams.get("key");
  const download = () => post("/download/premium", { key });
  assert.notEqual(key, reference);
  assert.match(await (await hit(orderPath)).text(), /Payment pending/);
  assert.equal((await download()).status, 403);

  assert.equal((await hit("/webhooks/stripe", { method: "POST", body: "{}" })).status, 400);
  assert.equal((await event("checkout.session.completed", session(), 1000000000)).status, 400);

  paymentStatus = "paid";
  const incorrect = { ...session(), amount_subtotal: 1 };
  assert.equal((await event("checkout.session.completed", incorrect)).status, 200);
  assert.equal((await download()).status, 403);

  assert.equal((await event("checkout.session.completed", session())).status, 200);
  assert.equal((await event("checkout.session.completed", session())).status, 200);
  assert.match(await (await hit(orderPath)).text(), /Payment confirmed/);
  const file = await download();
  assert.equal(await file.text(), "premium archive");
  assert.equal(file.headers.get("Cache-Control"), "private, no-store, no-transform");
  assert.equal((await event("charge.refunded", { payment_intent: "pi_example" })).status, 200);
  assert.equal((await download()).status, 403);
});

test("PayPal creates, approves, captures and confirms a download by server data", async (t) => {
  let callback;
  let hash;
  let paid = false;
  let revoked = false;
  const orderId = "ORDEREXAMPLE";
  const captureId = "CAPTUREEXAMPLE";
  const order = () => ({
    id: orderId,
    status: paid ? "COMPLETED" : "APPROVED",
    purchase_units: [{
      custom_id: hash,
      payments: { captures: [{ id: captureId, status: "COMPLETED", amount: { currency_code: "USD", value: "29.00" } }] },
    }],
  });
  const { env, hit, post } = setup(t, (url, opts) => {
    assert.match(url, /^https:\/\/api-m.sandbox.paypal.com/);
    if (url.endsWith("/oauth2/token")) return { access_token: "example" };
    if (url.endsWith("/checkout/orders")) {
      const payload = JSON.parse(opts.body);
      callback = new URL(payload.payment_source.paypal.experience_context.return_url);
      hash = payload.purchase_units[0].custom_id;
      return { id: orderId, links: [{ rel: "payer-action", href: "https://www.sandbox.paypal.com/checkoutnow" }] };
    }
    if (url.endsWith(`/orders/${orderId}/capture`)) {
      paid = true;
      return order();
    }
    if (url.endsWith(`/captures/${captureId}`)) return { status: revoked ? "REFUNDED" : "COMPLETED" };
    assert.ok(url.endsWith(`/orders/${orderId}`));
    return order();
  });
  env.ENABLE_PAYPAL = "true";
  env.PAYPAL_CLIENT_ID = "example";
  env.PAYPAL_CLIENT_SECRET = "example";
  const page = await (await hit("/")).text();
  assert.match(page, /Pay with PayPal/);
  assert.doesNotMatch(page, /Pay with Venmo/);

  assert.equal((await post("/checkout", { provider: "paypal" })).status, 303);
  const key = callback.searchParams.get("key");
  assert.match(await (await hit(callback.pathname + callback.search)).text(), /Confirm payment/);
  assert.equal((await post("/download/premium", { key })).status, 403);
  assert.match(await (await post("/order/capture", { key })).text(), /Payment confirmed/);
  assert.equal(await (await post("/download/premium", { key })).text(), "premium archive");
  revoked = true;
  assert.equal((await post("/download/premium", { key })).status, 403);
});
