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
const privacy = await readFile(new URL("./public/privacy.html", import.meta.url), "utf8");
const ads = await readFile(new URL("./public/ads.txt", import.meta.url), "utf8");
const discovery = new Map(await Promise.all(["robots.txt", "sitemap.xml", "llms.txt", "llms-full.txt"].map(async (file) => [
  `/${file}`, await readFile(new URL(`./public/${file}`, import.meta.url), "utf8"),
])));
const migrations = await Promise.all(["0001_orders.sql", "0002_paypal_tax.sql", "0003_managed_payments.sql"].map(
  (file) => readFile(new URL(`./migrations/${file}`, import.meta.url), "utf8"),
));

function setup(t, simulation) {
  const db = new DatabaseSync(":memory:");
  t.after(() => db.close());
  for (const migration of migrations) db.exec(migration);
  const prepare = (query) => ({
    bind: (...params) => ({
      first: () => db.prepare(query).get(...params),
      run: () => db.prepare(query).run(...params),
      all: () => ({ results: db.prepare(query).all(...params) }),
    }),
  });
  const env = {
    ORDERS: { prepare, batch: (statements) => statements.map((statement) => statement.run()) },
    RELEASES: {
      head: (key) => release.has(key) ? { size: release.get(key).length, httpEtag: '"test"' } : null,
      get: (key) => release.has(key) ? { size: release.get(key).length, httpEtag: '"test"', body: release.get(key) } : null,
    },
    ASSETS: {
      fetch(request) {
        const path = new URL(request.url).pathname;
        if (path === "/ads.txt") {
          return new Response(request.method === "HEAD" ? null : ads, {
            headers: { "Content-Type": "text/plain; charset=utf-8" },
          });
        }
        if (discovery.has(path)) {
          const type = path.endsWith(".xml") ? "application/xml" : "text/plain";
          return new Response(request.method === "HEAD" ? null : discovery.get(path), {
            headers: { "Content-Type": `${type}; charset=utf-8` },
          });
        }
        return new Response(path === "/privacy/" ? privacy : index);
      },
    },
    STORE_URL: origin,
    FREE_RELEASE: free,
    PREMIUM_RELEASE: premium,
    PREMIUM_CENTS: "2900",
    STRIPE_CHECKOUT_ENABLED: "true",
    STRIPE_PERSONAL_PRICE_ID: "price_personal",
    STRIPE_BUSINESS_PRICE_ID: "price_business",
    STRIPE_SECRET_KEY: "rk_test_example",
    STRIPE_WEBHOOK_SECRET: "whsec_example",
    BILLING_MODE: "test",
  };
  const fetcher = async (url, options) => {
    const result = await simulation(url, options);
    return Response.json(result);
  };
  const fetch = handler(fetcher);
  const hit = (path, init) => fetch(new Request(new URL(path, origin), init), env);
  const post = (path, body, headers = {}) => hit(path, {
    method: "POST", body: new URLSearchParams(body), headers: { Origin: origin, ...headers },
  });
  const event = (type, object, seconds = Math.floor(Date.now() / 1000)) => {
    const content = JSON.stringify({ type, data: { object }, livemode: false });
    const mac = createHmac("sha256", env.STRIPE_WEBHOOK_SECRET).update(`${seconds}.${content}`).digest("hex");
    return hit("/webhooks/stripe", { method: "POST", body: content, headers: { "Stripe-Signature": `t=${seconds},v1=${mac}` } });
  };
  return { env, hit, post, event, db, fetcher };
}

test("AdSense verification is public and its script runs only on the homepage", async (t) => {
  const { hit } = setup(t, () => assert.fail("Verification should not call the payment provider"));
  const home = await hit("/");
  assert.equal(home.status, 200);
  const head = (await home.text()).match(/<head>([\s\S]*?)<\/head>/)[1];
  const loader = "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js";
  const publisher = "ca-pub-1706083044457708";
  assert.ok(head.includes(`<meta name="google-adsense-account" content="${publisher}">`));
  assert.ok(head.includes(`<script async src="${loader}?client=${publisher}" crossorigin="anonymous"></script>`));
  assert.ok(home.headers.get("Content-Security-Policy").split("; ").includes(`script-src ${loader}`));

  const record = await hit("/ads.txt");
  assert.equal(record.status, 200);
  assert.match(record.headers.get("Content-Type"), /^text\/plain\b/);
  assert.equal(await record.text(), "google.com, pub-1706083044457708, DIRECT, f08c47fec0942fa0\n");
  const recordHead = await hit("/ads.txt", { method: "HEAD" });
  assert.equal(recordHead.status, 200);
  assert.equal(await recordHead.text(), "");
  const www = await hit("https://www.netdnsmonitor.com/ads.txt");
  assert.equal(www.status, 308);
  assert.equal(www.headers.get("Location"), `${origin}/ads.txt`);

  for (const path of ["/privacy/", "/order", "/checkout"]) {
    const response = await hit(path);
    assert.equal(response.headers.get("Referrer-Policy"), "no-referrer");
    assert.doesNotMatch(response.headers.get("Content-Security-Policy"), /googlesyndication/);
    assert.doesNotMatch(await response.text(), /adsbygoogle\.js/);
  }
});

test("search discovery serves only canonical public pages and preserves private routes", async (t) => {
  const { hit } = setup(t, () => assert.fail("Discovery should not call the payment provider"));
  for (const [path, expected] of discovery) {
    const response = await hit(path);
    assert.equal(response.status, 200);
    assert.match(response.headers.get("Content-Type"), path.endsWith(".xml") ? /^application\/xml\b/ : /^text\/plain\b/);
    assert.equal(await response.text(), expected);
    assert.equal(await (await hit(path, { method: "HEAD" })).text(), "");
    const alternate = await hit(`https://www.netdnsmonitor.com${path}`);
    assert.equal(alternate.status, 308);
    assert.equal(alternate.headers.get("Location"), origin + path);
    assert.doesNotMatch(expected, /https:\/\/netdnsmonitor\.com\/(?:order|checkout|download\/premium|webhooks)/);
  }
  const locations = [...discovery.get("/sitemap.xml").matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1]);
  assert.deepEqual(locations, [origin + "/", origin + "/privacy/"]);
  for (const location of locations) {
    const destination = await hit(location);
    assert.equal(destination.status, 200);
    assert.ok((await destination.text()).includes(`rel="canonical" href="${location}"`));
  }
  const privacyAlias = await hit("https://www.netdnsmonitor.com/privacy?ref=store");
  assert.equal(privacyAlias.headers.get("Location"), origin + "/privacy/?ref=store");
  const privateOrder = await hit("/order");
  assert.equal(privateOrder.status, 404);
  assert.match(await privateOrder.text(), /noindex,nofollow/);
  assert.equal((await hit("/download/premium")).status, 405);
  assert.equal((await hit("/not-a-real-page")).status, 404);
});

test("free delivery works and unavailable checkout is hidden", async (t) => {
  const { env, hit, post } = setup(t, () => assert.fail("Payment call should be disabled"));
  env.STRIPE_SECRET_KEY = undefined;
  const page = await (await hit("/")).text();
  assert.match(page, /href="\/download\/free"/);
  assert.doesNotMatch(page, /Buy with Stripe/);
  const file = await hit("/download/free");
  assert.match(file.headers.get("Content-Disposition"), /Net-DNS-Monitor-Free/);
  assert.equal(await file.text(), "free archive");
  assert.equal((await hit("/download/free", { method: "HEAD" })).headers.get("Content-Length"), "12");
  assert.equal((await hit("/download/premium")).status, 405);
  assert.equal((await post("/download/premium", { key: "0".repeat(64) })).status, 403);
  assert.equal((await post("/checkout", { buyer_use: "personal" }, { Origin: "https://other.example" })).status, 403);
  assert.equal((await post("/checkout", { buyer_use: "personal" }, {
    Origin: "null", "Sec-Fetch-Site": "cross-site",
  })).status, 403);
  assert.equal((await post("/checkout", { buyer_use: "personal" })).status, 503);

  env.BILLING_MODE = "live";
  env.STRIPE_SECRET_KEY = "rk_live_example";
  env.STRIPE_CHECKOUT_ENABLED = "false";
  const unconfigured = await (await hit("/")).text();
  assert.doesNotMatch(unconfigured, /Buy with Stripe|Pay with PayPal/);
});

for (const buyerUse of ["personal", "business"]) {
  test(`Managed Payments binds ${buyerUse} price and downloads only after confirmed payment`, async (t) => {
    let callback;
    let reference;
    let paymentStatus = "unpaid";
    let taxStatus = "requires_location_inputs";
    let managed = true;
    const session = () => ({
      object: "checkout.session", id: "cs_test_order", amount_subtotal: 2900,
      status: paymentStatus === "paid" ? "complete" : "open", mode: "payment",
      payment_status: paymentStatus, client_reference_id: reference, livemode: false,
      currency: "usd", payment_intent: "pi_example", customer: "cus_example",
      metadata: { sku: "net-dns-monitor-premium", price_id: `price_${buyerUse}`, buyer_use: buyerUse },
      managed_payments: { enabled: managed },
      automatic_tax: { enabled: true, liability: { type: "stripe" }, status: taxStatus },
      presentment_details: { presentment_currency: "cad", presentment_amount: 4230 },
    });
    const { hit, post, event, db } = setup(t, (url, opts) => {
      assert.equal(opts.headers["Stripe-Version"], "2026-02-25.preview");
      if (opts.method === "POST") {
        assert.equal(opts.body.get("line_items[0][price]"), `price_${buyerUse}`);
        assert.equal(opts.body.get("line_items[0][quantity]"), "1");
        assert.equal(opts.body.get("managed_payments[enabled]"), "true");
        assert.equal(opts.body.get("automatic_tax[enabled]"), null);
        assert.equal(opts.body.get("adaptive_pricing[enabled]"), null);
        assert.equal(opts.body.get("payment_method_types"), null);
        callback = new URL(opts.body.get("success_url"));
        reference = opts.body.get("client_reference_id");
        assert.equal(opts.headers["Idempotency-Key"], `netdns-checkout-${reference}`);
        return { ...session(), url: "https://checkout.stripe.com/example" };
      }
      assert.match(url, /checkout\/sessions\/cs_test_order$/);
      return session();
    });
    assert.match(await (await hit("/")).text(), /name="buyer_use"/);
    assert.equal((await post("/checkout", { buyer_use: "other" })).status, 400);
    managed = false;
    assert.equal((await post("/checkout", { buyer_use: buyerUse })).status, 502);
    assert.equal(db.prepare("SELECT count(*) AS total FROM orders").get().total, 0);
    managed = true;
    const start = await post("/checkout", { buyer_use: buyerUse }, {
      Origin: "null", "Sec-Fetch-Site": "same-origin",
    });
    assert.equal(start.status, 303);
    const orderPath = callback.pathname + callback.search;
    const key = callback.searchParams.get("key");
    const download = () => post("/download/premium", { key });
    assert.notEqual(key, reference);
    assert.match(await (await hit(orderPath)).text(), /Payment pending/);
    assert.equal((await download()).status, 403);
    assert.equal((await hit("/webhooks/stripe", { method: "POST", body: "{}" })).status, 400);
    assert.equal((await event("checkout.session.completed", session(), 1000000000)).status, 400);
    assert.equal((await event("checkout.session.completed", session())).status, 200);
    assert.equal((await download()).status, 403);

    paymentStatus = "paid";
    const noTax = await event("checkout.session.completed", session());
    assert.equal(noTax.status, 200);
    assert.equal((await download()).status, 403);
    taxStatus = "complete";
    const wrongPrice = { ...session(), metadata: { ...session().metadata, price_id: "price_wrong" } };
    assert.equal((await event("checkout.session.completed", wrongPrice)).status, 200);
    assert.equal((await download()).status, 403);

    const completed = buyerUse === "personal" ? "checkout.session.completed" : "checkout.session.async_payment_succeeded";
    assert.equal((await event(completed, session())).status, 200);
    assert.equal((await event(completed, session())).status, 200);
    assert.match(await (await hit(orderPath)).text(), /Payment confirmed/);
    const file = await download();
    assert.equal(await file.text(), "premium archive");
    assert.equal(file.headers.get("Cache-Control"), "private, no-store, no-transform");
    const record = db.prepare("SELECT * FROM orders").get();
    assert.equal(record.buyer_use, buyerUse);
    assert.equal(record.stripe_price_id, `price_${buyerUse}`);
    assert.equal(record.stripe_customer_id, "cus_example");
    assert.equal(record.payment_id, "pi_example");
    assert.equal((await event("charge.refunded", { payment_intent: "pi_example" })).status, 200);
    assert.equal((await download()).status, 403);
  });
}
