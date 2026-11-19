import {
  billingMode, checkoutRedirect, checkStripeSignature, decimalPrice, hasStripeKey,
  managedCheckout, managedPriceId, paidStripeSession, SKU, stripe, stripeReady,
} from "./payments.mjs";

const NO_STORE = "private, no-store, no-transform";
const SECURITY = {
  "Content-Security-Policy": "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self' https://checkout.stripe.com; base-uri 'none'; frame-ancestors 'none'",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
};
const HOME_CSP = SECURITY["Content-Security-Policy"] +
  "; script-src https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js";
const ORDER_KEY = /^[0-9a-f]{64}$/;
const PACKAGE_KEY = /^(free|premium)\/Net-DNS-Monitor-[A-Za-z0-9.-]+\.zip$/;
const PUBLIC_DISCOVERY = new Set(["/robots.txt", "/sitemap.xml", "/llms.txt", "/llms-full.txt"]);
const WWW_ALIASES = new Set(["/", "/ads.txt", "/privacy", "/privacy/", ...PUBLIC_DISCOVERY]);

function escape(text) {
  return String(text).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);
}

function html(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: { ...SECURITY, "Cache-Control": NO_STORE, "Content-Type": "text/html; charset=utf-8", ...headers },
  });
}

function orderPage(title, body, status = 200) {
  return html(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>${title} — Net DNS Monitor</title><link rel="icon" href="/favicon.png" type="image/png"><link rel="stylesheet" href="/site.css"><main class="wrap order-page"><a class="brand" href="/">Net DNS Monitor</a><h1>${title}</h1>${body}<p><a href="/#editions">Back to editions</a></p></main></html>`, status);
}

function text(message, status) {
  return new Response(message, {
    status,
    headers: { ...SECURITY, "Cache-Control": NO_STORE, "Content-Type": "text/plain; charset=utf-8" },
  });
}

const purchaseForm = `<form class="purchase-options" method="post" action="/checkout">
  <label for="buyer-use">How will you use Premium?</label>
  <select id="buyer-use" name="buyer_use" required>
    <option value="" disabled selected>Select use</option>
    <option value="personal">Personal</option>
    <option value="business">Business</option>
  </select>
  <button class="button primary" type="submit">Buy with Stripe</button>
  <p class="small">Cards and eligible wallets appear at checkout.</p>
</form>`;

function centsFor(env) {
  const cents = Number(env.PREMIUM_CENTS);
  return Number.isSafeInteger(cents) && cents >= 50 ? cents : null;
}

function releaseKey(value, edition) {
  return PACKAGE_KEY.test(value ?? "") && value.startsWith(`${edition}/`) ? value : null;
}

async function artifact(env, edition) {
  const key = releaseKey(env[`${edition.toUpperCase()}_RELEASE`], edition);
  return key && await env.RELEASES.head(key) ? key : null;
}

async function home(request, env) {
  const [free, premium, asset] = await Promise.all([
    artifact(env, "free"), artifact(env, "premium"),
    env.ASSETS.fetch(new Request(`${new URL(request.url).origin}/`)),
  ]);
  if (!asset.ok) return text("Storefront unavailable", 503);
  const cents = centsFor(env);
  let page = await asset.text();
  if (free) {
    page = page.replace('data-free href="#editions"', 'data-free href="/download/free"')
      .replace('<span class="small">Download temporarily unavailable.</span>',
        '<a class="button outline" href="/download/free">Download Free <span aria-hidden="true">↓</span></a>');
  } else {
    page = page.replace('data-free href="#editions">Download Free', 'data-free href="#editions">See Free');
  }
  if (cents) {
    page = page.replace("$29 <small>", `$${Number(decimalPrice(cents))} <small>`);
    page = page.replace("USD · one-time", "USD · one-time, plus applicable tax");
  }
  if (premium && cents && stripeReady(env)) {
    page = page.replace('<span class="small">Checkout temporarily unavailable.</span>', purchaseForm);
  }
  if (/^https:\/\/apps\.apple\.com\/[a-z/]+\/id\d+$/.test(env.APP_STORE_URL ?? "")) {
    page = page.replace('<span class="small">Waiting for Apple review.</span>',
      `<a class="button outline" href="${env.APP_STORE_URL}">View on the Mac App Store</a>`);
  }
  return html(request.method === "HEAD" ? null : page, 200, { "Content-Security-Policy": HOME_CSP });
}

function hex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function accessHash(key) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key));
  return hex(new Uint8Array(digest));
}

function findOrder(env, hash) {
  return env.ORDERS.prepare("SELECT * FROM orders WHERE access_hash = ?").bind(hash).first();
}

async function confirmPaid(env, order, session) {
  const customerId = /^cus_[A-Za-z0-9]+$/.test(session.customer ?? "") ? session.customer : null;
  await env.ORDERS.prepare(
    "UPDATE orders SET payment_id = ?, stripe_customer_id = ?, state = CASE WHEN EXISTS " +
    "(SELECT 1 FROM reversals WHERE payment_id = ?) THEN 'revoked' ELSE 'paid' END " +
    "WHERE access_hash = ? AND state = 'pending'",
  ).bind(session.payment_intent, customerId, session.payment_intent, order.access_hash).run();
}

async function reversePayment(env, paymentId) {
  await env.ORDERS.batch([
    env.ORDERS.prepare("INSERT OR IGNORE INTO reversals VALUES (?)").bind(paymentId),
    env.ORDERS.prepare("UPDATE orders SET state = 'revoked' WHERE payment_id = ?").bind(paymentId),
  ]);
}

async function checkout(request, env, fetcher) {
  const ip = request.headers.get("CF-Connecting-IP");
  if (ip && !(await env.CHECKOUT_LIMIT.limit({ key: ip })).success) {
    return text("Please wait before starting another checkout", 429);
  }
  const buyerUse = (await request.formData()).get("buyer_use");
  const priceId = managedPriceId(env, buyerUse);
  if (buyerUse !== "personal" && buyerUse !== "business") {
    return orderPage("Select personal or business use", "<p>Choose how you’ll use Premium before checking out.</p>", 400);
  }
  const cents = centsFor(env);
  const key = await artifact(env, "premium");
  if (!cents || !key || !priceId || !stripeReady(env)) {
    return orderPage("Checkout unavailable", "<p>Try again later.</p>", 503);
  }

  const token = hex(crypto.getRandomValues(new Uint8Array(32)));
  const hash = await accessHash(token);
  const live = billingMode(env) === "live";
  const session = await stripe("checkout/sessions", env, {
    mode: "payment",
    "line_items[0][price]": priceId,
    "line_items[0][quantity]": "1",
    "managed_payments[enabled]": "true",
    "metadata[sku]": SKU,
    "metadata[price_id]": priceId,
    "metadata[buyer_use]": buyerUse,
    "payment_intent_data[metadata][sku]": SKU,
    client_reference_id: hash,
    success_url: `${env.STORE_URL}/order?key=${token}`,
    cancel_url: `${env.STORE_URL}/#premium`,
  }, fetcher, `netdns-checkout-${hash}`);

  if (session.object !== "checkout.session" || session.amount_subtotal !== cents ||
      session.currency !== "usd" || session.livemode !== live ||
      !managedCheckout(session) || session.client_reference_id !== hash) {
    throw new Error("Unexpected Managed Payments checkout configuration");
  }
  const url = checkoutRedirect(session.url);
  await env.ORDERS.prepare(
    "INSERT INTO orders (access_hash, provider, provider_id, cents, release_key, stripe_price_id, buyer_use) " +
    "VALUES (?, 'stripe', ?, ?, ?, ?, ?)",
  ).bind(hash, session.id, cents, key, priceId, buyerUse).run();
  return new Response(null, { status: 303, headers: { ...SECURITY, Location: url, "Cache-Control": NO_STORE } });
}

async function stripeWebhook(request, env, fetcher) {
  const body = await request.text();
  if (body.length > 256_000 ||
      !await checkStripeSignature(body, request.headers.get("Stripe-Signature"), env.STRIPE_WEBHOOK_SECRET)) {
    return text("Invalid signature", 400);
  }
  const event = JSON.parse(body);
  if (event.livemode !== (billingMode(env) === "live")) return text("Wrong mode", 400);
  const object = event.data?.object;
  if (["checkout.session.completed", "checkout.session.async_payment_succeeded"].includes(event.type) &&
      object?.metadata?.sku === SKU && ORDER_KEY.test(object.client_reference_id ?? "")) {
    const order = await findOrder(env, object.client_reference_id);
    if (!order) return text("Order pending", 409);
    if (order.provider === "stripe" && paidStripeSession(object, order, event.livemode)) {
      await confirmPaid(env, order, object);
    }
  }
  if (["charge.refunded", "charge.dispute.created"].includes(event.type) &&
      /^pi_[a-zA-Z0-9]+$/.test(object?.payment_intent ?? "")) {
    const recorded = await env.ORDERS.prepare("SELECT provider FROM orders WHERE payment_id = ?")
      .bind(object.payment_intent).first();
    if (recorded?.provider === "stripe" || object.metadata?.sku === SKU) {
      await reversePayment(env, object.payment_intent);
    } else if (event.type === "charge.dispute.created" && hasStripeKey(env)) {
      const payment = await stripe(`payment_intents/${object.payment_intent}`, env, null, fetcher);
      if (payment.metadata?.sku === SKU) await reversePayment(env, object.payment_intent);
    }
  }
  return text("OK", 200);
}

function showOrder(key, order) {
  if (order.state === "paid") {
    return orderPage("Your Premium download", "<p>Payment confirmed. Save this private page’s address to download again.</p>" +
      `<form method="post" action="/download/premium"><input type="hidden" name="key" value="${escape(key)}"><button class="button primary" type="submit">Download Premium</button></form>`);
  }
  if (order.state === "revoked") return orderPage("Download unavailable", "<p>This payment was reversed.</p>", 403);
  return orderPage("Payment pending", `<p>Once Stripe confirms your payment, your download will appear here.</p><p><a href="/order?key=${key}">Check again</a></p>`);
}

async function readOrder(env, fetcher, key) {
  if (!ORDER_KEY.test(key ?? "")) return orderPage("Order not found", "", 404);
  let order = await findOrder(env, await accessHash(key));
  if (order?.provider !== "stripe") return orderPage("Order not found", "", 404);
  if (order.state === "pending" && hasStripeKey(env)) {
    const session = await stripe(`checkout/sessions/${order.provider_id}`, env, null, fetcher);
    if (paidStripeSession(session, order, billingMode(env) === "live")) {
      await confirmPaid(env, order, session);
      order = await findOrder(env, order.access_hash);
    }
  }
  return showOrder(key, order);
}

async function download(request, env, key, premium) {
  if (!key) return text("Download unavailable", 404);
  const object = request.method === "HEAD" ? await env.RELEASES.head(key) : await env.RELEASES.get(key);
  if (!object) return text("Download unavailable", 404);
  const headers = {
    ...SECURITY,
    "Content-Type": "application/zip",
    "Content-Disposition": `attachment; filename="${key.split("/").at(-1)}"`,
    "Content-Length": String(object.size),
    "Cache-Control": premium ? NO_STORE : "public, max-age=300",
    ETag: object.httpEtag,
  };
  return new Response(object.body ?? null, { headers });
}

async function premiumDownload(request, env) {
  const key = (await request.formData()).get("key");
  if (!ORDER_KEY.test(key ?? "")) return text("Payment required", 403);
  const order = await findOrder(env, await accessHash(key));
  if (order?.provider !== "stripe" || order.state !== "paid") return text("Payment required", 403);
  return download(request, env, releaseKey(order.release_key, "premium"), true);
}

export function handler(fetcher = fetch) {
  return async (request, env) => {
    const url = new URL(request.url);
    const origin = new URL(env.STORE_URL).origin;
    const { method } = request;
    const read = method === "GET" || method === "HEAD";
    if (url.origin !== origin) {
      if (read && url.hostname === `www.${new URL(origin).hostname}` && WWW_ALIASES.has(url.pathname)) {
        const path = url.pathname === "/privacy" ? "/privacy/" : url.pathname;
        return Response.redirect(`${origin}${path}${url.search}`, 308);
      }
      return text("Not found", 404);
    }
    try {
      if (method === "POST" && url.pathname === "/webhooks/stripe") return await stripeWebhook(request, env, fetcher);
      if (method === "POST") {
        const postedOrigin = request.headers.get("Origin");
        // Browsers use an opaque Origin for form navigation under no-referrer.
        const sameOriginNavigation = postedOrigin === "null" && request.headers.get("Sec-Fetch-Site") === "same-origin";
        if (postedOrigin !== origin && !sameOriginNavigation) return text("Forbidden", 403);
      }
      switch (url.pathname) {
        case "/":
          if (read) return await home(request, env);
          break;
        case "/privacy":
          if (read) return Response.redirect(`${origin}/privacy/${url.search}`, 308);
          break;
        case "/privacy/":
        case "/ads.txt":
        case "/robots.txt":
        case "/sitemap.xml":
        case "/llms.txt":
        case "/llms-full.txt":
        case "/site.css":
        case "/favicon.png":
          if (read) {
            const asset = await env.ASSETS.fetch(request);
            const headers = new Headers(asset.headers);
            for (const [name, value] of Object.entries(SECURITY)) headers.set(name, value);
            headers.set("Cache-Control", "public, max-age=0, must-revalidate, no-transform");
            return new Response(asset.body, { status: asset.status, headers });
          }
          break;
        case "/download/free":
          if (read) return await download(request, env, releaseKey(env.FREE_RELEASE, "free"), false);
          break;
        case "/checkout":
          if (method === "POST") return await checkout(request, env, fetcher);
          break;
        case "/order":
          if (method === "GET") return await readOrder(env, fetcher, url.searchParams.get("key"));
          break;
        case "/download/premium":
          if (method === "POST") return await premiumDownload(request, env);
          break;
        default:
          return text("Not found", 404);
      }
      return text("Method not allowed", 405);
    } catch {
      return orderPage("Something went wrong", "<p>Try again in a moment. If you already paid, keep your order link and retry from that page.</p>", 502);
    }
  };
}

export default { fetch: handler() };
