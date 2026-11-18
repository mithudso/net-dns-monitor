import {
  approvedPayPalOrderMatches, billingMode, checkoutRedirect, checkStripeSignature,
  decimalPrice, paidPayPalCapture, paidStripeSession, paypal, paypalAccess,
  paypalAmountMatches, paypalReady, SKU, stripe, stripeReady, taxEnabled,
} from "./payments.mjs";

const NO_STORE = "private, no-store, no-transform";
const SECURITY = {
  "Content-Security-Policy": "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self' https://checkout.stripe.com https://www.paypal.com https://www.sandbox.paypal.com https://venmo.com https://www.venmo.com; base-uri 'none'; frame-ancestors 'none'",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
};
const ORDER_KEY = /^[0-9a-f]{64}$/;
const PACKAGE_KEY = /^(free|premium)\/Net-DNS-Monitor-[A-Za-z0-9.-]+\.zip$/;

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

function form(action, name, value, label, style = "primary") {
  return `<form method="post" action="${action}"><input type="hidden" name="${name}" value="${escape(value)}"><button class="button ${style}" type="submit">${label}</button></form>`;
}

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
  const buttons = [];
  if (premium && cents && stripeReady(env)) {
    buttons.push(form("/checkout", "provider", "stripe", "Buy with Stripe"));
    buttons.push('<p class="small">Cards and eligible wallets appear at checkout.</p>');
  }
  if (premium && cents && paypalReady(env, "paypal")) {
    buttons.push(form("/checkout", "provider", "paypal", "Pay with PayPal", "outline"));
    if (paypalReady(env, "venmo")) {
      buttons.push(form("/checkout", "provider", "venmo", "Pay with Venmo", "outline"));
    }
  }
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
    if (taxEnabled(env)) page = page.replace("USD · one-time", "USD · one-time, plus applicable tax");
  }
  if (buttons.length) page = page.replace('<span class="small">Checkout temporarily unavailable.</span>', buttons.join(""));
  if (/^https:\/\/apps\.apple\.com\/[a-z/]+\/id\d+$/.test(env.APP_STORE_URL ?? "")) {
    page = page.replace('<span class="small">Waiting for Apple review.</span>',
      `<a class="button outline" href="${env.APP_STORE_URL}">View on the Mac App Store</a>`);
  }
  return html(request.method === "HEAD" ? null : page);
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

async function confirmPaid(env, order, paymentId) {
  await env.ORDERS.prepare(
    "UPDATE orders SET payment_id = ?, state = CASE WHEN EXISTS " +
    "(SELECT 1 FROM reversals WHERE payment_id = ?) THEN 'revoked' ELSE 'paid' END " +
    "WHERE access_hash = ? AND state = 'pending'",
  ).bind(paymentId, paymentId, order.access_hash).run();
}

async function reversePayment(env, paymentId) {
  await env.ORDERS.batch([
    env.ORDERS.prepare("INSERT OR IGNORE INTO reversals VALUES (?)").bind(paymentId),
    env.ORDERS.prepare("UPDATE orders SET state = 'revoked' WHERE payment_id = ?").bind(paymentId),
  ]);
}

function taxAddressPage(provider, status = 200) {
  const message = status === 400
    ? "<p>Enter a valid address so we can calculate sales tax.</p>"
    : "<p>Enter your billing address to calculate any sales tax on the download.</p>";
  return orderPage("Billing address", message +
    `<form class="address-form" method="post" action="/checkout">
      <input type="hidden" name="provider" value="${provider}">
      <input type="hidden" name="address_submitted" value="1">
      <label>Street address <input name="line1" autocomplete="address-line1" maxlength="200" required></label>
      <label>City <input name="city" autocomplete="address-level2" maxlength="100" required></label>
      <label>State or province <input name="state" autocomplete="address-level1" placeholder="NC" maxlength="100"></label>
      <label>Postal code <input name="postal_code" autocomplete="postal-code" maxlength="20"></label>
      <label>Country code <input name="country" autocomplete="country" value="US" maxlength="2" pattern="[A-Za-z]{2}" required></label>
      <button class="button primary" type="submit">Continue to ${provider === "paypal" ? "PayPal" : "Venmo"}</button>
    </form>`, status);
}

function billingAddress(fields) {
  const address = Object.fromEntries(["line1", "city", "state", "postal_code", "country"].map(
    (name) => [name, String(fields.get(name) ?? "").trim()],
  ));
  address.country = address.country.toUpperCase();
  if (address.country === "US") address.state = address.state.toUpperCase();
  if (!address.line1 || address.line1.length > 200 || !address.city || address.city.length > 100 ||
      address.state.length > 100 || address.postal_code.length > 20 ||
      !/^[A-Z]{2}$/.test(address.country)) return null;
  if (address.country === "US" &&
      (!/^[A-Z]{2}$/.test(address.state) || !/^\d{5}(-\d{4})?$/.test(address.postal_code))) return null;
  return address;
}

async function paypalTaxQuote(address, cents, env, fetcher) {
  const data = {
    currency: "usd",
    "line_items[0][amount]": cents,
    "line_items[0][reference]": SKU,
    "line_items[0][tax_code]": env.STRIPE_TAX_CODE,
    "line_items[0][tax_behavior]": "exclusive",
    "customer_details[address_source]": "billing",
  };
  for (const [name, value] of Object.entries(address)) {
    if (value) data[`customer_details[address][${name}]`] = value;
  }
  const quote = await stripe("tax/calculations", env, data, fetcher);
  const breaks = quote.tax_breakdown ?? [];
  const nc = quote.customer_details?.address?.state === "NC" || address.state === "NC";
  if (address.country === "US" && nc &&
      (!breaks.length || breaks.some((part) => part.taxability_reason === "not_collecting"))) {
    throw new Error("North Carolina is not ready for tax collection");
  }
  if (!/^taxcalc_[a-zA-Z0-9]+$/.test(quote.id ?? "") || quote.currency !== "usd" ||
      quote.livemode !== (billingMode(env) === "live") ||
      !Number.isSafeInteger(quote.tax_amount_exclusive) || quote.tax_amount_exclusive < 0 ||
      quote.amount_total !== cents + quote.tax_amount_exclusive ||
      !Number.isSafeInteger(quote.expires_at) || quote.expires_at <= Date.now() / 1000) {
    throw new Error("Invalid tax calculation");
  }
  return { cents: quote.tax_amount_exclusive, id: quote.id, expiresAt: quote.expires_at };
}

export async function recordPayPalTaxes(env, fetcher = fetch) {
  if (!env.STRIPE_API_KEY) return;
  const { results } = await env.ORDERS.prepare(
    "SELECT access_hash, provider_id, tax_calculation_id FROM orders " +
    "WHERE state = 'paid' AND tax_calculation_id IS NOT NULL AND tax_transaction_id IS NULL " +
    "AND tax_quote_expires_at > unixepoch() ORDER BY tax_quote_expires_at LIMIT 10",
  ).bind().all();
  let failed = 0;
  for (const order of results) {
    try {
      const reference = `netdns-paypal-${order.provider_id}`;
      const transaction = await stripe("tax/transactions/create_from_calculation", env, {
        calculation: order.tax_calculation_id, reference,
      }, fetcher, reference);
      if (!/^tax_[a-zA-Z0-9]+$/.test(transaction.id ?? "") || transaction.reference !== reference ||
          transaction.livemode !== (billingMode(env) === "live")) throw new Error("Invalid tax transaction");
      await env.ORDERS.prepare(
        "UPDATE orders SET tax_transaction_id = ? WHERE access_hash = ? AND tax_transaction_id IS NULL",
      ).bind(transaction.id, order.access_hash).run();
    } catch {
      failed += 1;
    }
  }
  if (failed) throw new Error(`Could not record ${failed} PayPal tax transactions`);
}

async function checkout(request, env, fetcher) {
  const ip = request.headers.get("CF-Connecting-IP");
  if (ip && !(await env.CHECKOUT_LIMIT.limit({ key: ip })).success) {
    return text("Please wait before starting another checkout", 429);
  }
  const fields = await request.formData();
  const provider = fields.get("provider");
  const cents = centsFor(env);
  const key = await artifact(env, "premium");
  const stripeCheckout = provider === "stripe" && stripeReady(env);
  const paypalCheckout = (provider === "paypal" || provider === "venmo") && paypalReady(env, provider);
  if (!cents || !key || !(stripeCheckout || paypalCheckout)) {
    return orderPage("Checkout unavailable", "<p>Try again later.</p>", 503);
  }
  let tax = { cents: 0, id: null, expiresAt: null };
  if (paypalCheckout && taxEnabled(env)) {
    if (fields.get("address_submitted") !== "1") return taxAddressPage(provider);
    const address = billingAddress(fields);
    if (!address) return taxAddressPage(provider, 400);
    tax = await paypalTaxQuote(address, cents, env, fetcher);
  }
  const token = hex(crypto.getRandomValues(new Uint8Array(32)));
  const hash = await accessHash(token);
  const returnURL = `${env.STORE_URL}/order?key=${token}`;
  const cancelURL = `${env.STORE_URL}/#premium`;
  let checkoutId;
  let destination;
  if (stripeCheckout) {
    const params = {
      mode: "payment",
      "line_items[0][price]": env.STRIPE_PRICE_ID,
      "line_items[0][quantity]": "1",
      "metadata[sku]": SKU,
      "payment_intent_data[metadata][sku]": SKU,
      "adaptive_pricing[enabled]": "false",
      client_reference_id: hash,
      success_url: returnURL,
      cancel_url: cancelURL,
      integration_identifier: "netdns-monitor-ntmcpqkr",
    };
    if (taxEnabled(env)) {
      params["automatic_tax[enabled]"] = "true";
      params["metadata[tax_required]"] = "true";
      params.billing_address_collection = "required";
    }
    const session = await stripe("checkout/sessions", env, params, fetcher);
    if (session.amount_subtotal !== cents || session.currency !== "usd" ||
        session.livemode !== (billingMode(env) === "live")) throw new Error("Unexpected Checkout price");
    checkoutId = session.id;
    destination = session.url;
  } else {
    const access = await paypalAccess(env, fetcher);
    const order = await paypal("v2/checkout/orders", env, access, fetcher, {
      intent: "CAPTURE",
      purchase_units: [{
        description: "Net DNS Monitor Premium",
        custom_id: hash,
        amount: {
          currency_code: "USD",
          value: decimalPrice(cents + tax.cents),
          breakdown: {
            item_total: { currency_code: "USD", value: decimalPrice(cents) },
            tax_total: { currency_code: "USD", value: decimalPrice(tax.cents) },
          },
        },
        items: [{
          name: "Net DNS Monitor Premium",
          quantity: "1",
          unit_amount: { currency_code: "USD", value: decimalPrice(cents) },
          tax: { currency_code: "USD", value: decimalPrice(tax.cents) },
          category: "DIGITAL_GOODS",
        }],
      }],
      payment_source: {
        [provider]: {
          experience_context: {
            brand_name: "Net DNS Monitor",
            shipping_preference: "NO_SHIPPING",
            user_action: "CONTINUE",
            return_url: returnURL,
            cancel_url: cancelURL,
          },
        },
      },
    }, token.slice(0, 32));
    checkoutId = order.id;
    destination = order.links?.find(({ rel }) => rel === "payer-action" || rel === "approve")?.href;
  }
  const url = checkoutRedirect(destination, provider);
  await env.ORDERS.prepare(
    "INSERT INTO orders (access_hash, provider, provider_id, cents, release_key, tax_cents, " +
    "tax_calculation_id, tax_quote_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
  ).bind(hash, provider, checkoutId, cents, key, tax.cents, tax.id, tax.expiresAt).run();
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
      await confirmPaid(env, order, object.payment_intent);
    }
  }
  if (["charge.refunded", "charge.dispute.created"].includes(event.type) &&
      /^pi_[a-zA-Z0-9]+$/.test(object?.payment_intent ?? "")) {
    const recorded = await env.ORDERS.prepare("SELECT provider FROM orders WHERE payment_id = ?")
      .bind(object.payment_intent).first();
    if (recorded?.provider === "stripe" || object.metadata?.sku === SKU) {
      await reversePayment(env, object.payment_intent);
    } else if (event.type === "charge.dispute.created" && stripeReady(env)) {
      const payment = await stripe(`payment_intents/${object.payment_intent}`, env, null, fetcher);
      if (payment.metadata?.sku === SKU) await reversePayment(env, object.payment_intent);
    }
  }
  return text("OK", 200);
}

function showOrder(key, order, approved = false) {
  if (order.state === "paid") {
    return orderPage("Your Premium download", "<p>Payment confirmed. Save this private page’s address to download again.</p>" +
      form("/download/premium", "key", key, "Download Premium"));
  }
  if (order.state === "revoked") return orderPage("Download unavailable", "<p>This payment was reversed.</p>", 403);
  if (approved) {
    const taxLine = order.tax_calculation_id
      ? `<p>Subtotal $${decimalPrice(order.cents)} · Sales tax $${decimalPrice(order.tax_cents)}</p>`
      : "";
    return orderPage("Confirm your purchase", taxLine +
      `<p>Net DNS Monitor Premium · $${decimalPrice(order.cents + order.tax_cents)} USD total</p>` +
      form("/order/capture", "key", key, "Confirm payment"));
  }
  return orderPage("Payment pending", `<p>Once the payment provider confirms your payment, your download will appear here.</p><p><a href="/order?key=${key}">Check again</a></p>`);
}

async function readOrder(env, fetcher, key, capture = false) {
  if (!ORDER_KEY.test(key ?? "")) return orderPage("Order not found", "", 404);
  let order = await findOrder(env, await accessHash(key));
  if (!order) return orderPage("Order not found", "", 404);
  if (order.state !== "pending") return showOrder(key, order);
  if (order.provider === "stripe") {
    if (!capture && stripeReady(env)) {
      const session = await stripe(`checkout/sessions/${order.provider_id}`, env, null, fetcher);
      if (paidStripeSession(session, order, billingMode(env) === "live")) {
        await confirmPaid(env, order, session.payment_intent);
        order = await findOrder(env, order.access_hash);
      }
    }
    return showOrder(key, order);
  }

  const access = await paypalAccess(env, fetcher);
  const path = `v2/checkout/orders/${order.provider_id}`;
  let remote = await paypal(path, env, access, fetcher);
  if (remote.status === "APPROVED") {
    if (!approvedPayPalOrderMatches(remote, order)) {
      return orderPage("Order amount changed", "<p>Start a new checkout to verify the total.</p>", 409);
    }
    if (order.tax_quote_expires_at !== null && order.tax_quote_expires_at <= Date.now() / 1000) {
      return orderPage("Sales tax quote expired", "<p>Start a new checkout to get an updated total.</p>", 409);
    }
  }
  if (capture && remote.status === "APPROVED") {
    try {
      remote = await paypal(`${path}/capture`, env, access, fetcher, {}, order.access_hash.slice(0, 38));
    } catch {
      remote = await paypal(path, env, access, fetcher);
      if (remote.status === "APPROVED") {
        return orderPage("Payment could not be confirmed", "<p>Return to the order page and try again.</p>", 502);
      }
    }
  }

  const paymentId = paidPayPalCapture(remote, order);
  if (paymentId) {
    await confirmPaid(env, order, paymentId);
    order = await findOrder(env, order.access_hash);
  }
  return showOrder(key, order, remote.status === "APPROVED");
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

async function premiumDownload(request, env, fetcher) {
  const key = (await request.formData()).get("key");
  if (!ORDER_KEY.test(key ?? "")) return text("Payment required", 403);
  const order = await findOrder(env, await accessHash(key));
  if (!order || order.state !== "paid") return text("Payment required", 403);
  if (order.provider !== "stripe") {
    const access = await paypalAccess(env, fetcher);
    const capture = await paypal(`v2/payments/captures/${order.payment_id}`, env, access, fetcher);
    if (capture.status !== "COMPLETED" || !paypalAmountMatches(capture.amount, order)) {
      return text("Payment required", 403);
    }
  }
  return download(request, env, releaseKey(order.release_key, "premium"), true);
}

export function handler(fetcher = fetch) {
  return async (request, env) => {
    const url = new URL(request.url);
    const origin = new URL(env.STORE_URL).origin;
    const { method } = request;
    const read = method === "GET" || method === "HEAD";
    if (url.origin !== origin) {
      if (read && url.hostname === `www.${new URL(origin).hostname}` &&
          ["/", "/privacy", "/privacy/"].includes(url.pathname)) {
        return Response.redirect(`${origin}${url.pathname}`, 308);
      }
      return text("Not found", 404);
    }
    try {
      if (method === "POST" && url.pathname === "/webhooks/stripe") return await stripeWebhook(request, env, fetcher);
      if (method === "POST" && request.headers.get("Origin") !== origin) return text("Forbidden", 403);
      switch (url.pathname) {
        case "/":
          if (read) return await home(request, env);
          break;
        case "/privacy":
          if (read) return Response.redirect(`${origin}/privacy/`, 308);
          break;
        case "/privacy/":
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
        case "/order/capture":
          if (method === "POST") return await readOrder(env, fetcher, (await request.formData()).get("key"), true);
          break;
        case "/download/premium":
          if (method === "POST") return await premiumDownload(request, env, fetcher);
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

export default {
  fetch: handler(),
  scheduled(_controller, env, ctx) {
    ctx.waitUntil(recordPayPalTaxes(env));
  },
};
