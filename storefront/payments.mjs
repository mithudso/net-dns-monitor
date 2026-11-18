export const SKU = "net-dns-monitor-premium";

export function billingMode(env) {
  return env.BILLING_MODE === "test" ? "test" : "live";
}

export function stripeReady(env) {
  const mode = billingMode(env);
  return new RegExp(`^(?:rk|sk)_${mode}_`).test(env.STRIPE_API_KEY ?? "") &&
    /^whsec_/.test(env.STRIPE_WEBHOOK_SECRET ?? "") &&
    /^price_[a-zA-Z0-9]+$/.test(env.STRIPE_PRICE_ID ?? "");
}

export function paypalReady(env, provider) {
  return Boolean(env.PAYPAL_CLIENT_ID && env.PAYPAL_CLIENT_SECRET &&
    env.STRIPE_AUTOMATIC_TAX !== "true" &&
    (provider === "paypal" || env.ENABLE_VENMO === "true"));
}

async function jsonFrom(response) {
  if (!response.ok) {
    throw new Error(`Payment provider returned ${response.status}`);
  }
  return response.json();
}

export async function stripe(path, env, data, fetcher) {
  return jsonFrom(await fetcher(`https://api.stripe.com/v1/${path}`, {
    method: data ? "POST" : "GET",
    headers: {
      Authorization: `Bearer ${env.STRIPE_API_KEY}`,
      "Stripe-Version": "2026-10-28.endive",
    },
    body: data ? new URLSearchParams(data) : undefined,
    signal: AbortSignal.timeout(10000),
  }));
}

function paypalBase(env) {
  return billingMode(env) === "test"
    ? "https://api-m.sandbox.paypal.com"
    : "https://api-m.paypal.com";
}

export async function paypalAccess(env, fetcher) {
  const credentials = btoa(`${env.PAYPAL_CLIENT_ID}:${env.PAYPAL_CLIENT_SECRET}`);
  const data = await jsonFrom(await fetcher(`${paypalBase(env)}/v1/oauth2/token`, {
    method: "POST",
    headers: { Authorization: `Basic ${credentials}` },
    body: new URLSearchParams({ grant_type: "client_credentials" }),
    signal: AbortSignal.timeout(10000),
  }));
  return data.access_token;
}

export async function paypal(path, env, access, fetcher, data, idempotencyKey) {
  const headers = {
    Authorization: `Bearer ${access}`,
    "Content-Type": "application/json",
    Prefer: "return=representation",
  };
  if (idempotencyKey) headers["PayPal-Request-Id"] = idempotencyKey;
  return jsonFrom(await fetcher(`${paypalBase(env)}/${path}`, {
    method: data ? "POST" : "GET",
    headers,
    body: data ? JSON.stringify(data) : undefined,
    signal: AbortSignal.timeout(10000),
  }));
}

export function checkoutRedirect(candidate, provider) {
  const url = new URL(candidate);
  const hosts = provider === "stripe"
    ? ["checkout.stripe.com"]
    : ["www.paypal.com", "www.sandbox.paypal.com", "venmo.com", "www.venmo.com"];
  if (url.protocol !== "https:" || url.username || url.password || url.port ||
      !hosts.includes(url.hostname)) {
    throw new Error("Invalid checkout redirect");
  }
  return url.href;
}

export function paidStripeSession(session, order, live) {
  return session?.object === "checkout.session" &&
    session.id === order.provider_id && session.client_reference_id === order.access_hash &&
    session.metadata?.sku === SKU && session.livemode === live &&
    session.mode === "payment" && session.status === "complete" &&
    session.payment_status === "paid" && session.currency === "usd" &&
    session.amount_subtotal === order.cents && /^pi_[a-zA-Z0-9]+$/.test(session.payment_intent);
}

export function paidPayPalCapture(orderData, order) {
  const items = orderData?.purchase_units;
  const unit = items?.[0];
  const captures = unit?.payments?.captures;
  const capture = captures?.[0];
  if (orderData?.id !== order.provider_id || orderData?.status !== "COMPLETED" ||
      items?.length !== 1 || unit.custom_id !== order.access_hash || captures?.length !== 1 ||
      capture.status !== "COMPLETED" || capture.amount?.currency_code !== "USD" ||
      capture.amount?.value !== decimalPrice(order.cents) ||
      !/^[A-Z0-9]{1,36}$/.test(capture.id)) return null;
  return capture.id;
}

export function decimalPrice(cents) {
  return (cents / 100).toFixed(2);
}

export async function checkStripeSignature(body, header, secret, now = Date.now()) {
  if (!header || !secret) return false;
  const parts = header.split(",").map((part) => part.trim().split("="));
  const timestamp = parts.find(([name]) => name === "t")?.[1];
  if (!/^\d{10}$/.test(timestamp ?? "") || Math.abs(now / 1000 - Number(timestamp)) > 300) {
    return false;
  }
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"],
  );
  for (const [name, value] of parts) {
    if (name === "v1" && /^[0-9a-f]{64}$/i.test(value ?? "")) {
      const signature = Uint8Array.from(value.match(/../g), (byte) => Number.parseInt(byte, 16));
      if (await crypto.subtle.verify("HMAC", key, signature, encoder.encode(`${timestamp}.${body}`))) {
        return true;
      }
    }
  }
  return false;
}
