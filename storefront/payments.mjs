export const SKU = "net-dns-monitor-premium";
export const STRIPE_API_VERSION = "2026-02-25.preview";

export function billingMode(env) {
  return env.BILLING_MODE === "test" ? "test" : "live";
}

function stripeKey(env) {
  return env.STRIPE_SECRET_KEY || env.STRIPE_API_KEY || "";
}

export function hasStripeKey(env) {
  return billingMode(env) === "test"
    ? /^(?:rk|sk|rkcs)_test_/.test(stripeKey(env))
    : /^(?:rk|sk)_live_/.test(stripeKey(env));
}

export function managedPriceId(env, buyerUse) {
  const prices = { personal: env.STRIPE_PERSONAL_PRICE_ID, business: env.STRIPE_BUSINESS_PRICE_ID };
  if (buyerUse !== "personal" && buyerUse !== "business") return null;
  return /^price_[A-Za-z0-9]+$/.test(prices[buyerUse] ?? "") ? prices[buyerUse] : null;
}

export function stripeReady(env) {
  const personal = managedPriceId(env, "personal");
  const business = managedPriceId(env, "business");
  return env.STRIPE_CHECKOUT_ENABLED === "true" && hasStripeKey(env) &&
    /^whsec_/.test(env.STRIPE_WEBHOOK_SECRET ?? "") &&
    Boolean(personal && business && personal !== business);
}

export async function stripe(path, env, data, fetcher, requestId) {
  const headers = {
    Authorization: `Bearer ${stripeKey(env)}`,
    "Stripe-Version": STRIPE_API_VERSION,
  };
  if (requestId) headers["Idempotency-Key"] = requestId;
  const response = await fetcher(`https://api.stripe.com/v1/${path}`, {
    method: data ? "POST" : "GET",
    headers,
    body: data ? new URLSearchParams(data) : undefined,
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) throw new Error(`Stripe returned ${response.status}`);
  return response.json();
}

export function checkoutRedirect(candidate) {
  const url = new URL(candidate);
  if (url.protocol !== "https:" || url.username || url.password || url.port ||
      url.hostname !== "checkout.stripe.com") {
    throw new Error("Invalid Checkout redirect");
  }
  return url.href;
}

export function managedCheckout(session) {
  return session?.managed_payments?.enabled === true &&
    session.automatic_tax?.enabled === true &&
    session.automatic_tax.liability?.type === "stripe";
}

export function paidStripeSession(session, order, live) {
  if (session?.object !== "checkout.session" || session.id !== order.provider_id ||
      session.client_reference_id !== order.access_hash || session.metadata?.sku !== SKU ||
      session.livemode !== live || session.mode !== "payment" || session.status !== "complete" ||
      session.payment_status !== "paid" || session.currency !== "usd" ||
      session.amount_subtotal !== order.cents || !/^pi_[a-zA-Z0-9]+$/.test(session.payment_intent)) {
    return false;
  }
  if (order.stripe_price_id) {
    return managedCheckout(session) && session.automatic_tax.status === "complete" &&
      session.metadata.price_id === order.stripe_price_id && session.metadata.buyer_use === order.buyer_use;
  }
  // An order created before the Managed Payments rollout has no price binding.
  return session.metadata.tax_required !== "true" ||
    (session.automatic_tax?.enabled === true && session.automatic_tax.status === "complete");
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
