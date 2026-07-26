// paymentService.js
// Payment service layer — swap provider implementations here in the future.

const PAYMENT_METHODS = {
  CASH_ON_DELIVERY: 'cash_on_delivery',
  ONLINE:           'online_payment', // Deema BNPL
  LOCAL:            'local_payment',  // MyFatoorah — KNET, cards & other local options
};

const PAYMENT_STATUS = {
  PENDING:   'pending',
  PAID:      'paid',
  FAILED:    'failed',
  REFUNDED:  'refunded',
};

// Deema's own order-status vocabulary (GET /purchase/status, webhook payload)
const DEEMA_STATUS = {
  PENDING:   'pending',
  EXPIRED:   'expired',
  CANCELLED: 'cancelled',
  CAPTURED:  'captured',
};

/**
 * Initialise a payment record before the order is saved.
 * Returns the fields to merge into the orders INSERT.
 */
function initPayment(payment_method) {
  const method = Object.values(PAYMENT_METHODS).includes(payment_method)
    ? payment_method
    : PAYMENT_METHODS.CASH_ON_DELIVERY;

  return {
    payment_method: method,
    payment_status: PAYMENT_STATUS.PENDING,
    transaction_id: null,
    paid_at:        null,
  };
}

/**
 * Simulate / process a payment.
 * Cash on delivery short-circuits; online payments go through createDeemaSession().
 * Returns { success, transaction_id, error? }
 */
async function processPayment({ payment_method, amount, customer_info }) {
  if (payment_method === PAYMENT_METHODS.CASH_ON_DELIVERY) {
    return { success: true, transaction_id: null };
  }
  return { success: false, error: 'Use createDeemaSession() for online payments.' };
}

/**
 * Create a Deema purchase/checkout session for an order.
 * Deema API: POST /api/merchant/v1/purchase
 * Docs: https://api-docs.deema.me/
 *
 * Request:  { amount, currency_code, merchant_order_id, merchant_urls: { success, failure } }
 * Response: { message, data: { order_reference, redirect_link } }
 *
 * order_reference is Deema's own ID for this purchase — we store it on the order
 * as transaction_id immediately so the webhook/status-check can match back to us
 * via merchant_order_id, and so we can call Get Order Status using order_reference.
 */
async function createDeemaSession({ orderId, amount, customer_info }) {
  if (!process.env.DEEMA_BASE_URL || !process.env.DEEMA_SECRET_KEY) {
    console.error('Deema env vars missing on this environment. DEEMA_BASE_URL set:', !!process.env.DEEMA_BASE_URL, 'DEEMA_SECRET_KEY set:', !!process.env.DEEMA_SECRET_KEY);
    return { success: false, error: 'Deema is not configured on this server (missing env vars).' };
  }
  try {
    const res = await fetch(`${process.env.DEEMA_BASE_URL}/api/merchant/v1/purchase`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.DEEMA_SECRET_KEY}`
      },
      body: JSON.stringify({
        amount: parseFloat(amount),
        currency_code: 'KWD',
        merchant_order_id: String(orderId),
        merchant_urls: {
          success: `${process.env.FRONTEND_URL}/pages/confirm.html?orderId=${orderId}`,
          failure: `${process.env.FRONTEND_URL}/pages/checkout.html?paymentFailed=1&orderId=${orderId}`
        }
      })
    });

    const data = await res.json();
    if (!res.ok || !data.data || !data.data.redirect_link) {
      // Log the raw response so the real reason shows up in Render logs —
      // Deema may not use a `message` field, so without this we only ever
      // see our own generic fallback text.
      console.error('Deema rejected session creation. status:', res.status, 'body:', JSON.stringify(data));
      const deemaMessage = (data && (data.message || data.error || data.errors)) || null;
      return {
        success: false,
        error: deemaMessage
          ? (typeof deemaMessage === 'string' ? deemaMessage : JSON.stringify(deemaMessage))
          : `Deema session creation failed (HTTP ${res.status}).`
      };
    }

    return {
      success: true,
      sessionUrl: data.data.redirect_link,
      sessionId:  data.data.order_reference
    };
  } catch (e) {
    console.error('createDeemaSession network/parse error:', e.message, e.stack);
    return { success: false, error: 'Deema request failed: ' + e.message };
  }
}

/**
 * Confirm an order's real-time status directly with Deema (server-to-server),
 * rather than trusting a webhook payload's claimed status outright.
 * Deema API: GET /api/merchant/v1/purchase/status?order_reference=...
 * Response: { message, data: { status: 'pending'|'expired'|'cancelled'|'captured' } }
 */
async function verifyDeemaPayment({ order_reference }) {
  try {
    if (!order_reference) return { success: false, error: 'order_reference required.' };

    const url = `${process.env.DEEMA_BASE_URL}/api/merchant/v1/purchase/status?order_reference=${encodeURIComponent(order_reference)}`;
    const res = await fetch(url, {
      headers: { 'Authorization': `Bearer ${process.env.DEEMA_SECRET_KEY}` }
    });
    const data = await res.json();

    if (!res.ok || !data.data) {
      return { success: false, error: (data && data.message) || 'Deema status check failed.' };
    }

    const status = data.data.status;
    return {
      success:        true,
      status:         status,
      isPaid:         status === DEEMA_STATUS.CAPTURED,
      isFailed:       status === DEEMA_STATUS.EXPIRED || status === DEEMA_STATUS.CANCELLED,
      transaction_id: order_reference
    };
  } catch (e) {
    console.error('verifyDeemaPayment error:', e.message);
    return { success: false, error: 'Deema verification request failed.' };
  }
}

/**
 * Validate the shared-secret header deema sends on every webhook call
 * (configured in the deema Merchant Portal → Webhook → Headers).
 * Compares against DEEMA_WEBHOOK_SECRET / DEEMA_WEBHOOK_HEADER_NAME env vars.
 */
function isValidWebhookRequest(headers) {
  const expectedHeaderName = (process.env.DEEMA_WEBHOOK_HEADER_NAME || 'x-deema-secret').toLowerCase();
  const expectedSecret     = process.env.DEEMA_WEBHOOK_SECRET;

  // If no secret is configured yet, don't block (sandbox/dev convenience) —
  // but this should always be set before going live.
  if (!expectedSecret) return true;

  const received = headers[expectedHeaderName];
  return received === expectedSecret;
}

/**
 * Build the update fields to mark an order as paid.
 */
function markPaid(transaction_id) {
  return {
    payment_status: PAYMENT_STATUS.PAID,
    transaction_id: transaction_id || null,
    paid_at:        new Date().toISOString(),
  };
}

/**
 * Build the update fields to mark an order's payment as failed.
 */
function markFailed(transaction_id) {
  return {
    payment_status: PAYMENT_STATUS.FAILED,
    transaction_id: transaction_id || null,
  };
}

module.exports = {
  PAYMENT_METHODS,
  PAYMENT_STATUS,
  DEEMA_STATUS,
  initPayment,
  processPayment,
  markPaid,
  markFailed,
  createDeemaSession,
  verifyDeemaPayment,
  isValidWebhookRequest,
};
