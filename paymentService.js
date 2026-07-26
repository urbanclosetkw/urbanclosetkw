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

// Deema's own order-status vocabulary
const DEEMA_STATUS = {
  PENDING:   'pending',
  EXPIRED:   'expired',
  CANCELLED: 'cancelled',
  CAPTURED:  'captured',
};

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

async function processPayment({ payment_method, amount, customer_info }) {
  if (payment_method === PAYMENT_METHODS.CASH_ON_DELIVERY) {
    return { success: true, transaction_id: null };
  }
  return { success: false, error: 'Use createDeemaSession() for online payments.' };
}

/**
 * Create a Deema purchase/checkout session for an order.
 * Deema API: POST /api/merchant/v1/purchase
 */
async function createDeemaSession({ orderId, amount, customer_info }) {
  // Check if environment variables are set
  if (!process.env.DEEMA_BASE_URL || !process.env.DEEMA_SECRET_KEY) {
    console.error('Deema env vars missing. DEEMA_BASE_URL:', !!process.env.DEEMA_BASE_URL, 'DEEMA_SECRET_KEY:', !!process.env.DEEMA_SECRET_KEY);
    return { 
      success: false, 
      error: 'Deema is not configured on this server. Please set DEEMA_BASE_URL and DEEMA_SECRET_KEY environment variables.' 
    };
  }

  try {
    // IMPORTANT: Deema expects the API key in a specific format
    // Some APIs use 'Bearer' with the secret key, others use just the key
    // Let's try both approaches
    
    const requestBody = {
      amount: parseFloat(amount),
      currency_code: 'KWD',
      merchant_order_id: String(orderId),
      merchant_urls: {
        success: `${process.env.FRONTEND_URL || 'https://urbanclosetkw.com'}/pages/confirm.html?orderId=${orderId}`,
        failure: `${process.env.FRONTEND_URL || 'https://urbanclosetkw.com'}/pages/checkout.html?paymentFailed=1&orderId=${orderId}`
      }
    };

    console.log('Deema request body:', JSON.stringify(requestBody, null, 2));

    const res = await fetch(`${process.env.DEEMA_BASE_URL}/api/merchant/v1/purchase`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.DEEMA_SECRET_KEY}`
      },
      body: JSON.stringify(requestBody)
    });

    const data = await res.json();
    
    console.log('Deema response status:', res.status);
    console.log('Deema response data:', JSON.stringify(data, null, 2));

    if (!res.ok) {
      // Deema may return error in different formats
      const errorMsg = data.message || data.error || data.errors || 'Unknown Deema error';
      console.error('Deema API error:', errorMsg);
      return {
        success: false,
        error: `Deema error: ${errorMsg}`
      };
    }

    if (!data.data || !data.data.redirect_link) {
      console.error('Deema response missing redirect_link:', data);
      return {
        success: false,
        error: 'Deema did not return a payment link. Please check your Deema configuration.'
      };
    }

    return {
      success: true,
      sessionUrl: data.data.redirect_link,
      sessionId: data.data.order_reference || null
    };
  } catch (e) {
    console.error('createDeemaSession error:', e.message, e.stack);
    return { 
      success: false, 
      error: 'Deema request failed: ' + e.message 
    };
  }
}

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

function isValidWebhookRequest(headers) {
  const expectedHeaderName = (process.env.DEEMA_WEBHOOK_HEADER_NAME || 'x-deema-secret').toLowerCase();
  const expectedSecret     = process.env.DEEMA_WEBHOOK_SECRET;

  if (!expectedSecret) return true;

  const received = headers[expectedHeaderName];
  return received === expectedSecret;
}

function markPaid(transaction_id) {
  return {
    payment_status: PAYMENT_STATUS.PAID,
    transaction_id: transaction_id || null,
    paid_at:        new Date().toISOString(),
  };
}

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