function ok(res, data, message) {
  return res.status(200).json({ success: true, message: message, data: data });
}

function fail(res, message, status) {
  // Include both `message` and `error` — some frontend pages check
  // data.error, others check data.message. Sending both keeps every
  // existing caller working without touching each page individually.
  return res.status(status).json({ success: false, message: message, error: message });
}

module.exports = { ok, fail };