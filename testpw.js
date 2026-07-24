const b = require('bcryptjs');
const hash = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy';
b.compare('admin123', hash).then(r => console.log('match:', r));
b.hash('admin123', 10).then(h => console.log('new hash:', h));
