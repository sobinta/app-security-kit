# shop-api

Backend for the Golkhooneh plant shop.

- `GET /api/products?page=1` — product list (20 per page) with signed prices
- `POST /api/coupons/redeem` `{ "code": "WELCOME50" }` — adds credit to the wallet (each coupon has a usage limit)
- `GET /api/wallet` — current wallet balance (`x-user` header identifies the user in this MVP)
- `POST /api/orders` `{ "productId": 1 }` — place an order (respects stock)

Start: `node server.js` (port 4000)
