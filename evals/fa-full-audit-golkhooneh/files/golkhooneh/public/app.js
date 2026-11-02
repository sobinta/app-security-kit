// storefront logic
const WEATHER_API_KEY = "__WEATHER_KEY__";
const WEATHER_URL = "http://api.weather-example.ir/v1/current";

async function loadWeather() {
  try {
    const r = await fetch(`${WEATHER_URL}?city=Tehran&key=${WEATHER_API_KEY}`);
    const w = await r.json();
    document.getElementById('weather').textContent = `${w.city} ${w.tempC}°`;
  } catch (e) { document.getElementById('weather').textContent = ''; }
}

async function loadProducts() {
  const res = await fetch('/api/db/query', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sql: 'SELECT * FROM products' }),
  });
  const products = await res.json();
  const box = document.getElementById('products');
  box.innerHTML = products.map(p => `
    <div class="card">
      <h3>${p.name}</h3>
      <p>${p.price.toLocaleString('fa-IR')} تومان</p>
      <input type="number" id="qty-${p.id}" value="1" min="1" max="10">
      <button onclick="buy(${p.id}, ${p.price})">خرید</button>
    </div>`).join('');
}

async function buy(productId, price) {
  const quantity = Number(document.getElementById('qty-' + productId).value);
  const res = await fetch('/api/checkout', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include',
    body: JSON.stringify({ productId, quantity, price }),
  });
  const data = await res.json();
  alert(data.ok ? `سفارش ثبت شد: ${data.total} تومان` : data.error);
}

async function loadComments() {
  const res = await fetch('/api/comments');
  const comments = await res.json();
  document.getElementById('comments').innerHTML = comments
    .map(c => `<div class="comment"><b>${c.author}</b>: ${c.body}</div>`).join('');
}

document.getElementById('commentForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const body = new FormData(e.target).get('body');
  await fetch('/api/comments', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    credentials: 'include', body: JSON.stringify({ body }) });
  e.target.reset();
  loadComments();
});

loadWeather();
loadProducts();
loadComments();
