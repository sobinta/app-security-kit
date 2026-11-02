// SQLite storage (Node 22+ built-in node:sqlite, no native build needed)
const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');

const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new DatabaseSync(path.join(dataDir, 'shop.db'));

function init() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      name TEXT,
      role TEXT DEFAULT 'user',
      prefs TEXT DEFAULT '{}'
    );
    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      price INTEGER NOT NULL,
      stock INTEGER DEFAULT 10
    );
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      author TEXT,
      body TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      product_id INTEGER,
      quantity INTEGER,
      total INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS reset_tokens (
      token TEXT,
      user_id INTEGER
    );
  `);

  const count = db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
  if (count === 0) {
    const addUser = db.prepare('INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)');
    addUser.run('sara@golkhooneh.ir', 'plant-lover', 'Sara', 'admin');
    addUser.run('ali@golkhooneh.ir', '123456', 'Ali', 'user');
    const addProduct = db.prepare('INSERT INTO products (name, price, stock) VALUES (?, ?, ?)');
    addProduct.run('Monstera Deliciosa', 1200000, 8);
    addProduct.run('Snake Plant', 450000, 15);
    addProduct.run('Fiddle Leaf Fig', 980000, 4);
    addProduct.run('Golden Pothos', 250000, 30);
    db.prepare('INSERT INTO orders (user_id, product_id, quantity, total) VALUES (?, ?, ?, ?)').run(1, 1, 1, 1200000);
    db.prepare('INSERT INTO comments (user_id, author, body) VALUES (?, ?, ?)').run(2, 'Ali', 'My monstera arrived healthy, thanks! 🌿');
  }
}

module.exports = { db, init };
