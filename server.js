const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const port = 3001;

// Google OAuth client
const client = new OAuth2Client(
  '830299530520-266jc77at2ei6vq1lug2ra4gk38h74ic.apps.googleusercontent.com'
);

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Connect to SQLite
const db = new sqlite3.Database('./budgetnest.db', (err) => {
  if (err) return console.error(err.message);
  console.log('✅ Connected to SQLite database');
});

// USERS table
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password TEXT
  );
`);

// EXPENSES table
db.run(`
  CREATE TABLE IF NOT EXISTS expenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT,
    salaryType TEXT,
    salaryAmount REAL,
    name TEXT,
    amount REAL
  );
`);

// ----------------------------- AUTH ROUTES -----------------------------

// Register
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ message: 'All fields are required.' });

  db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, email], async (err, row) => {
    if (row) return res.status(400).json({ message: 'Username or Email already exists.' });

    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      db.run(
        'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
        [username, email, hashedPassword],
        (err) => {
          if (err) return res.status(500).json({ message: 'Registration failed.' });
          return res.status(200).json({ message: 'Registration successful.' });
        }
      );
    } catch (err) {
      return res.status(500).json({ message: 'Error during registration.' });
    }
  });
});

// Login
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: 'All fields are required.' });

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (!user) return res.status(400).json({ message: 'Invalid credentials.' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ message: 'Invalid credentials.' });

    return res.status(200).json({
      message: 'Login successful.',
      success: true,
      username: user.username
    });
  });
});

// Google Login
app.post('/api/auth/google', async (req, res) => {
  const { credential } = req.body;
  try {
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: '830299530520-266jc77at2ei6vq1lug2ra4gk38h74ic.apps.googleusercontent.com'
    });

    const payload = ticket.getPayload();
    const email = payload.email;
    const username = payload.name;

    db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
      if (err) return res.status(500).json({ message: 'Internal error' });

      if (!row) {
        db.run(
          'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
          [username, email, 'google-login'],
          (err) => {
            if (err) return res.status(500).json({ message: 'Google login failed.' });
            return res.status(200).json({ message: 'Google login successful.', success: true, username });
          }
        );
      } else {
        return res.status(200).json({ message: 'Google login successful.', success: true, username: row.username });
      }
    });
  } catch (err) {
    console.error('Google login error:', err);
    return res.status(401).json({ message: 'Invalid Google login.' });
  }
});

// --------------------------- EXPENSE ROUTES ----------------------------

// Save Expense
app.post('/api/expense', (req, res) => {
  const { user, salaryType, salaryAmount, name, amount } = req.body;

  db.get(
    'SELECT * FROM expenses WHERE user = ? AND salaryType = ? AND salaryAmount IS NOT NULL',
    [user, salaryType],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });

      const insertExpense = (includeSalary) => {
        db.run(
          'INSERT INTO expenses (user, salaryType, salaryAmount, name, amount) VALUES (?, ?, ?, ?, ?)',
          [user, salaryType, includeSalary ? salaryAmount : null, name, amount],
          function (err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id: this.lastID });
          }
        );
      };

      if (!row) {
        insertExpense(true);
      } else {
        insertExpense(false);
      }
    }
  );
});

// Get all Expenses for a User
app.get('/api/expenses/:user', (req, res) => {
  const user = req.params.user;
  db.all('SELECT * FROM expenses WHERE user = ?', [user], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Get Salary
app.get('/api/salary/:user', (req, res) => {
  const user = req.params.user;
  db.get(
    'SELECT salaryAmount, salaryType FROM expenses WHERE user = ? AND salaryAmount IS NOT NULL LIMIT 1',
    [user],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(row || {});
    }
  );
});

// Clear Expenses for a User
app.delete('/api/expenses/:user', (req, res) => {
  const user = req.params.user;
  db.run('DELETE FROM expenses WHERE user = ?', [user], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Expenses cleared.' });
  });
});

// --------------------------- STATIC ROUTE ----------------------------

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'getstartedpage.html'));
});

// --------------------------- START SERVER ----------------------------

app.listen(port, () => {
  console.log(`🚀 Server running at http://localhost:${port}`);
});