// Минимальный сервер авторизации: регистрация, вход, проверка сессии.
// Для учёбы/старта. Перед продакшеном см. README.md — там про базу данных,
// хостинг и защиту.

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:5500';

if (!JWT_SECRET) {
  console.error('Не задан JWT_SECRET в .env — сгенерируйте случайную строку и добавьте её туда.');
  process.exit(1);
}

app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: FRONTEND_ORIGIN, // адрес, с которого открывается сайт
  credentials: true         // разрешает отправку cookie с токеном
}));

// ---------------------------------------------------------------
// Хранилище пользователей: JSON-файл для примера.
// В реальном проекте замените на настоящую базу данных
// (PostgreSQL / MySQL / MongoDB) — см. README.md.
// ---------------------------------------------------------------
const DB_PATH = path.join(__dirname, 'users.json');

function readUsers() {
  if (!fs.existsSync(DB_PATH)) return [];
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
}

function writeUsers(users) {
  fs.writeFileSync(DB_PATH, JSON.stringify(users, null, 2));
}

// ---------------------------------------------------------------
// Регистрация
// ---------------------------------------------------------------
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body || {};

  if (!name || !email || !password) {
    return res.status(400).json({ message: 'Заполните имя, почту и пароль' });
  }
  if (password.length < 6) {
    return res.status(400).json({ message: 'Пароль должен быть не короче 6 символов' });
  }

  const users = readUsers();
  const exists = users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (exists) {
    return res.status(409).json({ message: 'Такая почта уже зарегистрирована' });
  }

  // Пароль никогда не хранится в открытом виде — только хэш.
  const passwordHash = await bcrypt.hash(password, 10);
  const user = { id: Date.now().toString(), name, email, passwordHash };
  users.push(user);
  writeUsers(users);

  issueSessionCookie(res, user);
  res.json({ name: user.name, email: user.email });
});

// ---------------------------------------------------------------
// Вход
// ---------------------------------------------------------------
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ message: 'Введите почту и пароль' });
  }

  const users = readUsers();
  const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!user) {
    return res.status(401).json({ message: 'Неверная почта или пароль' });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    return res.status(401).json({ message: 'Неверная почта или пароль' });
  }

  issueSessionCookie(res, user);
  res.json({ name: user.name, email: user.email });
});

// ---------------------------------------------------------------
// Проверка текущей сессии (используется, чтобы не разлогинивать
// человека при обновлении страницы)
// ---------------------------------------------------------------
app.get('/api/me', (req, res) => {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({ message: 'Не авторизован' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    res.json({ name: payload.name, email: payload.email });
  } catch {
    res.status(401).json({ message: 'Сессия истекла' });
  }
});

// ---------------------------------------------------------------
// Выход
// ---------------------------------------------------------------
app.post('/api/logout', (req, res) => {
  res.clearCookie('session');
  res.json({ ok: true });
});

function issueSessionCookie(res, user) {
  const token = jwt.sign(
    { name: user.name, email: user.email },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
  res.cookie('session', token, {
    httpOnly: true,      // недоступна для JS в браузере — защита от XSS
    secure: process.env.NODE_ENV === 'production', // только через HTTPS в проде
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

app.listen(PORT, () => {
  console.log(`Сервер авторизации запущен: http://localhost:${PORT}`);
});
