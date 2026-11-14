// services/authService.js
//
// ── TASK 2 (7 marks): register — hash the password with bcrypt ───────────────
// ── TASK 3 (7 marks): login — verify password + issue a JWT ──────────────────
//
// Use bcryptjs for hashing/compare and jsonwebtoken for the token.
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const userRepository = require('../repositories/userRepository');
const AppError = require('../errors/AppError');

const SALT_ROUNDS = 10;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

function publicUser(user) {
  return { id: user.id, name: user.name, email: user.email };
}

// register({ name, email, password })
//   Validates input, prevents duplicate emails, stores only a bcrypt hash,
//   and returns a password-free public user object.
async function register(input = {}) {
  const { name, email, password } = input || {};

  if (
    typeof name !== 'string' || name.trim().length === 0 ||
    typeof email !== 'string' || email.trim().length === 0 ||
    typeof password !== 'string' || password.trim().length === 0
  ) {
    throw new AppError(
      400,
      'INVALID_INPUT',
      'name, email, password are required'
    );
  }

  const normalizedName = name.trim();
  const normalizedEmail = email.trim().toLowerCase();

  const existingUser = await userRepository.findByEmail(normalizedEmail);
  if (existingUser) {
    throw new AppError(409, 'EMAIL_EXISTS', 'Email already registered');
  }

  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
  const createdUser = await userRepository.create({
    name: normalizedName,
    email: normalizedEmail,
    passwordHash,
  });

  return publicUser(createdUser);
}

// login({ email, password })
//   Looks up the normalized email, verifies the password, and issues a JWT.
async function login(input = {}) {
  const { email, password } = input || {};

  if (
    typeof email !== 'string' || email.trim().length === 0 ||
    typeof password !== 'string' || password.trim().length === 0
  ) {
    throw new AppError(
      400,
      'INVALID_INPUT',
      'email and password are required'
    );
  }

  const normalizedEmail = email.trim().toLowerCase();
  const user = await userRepository.findByEmail(normalizedEmail);

  const passwordMatches = user
    ? await bcrypt.compare(password, user.passwordHash)
    : false;

  if (!passwordMatches) {
    throw new AppError(
      401,
      'INVALID_CREDENTIALS',
      'Invalid email or password'
    );
  }

  const token = jwt.sign(
    { sub: user.id },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  return { token };
}

module.exports = { register, login };
