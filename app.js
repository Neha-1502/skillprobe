import express from "express";
import bodyParser from "body-parser";
import { createClient } from "@libsql/client";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Fix BigInt serialization
BigInt.prototype.toJSON = function() {
  return parseInt(this.toString());
};

const app = express();
app.use(bodyParser.json());

// CORS configuration
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*'); // Change to your domain in production
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// Database connection
const db = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN
});

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const SALT_ROUNDS = 10;

// ========================================
// MIDDLEWARE
// ========================================

// Verify JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// Check user role
function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.user_type)) {
      return res.status(403).json({ error: 'Access denied: insufficient permissions' });
    }
    next();
  };
}

// ========================================
// AUTHENTICATION ROUTES
// ========================================

// Sign up
app.post("/api/auth/signup", async (req, res) => {
  const { username, full_name, email, password, user_type } = req.body;

  // Validation
  if (!username || !full_name || !email || !password || !user_type) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  if (!['student', 'faculty', 'admin'].includes(user_type)) {
    return res.status(400).json({ error: 'Invalid user type' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  try {
    // Check if user exists
    const existingUser = await db.execute({
      sql: `SELECT user_id FROM Users WHERE username = ? OR email = ?`,
      args: [username, email]
    });

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Insert user
    const result = await db.execute({
      sql: `INSERT INTO Users (username, full_name, email, password, user_type) 
            VALUES (?, ?, ?, ?, ?)`,
      args: [username, full_name, email, hashedPassword, user_type]
    });

    const userId = Number(result.lastInsertRowid);

    // Generate token
    const token = jwt.sign(
      { user_id: userId, username, user_type },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'Account created successfully',
      token,
      user: { user_id: userId, username, full_name, email, user_type }
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Error creating account' });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  try {
    const result = await db.execute({
      sql: `SELECT user_id, username, full_name, email, password, user_type, is_active 
            FROM Users WHERE username = ?`,
      args: [username]
    });

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    if (!user.is_active) {
      return res.status(403).json({ error: 'Account is inactive' });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign(
      { user_id: user.user_id, username: user.username, user_type: user.user_type },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        user_id: user.user_id,
        username: user.username,
        full_name: user.full_name,
        email: user.email,
        user_type: user.user_type
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Error during login' });
  }
});

// Get current user info
app.get("/api/auth/me", authenticateToken, async (req, res) => {
  try {
    const result = await db.execute({
      sql: `SELECT user_id, username, full_name, email, user_type FROM Users WHERE user_id = ?`,
      args: [req.user.user_id]
    });

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user: result.rows[0] });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Error fetching user data' });
  }
});

// ========================================
// DOMAIN ROUTES
// ========================================

// Get all active domains
app.get("/api/domains", authenticateToken, async (req, res) => {
  try {
    const result = await db.execute(
      "SELECT domain_id, domain_name FROM Domains WHERE is_active = 1 ORDER BY domain_name"
    );
    res.json({ domains: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// ========================================
// QUESTION ROUTES
// ========================================

// Upload questions (Faculty/Admin only)
app.post("/api/questions/upload", authenticateToken, requireRole('faculty', 'admin'), async (req, res) => {
  const { domain_id, questions } = req.body;
  const uploaded_by = req.user.user_id;

  if (!domain_id || !Array.isArray(questions) || questions.length === 0) {
    return res.status(400).json({ error: 'Domain and questions array required' });
  }

  try {
    const questionIds = [];

    for (const q of questions) {
      if (!q.question_text || !q.option_a || !q.option_b || !q.correct_option) {
        return res.status(400).json({ error: 'Missing required question fields' });
      }

      const result = await db.execute({
        sql: `INSERT INTO Questions 
              (domain_id, question_text, option_a, option_b, option_c, option_d, correct_option, uploaded_by)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        args: [
          domain_id,
          q.question_text,
          q.option_a,
          q.option_b,
          q.option_c || '',
          q.option_d || '',
          q.correct_option,
          uploaded_by
        ]
      });

      questionIds.push(Number(result.lastInsertRowid));
    }

    res.status(201).json({
      message: 'Questions uploaded successfully',
      total_questions: questionIds.length,
      question_ids: questionIds
    });

  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Error uploading questions' });
  }
});

// Get questions for a test (with shuffling)
app.get("/api/questions/:domain_id", authenticateToken, async (req, res) => {
  const { domain_id } = req.params;

  try {
    const result = await db.execute({
      sql: `SELECT question_id, question_text, option_a, option_b, option_c, option_d
            FROM Questions WHERE domain_id = ? AND is_active = 1`,
      args: [domain_id]
    });

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No questions found for this domain' });
    }

    // Shuffle questions (not options)
    const shuffled = shuffleArray([...result.rows]);

    const questions = shuffled.map(q => ({
      question_id: q.question_id,
      question_text: q.question_text,
      options: [
        { key: 'A', value: q.option_a },
        { key: 'B', value: q.option_b },
        { key: 'C', value: q.option_c },
        { key: 'D', value: q.option_d }
      ].filter(opt => opt.value && opt.value.trim() !== "")
    }));

    // Log test attempt
    await db.execute({
      sql: `INSERT INTO Test_Attempts (user_id, domain_id) VALUES (?, ?)`,
      args: [req.user.user_id, domain_id]
    });

    res.json({
      domain_id: parseInt(domain_id),
      total_questions: questions.length,
      questions
    });

  } catch (error) {
    console.error('Get questions error:', error);
    res.status(500).json({ error: 'Error fetching questions' });
  }
});

// ========================================
// TEST ROUTES
// ========================================

// Submit test
app.post("/api/tests/submit", authenticateToken, async (req, res) => {
  const { domain_id, answers } = req.body;
  const user_id = req.user.user_id;

  if (!domain_id || !Array.isArray(answers)) {
    return res.status(400).json({ error: 'Domain and answers required' });
  }

  try {
    const total_questions = answers.length;

    // Create test entry
    const testResult = await db.execute({
      sql: `INSERT INTO Tests (user_id, domain_id, total_questions, score, percentage) 
            VALUES (?, ?, ?, 0, 0)`,
      args: [user_id, domain_id, total_questions]
    });

    const test_id = Number(testResult.lastInsertRowid);
    let score = 0;

    // Evaluate answers
    for (const answer of answers) {
      const { question_id, selected_option } = answer;

      if (!question_id) continue;

      const questionResult = await db.execute({
        sql: `SELECT correct_option FROM Questions WHERE question_id = ?`,
        args: [question_id]
      });

      if (questionResult.rows.length === 0) continue;

      const correct_option = questionResult.rows[0].correct_option;
      const is_correct = selected_option === correct_option;

      if (is_correct) score++;

      // Store test question
      await db.execute({
        sql: `INSERT INTO Test_Questions (test_id, question_id, selected_option, is_correct)
              VALUES (?, ?, ?, ?)`,
        args: [test_id, question_id, selected_option, is_correct ? 1 : 0]
      });
    }

    const percentage = total_questions > 0 ? ((score / total_questions) * 100).toFixed(2) : 0;

    // Update test score
    await db.execute({
      sql: `UPDATE Tests SET score = ?, percentage = ? WHERE test_id = ?`,
      args: [score, percentage, test_id]
    });

    // Create progress report
    await db.execute({
      sql: `INSERT INTO Progress_Report (user_id, domain_id, test_id, total_questions, correct_answers, percentage)
            VALUES (?, ?, ?, ?, ?, ?)`,
      args: [user_id, domain_id, test_id, total_questions, score, percentage]
    });

    res.status(201).json({
      message: 'Test submitted successfully',
      test_id,
      score,
      total_questions,
      percentage: parseFloat(percentage)
    });

  } catch (error) {
    console.error('Submit test error:', error);
    res.status(500).json({ error: 'Error submitting test' });
  }
});

// Get user's test history
app.get("/api/tests/history", authenticateToken, async (req, res) => {
  try {
    const result = await db.execute({
      sql: `SELECT t.test_id, t.test_date, t.score, t.total_questions, t.percentage,
            d.domain_name
            FROM Tests t
            JOIN Domains d ON t.domain_id = d.domain_id
            WHERE t.user_id = ?
            ORDER BY t.test_date DESC`,
      args: [req.user.user_id]
    });

    res.json({ tests: result.rows });
  } catch (error) {
    console.error('Test history error:', error);
    res.status(500).json({ error: 'Error fetching test history' });
  }
});

// Get detailed test results
app.get("/api/tests/:test_id", authenticateToken, async (req, res) => {
  const { test_id } = req.params;

  try {
    // Verify test belongs to user (or user is faculty/admin)
    const testResult = await db.execute({
      sql: `SELECT t.*, d.domain_name, u.username, u.full_name
            FROM Tests t
            JOIN Domains d ON t.domain_id = d.domain_id
            JOIN Users u ON t.user_id = u.user_id
            WHERE t.test_id = ?`,
      args: [test_id]
    });

    if (testResult.rows.length === 0) {
      return res.status(404).json({ error: 'Test not found' });
    }

    const test = testResult.rows[0];

    // Check permissions
    if (test.user_id !== req.user.user_id && !['faculty', 'admin'].includes(req.user.user_type)) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Get question details
    const questionsResult = await db.execute({
      sql: `SELECT tq.question_id, tq.selected_option, tq.is_correct,
            q.question_text, q.option_a, q.option_b, q.option_c, q.option_d, q.correct_option
            FROM Test_Questions tq
            JOIN Questions q ON tq.question_id = q.question_id
            WHERE tq.test_id = ?`,
      args: [test_id]
    });

    res.json({
      test: test,
      questions: questionsResult.rows
    });

  } catch (error) {
    console.error('Test details error:', error);
    res.status(500).json({ error: 'Error fetching test details' });
  }
});

// ========================================
// FACULTY ROUTES
// ========================================

// Get students who took faculty's tests
app.get("/api/faculty/students", authenticateToken, requireRole('faculty', 'admin'), async (req, res) => {
  try {
    const result = await db.execute({
      sql: `SELECT DISTINCT u.user_id, u.username, u.full_name, u.email,
            COUNT(DISTINCT t.test_id) as total_tests
            FROM Users u
            JOIN Tests t ON u.user_id = t.user_id
            JOIN Questions q ON t.domain_id = q.domain_id
            WHERE q.uploaded_by = ? AND u.user_type = 'student'
            GROUP BY u.user_id, u.username, u.full_name, u.email`,
      args: [req.user.user_id]
    });

    res.json({ students: result.rows });
  } catch (error) {
    console.error('Faculty students error:', error);
    res.status(500).json({ error: 'Error fetching students' });
  }
});

// ========================================
// ADMIN ROUTES
// ========================================

// Get all users (Admin only)
app.get("/api/admin/users", authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    const result = await db.execute(
      `SELECT user_id, username, full_name, email, user_type, created_at, is_active 
       FROM Users ORDER BY user_type, username`
    );
    res.json({ users: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// ========================================
// UTILITY FUNCTIONS
// ========================================

function shuffleArray(array) {
  const shuffled = [...array];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled;
}

// ========================================
// SERVER START
// ========================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`🔐 Authentication enabled with JWT`);
  console.log(`📊 Database connected to Turso`);
});