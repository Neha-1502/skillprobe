import express from "express";
import bodyParser from "body-parser";
import { createClient } from "@libsql/client";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import crypto from 'crypto';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Fix BigInt serialization
BigInt.prototype.toJSON = function() {
  return parseInt(this.toString());
};

const app = express();
app.use(bodyParser.json());

// CORS configuration - Updated for separate frontend
app.use((req, res, next) => {
  const allowedOrigins = ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:5500', 'http://127.0.0.1:5500'];
  const origin = req.headers.origin;
  
  if (allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  }
  
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// Serve static files from the current directory
app.use(express.static(__dirname));

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
  const token = authHeader && authHeader.split(' ')[1];

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

// Serve landing page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Serve login page
app.get("/login.html", (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

// Serve signup page
app.get("/signup.html", (req, res) => {
  res.sendFile(path.join(__dirname, 'signup.html'));
});

// Serve forgot password page
app.get("/forgot-password.html", (req, res) => {
  res.sendFile(path.join(__dirname, 'forgot-password.html'));
});

// Serve reset password page
app.get("/reset-password.html", (req, res) => {
  res.sendFile(path.join(__dirname, 'reset-password.html'));
});

// Serve dashboard pages
app.get("/student-dashboard.html", authenticateToken, (req, res) => {
  if (req.user.user_type !== 'student') {
    return res.status(403).json({ error: 'Access denied' });
  }
  res.sendFile(path.join(__dirname, 'student-dashboard.html'));
});

app.get("/faculty-dashboard.html", authenticateToken, (req, res) => {
  if (req.user.user_type !== 'faculty') {
    return res.status(403).json({ error: 'Access denied' });
  }
  res.sendFile(path.join(__dirname, 'faculty-dashboard.html'));
});

app.get("/admin-dashboard.html", authenticateToken, (req, res) => {
  if (req.user.user_type !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  res.sendFile(path.join(__dirname, 'admin-dashboard.html'));
});

// Sign up
app.post("/api/auth/signup", async (req, res) => {
  const { username, full_name, email, password, user_type } = req.body;

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
    const existingUser = await db.execute({
      sql: `SELECT user_id FROM Users WHERE username = ? OR email = ?`,
      args: [username, email]
    });

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    const result = await db.execute({
      sql: `INSERT INTO Users (username, full_name, email, password, user_type) 
            VALUES (?, ?, ?, ?, ?)`,
      args: [username, full_name, email, hashedPassword, user_type]
    });

    const userId = Number(result.lastInsertRowid);

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

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

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

// Helper function to generate unique username
async function generateUniqueUsername(email) {
  const baseUsername = email.split('@')[0].replace(/[^a-zA-Z0-9]/g, '');
  let username = baseUsername;
  let counter = 1;

  while (true) {
    const result = await db.execute({
      sql: `SELECT user_id FROM Users WHERE username = ?`,
      args: [username]
    });

    if (result.rows.length === 0) {
      return username;
    }

    username = `${baseUsername}${counter}`;
    counter++;
    
    // Safety check to prevent infinite loop
    if (counter > 100) {
      throw new Error('Could not generate unique username');
    }
  }
}

// Google OAuth Login/Signup
app.post("/api/auth/google", async (req, res) => {
  const { email, name, googleId } = req.body;

  if (!email || !name || !googleId) {
    return res.status(400).json({ error: 'Google authentication data required' });
  }

  try {
    // Check if user exists by email
    let result = await db.execute({
      sql: `SELECT user_id, username, full_name, email, user_type, is_active, google_id, password 
            FROM Users WHERE email = ?`,
      args: [email]
    });

    let user;

    if (result.rows.length === 0) {
      // Create new user with Google account
      const username = await generateUniqueUsername(email);
      const user_type = 'student'; // Default to student for Google signups

      const insertResult = await db.execute({
        sql: `INSERT INTO Users (username, full_name, email, password, user_type, google_id) 
              VALUES (?, ?, ?, ?, ?, ?)`,
        args: [username, name, email, 'google_oauth', user_type, googleId]
      });

      user = {
        user_id: Number(insertResult.lastInsertRowid),
        username,
        full_name: name,
        email,
        user_type
      };
      
      console.log(`Created new Google user: ${email}`);
    } else {
      user = result.rows[0];
      
      if (!user.is_active) {
        return res.status(403).json({ error: 'Account is inactive' });
      }

      // Handle existing user cases
      if (user.google_id) {
        // User already has Google ID, verify it matches
        if (user.google_id !== googleId) {
          return res.status(400).json({ error: 'Google account mismatch. This email is already linked to a different Google account.' });
        }
        console.log(`Google login for existing linked user: ${user.email}`);
      } else {
        // Existing email/password user - link Google account
        await db.execute({
          sql: `UPDATE Users SET google_id = ? WHERE user_id = ?`,
          args: [googleId, user.user_id]
        });
        
        console.log(`Linked Google account to existing user: ${user.email}`);
      }
    }

    const token = jwt.sign(
      { user_id: user.user_id, username: user.username, user_type: user.user_type },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Google authentication successful',
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
    console.error('Google auth error:', error);
    res.status(500).json({ error: 'Error during Google authentication' });
  }
});

// Forgot Password - Accepts both username and email
app.post("/api/auth/forgot-password", async (req, res) => {
  const { username, email } = req.body;

  if (!username && !email) {
    return res.status(400).json({ error: 'Username or email is required' });
  }

  try {
    let result;
    let identifier;

    if (username) {
      // Find user by username
      result = await db.execute({
        sql: `SELECT user_id, username, full_name, email FROM Users WHERE username = ?`,
        args: [username]
      });
      identifier = `username: ${username}`;
    } else {
      // Find user by email
      result = await db.execute({
        sql: `SELECT user_id, username, full_name, email FROM Users WHERE email = ?`,
        args: [email]
      });
      identifier = `email: ${email}`;
    }

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = result.rows[0];
    
    // Generate simple 6-character reset token
    const resetToken = crypto.randomBytes(3).toString('hex'); // 6 characters
    const resetTokenExpiry = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes

    // Store reset token in database
    await db.execute({
      sql: `UPDATE Users SET reset_token = ?, reset_token_expiry = ? WHERE user_id = ?`,
      args: [resetToken, resetTokenExpiry.toISOString(), user.user_id]
    });

    console.log(`🔐 Password reset token generated for ${user.username} (${user.email}): ${resetToken}`);

    // Return token directly to user
    res.json({ 
      message: 'Password reset token generated successfully',
      reset_token: resetToken,
      user_id: user.user_id,
      user_full_name: user.full_name,
      user_email: user.email,
      expires_in: '30 minutes',
      reset_url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password.html?token=${resetToken}&user_id=${user.user_id}`,
      instructions: 'Copy the reset token and use it on the password reset page'
    });

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Error processing password reset request' });
  }
});

// Reset Password with Token
app.post("/api/auth/reset-password", async (req, res) => {
  const { user_id, reset_token, new_password } = req.body;

  if (!user_id || !reset_token || !new_password) {
    return res.status(400).json({ error: 'User ID, reset token, and new password are required' });
  }

  if (new_password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  try {
    // Verify token exists and hasn't expired
    const result = await db.execute({
      sql: `SELECT user_id, username FROM Users WHERE user_id = ? AND reset_token = ? AND reset_token_expiry > ?`,
      args: [user_id, reset_token, new Date().toISOString()]
    });

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    const user = result.rows[0];

    // Update password and clear reset token
    const hashedPassword = await bcrypt.hash(new_password, SALT_ROUNDS);
    
    await db.execute({
      sql: `UPDATE Users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE user_id = ?`,
      args: [hashedPassword, user_id]
    });

    console.log(`✅ Password reset successfully for user: ${user.username}`);

    res.json({ 
      message: 'Password reset successfully',
      redirect_url: '/login.html'
    });

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Error resetting password' });
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
  const { domain_id, questions, question_set_name } = req.body;
  const uploaded_by = req.user.user_id;

  if (!domain_id || !Array.isArray(questions) || questions.length === 0) {
    return res.status(400).json({ error: 'Domain and questions array required' });
  }

  try {
    const questionIds = [];

    // Generate a unique set identifier if not provided
    const questionSet = question_set_name || `Set_${Date.now()}`;

    for (const q of questions) {
      if (!q.question_text || !q.option_a || !q.option_b || !q.correct_option) {
        return res.status(400).json({ error: 'Missing required question fields' });
      }

      const result = await db.execute({
        sql: `INSERT INTO Questions 
              (domain_id, question_text, option_a, option_b, option_c, option_d, correct_option, uploaded_by, question_set)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        args: [
          domain_id,
          q.question_text,
          q.option_a,
          q.option_b,
          q.option_c || '',
          q.option_d || '',
          q.correct_option,
          uploaded_by,
          questionSet
        ]
      });

      questionIds.push(Number(result.lastInsertRowid));
    }

    res.status(201).json({
      message: 'Questions uploaded successfully',
      total_questions: questionIds.length,
      question_ids: questionIds,
      question_set: questionSet
    });

  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Error uploading questions' });
  }
});

// Get available question sets for a domain
app.get("/api/question-sets/:domain_id", authenticateToken, async (req, res) => {
  const { domain_id } = req.params;

  try {
    const result = await db.execute({
      sql: `SELECT DISTINCT question_set, COUNT(*) as question_count
            FROM Questions 
            WHERE domain_id = ? AND is_active = 1 
            GROUP BY question_set
            ORDER BY question_set`,
      args: [domain_id]
    });

    res.json({ question_sets: result.rows });
  } catch (error) {
    console.error('Get question sets error:', error);
    res.status(500).json({ error: 'Error fetching question sets' });
  }
});

// Get questions for a test from specific set (with shuffling and limiting)
app.get("/api/questions/:domain_id", authenticateToken, async (req, res) => {
  const { domain_id } = req.params;
  const { set: question_set, limit = 10 } = req.query;

  try {
    let sql = `SELECT question_id, question_text, option_a, option_b, option_c, option_d
               FROM Questions WHERE domain_id = ? AND is_active = 1`;
    let args = [domain_id];

    // If specific set is requested, filter by that set
    if (question_set && question_set !== 'all') {
      sql += ` AND question_set = ?`;
      args.push(question_set);
    }

    const result = await db.execute({ sql, args });

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No questions found for this domain' });
    }

    // Shuffle all questions first
    const shuffled = shuffleArray([...result.rows]);
    
    // Take only 'limit' number of questions
    const selectedQuestions = shuffled.slice(0, Math.min(limit, shuffled.length));

    const questions = selectedQuestions.map(q => ({
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
      total_available: result.rows.length,
      question_set: question_set || 'mixed',
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

// Get students who took tests on questions uploaded by this faculty
app.get("/api/faculty/student-reports", authenticateToken, requireRole('faculty', 'admin'), async (req, res) => {
  try {
    // Get all domains where this faculty uploaded questions
    const domainsResult = await db.execute({
      sql: `SELECT DISTINCT d.domain_id, d.domain_name, COUNT(DISTINCT q.question_id) as question_count
            FROM Questions q
            JOIN Domains d ON q.domain_id = d.domain_id
            WHERE q.uploaded_by = ?
            GROUP BY d.domain_id, d.domain_name`,
      args: [req.user.user_id]
    });

    if (domainsResult.rows.length === 0) {
      return res.json({ 
        message: 'You have not uploaded any questions yet',
        domains: [],
        student_reports: []
      });
    }

    const domainIds = domainsResult.rows.map(d => d.domain_id);
    const placeholders = domainIds.map(() => '?').join(',');

    // Get all students who took tests in these domains
    const studentsResult = await db.execute({
      sql: `SELECT DISTINCT u.user_id, u.username, u.full_name, u.email,
            COUNT(DISTINCT t.test_id) as total_tests_taken,
            AVG(t.percentage) as average_score
            FROM Users u
            JOIN Tests t ON u.user_id = t.user_id
            WHERE u.user_type = 'student' 
            AND t.domain_id IN (${placeholders})
            GROUP BY u.user_id, u.username, u.full_name, u.email
            ORDER BY u.full_name`,
      args: domainIds
    });

    // Get detailed test results for each student
    const detailedReports = [];
    
    for (const student of studentsResult.rows) {
      const testsResult = await db.execute({
        sql: `SELECT t.test_id, t.test_date, t.score, t.total_questions, t.percentage,
              d.domain_name
              FROM Tests t
              JOIN Domains d ON t.domain_id = d.domain_id
              WHERE t.user_id = ? AND t.domain_id IN (${placeholders})
              ORDER BY t.test_date DESC`,
        args: [student.user_id, ...domainIds]
      });

      detailedReports.push({
        student: {
          user_id: student.user_id,
          username: student.username,
          full_name: student.full_name,
          email: student.email,
          total_tests_taken: student.total_tests_taken,
          average_score: student.average_score ? parseFloat(student.average_score).toFixed(2) : '0.00'
        },
        tests: testsResult.rows
      });
    }

    res.json({
      faculty_domains: domainsResult.rows,
      total_students: studentsResult.rows.length,
      student_reports: detailedReports
    });

  } catch (error) {
    console.error('Faculty student reports error:', error);
    res.status(500).json({ error: 'Error fetching student reports: ' + error.message });
  }
});

// Get statistics for faculty's uploaded questions
app.get("/api/faculty/question-stats", authenticateToken, requireRole('faculty', 'admin'), async (req, res) => {
  try {
    const result = await db.execute({
      sql: `SELECT d.domain_name, 
            COUNT(DISTINCT q.question_id) as total_questions,
            COUNT(DISTINCT t.test_id) as times_used_in_tests,
            AVG(CASE WHEN tq.is_correct = 1 THEN 1.0 ELSE 0.0 END) * 100 as average_correct_rate
            FROM Questions q
            JOIN Domains d ON q.domain_id = d.domain_id
            LEFT JOIN Test_Questions tq ON q.question_id = tq.question_id
            LEFT JOIN Tests t ON tq.test_id = t.test_id
            WHERE q.uploaded_by = ?
            GROUP BY d.domain_name
            ORDER BY d.domain_name`,
      args: [req.user.user_id]
    });

    res.json({ statistics: result.rows });
  } catch (error) {
    console.error('Faculty stats error:', error);
    res.status(500).json({ error: 'Error fetching statistics' });
  }
});

// Get faculty's question sets
app.get("/api/faculty/question-sets", authenticateToken, requireRole('faculty', 'admin'), async (req, res) => {
  try {
    const result = await db.execute({
      sql: `SELECT d.domain_name, q.question_set, COUNT(*) as question_count
            FROM Questions q
            JOIN Domains d ON q.domain_id = d.domain_id
            WHERE q.uploaded_by = ?
            GROUP BY d.domain_name, q.question_set
            ORDER BY d.domain_name, q.question_set`,
      args: [req.user.user_id]
    });

    res.json({ question_sets: result.rows });
  } catch (error) {
    console.error('Faculty question sets error:', error);
    res.status(500).json({ error: 'Error fetching question sets' });
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
  console.log(`🔄 Password reset: Simple token system`);
  console.log(`📊 Database connected to Turso`);
  console.log(`📄 Serving static files from: ${__dirname}`);
});