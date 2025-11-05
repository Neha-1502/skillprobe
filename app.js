import express from "express";
import bodyParser from "body-parser";
import { createClient } from "@libsql/client";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

const app = express();
app.use(bodyParser.json());

// Connecting to Turso Database using environment variables
const db = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN
});

// Testing database connection
app.get("/", async (req, res) => {
  try {
    const result = await db.execute("SELECT name FROM sqlite_master WHERE type='table';");
    res.json({ message: "Connected to Turso DB successfully!", tables: result.rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Creating Paper API (Faculty uploads MCQs)
app.post("/api/create-paper", async (req, res) => {
  const { domain_id, uploaded_by, questions } = req.body;

  if (!domain_id || !uploaded_by || !Array.isArray(questions) || questions.length === 0) {
    return res.status(400).json({ message: "Invalid input data" });
  }

  try {
    for (const q of questions) {
      await db.execute({
        sql: `INSERT INTO Questions 
              (domain_id, question_text, option_a, option_b, option_c, option_d, correct_option, uploaded_by)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        args: [
          domain_id,
          q.question_text,
          q.option_a,
          q.option_b,
          q.option_c,
          q.option_d,
          q.correct_option,
          uploaded_by
        ]
      });
    }

    res.status(201).json({ message: "✅ Paper uploaded successfully!" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// Starting the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});