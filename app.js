import express from "express";
import bodyParser from "body-parser";
import { createClient } from "@libsql/client";

const app = express();
app.use(bodyParser.json());

//Connecting to Turso Database
const db = createClient({
  url: "libsql://skillprobe-neha-1502.aws-ap-south-1.turso.io",
  authToken: "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3NjIxODI2OTQsImlkIjoiNDFmNTY2MzAtOGJhNC00ZDY5LTk4YTQtMjExOGI1MjA2ZDkxIiwicmlkIjoiOTQxNjk2ZWEtZjBmNy00MjcxLTgxMmMtNDc5YzY2ZDc4M2UzIn0.98i4y4h3vvdSY5q4o_MHS1TdsSnqUWJpgs0mJIs0IDkFLwgdAcozTlwSncRkzQWyp8tY3-1GcQb4AHzC5-7uBw" // replace this with your Turso token
});

//Testing database connection
app.get("/", async (req, res) => {
  try {
    const result = await db.execute("SELECT name FROM sqlite_master WHERE type='table';");
    res.json({ message: "Connected to Turso DB successfully!", tables: result.rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

//Creating Paper API (Faculty uploads MCQs)
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

//Starting the server
app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
