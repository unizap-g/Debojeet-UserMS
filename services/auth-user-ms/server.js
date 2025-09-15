import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import cookieParser from "cookie-parser";
import mongoose from "mongoose";
import userRoutes from "./routes/user.routes.js";
import swaggerUi from "swagger-ui-express";
import fs from "fs";
import morgan from 'morgan';
dotenv.config();

const app = express();
app.use(morgan('dev'));
const PORT = process.env.PORT || 3001;

// ---------- Middleware ----------
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ---------- Database ----------
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected successfully."))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// ---------- Routes ----------
app.use("/", userRoutes);

app.get("/health", (req, res) =>
  res.json({ status: "health check working fine", service: "user-service" })
);

// ---------- Swagger ----------
const swaggerDocument = JSON.parse(
  fs.readFileSync("./swagger.json", "utf-8")
);
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocument));
app.use(morgan('dev'));
// ---------- Start Server ----------
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Auth & User Service running on http://0.0.0.0:${PORT}`);
  console.log(`📖 Swagger docs available at http://localhost:${PORT}/api-docs`);
});
