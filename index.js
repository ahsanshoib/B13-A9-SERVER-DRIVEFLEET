import "dotenv/config";
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import { MongoClient, ObjectId } from "mongodb";
import { betterAuth } from "better-auth";
import { jwt as jwtPlugin } from "better-auth/plugins";
import { mongodbAdapter } from "better-auth/adapters/mongodb";

const app = express();
const PORT = process.env.PORT || 5000;
const isProduction = process.env.NODE_ENV === "production";
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

const allowedOrigins = [
  "http://localhost:3000",
  "https://b13-a9-client-drivefleet.vercel.app",
  "https://b13-a9-client-drivefleet-54mm.vercel.app",
  process.env.CLIENT_URL,
].filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (!origin || allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin || "*");
  }
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS,PATCH");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization,Cookie,Set-Cookie");
  if (req.method === "OPTIONS") return res.status(200).end();
  next();
});

app.use(express.json());
app.use(cookieParser());

const client = new MongoClient(process.env.MONGODB_URI);
let db;
let auth;

async function connectDB() {
  await client.connect();
  db = client.db("FLEETDRIVE");
  console.log("MongoDB connected");
  initAuth();
}

function initAuth() {
  auth = betterAuth({
    database: mongodbAdapter(db),
    secret: process.env.BETTER_AUTH_SECRET,
    baseURL: BASE_URL,
    emailAndPassword: { enabled: true },
    plugins: [jwtPlugin()],
    trustedOrigins: allowedOrigins,
    socialProviders: {
      google: {
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      },
    },
    advanced: {
      cookiePrefix: "drivefleet",
      defaultCookieAttributes: {
        secure: isProduction,
        sameSite: isProduction ? "none" : "lax",
        httpOnly: true,
      },
    },
  });
}

connectDB();

// ─── JWT ROUTES ─────────────────────────────────────────────

app.post("/api/jwt/token", (req, res) => {
  const { email, name, photo } = req.body;
  if (!email) return res.status(400).json({ message: "Email required" });
  const token = jwt.sign({ email, name, photo }, process.env.JWT_SECRET, { expiresIn: "7d" });
  res.cookie("token", token, {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? "none" : "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
  res.json({ success: true });
});

app.post("/api/jwt/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? "none" : "lax",
  });
  res.json({ success: true });
});

// ─── BETTER AUTH HANDLER ────────────────────────────────────

app.all("/api/auth/*", async (req, res) => {
  try {
    const url = new URL(req.url, BASE_URL);
    const headers = new Headers();
    Object.entries(req.headers).forEach(([key, value]) => {
      if (value) headers.set(key, Array.isArray(value) ? value.join(",") : value);
    });
    const request = new Request(url.toString(), {
      method: req.method,
      headers,
      body: req.method !== "GET" && req.method !== "HEAD"
        ? JSON.stringify(req.body)
        : undefined,
    });
    const response = await auth.handler(request);
    response.headers.forEach((value, key) => {
      if (key.toLowerCase() !== "access-control-allow-origin") {
        res.setHeader(key, value);
      }
    });
    res.status(response.status);
    const text = await response.text();
    res.send(text);
  } catch (err) {
    console.error("Auth handler error:", err);
    res.status(500).json({ message: err.message });
  }
});

// ─── SESSION MIDDLEWARE ─────────────────────────────────────

async function getSession(req) {
  try {
    const url = new URL("/api/auth/get-session", BASE_URL);
    const headers = new Headers();
    Object.entries(req.headers).forEach(([key, value]) => {
      if (value) headers.set(key, Array.isArray(value) ? value.join(",") : value);
    });
    const request = new Request(url.toString(), { method: "GET", headers });
    const response = await auth.handler(request);
    return await response.json();
  } catch {
    return null;
  }
}

async function verifySession(req, res, next) {
  const data = await getSession(req);
  if (data?.user) {
    req.user = data.user;
    next();
  } else {
    res.status(401).json({ message: "Unauthorized" });
  }
}

async function getLoggedInEmail(req) {
  const data = await getSession(req);
  return data?.user?.email || null;
}

// ─── CARS ROUTES ───────────────────────────────────────────

app.get("/api/cars", async (req, res) => {
  try {
    const { search, type } = req.query;
    const loggedInEmail = await getLoggedInEmail(req);
    const query = {};
    if (search) query.name = { $regex: search, $options: "i" };
    if (type && type !== "All") query.type = { $regex: `^${type}$`, $options: "i" };
    if (loggedInEmail) {
      query.$or = [
        { isUserAdded: { $ne: true } },
        { isUserAdded: true, ownerEmail: loggedInEmail },
      ];
    } else {
      query.isUserAdded = { $ne: true };
    }
    const cars = await db.collection("cars").find(query).toArray();
    res.json(cars);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/api/cars/featured", async (req, res) => {
  try {
    const loggedInEmail = await getLoggedInEmail(req);
    const query = {};
    if (loggedInEmail) {
      query.$or = [
        { isUserAdded: { $ne: true } },
        { isUserAdded: true, ownerEmail: loggedInEmail },
      ];
    } else {
      query.isUserAdded = { $ne: true };
    }
    const cars = await db.collection("cars").find(query).limit(6).toArray();
    res.json(cars);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/api/cars/:id", async (req, res) => {
  try {
    const car = await db.collection("cars").findOne({ _id: new ObjectId(req.params.id) });
    if (!car) return res.status(404).json({ message: "Car not found" });
    res.json(car);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post("/api/cars", verifySession, async (req, res) => {
  try {
    const car = {
      ...req.body,
      ownerEmail: req.user.email,
      ownerName: req.user.name,
      booking_count: 0,
      isUserAdded: true,
      createdAt: new Date(),
    };
    const result = await db.collection("cars").insertOne(car);
    res.json({ insertedId: result.insertedId });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put("/api/cars/:id", verifySession, async (req, res) => {
  try {
    const car = await db.collection("cars").findOne({ _id: new ObjectId(req.params.id) });
    if (!car) return res.status(404).json({ message: "Car not found" });
    if (car.ownerEmail !== req.user.email) return res.status(403).json({ message: "Forbidden" });
    const { name, type, price, description, image, location, status, seats } = req.body;
    await db.collection("cars").updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { name, type, price, description, image, location, status, seats } }
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete("/api/cars/:id", verifySession, async (req, res) => {
  try {
    const car = await db.collection("cars").findOne({ _id: new ObjectId(req.params.id) });
    if (!car) return res.status(404).json({ message: "Car not found" });
    if (car.ownerEmail !== req.user.email) return res.status(403).json({ message: "Forbidden" });
    await db.collection("cars").deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/api/my-cars", verifySession, async (req, res) => {
  try {
    const cars = await db.collection("cars").find({ ownerEmail: req.user.email }).toArray();
    res.json(cars);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ─── BOOKINGS ───────────────────────────────────────────────

app.post("/api/bookings", verifySession, async (req, res) => {
  try {
    const { carId, driverNeeded, note } = req.body;
    const car = await db.collection("cars").findOne({ _id: new ObjectId(carId) });
    if (!car) return res.status(404).json({ message: "Car not found" });
    const booking = {
      carId: new ObjectId(carId),
      carName: car.name,
      carImage: car.image,
      carType: car.type,
      pricePerDay: car.price,
      driverNeeded,
      note,
      userEmail: req.user.email,
      userName: req.user.name,
      status: "booked",
      bookedAt: new Date(),
    };
    await db.collection("bookings").insertOne(booking);
    await db.collection("cars").updateOne(
      { _id: new ObjectId(carId) },
      { $inc: { booking_count: 1 } }
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/api/bookings", verifySession, async (req, res) => {
  try {
    const bookings = await db.collection("bookings")
      .find({ userEmail: req.user.email })
      .sort({ bookedAt: -1 })
      .toArray();
    res.json(bookings);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete("/api/bookings/:id", verifySession, async (req, res) => {
  try {
    const booking = await db.collection("bookings").findOne({ _id: new ObjectId(req.params.id) });
    if (!booking) return res.status(404).json({ message: "Not found" });
    if (booking.userEmail !== req.user.email) return res.status(403).json({ message: "Forbidden" });
    await db.collection("bookings").deleteOne({ _id: new ObjectId(req.params.id) });
    await db.collection("cars").updateOne(
      { _id: booking.carId },
      { $inc: { booking_count: -1 } }
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/", (req, res) => res.send("DriveFleet API running"));

if (!isProduction) {
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

export default app;