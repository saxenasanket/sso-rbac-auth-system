import express from "express";
import rateLimit from "express-rate-limit";
import axios from "axios";
import { createProxyMiddleware } from "http-proxy-middleware";
import redis from "ioredis";

// Create a Redis client
const redisClient = redis.createClient({
  host: "127.0.0.1",
  port: 6379, 
});

redisClient.on("error", (error) => {
  console.error("Redis client error:", error);
});

redisClient.on("end", () => {
  console.log("Redis client connection closed");
});


const app = express();
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // limit each IP to 100 requests per windowMs
  message: "Too many requests, please try again later.",
});
app.use(apiLimiter);

const authUrl = "http://localhost:3001"; 

const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).send("Missing authorization header");
  const token = authHeader.split(" ")[1];
  let cachedData = await redisClient.get(token);
  if (cachedData) {
    return next();
  }
  try {
    const response = await axios.get(`${authUrl}/verifyToken`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const { data } = response;
    await redisClient.set(token, JSON.stringify(data));
    next();
  } catch (error) {
    console.log({ error });
    res.status(401).send("Invalid or expired token");
  }
};

const service1Url = "http://localhost:3002";

// Set up proxy middleware for each service

app.use(
  "/api/auth",
  createProxyMiddleware({
    target: authUrl,
    changeOrigin: true,
    pathRewrite: {
      "^/api/auth": "",
    },
    onProxyReq: (proxyReq, req, res) => {
      if (req.method === "POST" && req.headers["content-type"]) {
        proxyReq.setHeader("Content-Type", req.headers["content-type"]);
      }
    },
  })
);


app.use(
  "/api/service1",
  authMiddleware,
  createProxyMiddleware({
    target: service1Url,
    changeOrigin: true,
    pathRewrite: {
      "^/api/service1": "",
    },
    onProxyReq: (proxyReq, req, res) => {
      if (req.method === "POST" && req.headers["content-type"]) {
        proxyReq.setHeader("Content-Type", req.headers["content-type"]);
      }
    },
  })
);



const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log(`API Gateway listening on port ${port}`);
});
