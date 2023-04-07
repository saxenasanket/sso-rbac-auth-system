import express from "express";
import dotenv from "dotenv";
import redis from "ioredis";
dotenv.config();

const redisClient = redis.createClient({
  host: "127.0.0.1", // Replace with your Redis server's IP address or hostname
  port: 6379, // Replace with your Redis server's port (default is 6379)
});

redisClient.on("error", (error) => {
  console.error("Redis client error:", error);
});

redisClient.on("end", () => {
  console.log("Redis client connection closed");
});

const app = express();
const errorHandlingMiddleware = (err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).send(err.message || "Internal server error");
};

app.use(async (req, res, next) => {
  const token = req.headers.authorization.split(" ")[1];
  const userDataString = await redisClient.get(token);
  if (userDataString) {
    req.user = JSON.parse(userDataString);
    next();
  } else {
    res.status(401).send("Invalid or expired user key");
  }
});

const authorizationMiddleware = (requiredRole) => {
  return async (req, res, next) => {
    try {
      const availableRoles = req.user.realm_access.roles;
      if (!availableRoles.includes(requiredRole)) throw new Error();
      next();
    } catch (err) {
      res.status(403).send({ error: "access denied" });
    }
  };
};

app.use(errorHandlingMiddleware);
app.use(express.json());

app.get("/authenticate", (req, res) => {
  res.send("success");
});

app.get("/authorize", authorizationMiddleware("admin1"), (req, res) => {
  res.send("success");
});

const port = process.env.PORT || 3002;
app.listen(port, () => {
  console.log(`Auth-service listening on port ${port}`);
});
