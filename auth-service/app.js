import express from "express";
import axios from "axios";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();
const app = express();

const errorHandlingMiddleware = (err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).send(err.message || "Internal server error");
};

app.use(errorHandlingMiddleware);
app.use(express.json());

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const { data } = await axios({
      method: "post",
      url: `${process.env.KEYCLOAK_AUTH_SERVER_URL}/realms/${process.env.KEYCLOAK_REALM}/protocol/openid-connect/token`,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      data: `grant_type=password&client_id=${process.env.KEYCLOAK_CLIENT_ID}&client_secret=${process.env.KEYCLOAK_CLIENT_SECRET}&username=${username}&password=${password}`,
    });
    const { access_token: accessToken, refresh_token: refreshToken } = data;
    res.json({
      accessToken,
      refreshToken,
      ...data
    });
  } catch (err) {
    console.error(err);
    res.status(401).send("Invalid credentials");
  }
});

app.post("/refreshToken", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const { data } = await axios({
      method: "post",
      url: `${process.env.KEYCLOAK_AUTH_SERVER_URL}/realms/${process.env.KEYCLOAK_REALM}/protocol/openid-connect/token`,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      data: `grant_type=refresh_token&client_id=${process.env.KEYCLOAK_CLIENT_ID}&client_secret=${process.env.KEYCLOAK_CLIENT_SECRET}&refresh_token=${refreshToken}`,
    });
    console.log({ data });
    const { access_token: accessToken } = data;
    let payload;
    if (accessToken) payload = jwt.decode(accessToken, { complete: true });
    res.json({ accessToken, refreshToken });
  } catch (error) {
    res.status(400).send(error.message);
  }
});

app.get("/verifyToken", async (req, res) => {
  try {
    const accessToken = req.headers.authorization.split(" ")[1];
    const { data } = await axios({
      method: "post",
      url: `${process.env.KEYCLOAK_AUTH_SERVER_URL}/realms/${process.env.KEYCLOAK_REALM}/protocol/openid-connect/token/introspect`,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Bearer ${accessToken}`,
      },
      data: `grant_type=password&client_id=${process.env.KEYCLOAK_CLIENT_ID}&client_secret=${process.env.KEYCLOAK_CLIENT_SECRET}&token=${accessToken}`,
    });
    const { active } = data;
    if (!active) throw new Error({ error: "invalid token" });
    res.send(data);
  } catch (error) {
    console.log(error.message);
    res.status(401).send(error.message);
  }
});

app.get("/signout", async (req, res) => {
  try {
    const refreshToken = req.session.refreshToken;
    const url = `${process.env.KEYCLOAK_AUTH_SERVER_URL}/realms/${process.env.KEYCLOAK_REALM}/protocol/openid-connect/revoke`;
    const { data } = await axios({
      method: "post",
      url,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      data: `client_id=${process.env.KEYCLOAK_CLIENT_ID}&client_secret=${process.env.KEYCLOAK_CLIENT_SECRET}&token=${refreshToken}&token_type_hint=refresh_token`,
    });
    res.send({ data });
  } catch (err) {
    res.status(500).send("Error logging out");
  }
});

/** ----- admin routes ------- */
app.patch("/suspend", async (req, res) => {
  const userId = req.body.userId;
  const adminToken = req.kauth.grant.access_token.token;
  const userUpdateUrl = `${process.env.KEYCLOAK_AUTH_SERVER_URL}/admin/realms/${process.env.KEYCLOAK_REALM}/users/${userId}`;
  try {
    await axios.put(
      userUpdateUrl,
      {
        enabled: false,
      },
      {
        headers: {
          Authorization: `Bearer ${adminToken}`,
          "Content-Type": "application/json",
        },
      }
    );
    res.send(`User with ID '${userId}' updated successfully.`);
  } catch (error) {
    console.error(`Failed to update user with ID '${userId}':`, error);
  }
});

const port = process.env.PORT || 3001;

app.listen(port, () => {
  console.log(`Auth-service listening on port ${port}`);
});
