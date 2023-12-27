const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const cors = require("cors");

app.use(express.json());
app.use(cors());
const users = [
  {
    id: "1",
    username: "john",
    password: "john2001",
  },
  {
    id: "2",
    username: "jane",
    password: "jane2001",
  },
];

let refreshTokens = [];

const generateAccessToken = (user) =>
  jwt.sign({ id: user.id }, "secretKey", { expiresIn: "2s" });

const generateRefreshToken = (user) => jwt.sign({ id: user.id }, "refreshKey");

const verify = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(" ")[1];

    jwt.verify(token, "secretKey", (err, user) => {
      if (err) {
        res.status(403).json("Invalid token");
      } else {
        req.user = user;
        next();
      }
    });
  } else {
    res.status(401).json("You are not authenticated");
  }
};

app.post("/refresh", (req, res) => {
  const refreshToken = req.body.token;

  if (!refreshToken) {
    return res.status(401).json("you are not authenticated");
  }
  if (!refreshTokens.includes(refreshToken)) {
    return res.status(403).json("refresh token is invalid");
  }

  jwt.verify(refreshToken, "refreshKey", (err, user) => {
    err && res.json(err);
    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);
    console.log(newAccessToken);
    refreshTokens.push(newRefreshToken);
    res.status(200).json({
      newAccessToken,
      newRefreshToken,
    });
  });
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => {
    return username === u.username && password === u.password;
  });
  if (user) {
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    refreshTokens.push(refreshToken);
    res.status(200).json({
      id: user.id,
      username: user.username,
      accessToken,
      refreshToken,
    });
  } else {
    res.status(404).json({ message: "failed" });
  }
});

app.delete("/user/:id", verify, (req, res) => {
  if (req.user.id === req.params.id) {
    res.status(200).json("successfully deleted");
  } else {
    res.status(403).json("you are not allowed delete");
  }
});

app.post("/logout", verify, (req, res) => {
  const refreshToken = req.body.token;
  refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
  res.status(200).json("logged out successfully");
});

app.listen(4000, () => console.log("server listening on 4000"));
