const jwt = require("jsonwebtoken");
const handler = require("express-async-handler");
const Talent = require("../Models/talentModel");
const Hirer = require("../Models/hirerModel");

const authHandler = handler(async (req, res, next) => {
  const authHeader =
    req.headers["authorization"] || req.headers["Authorization"];

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401);
    throw new Error("Authorization token missing or malformed");
  }

  const token = authHeader.replace("Bearer ", "");
  if (!token) {
    res.status(401);
    throw new Error("Token not provided");
  }

  const tokenParts = token.split(".");
  if (tokenParts.length !== 3) {
    console.error("Invalid token format:", token);
    res.status(401);
    throw new Error("Invalid token format");
  }

  try {
    console.log("Verifying token:", token);
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log("Decoded token:", decoded);

    const [talent, hirer] = await Promise.all([
      Talent.findById(decoded.id).select("-password"),
      Hirer.findById(decoded.id).select("-password"),
    ]);

    const user = talent || hirer;

    if (!user) {
      console.error("User not found for ID:", decoded.id);
      res.status(401);
      throw new Error("User not found");
    }

    console.log("Authenticated user:", {
      email: user.email,
      role: user.role,
      id: user._id,
    });

    req.user = { _id: user._id, role: user.role, email: user.email };
    next();
  } catch (err) {
    console.error("Token verification error:", err.message);
    if (err.name === "TokenExpiredError") {
      res.status(401);
      throw new Error("Token has expired");
    } else if (err.name === "JsonWebTokenError") {
      res.status(401);
      throw new Error("Invalid token");
    } else {
      res.status(401);
      throw new Error("Token verification failed");
    }
  }
});

module.exports = authHandler;
