const express = require("express");
const multer = require("multer");
const {
  registerHirer,
  loginHirer,
  verifyHirerOTP,
  forgotHirerPassword,
  resetHirerPassword,
  resendHirerOTP,
  updateHirerProfile,
  getHirerProfile,
  submitHirerSubmission,
  getAllHirerSubmissions,
  deleteHirerSubmission,
  updateHirerSubmission,
  getSubmissionsByHirerId,
} = require("../Controllers/hirerController");
const authHandler = require("../Middleware/authMiddleware");

const upload = multer({ storage: multer.memoryStorage() });
const hirerRouter = express.Router();

hirerRouter.post("/register", registerHirer);
hirerRouter.post("/login", loginHirer);
hirerRouter.post("/verify-otp", authHandler, verifyHirerOTP);
hirerRouter.post("/forgot-password", forgotHirerPassword);
hirerRouter.post("/reset-password/:token", resetHirerPassword);
hirerRouter.post("/resend-otp", authHandler, resendHirerOTP);
hirerRouter.put(
  "/update-profile",
  authHandler,
  upload.fields([{ name: "profilePic", maxCount: 1 }]),
  updateHirerProfile
);
hirerRouter.get("/get-profile", authHandler, getHirerProfile);
hirerRouter.post("/submit", authHandler, submitHirerSubmission);
hirerRouter.put(
  "/submissions/:submissionId",
  authHandler,
  updateHirerSubmission
);
hirerRouter.delete(
  "/submissions/:submissionId",
  authHandler,
  deleteHirerSubmission
);
hirerRouter.get("/submissions", authHandler, getAllHirerSubmissions);
hirerRouter.get("/hirer/:hirerId/submissions", authHandler, getSubmissionsByHirerId); // 

module.exports = hirerRouter;
