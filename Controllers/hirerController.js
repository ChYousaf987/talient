const handler = require("express-async-handler");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const cloudinary = require("cloudinary").v2;
const Hirer = require("../Models/hirerModel");
const HirerSubmission = require("../Models/hirerSubmissionModel");
const { Readable } = require("stream");

// Configure Cloudinary directly
console.log("Cloudinary Config in Controller:", {
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const generateOTP = () => Math.floor(100000 + Math.random() * 900000);

const sendOTP = (email, otp) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.MAIL_USER,
      pass: process.env.MAIL_PASS,
    },
  });

  const mailOptions = {
    from: '"Showbiz App" <' + process.env.MAIL_USER + ">",
    to: email,
    subject: "Verify Your Showbiz App Account",
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; color: #333;">
        <h2 style="color: #1a73e8;">Welcome to Showbiz App!</h2>
        <p>Thank you for joining Showbiz App. To complete your registration, please use the following One-Time Password (OTP):</p>
        <h3 style="background: #f1f3f4; padding: 10px; border-radius: 5px; text-align: center; color: #1a73e8;">
          ${otp}
        </h3>
        <p>This OTP is valid for 10 minutes. Please do not share it with anyone.</p>
        <p>If you did not request this OTP, please ignore this email or contact our support team at support@showbizapp.com.</p>
        <p style="margin-top: 20px;">Best regards,<br>The Showbiz App Team</p>
        <hr style="border-top: 1px solid #ddd; margin: 20px 0;">
        <p style="font-size: 12px; color: #777;">
          © ${new Date().getFullYear()} Showbiz App. All rights reserved.<br>
          <a href="https://www.showbizapp.com" style="color: #1a73e8; text-decoration: none;">Visit our website</a> | 
          <a href="https://www.showbizapp.com/privacy" style="color: #1a73e8; text-decoration: none;">Privacy Policy</a>
        </p>
      </div>
    `,
  };
  transporter.sendMail(mailOptions, (error) => {
    if (error) {
      console.error("Email sending error:", error);
      throw new Error("Failed to send OTP");
    }
    console.log(`OTP sent to email: ${email} | OTP: ${otp}`);
  });
};

const generateToken = (id, role) => {
  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET is not defined");
  }
  console.log("Generating token for ID:", id);
  return jwt.sign({ id, role }, process.env.JWT_SECRET, {
    expiresIn: "15d",
  });
};

// Register Hirer
const registerHirer = handler(async (req, res) => {
  const { name, email, phone, gender, role, password, deviceToken } = req.body;

  if (!name || !email || !phone || !gender || !role || !password) {
    res.status(400);
    throw new Error("All fields are required");
  }

  const existing = await Hirer.findOne({ email });
  if (existing && existing.isVerified) {
    res.status(409);
    throw new Error("Email already registered");
  }

  const hashedPass = await bcrypt.hash(password, 10);
  const otp = generateOTP();
  let createdHirer;

  if (existing && !existing.isVerified) {
    createdHirer = await Hirer.findOneAndUpdate(
      { email },
      {
        name,
        phone,
        gender,
        role,
        password: hashedPass,
        otp,
        isVerified: false,
        deviceToken,
      },
      { new: true }
    );
  } else {
    createdHirer = await Hirer.create({
      name,
      email,
      phone,
      gender,
      role,
      password: hashedPass,
      otp,
      isVerified: false,
      deviceToken,
    });
  }

  sendOTP(email, otp);

  const token = generateToken(createdHirer._id);

  res.json({
    message: "OTP sent to email. Please verify to complete registration.",
    userId: createdHirer._id,
    token,
  });
});

// Verify OTP
const verifyHirerOTP = handler(async (req, res) => {
  const { otp } = req.body;

  if (!req.user) {
    res.status(401);
    throw new Error("User not authenticated");
  }

  const user = await Hirer.findById(req.user._id);
  if (!user) {
    res.status(404);
    throw new Error("Hirer not found");
  }

  if (String(user.otp) !== String(otp)) {
    res.status(401);
    throw new Error("Invalid OTP");
  }

  user.otp = null;
  user.isVerified = true;
  await user.save();

  res.json({
    _id: user._id,
    name: user.name,
    email: user.email,
    phone: user.phone,
    role: user.role,
    token: generateToken(user._id),
    message: "OTP verified successfully",
  });
});

// Login Hirer
const loginHirer = handler(async (req, res) => {
  const { email, password, deviceToken } = req.body;

  const hirer = await Hirer.findOne({ email });
  if (!hirer || !(await bcrypt.compare(password, hirer.password))) {
    res.status(401);
    throw new Error("Invalid email or password");
  }

  if (!hirer.isVerified) {
    res.status(403);
    throw new Error("Please verify your OTP before logging in");
  }

  // Update deviceToken if provided
  if (deviceToken) {
    hirer.deviceToken = deviceToken;
    await hirer.save();
  }

  res.json({
    _id: hirer._id,
    name: hirer.name,
    email: hirer.email,
    phone: hirer.phone,
    role: hirer.role,
    token: generateToken(hirer._id),
  });
});

const forgotHirerPassword = handler(async (req, res) => {
  const { email } = req.body;
  const user = await Hirer.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  const resetToken = generateOTP();
  user.resetToken = resetToken;
  user.resetTokenExpire = Date.now() + 10 * 60 * 1000;
  await user.save();

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.MAIL_USER,
      pass: process.env.MAIL_PASS,
    },
  });

  transporter.sendMail(
    {
      from: process.env.MAIL_USER,
      to: email,
      subject: "Password Reset",
      html: `<p>Your reset code is: <strong>${resetToken}</strong>. It expires in 10 minutes.</p>`,
    },
    (error) => {
      if (error) {
        console.error("Email sending error:", error);
        res.status(500);
        throw new Error("Failed to send reset code");
      }
      console.log(
        `Password reset OTP sent to email: ${email} | OTP: ${resetToken}`
      );
      res.json({ message: "Reset code sent to email" });
    }
  );
});

// Reset Hirer Password
const resetHirerPassword = handler(async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  const user = await Hirer.findOne({
    resetToken: token,
    resetTokenExpire: { $gt: Date.now() },
  });

  if (!user) {
    res.status(400);
    throw new Error("Invalid or expired reset token");
  }

  user.password = await bcrypt.hash(newPassword, 10);
  user.resetToken = null;
  user.resetTokenExpire = null;
  await user.save();

  res.json({ message: "Password reset successfully" });
});

// Resend OTP
const resendHirerOTP = handler(async (req, res) => {
  const user = await Hirer.findById(req.user._id);

  if (!user) {
    res.status(404);
    throw new Error("Hirer not found");
  }

  if (user.isVerified) {
    res.status(400);
    throw new Error("Hirer is already verified");
  }

  const otp = generateOTP();
  user.otp = otp;
  await user.save();

  sendOTP(user.email, otp);

  res.json({ message: "New OTP sent to email" });
});

// Update Hirer Profile
const updateHirerProfile = handler(async (req, res) => {
  const user_id = req.user._id;
  const { name, email, phone, age, country, city, deviceToken } = req.body;
  const { profilePic } = req.files || {};

  console.log("Request body:", req.body);
  console.log("Request files:", req.files);

  try {
    // Fetch existing hirer
    const currentUser = await Hirer.findById(user_id);
    if (!currentUser) {
      res.status(404);
      throw new Error("Hirer not found");
    }

    // Validate email uniqueness
    if (email && email !== currentUser.email) {
      const existing = await Hirer.findOne({ email });
      if (existing && existing._id.toString() !== user_id.toString()) {
        res.status(409);
        throw new Error("Email already in use");
      }
    }

    // Initialize updates
    const updateFields = {};

    // Helper function to check if a value is non-empty
    const isNonEmpty = (value) =>
      value !== undefined && value !== null && value !== "";

    // Include non-empty fields in updates
    if (isNonEmpty(name)) updateFields.name = name;
    if (isNonEmpty(email)) updateFields.email = email;
    if (isNonEmpty(phone)) updateFields.phone = phone;
    if (isNonEmpty(age)) updateFields.age = age;
    if (isNonEmpty(country)) updateFields.country = country;
    if (isNonEmpty(city)) updateFields.city = city;
    if (isNonEmpty(deviceToken)) updateFields.deviceToken = deviceToken;

    // Handle profile picture upload
    if (profilePic) {
      console.log("Uploading profile picture to Cloudinary...");
      console.log("Profile picture buffer size:", profilePic[0].buffer.length);

      // Delete existing profile picture from Cloudinary if it exists
      if (currentUser.profilePic_id) {
        console.log(
          "Deleting existing profile picture with ID:",
          currentUser.profilePic_id
        );
        await cloudinary.uploader.destroy(currentUser.profilePic_id);
      }

      // Upload new profile picture to Cloudinary using buffer
      const uploadResult = await new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          {
            folder: `hirer_profiles/${user_id}`,
            resource_type: "image",
          },
          (error, result) => {
            if (error) {
              console.error("Cloudinary upload error:", error);
              reject(new Error("Failed to upload profile picture"));
            } else {
              console.log("Cloudinary upload result:", result);
              resolve(result);
            }
          }
        );

        // Create a readable stream from the buffer and pipe it to Cloudinary
        const bufferStream = new Readable();
        bufferStream.push(profilePic[0].buffer);
        bufferStream.push(null); // Signal end of stream
        bufferStream.pipe(uploadStream);
      });

      updateFields.profilePic_url = uploadResult.secure_url;
      updateFields.profilePic_id = uploadResult.public_id;
    }

    // Check if there are any fields to update
    if (Object.keys(updateFields).length === 0) {
      res.status(400);
      throw new Error(
        "At least one field or profile picture must be provided for update"
      );
    }

    // Update hirer profile
    console.log("Updating hirer profile with fields:", updateFields);
    const updatedProfile = await Hirer.findByIdAndUpdate(
      user_id,
      { $set: updateFields },
      { new: true }
    ).select("-password -otp -resetToken -resetTokenExpire");

    if (!updatedProfile) {
      res.status(500);
      throw new Error("Failed to update profile");
    }

    console.log("Updated profile:", updatedProfile);

    res.json({
      message: "Profile updated successfully",
      profile: updatedProfile,
    });
  } catch (error) {
    console.error("Error handling profile update:", error.message);
    res.status(500);
    throw new Error("Something went wrong: " + error.message);
  }
});

// Get Hirer Profile
const getHirerProfile = handler(async (req, res) => {
  const user = await Hirer.findById(req.user._id).select(
    "-password -otp -resetToken -resetTokenExpire"
  );

  if (!user) {
    res.status(404);
    throw new Error("Hirer not found");
  }

  res.json({
    message: "Profile retrieved successfully",
    profile: {
      ...user._doc,
      profilePic_url: user.profilePic_url || null,
    },
  });
});

const submitHirerSubmission = handler(async (req, res) => {
  const { subject, description } = req.body;
  const user_id = req.user._id;

  if (!subject || !description) {
    res.status(400);
    throw new Error("Subject and description are required");
  }

  // Verify the hirer exists before creating the submission
  const hirer = await Hirer.findById(user_id);
  if (!hirer) {
    res.status(404);
    throw new Error("Hirer not found");
  }

  const submission = await HirerSubmission.create({
    hirer: user_id,
    subject,
    description,
  });

  res.status(201).json({
    message: "Submission created successfully",
    submission: {
      _id: submission._id,
      hirer: submission.hirer,
      subject: submission.subject,
      description: submission.description,
      createdAt: submission.createdAt,
    },
  });
});

// Update Hirer Submission
const updateHirerSubmission = handler(async (req, res) => {
  const { submissionId } = req.params;
  const { subject, description } = req.body;
  const user_id = req.user._id;

  // Check if submission exists and belongs to the user
  const submission = await HirerSubmission.findOne({
    _id: submissionId,
    hirer: user_id,
  });

  if (!submission) {
    res.status(404);
    throw new Error(
      "Submission not found or you don't have permission to update it"
    );
  }

  // Validate input
  if (!subject && !description) {
    res.status(400);
    throw new Error(
      "At least one field (subject or description) must be provided"
    );
  }

  // Prepare update fields
  const updateFields = {};
  if (subject) updateFields.subject = subject;
  if (description) updateFields.description = description;

  // Update submission
  const updatedSubmission = await HirerSubmission.findByIdAndUpdate(
    submissionId,
    { $set: updateFields },
    { new: true }
  ).populate("hirer", "name profilePic_url");

  res.json({
    message: "Submission updated successfully",
    submission: {
      _id: updatedSubmission._id,
      hirer: {
        _id: updatedSubmission.hirer._id,
        name: updatedSubmission.hirer.name,
        profilePic: updatedSubmission.hirer.profilePic_url || null,
      },
      subject: updatedSubmission.subject,
      description: updatedSubmission.description,
      createdAt: updatedSubmission.createdAt,
    },
  });
});

// Delete Hirer Submission
const deleteHirerSubmission = handler(async (req, res) => {
  const { submissionId } = req.params;
  const user_id = req.user._id;

  // Check if submission exists and belongs to the user
  const submission = await HirerSubmission.findOne({
    _id: submissionId,
    hirer: user_id,
  });

  if (!submission) {
    res.status(404);
    throw new Error(
      "Submission not found or you don't have permission to delete it"
    );
  }

  // Delete submission
  await HirerSubmission.findByIdAndDelete(submissionId);

  res.json({
    message: "Submission deleted successfully",
    submissionId,
  });
});

// Get all hirer submissions with hirer details
const getAllHirerSubmissions = handler(async (req, res) => {
  console.log("Authenticated user:", req.user._id);

  // Fetch submissions with either hirer or talent field
  const submissions = await HirerSubmission.find({
    $or: [{ hirer: { $exists: true } }, { talent: { $exists: true } }],
  })
    .populate({ path: "hirer", select: "name profilePic_url role" })
    .populate({
      path: "talent",
      select: "name profilePic",
      strictPopulate: false,
    })
    .select("subject description createdAt hirer talent") // Explicitly select createdAt
    .lean();

  console.log("Raw submissions:", submissions);

  if (!submissions || submissions.length === 0) {
    res.status(404);
    throw new Error("No submissions found");
  }

  // Fetch authenticated user's profile as fallback
  const currentUser = await Hirer.findById(req.user._id)
    .select("name profilePic_url role")
    .lean();

  // Map submissions to response format
  const formattedSubmissions = submissions.map((submission) => {
    let hirerData = submission.hirer || submission.talent;

    // Fallback to current user's profile if hirer/talent is null/undefined or matches req.user._id
    if (
      !hirerData &&
      (!submission.hirer ||
        !submission.talent ||
        String(submission.hirer) === String(req.user._id) ||
        String(submission.talent) === String(req.user._id))
    ) {
      hirerData = currentUser;
    }

    return {
      _id: submission._id,
      subject: submission.subject,
      description: submission.description,
      createdAt: submission.createdAt || new Date(), // Fallback to current date if createdAt is missing
      hirer: {
        name: hirerData?.name || "Unknown Hirer",
        profilePic: hirerData?.profilePic_url || hirerData?.profilePic || null,
        role: hirerData?.role || "Unknown Role",
      },
    };
  });

  res.json({
    message: "Submissions retrieved successfully",
    submissions: formattedSubmissions,
  });
});
// Get Hirer Submission by ID
// Get Submissions by Hirer ID
const getSubmissionsByHirerId = handler(async (req, res) => {
  const { hirerId } = req.params;
  const user_id = req.user._id;

  // Ensure the authenticated user is either the hirer or an admin
  const user = await Hirer.findById(user_id);
  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  if (String(hirerId) !== String(user_id) && user.role !== "admin") {
    res.status(403);
    throw new Error("Not authorized to view submissions for this hirer");
  }

  // Fetch submissions for the specified hirer
  const submissions = await HirerSubmission.find({ hirer: hirerId })
    .populate("hirer", "name profilePic_url")
    .lean();

  if (!submissions || submissions.length === 0) {
    res.status(404);
    throw new Error("No submissions found for this hirer");
  }

  // Format submissions for response
  const formattedSubmissions = submissions.map((submission) => ({
    _id: submission._id,
    hirer: {
      _id: submission.hirer._id,
      name: submission.hirer.name,
      profilePic: submission.hirer.profilePic_url || null,
    },
    subject: submission.subject,
    description: submission.description,
    createdAt: submission.createdAt,
  }));

  res.json({
    message: "Submissions retrieved successfully",
    submissions: formattedSubmissions,
  });
});

module.exports = {
  registerHirer,
  verifyHirerOTP,
  loginHirer,
  forgotHirerPassword,
  resetHirerPassword,
  resendHirerOTP,
  updateHirerProfile,
  getHirerProfile,
  submitHirerSubmission,
  updateHirerSubmission,
  deleteHirerSubmission,
  getAllHirerSubmissions,
  getSubmissionsByHirerId,
};
