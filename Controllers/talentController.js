const handler = require("express-async-handler");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const cloudinary = require("cloudinary").v2;
const talentModel = require("../Models/talentModel");
const talentSubmissionModel = require("../Models/hirerSubmissionModel");
const hiringRequestModel = require("../Models/hiringRequestModel");
const { Readable } = require("stream");

// Configure Cloudinary
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

// Register Talent
const registerTalent = handler(async (req, res) => {
  const { name, email, phone, gender, role, password, deviceToken } = req.body;

  if (!name || !email || !phone || !gender || !role || !password) {
    res.status(400);
    throw new Error("All fields are required");
  }

  const existing = await talentModel.findOne({ email });
  if (existing && existing.isVerified) {
    res.status(409);
    throw new Error("Email already registered");
  }

  const hashedPass = await bcrypt.hash(password, 10);
  const otp = generateOTP();
  let createdTalent;

  if (existing && !existing.isVerified) {
    createdTalent = await talentModel.findOneAndUpdate(
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
    createdTalent = await talentModel.create({
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

  const token = generateToken(createdTalent._id, createdTalent.role);

  res.json({
    message: "OTP sent to email. Please verify to complete registration.",
    userId: createdTalent._id,
    token,
  });
});

// Login Talent
const loginTalent = handler(async (req, res) => {
  const { email, password, deviceToken } = req.body;

  const talent = await talentModel.findOne({ email });
  if (!talent || !(await bcrypt.compare(password, talent.password))) {
    res.status(401);
    throw new Error("Invalid email or password");
  }

  if (!talent.isVerified) {
    res.status(403);
    throw new Error("Please verify your OTP before logging in");
  }

  // Update deviceToken if provided
  if (deviceToken) {
    talent.deviceToken = deviceToken;
    await talent.save();
  }

  res.json({
    _id: talent._id,
    name: talent.name,
    email: talent.email,
    phone: talent.phone,
    role: talent.role,
    token: generateToken(talent._id, talent.role),
  });
});

// Verify OTP
const verifyTalentOTP = handler(async (req, res) => {
  const { otp } = req.body;

  if (!req.user) {
    res.status(401);
    throw new Error("User not authenticated");
  }

  const user = await talentModel.findById(req.user._id);
  if (!user) {
    res.status(404);
    throw new Error("Talent not found");
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
    token: generateToken(user._id, user.role),
    message: "OTP verified successfully",
  });
});

// Forgot Password
const forgotTalentPassword = handler(async (req, res) => {
  const { email } = req.body;
  const user = await talentModel.findOne({ email });

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

// Reset Password
const resetTalentPassword = handler(async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  const user = await talentModel.findOne({
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
const resendTalentOTP = handler(async (req, res) => {
  const user = await talentModel.findById(req.user._id);

  if (!user) {
    res.status(404);
    throw new Error("Talent not found");
  }

  if (user.isVerified) {
    res.status(400);
    throw new Error("Talent is already verified");
  }

  const otp = generateOTP();
  user.otp = otp;
  await user.save();

  sendOTP(user.email, otp);

  res.json({ message: "New OTP sent to email" });
});

// Update Talent Profile
const updateTalentProfile = handler(async (req, res) => {
  const user_id = req.user._id;
  const {
    name,
    email,
    phone,
    age,
    height,
    weight,
    bodyType,
    skinTone,
    language,
    skills,
    makeoverNeeded,
    willingToWorkAsExtra,
    aboutYourself,
    deviceToken,
  } = req.body || {};
  const files = req.files || {};

  console.log("Request body:", req.body);
  console.log("Request files:", req.files);

  try {
    // Fetch existing talent
    const currentUser = await talentModel.findById(user_id);
    if (!currentUser) {
      res.status(404);
      throw new Error("Talent not found");
    }

    // Validate email uniqueness
    if (email && email !== currentUser.email) {
      const existing = await talentModel.findOne({ email });
      if (existing && existing._id.toString() !== user_id.toString()) {
        res.status(409);
        throw new Error("Email already in use");
      }
    }

    // Initialize updates
    const updateFields = {};
    const images = currentUser.images ? { ...currentUser.images } : {};

    // Helper function to check if a value is non-empty
    const isNonEmpty = (value) =>
      value !== undefined && value !== null && value !== "";

    // Include non-empty fields in updates
    if (isNonEmpty(name)) updateFields.name = name;
    if (isNonEmpty(email)) updateFields.email = email;
    if (isNonEmpty(phone)) updateFields.phone = phone;
    if (isNonEmpty(age)) updateFields.age = parseInt(age);
    if (isNonEmpty(height)) updateFields.height = height;
    if (isNonEmpty(weight)) updateFields.weight = weight;
    if (isNonEmpty(bodyType)) updateFields.bodyType = bodyType;
    if (isNonEmpty(skinTone)) updateFields.skinTone = skinTone;
    if (isNonEmpty(language)) updateFields.language = language;
    if (isNonEmpty(skills)) updateFields.skills = skills;
    if (isNonEmpty(makeoverNeeded))
      updateFields.makeoverNeeded =
        makeoverNeeded === "true" || makeoverNeeded === true;
    if (isNonEmpty(willingToWorkAsExtra))
      updateFields.willingToWorkAsExtra =
        willingToWorkAsExtra === "true" || willingToWorkAsExtra === true;
    if (isNonEmpty(aboutYourself)) updateFields.aboutYourself = aboutYourself;
    if (isNonEmpty(deviceToken)) updateFields.deviceToken = deviceToken;

    // Handle image uploads
    const imageFields = ["front", "left", "right", "profilePic"];
    for (const field of imageFields) {
      if (files[field] && files[field][0]) {
        console.log(`Uploading ${field} image to Cloudinary...`);
        console.log(`Image buffer size: ${files[field][0].buffer.length}`);

        // Delete existing image from Cloudinary if it exists
        if (currentUser.images && currentUser.images[field]?.id) {
          console.log(
            `Deleting existing ${field} image with ID: ${currentUser.images[field].id}`
          );
          await cloudinary.uploader.destroy(currentUser.images[field].id);
        }

        // Upload new image
        const uploadResult = await new Promise((resolve, reject) => {
          const uploadStream = cloudinary.uploader.upload_stream(
            {
              folder: `talent_profiles/${user_id}`,
              resource_type: "image",
            },
            (error, result) => {
              if (error) {
                console.error(`Cloudinary upload error for ${field}:`, error);
                reject(new Error(`Failed to upload ${field} image`));
              } else {
                console.log(`Cloudinary upload result for ${field}:`, result);
                resolve(result);
              }
            }
          );

          const bufferStream = new Readable();
          bufferStream.push(files[field][0].buffer);
          bufferStream.push(null);
          bufferStream.pipe(uploadStream);
        });

        images[field] = {
          url: uploadResult.secure_url,
          id: uploadResult.public_id,
        };
      }
    }

    // Handle video upload
    if (files.video && files.video[0]) {
      console.log("Uploading video to Cloudinary...");
      console.log(`Video buffer size: ${files.video[0].buffer.length}`);

      // Delete existing video from Cloudinary if it exists
      if (currentUser.video?.id) {
        console.log(`Deleting existing video with ID: ${currentUser.video.id}`);
        await cloudinary.uploader.destroy(currentUser.video.id, {
          resource_type: "video",
        });
      }

      // Upload new video
      const uploadResult = await new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          {
            folder: `talent_profiles/${user_id}`,
            resource_type: "video",
          },
          (error, result) => {
            if (error) {
              console.error("Cloudinary upload error for video:", error);
              reject(new Error("Failed to upload video"));
            } else {
              console.log("Cloudinary upload result for video:", result);
              resolve(result);
            }
          }
        );

        const bufferStream = new Readable();
        bufferStream.push(files.video[0].buffer);
        bufferStream.push(null);
        bufferStream.pipe(uploadStream);
      });

      updateFields.video = {
        url: uploadResult.secure_url,
        id: uploadResult.public_id,
      };
    }

    if (Object.keys(images).length > 0) {
      updateFields.images = images;
    }

    if (Object.keys(updateFields).length === 0) {
      res.status(400);
      throw new Error(
        "At least one field, image, or video must be provided for update"
      );
    }

    // Update talent profile
    console.log("Updating talent profile with fields:", updateFields);
    const updatedProfile = await talentModel
      .findByIdAndUpdate(user_id, { $set: updateFields }, { new: true })
      .select("-password -otp -resetToken -resetTokenExpire");

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

// Get Talent Profile
const getTalentProfile = handler(async (req, res) => {
  const user = await talentModel
    .findById(req.user._id)
    .select("-password -otp -resetToken -resetTokenExpire");

  if (!user) {
    res.status(404);
    throw new Error("Talent not found");
  }

  res.json({
    message: "Profile retrieved successfully",
    profile: {
      ...user._doc,
      images: user.images || {},
      video: user.video || null,
      makeoverNeeded: user.makeoverNeeded || false,
      willingToWorkAsExtra: user.willingToWorkAsExtra || false,
      aboutYourself: user.aboutYourself || "",
    },
  });
});

// Get All Talents
const getAllTalents = handler(async (req, res) => {
  console.log("Authenticated user:", req.user._id);

  // Check if user is a Hirer
  if (!req.user || req.user.userType !== "Hirer") {
    res.status(403);
    throw new Error("Only hirers can view all talents");
  }

  // Fetch all talents with complete data
  const talents = await talentModel
    .find({
      name: { $exists: true, $ne: null, $ne: "" },
      role: { $exists: true, $ne: null, $ne: "" },
      gender: { $exists: true, $ne: null, $ne: "" },
      age: { $exists: true, $ne: null },
      height: { $exists: true, $ne: null, $ne: "" },
      weight: { $exists: true, $ne: null, $ne: "" },
      bodyType: { $exists: true, $ne: null, $ne: "" },
      skinTone: { $exists: true, $ne: null, $ne: "" },
      language: { $exists: true, $ne: null, $ne: "" },
      skills: { $exists: true, $ne: null, $ne: "" },
      "images.front.url": { $exists: true, $ne: null, $ne: "" },
      "images.left.url": { $exists: true, $ne: null, $ne: "" },
      "images.right.url": { $exists: true, $ne: null, $ne: "" },
      "video.url": { $exists: true, $ne: null, $ne: "" },
      makeoverNeeded: { $exists: true, $ne: null },
      willingToWorkAsExtra: { $exists: true, $ne: null },
      aboutYourself: { $exists: true, $ne: null, $ne: "" },
      deviceToken: { $exists: true, $ne: null, $ne: "" },
      createdAt: { $exists: true, $ne: null },
      updatedAt: { $exists: true, $ne: null },
    })
    .select(
      "name email phone role gender age height weight bodyType skinTone language skills images.profilePic images.front images.left images.right video makeoverNeeded willingToWorkAsExtra aboutYourself deviceToken createdAt updatedAt"
    )
    .lean();

  if (!talents || talents.length === 0) {
    res.status(404);
    throw new Error("No talents with complete data found");
  }

  // Fetch accepted hiring requests for the authenticated hirer
  const acceptedRequests = await hiringRequestModel
    .find({
      hirer: req.user._id,
      status: "Accepted",
    })
    .select("talent")
    .lean();

  // Create a Set of talent IDs with accepted requests
  const connectedTalentIds = new Set(
    acceptedRequests.map((request) => request.talent.toString())
  );

  // Format talents for response, including email and phone for all talents
  const formattedTalents = talents.map((talent) => {
    const isConnected = connectedTalentIds.has(talent._id.toString());
    return {
      _id: talent._id,
      name: talent.name,
      role: talent.role,
      gender: talent.gender,
      deviceToken: talent.deviceToken,
      age: talent.age,
      height: talent.height,
      weight: talent.weight,
      bodyType: talent.bodyType,
      skinTone: talent.skinTone,
      language: Array.isArray(talent.language)
        ? talent.language.join(", ")
        : talent.language,
      skills: Array.isArray(talent.skills)
        ? talent.skills.join(", ")
        : talent.skills,
      profilePic: talent.images?.profilePic?.url || null,
      frontImage: talent.images.front.url,
      leftImage: talent.images.left.url,
      rightImage: talent.images.right.url,
      video: talent.video.url,
      makeoverNeeded: talent.makeoverNeeded,
      willingToWorkAsExtra: talent.willingToWorkAsExtra,
      aboutYourself: talent.aboutYourself,
      createdAt: talent.createdAt,
      updatedAt: talent.updatedAt,
      email: isConnected ? talent.email : "",
      phone: isConnected ? talent.phone : "",
      token: generateToken(talent._id, talent.role),
    };
  });

  res.json({
    message: "Talents with complete data retrieved successfully",
    talents: formattedTalents,
  });
});

module.exports = {
  registerTalent,
  loginTalent,
  verifyTalentOTP,
  forgotTalentPassword,
  resetTalentPassword,
  resendTalentOTP,
  updateTalentProfile,
  getTalentProfile,
  getAllTalents,
};
