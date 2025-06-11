const handler = require("express-async-handler");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const cloudinary = require("cloudinary").v2;
const talentModel = require("../Models/talentModel");
const talentSubmissionModel = require("../Models/hirerSubmissionModel");
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
    from: process.env.MAIL_USER,
    to: email,
    subject: "OTP Verification",
    html: `<h2>Your OTP is: <strong>${otp}</strong></h2>`,
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

  const token = generateToken(createdTalent._id);

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
    token: generateToken(talent._id),
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
    token: generateToken(user._id),
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

  const talents = await talentModel
    .find()
    .select(
      "name role gender age height weight bodyType skinTone language skills images.profilePic images.front images.left images.right video makeoverNeeded willingToWorkAsExtra aboutYourself createdAt updatedAt"
    )
    .lean();

  if (!talents || talents.length === 0) {
    res.status(404);
    throw new Error("No talents found");
  }

  // Format talents to ensure default values and include token
  const formattedTalents = talents.map((talent) => ({
    _id: talent._id,
    name: talent.name,
    role: talent.role,
    gender: talent.gender,
    age: talent.age || null,
    height: talent.height || null,
    weight: talent.weight || null,
    bodyType: talent.bodyType || "",
    skinTone: talent.skinTone || "",
    language: Array.isArray(talent.language)
      ? talent.language.join(", ")
      : talent.language || "",
    skills: Array.isArray(talent.skills)
      ? talent.skills.join(", ")
      : talent.skills || "",
    profilePic: talent.images?.profilePic?.url || null,
    frontImage: talent.images?.front?.url || null,
    leftImage: talent.images?.left?.url || null,
    rightImage: talent.images?.right?.url || null,
    video: talent.video?.url || null,
    makeoverNeeded: talent.makeoverNeeded || false,
    willingToWorkAsExtra: talent.willingToWorkAsExtra || false,
    aboutYourself: talent.aboutYourself || "",
    createdAt: talent.createdAt,
    updatedAt: talent.updatedAt,
    token: generateToken(talent._id, talent.role), // Generate and include token
  }));

  res.json({
    message: "Talents retrieved successfully",
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
