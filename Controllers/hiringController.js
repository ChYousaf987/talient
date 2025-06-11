const handler = require("express-async-handler");
const hiringRequestModel = require("../Models/hiringRequestModel");
const talentModel = require("../Models/talentModel");

// Send a hiring request
const sendHiringRequest = handler(async (req, res) => {
  const { talentId, message } = req.body;
  const hirerId = req.user._id;

  const talent = await talentModel.findById(talentId);
  if (!talent) {
    res.status(404);
    throw new Error("Talent not found");
  }

  const existingRequest = await hiringRequestModel.findOne({
    hirer: hirerId,
    talent: talentId,
  });
  if (existingRequest) {
    res.status(400);
    throw new Error("You have already sent a request to this talent");
  }

  const request = await hiringRequestModel.create({
    hirer: hirerId,
    talent: talentId,
    message,
  });

  res
    .status(201)
    .json({ message: "Hiring request sent successfully", request });
});

// Get requests received by a talent
const getTalentRequests = handler(async (req, res) => {
  const talentId = req.user._id;

  const requests = await hiringRequestModel
    .find({ talent: talentId })
    .populate("hirer", "name profilePic_url role");
  res.json(requests);
});

// Get requests sent by a hirer
// Get requests sent by a hirer
const getHirerRequests = handler(async (req, res) => {
  const hirerId = req.user._id;

  const requests = await hiringRequestModel
    .find({ hirer: hirerId })
    .populate("talent", "name profilePic role") // Talent fields
    .populate("hirer", "name profilePic_url role") // Hirer fields for consistency
    .select("message status createdAt") // Explicitly select createdAt
    .lean();

  if (!requests || requests.length === 0) {
    res.status(404);
    throw new Error("No hiring requests found for this hirer");
  }

  // Format requests for response
  const formattedRequests = requests.map((request) => ({
    _id: request._id,
    message: request.message,
    status: request.status,
    createdAt: request.createdAt || new Date(), // Fallback to current date if createdAt is missing
    hirer: {
      _id: request.hirer._id,
      name: request.hirer.name || "Unknown Hirer",
      profilePic: request.hirer.profilePic_url || null,
      role: request.hirer.role || "Unknown Role",
    },
    talent: {
      _id: request.talent._id,
      name: request.talent.name || "Unknown Talent",
      profilePic: request.talent.profilePic || null,
      role: request.talent.role || "Unknown Role",
    },
  }));

  res.json({
    message: "Hiring requests retrieved successfully",
    requests: formattedRequests,
  });
});

// Update request status (accept/reject) - Only talent can update
const updateRequestStatus = handler(async (req, res) => {
  const { requestId, status } = req.body;
  const talentId = req.user._id;

  if (!["Accepted", "Rejected"].includes(status)) {
    res.status(400);
    throw new Error("Invalid status");
  }

  const request = await hiringRequestModel.findById(requestId);
  if (!request) {
    res.status(404);
    throw new Error("Request not found");
  }

  // Check if the user is the talent associated with the request
  if (request.talent.toString() !== talentId.toString()) {
    res.status(403);
    throw new Error("Only the talent can accept or reject this request");
  }

  if (status === "Rejected") {
    // Delete the request if rejected
    await hiringRequestModel.deleteOne({ _id: requestId });
    res.json({ message: "Request rejected and deleted" });
  } else {
    // Update status if accepted
    request.status = status;
    await request.save();
    res.json({ message: "Request updated", request });
  }
});

module.exports = {
  sendHiringRequest,
  getTalentRequests,
  getHirerRequests,
  updateRequestStatus,
};
