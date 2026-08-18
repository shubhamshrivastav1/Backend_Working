import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";


// ======================================================
// Generate Access Token + Refresh Token
// ======================================================

const generateAccessAndRefreshTokens = async (userId) => {
  try {
    const user = await User.findById(userId);

    if (!user) {
      throw new ApiError(404, "User not found");
    }

    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    // Refresh token database me store hoga
    user.refreshToken = refreshToken;

    await user.save({
      validateBeforeSave: false
    });

    return {
      accessToken,
      refreshToken
    };

  } catch (error) {
    throw new ApiError(
      500,
      "Something went wrong while generating access and refresh token"
    );
  }
};


// ======================================================
// Register User
// ======================================================

const registerUser = asyncHandler(async (req, res) => {

  // 1. Get user details from frontend
  const {
    fullName,
    email,
    username,
    password
  } = req.body;


  // 2. Validate user details
  if (
    [fullName, email, username, password].some(
      (field) => !field || field.trim() === ""
    )
  ) {
    throw new ApiError(400, "All fields are required");
  }


  // 3. Normalize username and email
  const normalizedUsername = username.toLowerCase();
  const normalizedEmail = email.toLowerCase();


  // 4. Check if user already exists
  const existedUser = await User.findOne({
    $or: [
      { username: normalizedUsername },
      { email: normalizedEmail }
    ]
  });


  if (existedUser) {
    throw new ApiError(
      409,
      "User with email or username already exists"
    );
  }


  // 5. Get image paths from Multer
  const avatarLocalPath = req.files?.avatar?.[0]?.path;
  const coverImageLocalPath = req.files?.coverImage?.[0]?.path;


  // 6. Avatar is required
  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar file is required");
  }


  // 7. Upload avatar to Cloudinary
  const avatar = await uploadOnCloudinary(avatarLocalPath);


  if (!avatar?.url) {
    throw new ApiError(
      400,
      "Avatar upload failed"
    );
  }


  // 8. Upload cover image only if provided
  let coverImage = null;

  if (coverImageLocalPath) {
    coverImage = await uploadOnCloudinary(coverImageLocalPath);
  }


  // 9. Create user in database
  const user = await User.create({
    fullName,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
    email: normalizedEmail,
    password,
    username: normalizedUsername
  });


  // 10. Get created user without password and refreshToken
  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );


  // 11. Check user creation
  if (!createdUser) {
    throw new ApiError(
      500,
      "Something went wrong while registering the user"
    );
  }


  // 12. Send response
  return res
    .status(201)
    .json(
      new ApiResponse(
        201,
        createdUser,
        "User registered successfully"
      )
    );
});


// ======================================================
// Login User
// ======================================================

const loginUser = asyncHandler(async (req, res) => {

  // 1. Get login data
  const {
    email,
    username,
    password
  } = req.body;


  // 2. Username or email required
  if (!username && !email) {
    throw new ApiError(
      400,
      "Username or email is required"
    );
  }


  // 3. Password required
  if (!password) {
    throw new ApiError(
      400,
      "Password is required"
    );
  }


  // 4. Normalize username/email
  const normalizedUsername = username?.toLowerCase();
  const normalizedEmail = email?.toLowerCase();


  // 5. Find user
  const user = await User.findOne({
    $or: [
      ...(normalizedUsername
        ? [{ username: normalizedUsername }]
        : []),

      ...(normalizedEmail
        ? [{ email: normalizedEmail }]
        : [])
    ]
  });


  // 6. User not found
  if (!user) {
    throw new ApiError(
      404,
      "User does not exist"
    );
  }


  // 7. Check password
  const isPasswordValid =
    await user.isPasswordCorrect(password);


  if (!isPasswordValid) {
    throw new ApiError(
      401,
      "Invalid user credentials"
    );
  }


  // 8. Generate tokens
  const {
    accessToken,
    refreshToken
  } = await generateAccessAndRefreshTokens(
    user._id
  );


  // 9. Get logged-in user without sensitive data
  const loggedInUser =
    await User.findById(user._id)
      .select("-password -refreshToken");


  // 10. Cookie options
  const options = {
    httpOnly: true,
    secure: false
  };


  // 11. Send response
  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        {
          user: loggedInUser,
          accessToken,
          refreshToken
        },
        "User logged in successfully"
      )
    );
});


// ======================================================
// Logout User
// ======================================================

const logoutUser = asyncHandler(async (req, res) => {

  // Remove refresh token from database
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        refreshToken: undefined
      }
    },
    {
      new: true
    }
  );


  const options = {
    httpOnly: true,
    secure: false
  };


  // Remove cookies
  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(
      new ApiResponse(
        200,
        {},
        "User logged out successfully"
      )
    );
});


// ======================================================
// Refresh Access Token
// ======================================================

const refreshAccessToken = asyncHandler(async (req, res) => {

  // Refresh token cookie ya request body se lo
  const incomingRefreshToken =
    req.cookies?.refreshToken ||
    req.body?.refreshToken;


  // Refresh token nahi mila
  if (!incomingRefreshToken) {
    throw new ApiError(
      401,
      "Unauthorized request"
    );
  }


  try {

    // 1. Verify refresh token
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );


    // 2. Find user
    const user = await User.findById(
      decodedToken?._id
    );


    if (!user) {
      throw new ApiError(
        401,
        "Invalid refresh token"
      );
    }


    // 3. Compare incoming refresh token
    // with database refresh token
    if (
      incomingRefreshToken !== user.refreshToken
    ) {
      throw new ApiError(
        401,
        "Refresh token is expired or already used"
      );
    }


    // 4. Generate new tokens
    const {
      accessToken,
      refreshToken
    } = await generateAccessAndRefreshTokens(
      user._id
    );


    const options = {
      httpOnly: true,
      secure: false
    };


    // 5. Send new tokens
    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", refreshToken, options)
      .json(
        new ApiResponse(
          200,
          {
            accessToken,
            refreshToken
          },
          "Access token refreshed successfully"
        )
      );

  } catch (error) {

    throw new ApiError(
      401,
      error?.message || "Invalid refresh token"
    );
  }
});


// ======================================================
// Change Current Password
// ======================================================

const changeCurrentPassword = asyncHandler(
  async (req, res) => {

    const {
      oldPassword,
      newPassword
    } = req.body;


    // Validate passwords
    if (!oldPassword || !newPassword) {
      throw new ApiError(
        400,
        "Old password and new password are required"
      );
    }


    // Find current user
    const user = await User.findById(
      req.user?._id
    );


    if (!user) {
      throw new ApiError(
        404,
        "User not found"
      );
    }


    // Check old password
    const isPasswordCorrect =
      await user.isPasswordCorrect(
        oldPassword
      );


    if (!isPasswordCorrect) {
      throw new ApiError(
        400,
        "Invalid old password"
      );
    }


    // Update password
    user.password = newPassword;


    await user.save({
      validateBeforeSave: false
    });


    return res
      .status(200)
      .json(
        new ApiResponse(
          200,
          {},
          "Password changed successfully"
        )
      );
  }
);


// ======================================================
// Get Current User
// ======================================================

const getCurrentUser = asyncHandler(
  async (req, res) => {

    return res
      .status(200)
      .json(
        new ApiResponse(
          200,
          req.user,
          "Current user fetched successfully"
        )
      );
  }
);


// ======================================================
// Update Account Details
// ======================================================

const updateAccountDetails = asyncHandler(
  async (req, res) => {

    const {
      fullName,
      email
    } = req.body;


    // At least one field required
    if (!fullName && !email) {
      throw new ApiError(
        400,
        "At least one field is required to update"
      );
    }


    const updateData = {};


    if (fullName) {
      updateData.fullName = fullName;
    }


    if (email) {
      updateData.email = email.toLowerCase();
    }


    const user =
      await User.findByIdAndUpdate(
        req.user?._id,
        {
          $set: updateData
        },
        {
          new: true
        }
      ).select("-password -refreshToken");


    if (!user) {
      throw new ApiError(
        404,
        "User not found"
      );
    }


    return res
      .status(200)
      .json(
        new ApiResponse(
          200,
          user,
          "Account details updated successfully"
        )
      );
  }
);


// ======================================================
// Update User Avatar
// ======================================================

const updateUserAvatar = asyncHandler(
  async (req, res) => {

    // Get local file path
    const avatarLocalPath =
      req.file?.path;


    if (!avatarLocalPath) {
      throw new ApiError(
        400,
        "Avatar file is missing"
      );
    }


    // Upload to Cloudinary
    const avatar =
      await uploadOnCloudinary(
        avatarLocalPath
      );


    if (!avatar?.url) {
      throw new ApiError(
        400,
        "Error while uploading avatar"
      );
    }


    // Update database
    const user =
      await User.findByIdAndUpdate(
        req.user?._id,
        {
          $set: {
            avatar: avatar.url
          }
        },
        {
          new: true
        }
      ).select("-password -refreshToken");


    if (!user) {
      throw new ApiError(
        404,
        "User not found"
      );
    }


    return res
      .status(200)
      .json(
        new ApiResponse(
          200,
          user,
          "Avatar updated successfully"
        )
      );
  }
);


// ======================================================
// Update User Cover Image
// ======================================================

const updateUserCoverImage = asyncHandler(
  async (req, res) => {

    // Get local file path
    const coverImageLocalPath =
      req.file?.path;


    if (!coverImageLocalPath) {
      throw new ApiError(
        400,
        "Cover image file is missing"
      );
    }


    // Upload to Cloudinary
    const coverImage =
      await uploadOnCloudinary(
        coverImageLocalPath
      );


    if (!coverImage?.url) {
      throw new ApiError(
        400,
        "Error while uploading cover image"
      );
    }


    // Update database
    const user =
      await User.findByIdAndUpdate(
        req.user?._id,
        {
          $set: {
            coverImage: coverImage.url
          }
        },
        {
          new: true
        }
      ).select("-password -refreshToken");


    if (!user) {
      throw new ApiError(
        404,
        "User not found"
      );
    }


    return res
      .status(200)
      .json(
        new ApiResponse(
          200,
          user,
          "Cover image updated successfully"
        )
      );
  }
);


// ======================================================
// Export Controllers
// ======================================================


const getUserChannelProfile = asyncHandler(async (req, res) => {
 const {username} = req.params

 if(!username) {
  throw new ApiError(400, "Username is missing")
 }

const channel = await User.aggregate([
   {
      $match: {
        username: username?.toLowerCase()

      }
    },
    {
        $lookup: {
          from: "subscriptions",
          localField: "_id",
          foreignField: "channel",
          as: "subscribers"
        }
    },
    {
      $lookup: {
        from: "subscriptions",
        localField: "_id",
        foreignField: "subscriber",
        as: "subscribedTo"     
      }
    },
    {
      $addFields: {
        subscribersCount: { 
          $size: "$subscribers"
        },
        channelsSubscribedToCount: {
          $size: "$subscribedTo"
        },
        isSubscribed: {
          $cond: {
            if: {
              $in: [req.user?._id, "$subscribers.subscriber"]
            },
            then: true,
            else: false
          }
        }
      }
    },
    {
      $project: {
        fullName: 1,
        username: 1,
        avatar: 1,
        email: 1,
        coverImage: 1,
        subscribersCount: 1,
        channelsSubscribedToCount: 1,
        isSubscribed: 1,
      }
    }
   
])

if(!channel?.length){
   throw new ApiError(404, "Channel not found")
}

return res
.status(200)
.json(
  new ApiResponse(200, channel[0], "Channel profile fetched successfully")
)

})

const getWatchHistory = asyncHandler(async (req, res) => {
    const user = await User.aggregate([
      {
        $match: {
          _id: new mongoose.Types.ObjectId(req.user._id)
        }
      },
      {
        $lookup: {
          from: "videos",
          localField: "watchHistory",
          foreignField: "_id",
          as: "watchHistory",
          pipeline: [
            {
              $lookup: {
                from: "users",
                localField: "owner",
                foreignField: "_id",
                as: "owner",
                pipeline: [
                  {
                    $project: {
                      fullName: 1,
                      username: 1,
                      avatar: 1
                    }
                  }
                ]
              }
            },
            {
              $addFields: {
                owner: { 
                  $first: "$owner"
                 }
              }
            }
          ]
        }
      }
    ])

    return res
    .status(200)
    .json(
      new ApiResponse(200, user[0]?.watchHistory || [], "Watch history fetched successfully")
    )
})


export {
  registerUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  changeCurrentPassword,
  getCurrentUser,
  updateAccountDetails,
  updateUserAvatar,
  updateUserCoverImage,
  getUserChannelProfile,
  getWatchHistory
};