import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";


const registerUser = asyncHandler(async (req, res) => {

  // 1. Get user details from frontend
  const { fullName, email, username, password } = req.body;


  // 2. Validate user details
  if (
    [fullName, email, username, password].some(
      (field) => field?.trim() === ""
    )
  ) {
    throw new ApiError(400, "All fields are required");
  }


  // 3. Check if user already exists
  const existedUser = await User.findOne({
    $or: [{ username }, { email }]
  });


  if (existedUser) {
    throw new ApiError(
      409,
      "User with email or username already exists"
    );
  }


  // 4. Get image paths from Multer
  const avatarLocalPath = req.files?.avatar?.[0]?.path;
  const coverImageLocalPath = req.files?.coverImage?.[0]?.path;


  // 5. Avatar is required
  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar file is required");
  }


  // 6. Upload avatar to Cloudinary
  const avatar = await uploadOnCloudinary(avatarLocalPath);


  if (!avatar) {
    throw new ApiError(
      400,
      "Avatar upload failed"
    );
  }


  // 7. Upload cover image if provided
  const coverImage = await uploadOnCloudinary(
    coverImageLocalPath
  );


  // 8. Create user in database
  const user = await User.create({
    fullName,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
    email,
    password,
    username: username.toLowerCase()
  });


  // 9. Get created user without password and refreshToken
  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );


  // 10. Check user creation
  if (!createdUser) {
    throw new ApiError(
      500,
      "Something went wrong while registering the user"
    );
  }


  // 11. Send response
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


export { registerUser };