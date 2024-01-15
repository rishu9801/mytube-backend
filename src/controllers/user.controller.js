import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js"
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";

const generateAccessAndRefreshToken = async (userId) => {
    try {
        const user = await User.findById(userId);
        const accessToken = await user.generateAccessToken();
        const refreshToken = await user.generateRefreshToken();
        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false });
        console.log(accessToken, refreshToken, "tokens", user, userId);
        return { accessToken, refreshToken };
    } catch (err) {
        console.log(err, "error generating tokens");
        throw new ApiError(500, "Something went wrong while generating tokens");
    }
}


const registerUser = asyncHandler(async (req, res) => {
    const { fullName, email, userName, password } = req.body;

    if (
        [fullName, email, userName, password].some((field) => field?.trim() === "")
    ) {
        throw new ApiError(400, "All fields are required")
    }

    const existedUser = await User.findOne({
        $or: [{ userName }, { email }]
    })

    if (existedUser) {
        throw new ApiError(409, "User with email or username already exits")
    }

    console.log(req.files, "files from req");
    const avatarLocalPath = req.files?.avatar[0]?.path
    // const coverImageLocalPath = req.files?.coverImage[0]?.path

    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files.coverImage[0].path
    }

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is required")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if (!avatar) {
        throw new ApiError(400, "Avatar file is required")
    }

    let user = await User.create({
        fullName,
        avatar: avatar.url,
        email,
        userName: userName.toLowerCase(),
        coverImage: coverImage?.url || "",
        password
    });

    user = await user.save()

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    );

    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while registering user");
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registered successfully")
    )
});

const loginUser = asyncHandler(async (req, res) => {
    const { userName, email, password } = req.body;
    console.log(userName, email, password);

    if (!(userName || email)) {
        throw new ApiError(400, "Username or email is required")
    }

    if (!password) {
        throw new ApiError(400, "Password is required")
    }

    const user = await User.findOne({
        $or: [{ userName }, { email }]
    })

    if (!user) {
        throw new ApiError(404, "User does not exist!!")
    }

    const isPasswordCorrect = await user.isPasswordCorrect(password);

    if (!isPasswordCorrect) {
        throw new ApiError(401, "Password is incorrect")
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(user._id);

    // user.refreshToken = refreshToken;
    // const accessToken = await user.generateAccessToken();
    // const refreshToken = await user.generateRefreshToken();
    const loggedInUser = await User.findById(user._id).select("-password -refreshToken");

    const options = {
        httpOnly: true,
        secure: true
    }
    console.log(accessToken, refreshToken, "tokens");
    return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new ApiResponse(200, { user: loggedInUser, accessToken, refreshToken }, "User logged in successfully")
        )

});


const logoutUser = asyncHandler(async (req, res) => {
    const { user } = req;
    await User.findByIdAndUpdate(user._id, {
        $set: {
            refreshToken: ""
        }
    },
        {
            new: true,
        }
    );

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(
            200, {}, "User logged out successfully"
        )

});


const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;
    console.log(incomingRefreshToken, "incomingRefreshToken");
    if (!incomingRefreshToken) {
        throw new ApiError(401, "Please login to continue")
    }
    try {

        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);

        const user = await User.findById(decodedToken?._id)
        console.log(user, "user");
        if (!user) {
            throw new ApiError(401, "Invalid refresh token");
        }

        if (user.refreshToken !== incomingRefreshToken) {
            throw new ApiError(401, "Invalid refresh token");
        }
        console.log(user);

        const options = {
            httpOnly: true,
            secure: true
        }
        const { accessToken, refreshToken: newRefreshToken } = await generateAccessAndRefreshToken(user._id);

        return res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", newRefreshToken, options)
            .json(
                new ApiResponse(200, { accessToken, refreshToken: newRefreshToken }, "Access token refreshed successfully")
            )
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token");
    }

});




export { registerUser, loginUser, logoutUser, refreshAccessToken };
