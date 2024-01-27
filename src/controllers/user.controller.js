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

const changeCurrentPassword = asyncHandler(async (req, res) => {
    const { oldPassword, newPassword } = req.body;

    const user = await User.findById(req.user?._id);

    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);

    if (!isPasswordCorrect) {
        throw new ApiError(400, "Password is incorrect")
    }

    user.password = newPassword;

    await user.save({ validateBeforeSave: false });

    return res.status(200).json(new ApiResponse(200, {}, "Password changed successfully"));
});

const getCurrentUser = asyncHandler(async (req, res) => {
    const { user } = req;
    return res.status(200).json(new ApiResponse(200, user, "User fetched successfully"));
});

const updateAccountDetails = asyncHandler(async (req, res) => {
    const { fullName, email } = req.body;

    if (!fullName || !email) {
        throw new ApiError(400, "All fields are required")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullName,
                email
            }
        }, {
        new: true
    }).select("-password -refreshToken");

    return res.status(200).json(new ApiResponse(200, user, "User updated successfully"));
});

const updateUserAvatar = asyncHandler(async (req, res) => {
    // TODO : add an utility function to delete the old avatar from cloudinary
    const avatarLocalPath = req.file?.path;

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is required")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath);

    if (!avatar?.url) {
        throw new ApiError(400, "Error uploading avatar file")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                avatar: avatar.url
            }
        }, {
        new: true
    }).select("-password -refreshToken");

    return res.status(200).json(new ApiResponse(200, user, "User avatar updated successfully"));

});

const updateCoverImage = asyncHandler(async (req, res) => {
    const coverImageLocalPath = req.file?.path;

    if (!coverImageLocalPath) {
        throw new ApiError(400, "Cover image file is required")
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if (!coverImage?.url) {
        throw new ApiError(400, "Error uploading cover image file")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                coverImage: coverImage.url
            }
        },
        { new: true }
    ).select("-password -refreshToken");

    return res.status(200).json(new ApiResponse(200, user, "User cover image updated successfully"));
});

const getUserChannelProfile = asyncHandler(async (req, res) => {
    const { userName } = req.params;

    if (!userName?.trim()) {
        throw new ApiError(400, "Username is required")
    }

    const channel = await User.aggregate([
        {
            $match: {
                userName: userName?.toLowerCase()
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
                subscriberCount: { $size: "$subscribers" },
                channelsSubscribedToCount: { $size: "$subscribedTo" },
                isSubscribed: {
                    $cond: {
                        if: { $in: [req.user?._id, "$subscribers.subscriber"] },
                        then: true,
                        else: false
                    }
                }
            }
        },
        {
            $project: {
                fullName: 1,
                userName: 1,
                avatar: 1,
                coverImage: 1,
                email: 1,
                subscribers: 0,
                subscribedTo: 0,
                password: 0,
                refreshToken: 0,
                createdAt: 0,
                updatedAt: 0,
                isSubscribed: 1,
                subscribedTo: 1,
                channelsSubscribedToCount: 1
            }
        }
    ]);

    console.log(channel, "channel");

    if (!channel?.length) {
        throw new ApiError(404, "Channel not found")
    }

    return res.status(200).json(new ApiResponse(200, channel[0], "Channel fetched successfully"));
});

const getWatchHistory = asyncHandler(async (req, res) => {
    const user = await User.aggregate([
        {
            $match: {
                _id: new mongoose.Types.ObjectId(req.user._id)
            },
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
                                        userName: 1,
                                        avatar: 1
                                    }
                                }
                            ]
                        },
                    },
                    {
                        $addFields: {
                            owner: { $arrayElemAt: ["$owner", 0] }
                        }
                    }
                ]
            }
        }
    ]);

    if (!user?.length) {
        throw new ApiError(404, "User not found")
    }

    return res.status(200).json(new ApiResponse(200, user[0].watchHistory, "Watch history fetched successfully"));
});


export { registerUser, loginUser, logoutUser, refreshAccessToken, changeCurrentPassword, getCurrentUser, updateAccountDetails, updateUserAvatar, updateCoverImage, getUserChannelProfile, getWatchHistory };
