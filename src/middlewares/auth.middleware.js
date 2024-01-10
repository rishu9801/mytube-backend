import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";


export const verifyJWT = asyncHandler(async (req, _, next) => {
    const token = req.cookies?.accessToken || req.header("Authorization")?.split(" ")[1];

    try {
        if (!token) {
            throw new ApiError(401, "Please login to access this resource")
        }

        const decoded = await jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

        const user = await User.findById(decoded?._id).select("-password -refreshToken");

        if (!user) {
            throw new ApiError(404, "Invalid accesstoken")
        }

        req.user = user;

        next();
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid accesstoken");
    }
});