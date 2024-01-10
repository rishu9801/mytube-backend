import { v2 as cloudinary } from "cloudinary";
import fs from "fs";

cloudinary.config({
    cloud_name: process.env.CLOUD_NAME,
    api_key: process.env.API_KEY,
    api_secret: process.env.API_SECRET
});

console.log(process.env.CLOUD_NAME, process.env.API_KEY, process.env.API_SECRET);

const uploadOnCloudinary = async (localFilePath) => {
    try {
        if (!localFilePath) return null;
        const response = await cloudinary.uploader.upload(localFilePath, {
            resource_type: "auto"
        });
        console.log("File has been uploaded on cloudinary", response.url);
        fs.unlinkSync(localFilePath);
        return response;
    } catch (err) {
        console.log(err, "error uploading on cloudinary");
        fs.unlinkSync(localFilePath); //remove locally saved temp file as upload failed
        return null;
    }
}


export { uploadOnCloudinary };