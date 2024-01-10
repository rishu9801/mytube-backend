import dotenv from "dotenv";
import mongoose from "mongoose";
import { DB_NAME } from "./constants.js";
import connectDb from "./db/index.js";
import { app } from "./app.js";


dotenv.config({
    path: "./.env"
})

connectDb()
    .then(
        () => {
            let PORT = process.env.PORT || 8080
            app.listen(PORT, () => {
                console.log("Server is running on PORT:", PORT);
            })
        }
    )
    .catch((err) => {
        console.log("Mongo connection failed : ", err);
    })













// import express from "express";

// const app = express();

// (async () => {
//     try {
//         mongoose.connect(`${process.env.MONGO_URI}/${DB_NAME}`)

//         app.on("error", (err) => {
//             console.log(err, "Error");
//             throw err;
//         });

//         app.listen(process.env.PORT, () => {
//             console.log(`Server is running on port ${process.env.PORT}`);
//         });
//     } catch (err) {
//         console.log(err, "Error");
//     }
// })();