//  Require dependencies
const User = require("../models/user.model");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const bcrypt = require("bcrypt");
const { sendMail } = require("../database/sendMail");

//  creating  a user
const registerUser = async (req, res, next) => {
  try {
    const { firstName, lastName, phoneNumber, email, password,} =
      req.body;
    // validating phoneNumber
    const phoneNumberExist = await User.findOne({ phoneNumber });
    if (phoneNumberExist) {
      return res.status(401).json({
        message: "phoneNumber exists, please login",
      });
    }
    // validating email
    const emailExist = await User.findOne({ email });
    if (emailExist) {
      return res.status(401).json({
        message: "email exists, please login",
      });
    }
    if (
      !firstName ||
      !lastName ||
      !phoneNumber ||
      !email ||
      !password
    ) {
      return res.status(400).json({
        message: "please fill in the required details",
      });
    }
    //  hashing password
    const hashPassword = await bcrypt.hash(password, 10);
    // creating a new user
    const newUser = await User.create({
      firstName,
      lastName,
      phoneNumber,
      email,
      password: hashPassword,
    });
    const payload = {
      id: newUser._id,
      email: newUser.email,
      role: newUser.role,
    };
    const token = await jwt.sign(payload, process.env.SECRET_TOKEN, {
      expiresIn: "1h",
    });
     let mailOptions = {
       to: newUser.email,
       subject: "Verify Mail",
       text: "pls verify your email address",
     };
     await sendMail(mailOptions);
     return res.status(201).json({
       newUser,
     });
  } catch (error) {
    return res.status(500).json({
      message: error.message,
    });
  }
};

// logging in a user
const loginUser = async (req, res, next) => {
  try {
    const { phoneNumber, password } = req.body;
    const phoneNumberExist = await User.findOne({ phoneNumber });
    if (!phoneNumberExist) {
      return res.status(401).json({
        message: "phoneNumber does not exist, please create an account",
      });
    }
    let isPasswordExist = await bcrypt.compare(
      password,
      phoneNumberExist.password
    );
    if (!isPasswordExist) {
      return res.status(401).json({
        message: "Password Not Correct",
      });
    }
    if (phoneNumberExist.blocked == true) {
      return res.status(403).json({
        message:
          "Your account has been suspended, please contact customer care",
      });
    }
    const data = {
      id: phoneNumberExist._id,
      phoneNumber: phoneNumberExist.phoneNumber,
      role: phoneNumberExist.role,
    };

    const token = await jwt.sign(data, process.env.SECRET_TOKEN, {
      expiresIn: "1h",
    });
    return res.status(200).json({
      success: true,
      message: "User login successfully",
      token,
    });
  } catch (error) {
    return res.status(500).json({
      message: error.message,
    });
  }
};
//   exporting modules
module.exports = { registerUser, loginUser};