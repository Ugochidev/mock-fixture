//  Require dependencies
const Admin = require("../models/admin.model");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const bcrypt = require("bcrypt");
const { sendMail } = require("../database/sendMail");

//  creating  Admin
const registerAdmin = async (req, res, next) => {
  try {
    const { firstName, lastName, phoneNumber, email, password} = req.body;
    // validating phoneNumber
    const phoneNumberExist = await Admin.findOne({ phoneNumber });
    if (phoneNumberExist) {
      return res.status(401).json({
        message: "phoneNumber exists, please login",
      });
    }
    // validating email
    const emailExist = await Admin.findOne({ email });
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
    // hashing password
    const hashPassword = await bcrypt.hash(password, 10);

    // create  a new Admin
    const newAdmin = await Admin.create({
      firstName,
      lastName,
      phoneNumber,
      email,
      password: hashPassword,
    });
    const payload = {
      id: newAdmin._id,
      email: newAdmin.email,
      role: newAdmin.role,
    };
    const token = await jwt.sign(payload, process.env.SECRET_TOKEN, {
      expiresIn: "1h",
    });
    let mailOptions = {
      to: newAdmin.email,
      subject: "Verify Mail",
      text: "pls verify your email address",
    };
    await sendMail(mailOptions);
    return res.status(201).json({
      message: "Admin  created",
      newAdmin,
      token,
    });
  } catch (error) {
    return res.status(500).json({
      message: error.message,
    });
  }
};
//  login for Admin
const loginAdmin = async (req, res, next) => {
  try {
    const { phoneNumber, password } = req.body;
    const phoneNumberExist = await Admin.findOne({ phoneNumber });
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
    if (phoneNumberExist.role == "User") {
      return res.status(401).json({
        message: "Unauthorized",
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
      message: "Admin login successfully",
      token,
    });
  } catch (error) {
    return res.status(500).json({
      message: error.message,
    });
  }
};
//   exporting modules
module.exports = { registerAdmin, loginAdmin };
