//  require dependencies
const express = require("express");
const router = express.Router();
const { registerUser, loginUser } = require("../controllers/user.controller");
//  creating a route
router.post("/registerUser", registerUser);
router.post("/loginUser", loginUser);

//    exporting modules
module.exports = router;
