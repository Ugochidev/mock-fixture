//  require dependencies
const express = require("express");
const router = express.Router();
const {
  registerAdmin,
  loginAdmin,
} = require("../controllers/admin.controller");
//  creating a route
router.post("/registerAdmin", registerAdmin);
router.post("/loginAdmin", loginAdmin);

//    exporting modules
module.exports = router;
