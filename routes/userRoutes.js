const router = require("express").Router();
const {
  uploadUserPhoto,
  resizeUserPhoto,
  getMe,
  updateMe,
  deleteMe,
  createUser,
  readAllUsers,
  readUser,
  updateUser,
  deleteUser,
} = require("./../controllers/userController");
const {
  signup,
  login,
  logout,
  protect,
  restrictTo,
  forgotPassword,
  resetPassword,
  updatePassword,
} = require("./../controllers/authController");

router.post("/signup", signup);
router.post("/login", login);
router.get("/logout", logout);

router.post("/forgot-password", forgotPassword);
router.patch("/reset-password/:token", resetPassword);

// Protect all routes after this middleware
router.use(protect);

router.patch("/update-password", updatePassword);
router.get("/me", getMe, readUser);
router.patch("/update-me", uploadUserPhoto, resizeUserPhoto, updateMe);
router.delete("/delete-me", deleteMe);

// All the routes below are restricted only to admin
router.use(restrictTo("admin"));

router.route("/").get(readAllUsers).post(createUser);
router.route("/:id").get(readUser).patch(updateUser).delete(deleteUser);

module.exports = router;
