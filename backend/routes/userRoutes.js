/**
 * User Routes
 * Handles CRUD operations for users
 */

const express = require('express');
const router = express.Router();
const {
  createUser,
  getUserById,
  getAllUsers,
  updateUser,
  deleteUser,
  getPatientHistory,
} = require('../controllers/userController');
const { protect, authorize } = require('../middleware/auth');

// All routes are protected
router.use(protect);

// @route   POST /api/users
// @desc    Create a new user
// @access  Private/Admin
router.post('/', authorize('admin'), createUser);

// @route   GET /api/users
// @desc    Get all users
// @access  Private/Admin
router.get('/', authorize('admin'), getAllUsers);

// @route   GET /api/users/:id
// @desc    Get user by ID
// @access  Private
router.get('/:id', getUserById);

// @route   PUT /api/users/:id
// @desc    Update user
// @access  Private
router.put('/:id', updateUser);

// @route   DELETE /api/users/:id
// @desc    Delete user
// @access  Private/Admin
router.delete('/:id', authorize('admin'), deleteUser);

// @route   GET /api/users/:id/appointments
// @desc    Get patient's appointment history
// @access  Private
router.get('/:id/appointments', getPatientHistory);

module.exports = router;

