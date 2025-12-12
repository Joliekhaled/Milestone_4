/**
 * Doctor Routes
 * Handles CRUD operations for doctors
 */

const express = require('express');
const router = express.Router();
const {
  createDoctor,
  getAllDoctors,
  getDoctorById,
  updateDoctor,
  deleteDoctor,
} = require('../controllers/doctorController');
const { protect, authorize } = require('../middleware/auth');

// @route   GET /api/doctors
// @desc    Get all doctors
// @access  Public
router.get('/', getAllDoctors);

// @route   GET /api/doctors/:id
// @desc    Get doctor by ID
// @access  Public
router.get('/:id', getDoctorById);

// All routes below require authentication
router.use(protect);

// @route   POST /api/doctors
// @desc    Create a new doctor
// @access  Private/Admin
router.post('/', authorize('admin'), createDoctor);

// @route   PUT /api/doctors/:id
// @desc    Update doctor
// @access  Private/Admin
router.put('/:id', authorize('admin'), updateDoctor);

// @route   DELETE /api/doctors/:id
// @desc    Delete doctor
// @access  Private/Admin
router.delete('/:id', authorize('admin'), deleteDoctor);

module.exports = router;










