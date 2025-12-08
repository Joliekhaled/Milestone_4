/**
 * Appointment Routes
 * Handles CRUD operations for appointments
 */

const express = require('express');
const router = express.Router();
const {
  createAppointment,
  getAllAppointments,
  getAppointmentById,
  updateAppointment,
  deleteAppointment,
} = require('../controllers/appointmentController');
const { protect } = require('../middleware/auth');

// @route   GET /api/appointments
// @desc    Get all appointments
// @access  Private
router.get('/', protect, getAllAppointments);

// @route   GET /api/appointments/:id
// @desc    Get appointment by ID
// @access  Private
router.get('/:id', protect, getAppointmentById);

// @route   POST /api/appointments
// @desc    Create appointment (public for booking, but can be authenticated)
// @access  Public (can add protect middleware if needed)
router.post('/', createAppointment);

// @route   PUT /api/appointments/:id
// @desc    Update appointment
// @access  Private
router.put('/:id', protect, updateAppointment);

// @route   DELETE /api/appointments/:id
// @desc    Delete appointment
// @access  Private
router.delete('/:id', protect, deleteAppointment);

module.exports = router;

