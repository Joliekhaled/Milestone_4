/**
 * Service Routes
 * Handles CRUD operations for services
 */

const express = require('express');
const router = express.Router();
const {
  createService,
  getAllServices,
  getServiceById,
  updateService,
  deleteService,
} = require('../controllers/serviceController');
const { protect, authorize } = require('../middleware/auth');

// @route   GET /api/services
// @desc    Get all services
// @access  Public
router.get('/', getAllServices);

// @route   GET /api/services/:id
// @desc    Get service by ID
// @access  Public
router.get('/:id', getServiceById);

// All routes below require authentication
router.use(protect);

// @route   POST /api/services
// @desc    Create a new service
// @access  Private/Admin
router.post('/', authorize('admin'), createService);

// @route   PUT /api/services/:id
// @desc    Update service
// @access  Private/Admin
router.put('/:id', authorize('admin'), updateService);

// @route   DELETE /api/services/:id
// @desc    Delete service
// @access  Private/Admin
router.delete('/:id', authorize('admin'), deleteService);

module.exports = router;

