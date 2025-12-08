/**
 * Service Controller
 * Handles CRUD operations for services
 */

const Service = require('../models/Service');
const { AppError } = require('../middleware/errorHandler');

/**
 * @route   POST /api/services
 * @desc    Create a new service
 * @access  Private/Admin
 */
const createService = async (req, res, next) => {
  try {
    const { name, description, category, duration, price } = req.body;

    const service = await Service.create({
      name,
      description,
      category,
      duration,
      price,
    });

    res.status(201).json({
      success: true,
      message: 'Service created successfully',
      data: {
        service,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/services
 * @desc    Get all services
 * @access  Public
 */
const getAllServices = async (req, res, next) => {
  try {
    const { category, isActive } = req.query;
    const query = {};

    if (category) query.category = category;
    if (isActive !== undefined) query.isActive = isActive === 'true';

    const services = await Service.find(query);

    res.status(200).json({
      success: true,
      count: services.length,
      data: {
        services,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/services/:id
 * @desc    Get service by ID
 * @access  Public
 */
const getServiceById = async (req, res, next) => {
  try {
    const service = await Service.findById(req.params.id);

    if (!service) {
      return next(new AppError(`Service not found with id of ${req.params.id}`, 404));
    }

    res.status(200).json({
      success: true,
      data: {
        service,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   PUT /api/services/:id
 * @desc    Update service
 * @access  Private/Admin
 */
const updateService = async (req, res, next) => {
  try {
    const { name, description, category, duration, price, isActive } = req.body;

    const updateFields = {};
    if (name) updateFields.name = name;
    if (description !== undefined) updateFields.description = description;
    if (category) updateFields.category = category;
    if (duration) updateFields.duration = duration;
    if (price !== undefined) updateFields.price = price;
    if (isActive !== undefined) updateFields.isActive = isActive;

    const service = await Service.findByIdAndUpdate(
      req.params.id,
      updateFields,
      {
        new: true,
        runValidators: true,
      }
    );

    if (!service) {
      return next(new AppError(`Service not found with id of ${req.params.id}`, 404));
    }

    res.status(200).json({
      success: true,
      message: 'Service updated successfully',
      data: {
        service,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   DELETE /api/services/:id
 * @desc    Delete service
 * @access  Private/Admin
 */
const deleteService = async (req, res, next) => {
  try {
    const service = await Service.findById(req.params.id);

    if (!service) {
      return next(new AppError(`Service not found with id of ${req.params.id}`, 404));
    }

    await Service.findByIdAndDelete(req.params.id);

    res.status(200).json({
      success: true,
      message: 'Service deleted successfully',
      data: {},
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  createService,
  getAllServices,
  getServiceById,
  updateService,
  deleteService,
};

