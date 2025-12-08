/**
 * Doctor Controller
 * Handles CRUD operations for doctors
 */

const Doctor = require('../models/Doctor');
const { AppError } = require('../middleware/errorHandler');

/**
 * @route   POST /api/doctors
 * @desc    Create a new doctor
 * @access  Private/Admin
 */
const createDoctor = async (req, res, next) => {
  try {
    const { name, specialty, image, availableTimes, bio } = req.body;

    const doctor = await Doctor.create({
      name,
      specialty,
      image,
      availableTimes: availableTimes || [],
      bio,
    });

    res.status(201).json({
      success: true,
      message: 'Doctor created successfully',
      data: {
        doctor,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/doctors
 * @desc    Get all doctors
 * @access  Public
 */
const getAllDoctors = async (req, res, next) => {
  try {
    const { specialty, isActive } = req.query;
    const query = {};

    if (specialty) query.specialty = specialty;
    if (isActive !== undefined) query.isActive = isActive === 'true';

    const doctors = await Doctor.find(query);

    res.status(200).json({
      success: true,
      count: doctors.length,
      data: {
        doctors,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/doctors/:id
 * @desc    Get doctor by ID
 * @access  Public
 */
const getDoctorById = async (req, res, next) => {
  try {
    const doctor = await Doctor.findById(req.params.id);

    if (!doctor) {
      return next(new AppError(`Doctor not found with id of ${req.params.id}`, 404));
    }

    res.status(200).json({
      success: true,
      data: {
        doctor,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   PUT /api/doctors/:id
 * @desc    Update doctor
 * @access  Private/Admin
 */
const updateDoctor = async (req, res, next) => {
  try {
    const { name, specialty, image, availableTimes, bio, isActive } = req.body;

    const updateFields = {};
    if (name) updateFields.name = name;
    if (specialty) updateFields.specialty = specialty;
    if (image !== undefined) updateFields.image = image;
    if (availableTimes) updateFields.availableTimes = availableTimes;
    if (bio !== undefined) updateFields.bio = bio;
    if (isActive !== undefined) updateFields.isActive = isActive;

    const doctor = await Doctor.findByIdAndUpdate(
      req.params.id,
      updateFields,
      {
        new: true,
        runValidators: true,
      }
    );

    if (!doctor) {
      return next(new AppError(`Doctor not found with id of ${req.params.id}`, 404));
    }

    res.status(200).json({
      success: true,
      message: 'Doctor updated successfully',
      data: {
        doctor,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   DELETE /api/doctors/:id
 * @desc    Delete doctor
 * @access  Private/Admin
 */
const deleteDoctor = async (req, res, next) => {
  try {
    const doctor = await Doctor.findById(req.params.id);

    if (!doctor) {
      return next(new AppError(`Doctor not found with id of ${req.params.id}`, 404));
    }

    await Doctor.findByIdAndDelete(req.params.id);

    res.status(200).json({
      success: true,
      message: 'Doctor deleted successfully',
      data: {},
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  createDoctor,
  getAllDoctors,
  getDoctorById,
  updateDoctor,
  deleteDoctor,
};

