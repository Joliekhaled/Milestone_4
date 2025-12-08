/**
 * User/Patient Controller
 * Handles CRUD operations for users/patients
 */

const User = require('../models/User');
const Appointment = require('../models/Appointment');
const { AppError } = require('../middleware/errorHandler');

/**
 * @route   POST /api/users
 * @desc    Create a new user
 * @access  Private/Admin
 */
const createUser = async (req, res, next) => {
  try {
    const { name, email, password, role, phone, age, gender } = req.body;

    const user = await User.create({
      name,
      email,
      password,
      role: role || 'patient',
      phone,
      age,
      gender,
    });

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      data: {
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
          createdAt: user.createdAt,
        },
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/users/:id
 * @desc    Get user by ID
 * @access  Private
 */
const getUserById = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);

    if (!user) {
      return next(new AppError(`User not found with id of ${req.params.id}`, 404));
    }

    res.status(200).json({
      success: true,
      data: {
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt,
        },
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/users
 * @desc    Get all users
 * @access  Private/Admin
 */
const getAllUsers = async (req, res, next) => {
  try {
    const users = await User.find().select('-password');

    res.status(200).json({
      success: true,
      count: users.length,
      data: {
        users,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   PUT /api/users/:id
 * @desc    Update user
 * @access  Private
 */
const updateUser = async (req, res, next) => {
  try {
    const { name, email, role, phone, age, gender, medicalHistory } = req.body;

    // Build update object (only include fields that are provided)
    const updateFields = {};
    if (name) updateFields.name = name;
    if (email) updateFields.email = email;
    if (role && req.user.role === 'admin') updateFields.role = role;
    if (phone !== undefined) updateFields.phone = phone;
    if (age !== undefined) updateFields.age = age;
    if (gender) updateFields.gender = gender;
    if (medicalHistory !== undefined) updateFields.medicalHistory = medicalHistory;

    const user = await User.findByIdAndUpdate(
      req.params.id,
      updateFields,
      {
        new: true,
        runValidators: true,
      }
    );

    if (!user) {
      return next(new AppError(`User not found with id of ${req.params.id}`, 404));
    }

    // Check if user is updating their own profile or is admin
    if (req.user.id !== req.params.id && req.user.role !== 'admin') {
      return next(new AppError('Not authorized to update this user', 403));
    }

    res.status(200).json({
      success: true,
      message: 'User updated successfully',
      data: {
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
          updatedAt: user.updatedAt,
        },
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   DELETE /api/users/:id
 * @desc    Delete user
 * @access  Private/Admin
 */
const deleteUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);

    if (!user) {
      return next(new AppError(`User not found with id of ${req.params.id}`, 404));
    }

    await User.findByIdAndDelete(req.params.id);

    res.status(200).json({
      success: true,
      message: 'User deleted successfully',
      data: {},
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/users/:id/appointments
 * @desc    Get patient's appointment history
 * @access  Private
 */
const getPatientHistory = async (req, res, next) => {
  try {
    const userId = req.params.id;

    // Check if user has permission
    if (req.user.role === 'patient' && req.user.id !== userId) {
      return next(new AppError('Not authorized to view this history', 403));
    }

    // Get user info to match by phone/name as well
    const user = await User.findById(userId);
    
    // Find appointments by patient ID OR by phone/name (for appointments made without account)
    const query = {
      $or: [
        { patient: userId },
        ...(user && user.phone ? [{ patientPhone: user.phone }] : []),
        ...(user && user.name ? [{ patientName: user.name }] : [])
      ]
    };

    const appointments = await Appointment.find(query)
      .sort({ date: -1, time: -1 });

    res.status(200).json({
      success: true,
      count: appointments.length,
      data: {
        appointments,
      },
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  createUser,
  getUserById,
  getAllUsers,
  updateUser,
  deleteUser,
  getPatientHistory,
};

