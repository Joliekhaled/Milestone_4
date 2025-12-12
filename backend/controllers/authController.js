/**
 * Authentication Controller
 * Handles user registration and login
 */

const jwt = require('jsonwebtoken');
const User = require('../models/User');
const jwtConfig = require('../config/jwt');
const { AppError } = require('../middleware/errorHandler');

/**
 * Generate JWT token
 * @param {string} id - User ID
 * @returns {string} JWT token
 */
const generateToken = (id) => {
  return jwt.sign({ id }, jwtConfig.secret, {
    expiresIn: jwtConfig.expiresIn,
  });
};

/**
 * @route   POST /api/auth/register
 * @desc    Register a new user
 * @access  Public
 */
const register = async (req, res, next) => {
  try {
    const { name, email, password, phone, age, gender } = req.body;

    // Check if user already exists (include password for comparison)
    const existingUser = await User.findOne({ email }).select('+password');

    if (existingUser) {
      if (!password) {
        return next(
          new AppError('Account already exists with this email. Please login.', 400)
        );
      }

      const isSamePassword = await existingUser.comparePassword(password);
      if (!isSamePassword) {
        return next(
          new AppError(
            'Account already exists with this email. Please login with your original password.',
            400
          )
        );
      }

      // Optionally backfill contact info if it was missing before
      let profileUpdated = false;
      if (phone && !existingUser.phone) {
        existingUser.phone = phone;
        profileUpdated = true;
      }
      if (age && !existingUser.age) {
        existingUser.age = age;
        profileUpdated = true;
      }
      if (gender && !existingUser.gender) {
        existingUser.gender = gender;
        profileUpdated = true;
      }
      if (profileUpdated) {
        await existingUser.save();
      }

      const token = generateToken(existingUser._id);

      return res.status(200).json({
        success: true,
        message: 'Existing patient recognized. Logged in successfully.',
        data: {
          user: {
            id: existingUser._id,
            name: existingUser.name,
            email: existingUser.email,
            role: existingUser.role,
            phone: existingUser.phone,
          },
          token,
        },
      });
    }

    // Create new user
    const user = await User.create({
      name,
      email,
      password,
      phone,
      age,
      gender,
    });

    const token = generateToken(user._id);

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
          phone: user.phone,
        },
        token,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   POST /api/auth/login
 * @desc    Login user
 * @access  Public
 */
const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // Validate email and password
    if (!email || !password) {
      return next(new AppError('Please provide email and password', 400));
    }

    // Check for user and include password field
    const user = await User.findOne({ email }).select('+password');

    if (!user || !(await user.comparePassword(password))) {
      return next(new AppError('Invalid credentials', 401));
    }

    // Generate token
    const token = generateToken(user._id);

    res.status(200).json({
      success: true,
      message: 'Login successful',
      data: {
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
          phone: user.phone,
        },
        token,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/auth/me
 * @desc    Get current logged in user
 * @access  Private
 */
const getMe = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);

    res.status(200).json({
      success: true,
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

module.exports = {
  register,
  login,
  getMe,
};
