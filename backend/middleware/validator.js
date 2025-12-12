/**
 * Validation Middleware
 * Handles express-validator errors
 */

const { validationResult } = require('express-validator');
const { AppError } = require('./errorHandler');

/**
 * Middleware to check validation results
 * Returns errors if validation fails
 */
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const errorMessages = errors.array().map((error) => error.msg).join('. ');
    return next(new AppError(errorMessages, 400));
  }
  next();
};

module.exports = validate;










