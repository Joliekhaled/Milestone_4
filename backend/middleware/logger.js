/**
 * Logging Middleware
 * Logs HTTP requests using Morgan
 */

const morgan = require('morgan');

/**
 * Custom token for logging request body (for POST/PUT requests)
 */
morgan.token('body', (req) => {
  return JSON.stringify(req.body);
});

/**
 * Custom format for development logging
 */
const devFormat = ':method :url :status :response-time ms - :res[content-length] :body';

/**
 * Custom format for production logging
 */
const prodFormat = ':method :url :status :response-time ms - :res[content-length]';

/**
 * Logger middleware based on environment
 */
const logger = () => {
  if (process.env.NODE_ENV === 'development') {
    return morgan(devFormat);
  } else {
    return morgan(prodFormat);
  }
};

module.exports = logger;










