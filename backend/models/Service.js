/**
 * Service Model
 * Defines the schema for service documents in MongoDB
 */

const mongoose = require('mongoose');

const serviceSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Service name is required'],
      trim: true,
      unique: true,
    },
    description: {
      type: String,
      trim: true,
    },
    category: {
      type: String,
      enum: ['General', 'Cosmetic', 'Emergency', 'Specialty'],
      default: 'General',
    },
    duration: {
      type: Number, // Duration in minutes
      default: 30,
    },
    price: {
      type: Number,
    },
    isActive: {
      type: Boolean,
      default: true,
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model('Service', serviceSchema);










