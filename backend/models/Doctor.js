/**
 * Doctor Model
 * Defines the schema for doctor documents in MongoDB
 */

const mongoose = require('mongoose');

const doctorSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Doctor name is required'],
      trim: true,
    },
    specialty: {
      type: String,
      required: [true, 'Doctor specialty is required'],
      trim: true,
    },
    image: {
      type: String,
      default: '',
    },
    availableTimes: {
      type: [String],
      default: [],
    },
    bio: {
      type: String,
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

module.exports = mongoose.model('Doctor', doctorSchema);

