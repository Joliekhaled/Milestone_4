/**
 * Appointment Model
 * Defines the schema for appointment documents in MongoDB
 */

const mongoose = require('mongoose');

const appointmentSchema = new mongoose.Schema(
  {
    patient: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      // Optional - appointments can be made without patient account
    },
    doctor: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Doctor',
      required: [true, 'Appointment must have a doctor'],
    },
    service: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Service',
    },
    date: {
      type: Date,
      required: [true, 'Appointment must have a date'],
    },
    time: {
      type: String,
      required: [true, 'Appointment must have a time'],
    },
    status: {
      type: String,
      enum: ['pending', 'confirmed', 'completed', 'cancelled'],
      default: 'pending',
    },
    type: {
      type: String,
      enum: ['regular', 'emergency'],
      default: 'regular',
    },
    patientName: {
      type: String,
      required: [true, 'Patient name is required'],
    },
    patientPhone: {
      type: String,
      required: [true, 'Patient phone is required'],
    },
    patientAge: {
      type: Number,
    },
    patientGender: {
      type: String,
      enum: ['Male', 'Female', 'Other'],
    },
    notes: {
      type: String,
    },
    emergencyType: {
      type: String,
      enum: ['Severe Tooth Pain', 'Bleeding', 'Broken Tooth', 'Swelling', 'Accident Trauma'],
    },
    emergencyDescription: {
      type: String,
    },
  },
  {
    timestamps: true,
  }
);

/**
 * Populate patient, doctor, and service when querying appointments
 * Only populate patient if it exists (appointments can be made without patient account)
 */
appointmentSchema.pre(/^find/, function (next) {
  this.populate({
    path: 'patient',
    select: 'name email phone',
    options: { lean: true }, // Handle null patient gracefully
  })
    .populate({
      path: 'doctor',
      select: 'name specialty',
    })
    .populate({
      path: 'service',
      select: 'name description',
    });
  next();
});

module.exports = mongoose.model('Appointment', appointmentSchema);

