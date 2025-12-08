/**
 * Appointment Controller
 * Handles CRUD operations for appointments
 */

const Appointment = require('../models/Appointment');
const { AppError } = require('../middleware/errorHandler');

/**
 * @route   POST /api/appointments
 * @desc    Create a new appointment
 * @access  Public (for booking) / Private (for authenticated users)
 */
const createAppointment = async (req, res, next) => {
  try {
    const {
      doctor,
      service,
      date,
      time,
      type,
      patientName,
      patientPhone,
      patientAge,
      patientGender,
      notes,
      emergencyType,
      emergencyDescription,
    } = req.body;

    // If user is logged in, use their ID, otherwise create appointment without patient ID
    const patientId = req.user ? req.user.id : null;

    const appointment = await Appointment.create({
      patient: patientId,
      doctor,
      service,
      date,
      time,
      type: type || 'regular',
      patientName,
      patientPhone,
      patientAge,
      patientGender,
      notes,
      emergencyType,
      emergencyDescription,
      status: 'pending',
    });

    res.status(201).json({
      success: true,
      message: 'Appointment booked successfully',
      data: {
        appointment,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/appointments
 * @desc    Get all appointments
 * @access  Private
 */
const getAllAppointments = async (req, res, next) => {
  try {
    const { status, type, doctor, patient } = req.query;
    const query = {};

    if (status) query.status = status;
    if (type) query.type = type;
    if (doctor) query.doctor = doctor;
    if (patient) query.patient = patient;

    // If user is patient, only show their appointments (by patient ID or phone/name match)
    if (req.user && req.user.role === 'patient') {
      // Get user info to match by phone/name as well
      const User = require('../models/User');
      const user = await User.findById(req.user.id);
      
      const orConditions = [{ patient: req.user.id }];
      if (user && user.phone) {
        orConditions.push({ patientPhone: user.phone });
      }
      if (user && user.name) {
        orConditions.push({ patientName: user.name });
      }
      
      // Combine with existing query conditions
      const baseQuery = { ...query };
      query = {
        $and: [
          { $or: orConditions },
          baseQuery
        ]
      };
    }

    const appointments = await Appointment.find(query).sort({ date: 1, time: 1 });

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

/**
 * @route   GET /api/appointments/:id
 * @desc    Get appointment by ID
 * @access  Private
 */
const getAppointmentById = async (req, res, next) => {
  try {
    const appointment = await Appointment.findById(req.params.id);

    if (!appointment) {
      return next(new AppError(`Appointment not found with id of ${req.params.id}`, 404));
    }

    // Check if user has permission to view this appointment
    if (req.user && req.user.role === 'patient') {
      // If appointment has a patient ID, check if it matches
      if (appointment.patient && appointment.patient.toString() !== req.user.id) {
        return next(new AppError('Not authorized to view this appointment', 403));
      }
      
      // If appointment has no patient ID, check if phone/name matches
      if (!appointment.patient) {
        const User = require('../models/User');
        const user = await User.findById(req.user.id);
        
        const phoneMatch = user && user.phone && appointment.patientPhone === user.phone;
        const nameMatch = user && user.name && appointment.patientName === user.name;
        
        if (!phoneMatch && !nameMatch) {
          return next(new AppError('Not authorized to view this appointment', 403));
        }
      }
    }

    res.status(200).json({
      success: true,
      data: {
        appointment,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   PUT /api/appointments/:id
 * @desc    Update appointment
 * @access  Private
 */
const updateAppointment = async (req, res, next) => {
  try {
    const {
      doctor,
      service,
      date,
      time,
      status,
      notes,
    } = req.body;

    let appointment = await Appointment.findById(req.params.id);

    if (!appointment) {
      return next(new AppError(`Appointment not found with id of ${req.params.id}`, 404));
    }

    // Check permissions
    if (req.user && req.user.role === 'patient') {
      // If appointment has a patient ID, check if it matches
      if (appointment.patient && appointment.patient.toString() !== req.user.id) {
        return next(new AppError('Not authorized to update this appointment', 403));
      }
      
      // If appointment has no patient ID, check if phone/name matches
      if (!appointment.patient) {
        const User = require('../models/User');
        const user = await User.findById(req.user.id);
        
        if (!user) {
          return next(new AppError('User not found', 404));
        }
        
        // Normalize phone numbers (remove spaces, dashes, etc.)
        const normalizePhone = (phone) => phone ? phone.replace(/\s|-|\(|\)/g, '') : '';
        const userPhone = normalizePhone(user.phone || '');
        const appointmentPhone = normalizePhone(appointment.patientPhone || '');
        
        // Normalize names (trim, lowercase)
        const normalizeName = (name) => name ? name.trim().toLowerCase() : '';
        const userName = normalizeName(user.name || '');
        const appointmentName = normalizeName(appointment.patientName || '');
        
        const phoneMatch = userPhone && appointmentPhone && userPhone === appointmentPhone;
        const nameMatch = userName && appointmentName && userName === appointmentName;
        
        if (!phoneMatch && !nameMatch) {
          return next(new AppError('Not authorized to update this appointment. Phone or name does not match.', 403));
        }
      }
    }

    const updateFields = {};
    if (doctor) updateFields.doctor = doctor;
    if (service) updateFields.service = service;
    if (date) updateFields.date = date;
    if (time) updateFields.time = time;
    if (status) updateFields.status = status;
    if (notes !== undefined) updateFields.notes = notes;

    appointment = await Appointment.findByIdAndUpdate(
      req.params.id,
      updateFields,
      {
        new: true,
        runValidators: true,
      }
    );

    res.status(200).json({
      success: true,
      message: 'Appointment updated successfully',
      data: {
        appointment,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   DELETE /api/appointments/:id
 * @desc    Delete appointment
 * @access  Private
 */
const deleteAppointment = async (req, res, next) => {
  try {
    const appointment = await Appointment.findById(req.params.id);

    if (!appointment) {
      return next(new AppError(`Appointment not found with id of ${req.params.id}`, 404));
    }

    // Check permissions
    if (req.user && req.user.role === 'patient') {
      // If appointment has a patient ID, check if it matches
      if (appointment.patient && appointment.patient.toString() !== req.user.id) {
        return next(new AppError('Not authorized to delete this appointment', 403));
      }
      
      // If appointment has no patient ID, check if phone/name matches
      if (!appointment.patient) {
        const User = require('../models/User');
        const user = await User.findById(req.user.id);
        
        if (!user) {
          return next(new AppError('User not found', 404));
        }
        
        // Normalize phone numbers (remove spaces, dashes, etc.)
        const normalizePhone = (phone) => phone ? phone.replace(/\s|-|\(|\)/g, '') : '';
        const userPhone = normalizePhone(user.phone || '');
        const appointmentPhone = normalizePhone(appointment.patientPhone || '');
        
        // Normalize names (trim, lowercase)
        const normalizeName = (name) => name ? name.trim().toLowerCase() : '';
        const userName = normalizeName(user.name || '');
        const appointmentName = normalizeName(appointment.patientName || '');
        
        const phoneMatch = userPhone && appointmentPhone && userPhone === appointmentPhone;
        const nameMatch = userName && appointmentName && userName === appointmentName;
        
        if (!phoneMatch && !nameMatch) {
          return next(new AppError('Not authorized to delete this appointment. Phone or name does not match.', 403));
        }
      }
    }

    await Appointment.findByIdAndDelete(req.params.id);

    res.status(200).json({
      success: true,
      message: 'Appointment deleted successfully',
      data: {},
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  createAppointment,
  getAllAppointments,
  getAppointmentById,
  updateAppointment,
  deleteAppointment,
};

