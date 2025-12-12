# Smile Dental Clinic - Backend API

Backend API for Smile Dental Clinic built with Node.js, Express.js, and MongoDB. This API powers the dental clinic's booking system, patient management, and appointment scheduling.

## Features

- ✅ **Appointment Management** - Book, view, update, and cancel appointments
- ✅ **Doctor Management** - CRUD operations for doctors and their schedules
- ✅ **Service Management** - Manage dental services offered
- ✅ **Patient Management** - User accounts with medical history
- ✅ **Authentication** - JWT-based authentication for patients and admins
- ✅ **Patient History** - View appointment history and medical records
- ✅ **Emergency Appointments** - Special handling for urgent cases
- ✅ **RESTful API** - Clean, well-documented endpoints

## Project Structure

```
backend/
├── config/
│   ├── database.js          # MongoDB connection
│   └── jwt.js               # JWT configuration
├── controllers/
│   ├── authController.js    # Authentication (register/login)
│   ├── appointmentController.js  # Appointment CRUD
│   ├── doctorController.js  # Doctor CRUD
│   ├── serviceController.js # Service CRUD
│   └── userController.js    # Patient CRUD
├── middleware/
│   ├── auth.js              # JWT authentication
│   ├── errorHandler.js      # Error handling
│   ├── logger.js            # Request logging
│   └── validator.js         # Input validation
├── models/
│   ├── Appointment.js       # Appointment schema
│   ├── Doctor.js            # Doctor schema
│   ├── Service.js           # Service schema
│   └── User.js              # Patient/User schema
├── routes/
│   ├── authRoutes.js        # Auth endpoints
│   ├── appointmentRoutes.js # Appointment endpoints
│   ├── doctorRoutes.js      # Doctor endpoints
│   ├── serviceRoutes.js     # Service endpoints
│   └── userRoutes.js        # User endpoints
├── scripts/
│   └── seedData.js          # Seed initial data
└── server.js                # Entry point
```

## Installation

1. **Install dependencies:**
   ```bash
   cd backend
   npm install
   ```

2. **Set up environment variables:**
   ```bash
   cp .env.example .env
   ```
   
   Update `.env` with your MongoDB Atlas connection string:
   ```
   MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/dental-clinic-api
   JWT_SECRET=your-secret-key
   ```

3. **Seed initial data (doctors and services):**
   ```bash
   npm run seed
   ```

4. **Start the server:**
   ```bash
   npm run dev  # Development mode
   # or
   npm start    # Production mode
   ```

## API Endpoints

### Authentication

- `POST /api/auth/register` - Register a new patient
- `POST /api/auth/login` - Login patient
- `GET /api/auth/me` - Get current user (requires token)

### Appointments

- `POST /api/appointments` - Book an appointment (public)
- `GET /api/appointments` - Get all appointments (requires token)
- `GET /api/appointments/:id` - Get appointment by ID (requires token)
- `PUT /api/appointments/:id` - Update appointment (requires token)
- `DELETE /api/appointments/:id` - Cancel appointment (requires token)

### Doctors

- `GET /api/doctors` - Get all doctors (public)
- `GET /api/doctors/:id` - Get doctor by ID (public)
- `POST /api/doctors` - Create doctor (admin only)
- `PUT /api/doctors/:id` - Update doctor (admin only)
- `DELETE /api/doctors/:id` - Delete doctor (admin only)

### Services

- `GET /api/services` - Get all services (public)
- `GET /api/services/:id` - Get service by ID (public)
- `POST /api/services` - Create service (admin only)
- `PUT /api/services/:id` - Update service (admin only)
- `DELETE /api/services/:id` - Delete service (admin only)

### Patients/Users

- `GET /api/users` - Get all users (admin only)
- `GET /api/users/:id` - Get user by ID (requires token)
- `GET /api/users/:id/appointments` - Get patient history (requires token)
- `PUT /api/users/:id` - Update user (requires token)
- `DELETE /api/users/:id` - Delete user (admin only)

## Example API Calls

### Register a Patient
```bash
POST /api/auth/register
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "password123",
  "phone": "01012345678",
  "age": 30,
  "gender": "Male"
}
```

### Book an Appointment
```bash
POST /api/appointments
{
  "doctor": "doctor_id_here",
  "service": "service_id_here",
  "date": "2025-12-15",
  "time": "14:00",
  "patientName": "John Doe",
  "patientPhone": "01012345678",
  "patientAge": 30,
  "patientGender": "Male",
  "type": "regular"
}
```

### Book Emergency Appointment
```bash
POST /api/appointments
{
  "doctor": "doctor_id_here",
  "date": "2025-12-08",
  "time": "12:00",
  "patientName": "Jane Doe",
  "patientPhone": "01098765432",
  "type": "emergency",
  "emergencyType": "Severe Tooth Pain",
  "emergencyDescription": "Severe pain in upper left molar"
}
```

### Get Patient History
```bash
GET /api/users/:patientId/appointments
Headers: Authorization: Bearer <token>
```

## Frontend Integration

The backend serves your frontend files from the parent directory. Your frontend HTML files (index.html, BookingDP.html, etc.) can make API calls to:

```
http://localhost:3000/api/*
```

### CORS Configuration

CORS is enabled, so your frontend can make requests from any origin. Update `server.js` if you need to restrict origins.

## Database Models

### Appointment
- Patient reference
- Doctor reference
- Service reference
- Date and time
- Status (pending, confirmed, completed, cancelled)
- Type (regular, emergency)
- Patient information
- Emergency details (if applicable)

### Doctor
- Name
- Specialty
- Image URL
- Available times
- Bio
- Active status

### Service
- Name
- Description
- Category (General, Cosmetic, Emergency, Specialty)
- Duration (minutes)
- Price
- Active status

### User/Patient
- Name, email, password
- Phone, age, gender
- Medical history
- Role (patient, admin)

## Security Features

- Password hashing with bcrypt
- JWT token authentication
- Protected routes with role-based access
- Input validation
- Secure error handling

## Testing

Use Postman or curl to test endpoints:

```bash
# Health check
curl http://localhost:3000/api/health

# Get doctors
curl http://localhost:3000/api/doctors

# Get services
curl http://localhost:3000/api/services
```

## Next Steps

1. Update your frontend HTML files to connect to the API
2. Replace hardcoded data with API calls
3. Add authentication to patient history page
4. Connect booking form to `/api/appointments` endpoint
5. Connect emergency form to `/api/appointments` with `type: "emergency"`

## Support

For issues or questions, check the main README.md or contact the development team.










