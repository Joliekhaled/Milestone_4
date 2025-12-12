/**
 * Seed Data Script
 * Populates the database with initial doctors and services
 */

require('dotenv').config();
const mongoose = require('mongoose');
const Doctor = require('../models/Doctor');
const Service = require('../models/Service');

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('MongoDB Connected for seeding...');
  } catch (error) {
    console.error('Error connecting to MongoDB:', error);
    process.exit(1);
  }
};

const doctors = [
  {
    name: 'Dr. Ahmed Amer',
    specialty: 'Root Canal Specialist',
    image: 'https://placehold.co/250x250?text=Ahmed',
    availableTimes: ['12:00', '13:00', '14:00', '15:00'],
  },
  {
    name: 'Dr. Sarah Hany',
    specialty: 'Cosmetic Dentistry',
    image: 'https://placehold.co/250x250?text=Sarah',
    availableTimes: ['12:00', '14:00', '16:00'],
  },
  {
    name: 'Dr. Youmna Galeb',
    specialty: 'Pediatric Dentistry',
    image: 'https://placehold.co/250x250?text=Youmna',
    availableTimes: ['13:00', '15:00'],
  },
  {
    name: 'Dr. Mai Mansour',
    specialty: 'Orthodontics',
    image: 'https://placehold.co/250x250?text=Mai',
    availableTimes: ['12:00', '13:00', '14:00'],
  },
  {
    name: 'Dr. Youssef Kamel',
    specialty: 'Oral Surgery',
    image: 'https://placehold.co/250x250?text=Youssef',
    availableTimes: ['14:00', '15:00', '16:00'],
  },
];

const services = [
  {
    name: 'General Checkups',
    description: 'Routine examinations to keep your smile healthy.',
    category: 'General',
    duration: 30,
  },
  {
    name: 'Teeth Cleaning',
    description: 'Deep cleaning to remove plaque and protect gums.',
    category: 'General',
    duration: 45,
  },
  {
    name: 'X-rays & Imaging',
    description: 'Modern digital X-rays & treatment history.',
    category: 'General',
    duration: 20,
  },
  {
    name: 'Root Canal Treatment',
    description: 'Expert root canal procedures.',
    category: 'Specialty',
    duration: 90,
  },
  {
    name: 'Cosmetic Dentistry',
    description: 'Whitening, veneers & smile makeovers.',
    category: 'Cosmetic',
    duration: 60,
  },
  {
    name: 'Emergency Dental Care',
    description: 'Same-day pain relief for urgent cases.',
    category: 'Emergency',
    duration: 30,
  },
];

const seedData = async () => {
  try {
    await connectDB();

    // Clear existing data (optional - comment out if you want to keep existing data)
    await Doctor.deleteMany({});
    await Service.deleteMany({});

    // Insert doctors
    const insertedDoctors = await Doctor.insertMany(doctors);
    console.log(`✅ Inserted ${insertedDoctors.length} doctors`);

    // Insert services
    const insertedServices = await Service.insertMany(services);
    console.log(`✅ Inserted ${insertedServices.length} services`);

    console.log('✅ Database seeded successfully!');
    process.exit(0);
  } catch (error) {
    console.error('❌ Error seeding database:', error);
    process.exit(1);
  }
};

seedData();










