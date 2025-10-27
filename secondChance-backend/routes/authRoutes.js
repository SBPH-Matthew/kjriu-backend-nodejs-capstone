const express = require('express');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const connectToDatabase = require('../models/db');
const dotenv = require('dotenv');
const pino = require('pino');
const { body, validationResult } = require('express-validator');

dotenv.config();
const router = express.Router();
const logger = pino();
const JWT_SECRET = process.env.JWT_SECRET;

// ==================== REGISTER ====================
router.post(
  '/register',
  [
    body('email').isEmail().withMessage('Valid email is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    body('firstName').notEmpty().withMessage('First name is required'),
    body('lastName').notEmpty().withMessage('Last name is required'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Validation failed during registration', errors.array());
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const db = await connectToDatabase();
      const collection = db.collection('users');
      const existingEmail = await collection.findOne({ email: req.body.email });

      if (existingEmail) {
        logger.error('Email already exists');
        return res.status(400).json({ error: 'Email already exists' });
      }

      const salt = await bcryptjs.genSalt(10);
      const hash = await bcryptjs.hash(req.body.password, salt);

      const newUser = await collection.insertOne({
        email: req.body.email,
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        password: hash,
        createdAt: new Date(),
      });

      const payload = { user: { id: newUser.insertedId } };
      const authtoken = jwt.sign(payload, JWT_SECRET);

      logger.info('User registered successfully');
      res.status(201).json({ authtoken, email: req.body.email });
    } catch (e) {
      logger.error(e);
      res.status(500).send('Internal server error');
    }
  }
);

// ==================== LOGIN ====================
router.post(
  '/login',
  [
    body('email').isEmail().withMessage('Valid email is required'),
    body('password').notEmpty().withMessage('Password is required'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Validation failed during login', errors.array());
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const db = await connectToDatabase();
      const collection = db.collection('users');
      const theUser = await collection.findOne({ email: req.body.email });

      if (!theUser) {
        logger.error('User not found');
        return res.status(404).json({ error: 'User not found' });
      }

      const result = await bcryptjs.compare(req.body.password, theUser.password);
      if (!result) {
        logger.error('Invalid password');
        return res.status(401).json({ error: 'Wrong password' });
      }

      const payload = { user: { id: theUser._id.toString() } };
      const authtoken = jwt.sign(payload, JWT_SECRET);

      logger.info('User logged in successfully');
      res.status(200).json({
        authtoken,
        userName: theUser.firstName,
        userEmail: theUser.email,
      });
    } catch (e) {
      logger.error(e);
      res.status(500).json({ error: 'Internal server error', details: e.message });
    }
  }
);

// ==================== UPDATE USER ====================
router.put(
  '/update',
  [
    body('firstName').notEmpty().withMessage('First name is required'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Validation errors in update request', errors.array());
      return res.status(400).json({ errors: errors.array() });
    }

    const email = req.headers.email;
    if (!email) {
      logger.error('Email not found in request headers');
      return res.status(400).json({ error: 'Email not found in request headers' });
    }

    try {
      const db = await connectToDatabase();
      const collection = db.collection('users');
      const existingUser = await collection.findOne({ email });

      if (!existingUser) {
        logger.error('User not found');
        return res.status(404).json({ error: 'User not found' });
      }

      const updatedData = {
        firstName: req.body.firstName,
        updatedAt: new Date(),
      };

      const updatedUser = await collection.findOneAndUpdate(
        { email },
        { $set: updatedData },
        { returnDocument: 'after' }
      );

      const payload = { user: { id: updatedUser.value._id.toString() } };
      const authtoken = jwt.sign(payload, JWT_SECRET);

      logger.info('User updated successfully');
      res.json({ authtoken });
    } catch (error) {
      logger.error(error);
      res.status(500).send('Internal server error');
    }
  }
);

module.exports = router;
