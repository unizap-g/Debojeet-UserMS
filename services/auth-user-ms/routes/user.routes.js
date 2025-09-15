import express from 'express';
import {
    authenticateUser,
    sendOtp,
    verifyOtp,
    getUserDetails,
    updateUserDetails,
    deleteUser,
    managePassword,
    getDashboardData,
    createQRCode,
    getQRCodes
} from '../controllers/user.controller.js';

const router = express.Router();

// --- Authentication Routes ---
router.post('/api/v1/auth', authenticateUser);
router.post('/api/v1/auth/send-otp', sendOtp);
router.post('/api/v1/auth/verify-otp', verifyOtp);
router.put('/api/v1/auth/password', managePassword);

router.get('/api/v1/auth/user', getUserDetails);
router.put('/api/v1/auth/user', updateUserDetails);
router.delete('/api/v1/auth/user', deleteUser);
router.post('/api/v1/dashboard', getDashboardData);
// Create QR Code
router.post("/api/v1/createQr", createQRCode);

// Get all QR Codes (with pagination)
router.get("api/v1/createQr", getQRCodes);
export default router;

