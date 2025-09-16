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
    listQRCodes,
    duplicateQRCode,
    deleteQRCode
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
// router.post("/api/v1/createQr", createQRCode);

// // Get all QR Codes (with pagination)
// router.get("api/v1/createQr", getQRCodes);

router.post('/api/v1/createQr', createQRCode);

// Route to get a list of QR codes for the logged-in user
// GET /api/v1/listQr
router.get('/api/v1/listQr', listQRCodes);

// Route to duplicate an existing QR code
// POST /api/v1/duplicateQr/:qr_id
router.post('/api/v1/duplicateQr/:qr_id', duplicateQRCode);

// Route to delete a QR code
// DELETE /api/v1/deleteQr/:qr_id
router.delete('/api/v1/deleteQr/:qr_id', deleteQRCode);
export default router;

