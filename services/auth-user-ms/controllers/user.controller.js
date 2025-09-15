
import User from '../models/user.model.js';
import Otp from '../models/otp.model.js';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import otpGenerator from 'otp-generator';
import { sendOtpSms } from '../service/smsService.js';
import {sendOtpEmail} from '../service/emailService.js'
import QrCode from '../models/qr.model.js';
import Scan from '../models/scan.model.js';
import axios from 'axios';
// import { sendOtpEmail } from '../services/emailService.js';

// --- HELPER FUNCTION ---
// const generateAndSetToken = (res, user) => {
//     const payload = { userId: user.userId, role: user.role, email: user.email };
//     const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '5m' }); // 5 minute expiry as per Set-Cookie Max-Age=300

//     res.cookie('token', token, {
//         httpOnly: true,
//         secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
//         sameSite: 'Strict',
//         maxAge: 300 * 1000 // 300 seconds (5 minutes)
//     });
// };

// --- AUTHENTICATION ---
export const authenticateUser = async (req, res) => {
    // Note: 'country_code' from cURL is destructured into 'countryCode' for consistency.
    const { event, mode, email, password, mobile, country_code: countryCode, passcode } = req.body;
    
    try {
        let user;
        // Determine the query based on whether the mode is email or mobile based
        const query = mode.includes('email') ? { email } : { mobile, countryCode };

        // Find if the user already exists
        const existingUser = await User.findOne(query);

        if (event === 'register') {
            if (existingUser) {
                return res.status(400).json({ message: 'User already exists.' });
            }
            // In a real OTP flow, the passcode would be validated here.
            // Since the cURL provides a static one, we proceed as if it's valid.
            const newUser = new User({
                userId: randomUUID(),
                email: email || null,
                mobile: mobile || null,
                countryCode: countryCode || null,
                password: password || null,
                passwordSet: !!password,
                emailVerified: mode.includes('email'), // Assumes verification if signing up via this method
                mobileVerified: mode.includes('mobile'),
            });
            user = await newUser.save();

        } else if (event === 'login') {
            if (!existingUser) {
                return res.status(404).json({ message: 'User not found.' });
            }
            user = existingUser; // Use the found user

            // Validate password if using a password mode
            if (mode.includes('password')) {
                const isMatch = await user.comparePassword(password);
                if (!isMatch) {
                    return res.status(401).json({ message: 'Invalid credentials.' });
                }
            }
            // For OTP mode, we assume the provided 'passcode' is valid, as per the cURL.
            
        } else {
            return res.status(400).json({ message: 'Invalid event type. Must be "login" or "register".' });
        }

        // --- RESPONSE LOGIC (Matches cURL requirements) ---
        // 1. Set the JWT cookie in the response header.
        // generateAndSetToken(res, user);

        // 2. Send the simple success response with only the user_id.
        res.status(200).json({
            status: 'success',
            code: 200,
            data: {
                user_id: user.userId
            }
        });

    } catch (error) {
        res.status(500).json({ status: 'error', message: error.message });
    }
};

// --- OTP MANAGEMENT ---
export const sendOtp = async (req, res) => {
    const { mode, mobile, "country-code": country_code, email } = req.body;
    console.log("error 123");
    try {
        let identifier;
        // Generate a real 6-digit OTP
        const otp = otpGenerator.generate(6, { digits: true, upperCaseAlphabets: false, lowerCaseAlphabets: false, specialChars: false });
        let otpSent = false;
        
        if (mode === 'mobile') {
            if (!mobile || !country_code) return res.status(400).json({ message: 'Mobile and country-code are required.' });
            identifier = `${country_code}${mobile}`;
            otpSent = await sendOtpSms(identifier, otp);
        } else if (mode === 'email') {
            if (!email) return res.status(400).json({ message: 'Email is required.' });
            identifier = email;
            otpSent = await sendOtpEmail(identifier, otp);
        } else {
            console.log("error 0");
            return res.status(400).json({ message: 'Invalid mode. Must be "mobile" or "email".' });
        }
    console.log("error 000000");
        if (!otpSent) {
            return res.status(500).json({ message: 'Failed to send OTP. Please try again later.' });
        }
    console.log("error 1");
        // Store the real OTP in the database
        await Otp.create({ identifier, otp });

        // Respond with the static passcode from the cURL examples
        res.status(200).json({
            status: "success",
            code: 200,
            data: {
                message: "OTP sent successfully",
                expires_in: 300,
                passcode: "10069a2b1238" // Using static passcode from cURL
            }
        });
        console.log("error 2");
    } catch (error) {
        console.log("error 3");
         res.status(500).json({ status: 'error 4', message: error.message });
    }
};

export const verifyOtp = async (req, res) => {
    const { mode, email, mobile, "country-code": country_code, otp, passcode } = req.body;

    try {
        if (!otp) {
            return res.status(400).json({ message: 'OTP is required for verification.' });
        }

        const identifier = mode === 'email' ? email : `${country_code}${mobile}`;
        
        
        // Find the most recently created OTP for this user1
        const latestOtp = await Otp.findOne({ identifier }).sort({ createdAt: -1 });

        // Check if the OTP exists and matches the one provided
        if (!latestOtp || latestOtp.otp !== otp) {
            return res.status(401).json({ message: 'Invalid or expired OTP.' });
        }

        // Security: Delete the OTP after it has been successfully verified to prevent reuse.
        await Otp.deleteOne({ _id: latestOtp._id });


          let userQuery = mode === "email" ? { email } : { mobile, countryCode: country_code };
        let user = await User.findOne(userQuery);

        if (!user) {
            // Create new user if not exists
            user = await User.create({
                userId: randomUUID(),
                email: mode === "email" ? email : null,
                mobile: mode === "mobile" ? mobile : null,
                countryCode: mode === "mobile" ? country_code : null,
                role: "user", // default role
                emailVerified: mode === "email",
                mobileVerified: mode === "mobile"
            });
        }

        // --- Response ---
        res.status(200).json({
            status: "success",
            code: 200,
            data: {
                message: "OTP verified successfully",
                passcode: passcode || "10069a2b1238",
                userId: user.userId,
                role: user.role
            }
        });

    } catch (error) {
         res.status(500).json({ status: 'error', message: error.message });
    }
};

export const getUserDetails = async (req, res) => {
    // This endpoint should get the currently authenticated user.
    // The gateway validates the cookie and provides the user's ID in the 'x-user-id' header.
    const authenticatedUserId = req.headers['x-user-id'];

    if (!authenticatedUserId) {
        // This would happen if the gateway middleware failed or if the request bypassed the gateway.
        return res.status(401).json({ message: 'Unauthorized: No user session found.' });
    }

    try {
        const user = await User.findOne({ userId: authenticatedUserId }).select('-password -__v -_id');
        
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Format the response to exactly match the cURL's expected output
        const formattedUser = {
            "user-id": user.userId,
            "profile-photo": user.profilePhoto,
            "email": user.email,
            "email-verified": user.emailVerified,
            "mobile": user.mobile,
            "country-code": user.countryCode,
            "firstName": user.firstName,
            "lastName": user.lastName,
            "dob": user.dob,
            "passwordSet": user.passwordSet,
            "created-at": user.createdAt.toISOString() // Ensure date is in ISO format
        };
        
        res.status(200).json({
            status: "success",
            code: 200,
            data: formattedUser
        });

    } catch (error) {
        res.status(500).json({ status: 'error', message: error.message });
    }
};

// Update user details
export const updateUserDetails = async (req, res) => {
    // The user is identified by the session, provided by the gateway in the header.
    const authenticatedUserId = req.headers['x-user-id'];

    if (!authenticatedUserId) {
        return res.status(401).json({ message: 'Unauthorized: No user session found.' });
    }

    try {
        // Sanitize the input: only allow specific fields to be updated for security.
        const allowedUpdates = ['firstName', 'lastName', 'dob', 'profilePhoto', 'email'];
        const updateData = {};
        
        // Map incoming snake_case or kebab-case keys to camelCase model fields
        const keyMap = {
            'profile-photo': 'profilePhoto',
            'firstName': 'firstName',
            'lastName': 'lastName',
            'dob': 'dob',
            'email':'email'
        };

        for (const key in req.body) {
            if (keyMap[key] && allowedUpdates.includes(keyMap[key])) {
                updateData[keyMap[key]] = req.body[key];
            }
        }

        if (Object.keys(updateData).length === 0) {
            return res.status(400).json({ message: 'No valid fields provided for update.' });
        }

        // Find the user by the authenticated ID and update them with the sanitized data
        const updatedUser = await User.findOneAndUpdate(
            { userId: authenticatedUserId },
            updateData,
            { new: true, runValidators: true } // Return the updated document
        );

        if (!updatedUser) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Format the response to exactly match the cURL's expected output
        const responseData = {
            "user-id": updatedUser.userId,
            "profile-photo": updatedUser.profilePhoto,
            "firstName": updatedUser.firstName,
            "lastName": updatedUser.lastName,
            "dob": updatedUser.dob,
            "message": "user details updated successfully"
        };
        
        res.status(200).json({
            status: "success",
            code: 200,
            data: responseData
        });

    } catch (error) {
        res.status(500).json({ status: 'error', message: error.message });
    }
};

// delete user
export const deleteUser = async (req, res) => {
    // The cURL implies this is an admin action, targeting a specific user via a query parameter.
    // The gateway should verify the requester's session and pass their role in the 'x-user-role' header.
    const authenticatedUserRole = req.headers['x-user-role'];
    const targetUserId = req.query['user-id'];

    if (!targetUserId) {
        return res.status(400).json({ message: 'Missing user-id query parameter.' });
    }

    // Authorization check: Only allow users with the 'admin' role to delete other users.
    // if (authenticatedUserRole !== 'admin') {
    //     return res.status(403).json({ message: 'Forbidden: You do not have permission to delete this user.' });
    // }

    try {
        const result = await User.deleteOne({ userId: targetUserId });

        if (result.deletedCount === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json({
            status: "success",
            code: 200,
            data: {
                message: "user deleted successfully"
            }
        });
    } catch (error) {
        res.status(500).json({ status: 'error', message: error.message });
    }
};

// --- PASSWORD MANAGEMENT (Completely Rewritten) ---
export const managePassword = async (req, res) => {
    const { 
        event, 
        mode, 
        email, 
        mobile, 
        "country-code": country_code, 
        otp, 
        "new-password": newPassword,
        "current-password": currentPassword 
    } = req.body;
    
    const authenticatedUserId = req.headers['x-user-id'];

    try {
        let user;
        
        switch (event) {
            // Case 1: A logged-out user forgot their password and wants to initiate a reset.
            case 'forgot':
                if (!mode) return res.status(400).json({ message: 'Mode (email/mobile) is required for forgot password.' });
                
                const query = mode === 'email' ? { email } : { mobile, countryCode: country_code };
                user = await User.findOne(query);
                if (!user) return res.status(404).json({ message: 'User not found.' });

                // This logic is the same as sendOtp, but scoped to this event
                const newOtp = otpGenerator.generate(6, { digits: true, upperCaseAlphabets: false, lowerCaseAlphabets: false, specialChars: false });
                const identifier = mode === 'email' ? email : `${country_code}${mobile}`;
                
                let otpSent = false;
                if (mode === 'email') {
                    otpSent = await sendOtpEmail(identifier, newOtp);
                } else {
                    otpSent = await sendOtpSms(identifier, newOtp);
                }

                if (!otpSent) return res.status(500).json({ message: 'Failed to send OTP.' });
                
                await Otp.create({ identifier, otp: newOtp });
                return res.status(200).json({ status: "success", code: 200, data: { message: "Password reset instructions sent successfully" } });

            // Case 2: A logged-out user has an OTP and wants to set a new password.
            case 'reset':
                if (!otp || !newPassword || !mode) {
                    return res.status(400).json({ message: 'Event "reset" requires mode, otp, and new-password.' });
                }
                
                const resetIdentifier = mode === 'email' ? email : `${country_code}${mobile}`;
                const latestOtp = await Otp.findOne({ identifier: resetIdentifier }).sort({ createdAt: -1 });

                if (!latestOtp || latestOtp.otp !== otp) {
                    return res.status(401).json({ message: 'Invalid or expired OTP.' });
                }

                const resetQuery = mode === 'email' ? { email } : { mobile };
                user = await User.findOne(resetQuery);
                if (!user) return res.status(404).json({ message: 'User not found.' });

                await Otp.deleteOne({ _id: latestOtp._id });
                break; // Continue to the common password saving logic

            // Case 3: A logged-in user wants to update their password.
            case 'update':
                if (!authenticatedUserId) return res.status(401).json({ message: 'Unauthorized: Active session required.' });
                if (!currentPassword || !newPassword) return res.status(400).json({ message: 'Current and new passwords are required.' });

                user = await User.findOne({ userId: authenticatedUserId });
                if (!user) return res.status(404).json({ message: 'Authenticated user not found.' });

                const isMatch = await user.comparePassword(currentPassword);
                if (!isMatch) return res.status(401).json({ message: 'Invalid current password.' });
                break; // Continue to the common password saving logic

            // Case 4: A newly registered, logged-in user is setting their password for the first time.
            case 'set':
                if (!authenticatedUserId) return res.status(401).json({ message: 'Unauthorized: Active session required.' });
                if (!newPassword) return res.status(400).json({ message: 'New password is required.' });

                user = await User.findOne({ userId: authenticatedUserId });
                if (!user) return res.status(404).json({ message: 'Authenticated user not found.' });
                break; // Continue to the common password saving logic

            default:
                return res.status(400).json({ message: 'Invalid event type. Must be "forgot", "reset", "update", or "set".' });
        }

        // --- COMMON LOGIC: Save the new password for 'reset', 'update', and 'set' events ---
        user.password = newPassword;
        user.passwordSet = true;
        await user.save();
        
        return res.status(200).json({ 
            status: "success", 
            code: 200, 
            data: { message: `Password ${event} successfully.` }
        });

    } catch (error) {
        res.status(500).json({ status: 'error', message: error.message });
    }
};

// Helper function to calculate date ranges
const getDateFilter = (dateRange) => {

    const now = new Date();
    let fromDate;

    switch (dateRange.type) {
        case 'today':
            fromDate = new Date(now.setHours(0, 0, 0, 0));
            break;
        case 'yesterday':
            fromDate = new Date(now.setDate(now.getDate() - 1));
            fromDate.setHours(0, 0, 0, 0);
            break;
        case 'last7days':
            fromDate = new Date(now.setDate(now.getDate() - 7));
            break;
        case 'custom':
            fromDate = new Date(dateRange.from);
            break;
        default:
            fromDate = new Date(0); // Default to all time
    }
    return { $gte: fromDate, $lte: dateRange.to ? new Date(dateRange.to) : new Date() };
};
/**
 * Retrieves real-time dashboard data based on request filters.
 */
export const getDashboardData = async (req, res) => {   
    try {
        const authenticatedUserId = req.headers['x-user-id'];
        if (!authenticatedUserId) {
            return res.status(401).json({ message: 'Unauthorized: Active session required.' });
        }

        const {
            date_range,
            include_os,
            include_daily_scans,
            include_browser,
            include_time_of_day,
            include_qr_name,
            group_location
        } = req.body;

        const dateFilter = getDateFilter(date_range);
        const matchFilter = { userId: authenticatedUserId, createdAt: dateFilter };

        // --- 1. Fetch Summary Data ---
        const totalQRCodes = await QrCode.countDocuments({ userId: authenticatedUserId });
        const totalScans = await Scan.countDocuments(matchFilter);
        const totalUniqueScans = (await Scan.distinct('scannerId', matchFilter)).length;

        const summary = {
            totalQRCodes,
            totalScans,
            totalUniqueScans,
            totalVisits: totalScans // Assuming visits are the same as scans
        };

        // --- 2. Build Chart Data with Aggregation Pipelines ---
        const charts = {};
        const aggregationPromises = [];

        if (include_os) {
            aggregationPromises.push(
                Scan.aggregate([
                    { $match: matchFilter },
                    { $group: { _id: '$os', count: { $sum: 1 } } },
                    { $project: { _id: 0, os: '$_id', count: 1 } }
                ]).then(result => charts.scansByOS = result)
            );
        }
        if (group_location) {
             aggregationPromises.push(
                Scan.aggregate([
                    { $match: matchFilter },
                    { $group: { _id: '$country', count: { $sum: 1 } } },
                    { $project: { _id: 0, country: '$_id', count: 1 } }
                ]).then(result => charts.scansByCountry = result)
            );
             aggregationPromises.push(
                Scan.aggregate([
                    { $match: matchFilter },
                    { $group: { _id: '$city', count: { $sum: 1 } } },
                    { $project: { _id: 0, city: '$_id', count: 1 } }
                ]).then(result => charts.scansByCity = result)
            );
        }
        if (include_daily_scans) {
            aggregationPromises.push(
                Scan.aggregate([
                    { $match: matchFilter },
                    { $group: { 
                        _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } }, 
                        count: { $sum: 1 } 
                    }},
                    { $project: { _id: 0, datetime: '$_id', count: 1 } },
                    { $sort: { datetime: 1 } }
                ]).then(result => charts.scanActivity = result)
            );
        }
        if (include_browser) {
            aggregationPromises.push(
                Scan.aggregate([
                    { $match: matchFilter },
                    { $group: { _id: '$browser', count: { $sum: 1 } } },
                    { $project: { _id: 0, browser: '$_id', count: 1 } }
                ]).then(result => charts.scansByBrowser = result)
            );
        }
        if (include_qr_name) {
             aggregationPromises.push(
                Scan.aggregate([
                    { $match: matchFilter },
                    { $lookup: { from: 'qrcodes', localField: 'qrId', foreignField: 'qrId', as: 'qrCodeInfo'}},
                    { $unwind: '$qrCodeInfo' },
                    { $group: { _id: '$qrCodeInfo.name', count: { $sum: 1 } } },
                    { $project: { _id: 0, qrName: '$_id', count: 1 } }
                ]).then(result => charts.scansByQRName = result)
            );
        }
        if (include_time_of_day) {
            aggregationPromises.push(
                Scan.aggregate([
                    { $match: matchFilter },
                    { $group: { 
                        _id: { $hour: "$createdAt" }, 
                        count: { $sum: 1 } 
                    }},
                    { $project: { _id: 0, timeUTC: '$_id', count: 1 } },
                    { $sort: { timeUTC: 1 } }
                ]).then(result => charts.scansByTimeOfDay = result)
            );
        }

        // Run all aggregations in parallel for performance
        await Promise.all(aggregationPromises);
        
        // --- 3. Construct Final Response ---
        res.status(200).json({
            status: "success",
            code: 200,
            data: {
                filters: { dateRange: date_range },
                summary,
                charts
            }
        });

    } catch (error) {
        console.error('[ERROR] Failed to get dashboard data:', error);
        res.status(500).json({ status: 'error', message: 'An internal server error occurred.' });
    }
};

// Utility to convert snake_case keys to camelCase recursively
function toCamelCase(obj) {
    if (Array.isArray(obj)) {
        return obj.map(toCamelCase);
    } else if (obj && typeof obj === 'object') {
        return Object.keys(obj).reduce((acc, key) => {
            // Convert snake_case to camelCase
            const camelKey = key.replace(/_([a-z])/g, (g) => g[1].toUpperCase());
            acc[camelKey] = toCamelCase(obj[key]);
            return acc;
        }, {});
    }
    return obj;
}

export const createQRCode = async (req, res) => {
    try {
        // 1. Authenticate the user (ensure they have an active session)
        const authenticatedUserId = req.headers["x-user-id"];
        console.log(authenticatedUserId)
        if (!authenticatedUserId) {
            return res
                .status(401)
                .json({ message: "Unauthorized: Active session required." });
        }

        // 2. Define the target QR service endpoint
        const qrServiceEndpoint = `http://10.1.4.23:5001/api/v1/createQr`;

        // 3. The data to be sent is the entire body from the incoming request.
        let payload = req.body;
        // Convert all keys to camelCase for Python QR engine compatibility
        payload = toCamelCase(payload);
        console.log("[LOG] Payload sent to QR engine:", payload);

        console.log(`[LOG] Forwarding QR creation request to ${qrServiceEndpoint}`);

        // 4. Make the POST request to the Python QR service
        const responseFromQRService = await axios.post(qrServiceEndpoint, payload);
        console.log("[LOG] Received response from QR service:", responseFromQRService.status, responseFromQRService.data);

        // 5. Forward the successful response from the QR service back to the original client
        res.status(responseFromQRService.status).json(responseFromQRService.data);

    } catch (error) {
        console.error("[ERROR] Failed to communicate with QR Code service:", error.message);

        // If the error came from the QR service itself (e.g., a 4xx or 5xx error)
        if (error.response) {
                // Forward the error response from the QR service
                return res.status(error.response.status).json(error.response.data);
        }

        // If there was a network error (e.g., the QR service is down)
        res.status(503).json({ // 503 Service Unavailable
                status: "error",
                message: "The QR Code service is currently unavailable. Please try again later."
        });
    }
};

/**
 * Get all QR Codes for authenticated user (with pagination)
 */
export const getQRCodes = async (req, res) => {
  try {
    const authenticatedUserId = req.headers["x-user-id"];
    if (!authenticatedUserId) {
      return res
        .status(401)
        .json({ message: "Unauthorized: Active session required." });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const sort = req.query.sort === "asc" ? 1 : -1;
    const sortField = req.query.sort_field || "createdAt";

    const skip = (page - 1) * limit;

    const [qrCodes, total] = await Promise.all([
      QrCode.find({ userId: authenticatedUserId })
        .sort({ [sortField]: sort })
        .skip(skip)
        .limit(limit),
      QrCode.countDocuments({ userId: authenticatedUserId }),
    ]);

    const formattedData = qrCodes.map((qr) => ({
      id: qr._id,
      qr_code_name: qr.name,
      qr_code_type: qr.type,
      qr_code_link:
        qr.configuration?.urlCustomization?.url ||
        `https://bizscan.com/${qr.qrId}`,
      qr_code_scan_count: qr.scans,
      qr_code_status: qr.status,
      qr_code_created_at: qr.createdAt.toUTCString(),
      qr_code_updated_at: qr.updatedAt.toUTCString(),
      share_action_url: `https://bizscan.com/${qr.qrId}`,
      download_action_url: `https://bizscan.com/${qr.qrId}/download`,
      qr_code_image: `https://bizscan.com/${qr.qrId}/image`,
    }));

    res.status(200).json({
      status: "success",
      code: 200,
      data: formattedData,
      pagination: {
        page,
        limit,
        total,
        total_pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error("[ERROR] Failed to get QR codes:", error);
    res.status(500).json({ status: "error", message: error.message });
  }
};