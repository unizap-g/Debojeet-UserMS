import mongoose from 'mongoose';

const otpSchema = new mongoose.Schema({
    // Stores either the user's email or their full mobile number (e.g., "919876543210")
    identifier: { 
        type:   String, 
        required: true,
        trim: true,
        index: true // Index for faster lookups
    },
    otp: { 
        type: String, 
        required: true 
    },
    // This is a TTL (Time To Live) index. MongoDB will automatically delete this document
    // 300 seconds (5 minutes) after its creation.
    createdAt: { 
        type: Date, 
        default: Date.now, 
        expires: 300 
    },
});

const Otp = mongoose.model('Otp', otpSchema);

export default Otp;
