import mongoose from 'mongoose';

const scanSchema = new mongoose.Schema({
    scanId: { type: String, required: true, unique: true },
    userId: { type: String, required: true, index: true }, // The user who owns the QR code
    qrId: { type: String, required: true, index: true }, // The QR code that was scanned
    os: { type: String },
    browser: { type: String },
    country: { type: String },
    city: { type: String },
    // We'll add a unique identifier for the scanner to calculate unique scans
    scannerId: { type: String, required: true, index: true } 
}, { timestamps: true }); // 'createdAt' will be our scan timestamp

const Scan = mongoose.model('Scan', scanSchema);
export default Scan;
