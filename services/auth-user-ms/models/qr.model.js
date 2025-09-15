import mongoose from 'mongoose';
import { randomUUID } from 'crypto';

const qrCodeSchema = new mongoose.Schema({
    // Core Fields
    qrId: { type: String, required: true, unique: true},
    userId: { type: String, required: true, index: true }, // Foreign key to the User
    name: { type: String, required: true },
    type: { type: String },
    status: { type: String, default: 'ACTIVE' },
    scans: { type: Number, default: 0 },
    favorite: { type: Boolean, default: false },
    is_premium: { type: Boolean, default: false },
    icon: { type: String },

    // Complex Nested Data stored as flexible objects
    data: { type: mongoose.Schema.Types.Mixed },
    style: { type: mongoose.Schema.Types.Mixed },
    configuration: { type: mongoose.Schema.Types.Mixed },
    
}, { timestamps: true });

const QrCode = mongoose.model('QrCode', qrCodeSchema);
export default QrCode;