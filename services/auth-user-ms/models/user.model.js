import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const userSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true },

  // ✅ No direct unique here (handled via partial indexes below)
  email: { type: String },
  mobile: { type: String },
  
  countryCode: { type: String },
  password: { type: String },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  firstName: { type: String },
  lastName: { type: String },
  dob: { type: String },
  profilePhoto: { type: String },
  emailVerified: { type: Boolean, default: false },
  mobileVerified: { type: Boolean, default: false },
  passwordSet: { type: Boolean, default: false },
}, { timestamps: true });

// ✅ Add partial indexes so unique applies only when value exists
userSchema.index(
  { email: 1 },
  { unique: true, partialFilterExpression: { email: { $type: "string" } } }
);

userSchema.index(
  { mobile: 1 },
  { unique: true, partialFilterExpression: { mobile: { $type: "string" } } }
);

// Hash password before saving
userSchema.pre('save', async function (next) {
  if (!this.isModified('password') || !this.password) {
    return next();
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Method to compare passwords
userSchema.methods.comparePassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);
export default User;
