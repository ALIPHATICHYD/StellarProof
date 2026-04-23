import mongoose, { Schema, Document } from 'mongoose';
import bcrypt from 'bcryptjs';

const BCRYPT_SALT_ROUNDS = 12;

/**
 * User Interface
 * Represents a creator, developer, or platform interacting with StellarProof.
 */
export interface IUser extends Document {
  email: string;               // Primary identifier for Web2 login
  passwordHash: string;        // Hashed password

  // Password Reset Flow
  resetPasswordToken?: string;
  resetPasswordExpires?: Date;

  stellarPublicKey?: string;   // Added later when they connect Freighter wallet
  nonce?: string;              // For SIWE (Sign-In With Ethereum/Stellar) flow if needed later
  role: 'creator' | 'developer' | 'admin';
  apiKeys: string[];           // For developer API access (Phase 2)
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;

  comparePassword(candidatePassword: string): Promise<boolean>;
}

const UserSchema: Schema = new Schema(
  {
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address'],
    },
    passwordHash: {
      type: String,
      required: [true, 'Password is required'],
      select: false,
    },
    resetPasswordToken: {
      type: String,
      select: false,
    },
    resetPasswordExpires: {
      type: Date,
      select: false,
    },
    stellarPublicKey: {
      type: String,
      unique: true,
      sparse: true,
      index: true,
    },
    nonce: {
      type: String,
    },
    role: {
      type: String,
      enum: ['creator', 'developer', 'admin'],
      default: 'creator',
    },
    apiKeys: [{
      type: String,
    }],
    isActive: {
      type: Boolean,
      default: true,
    }
  },
  { timestamps: true }
);

UserSchema.pre<IUser>('save', async function (next) {
  if (!this.isModified('passwordHash')) return next();
  this.passwordHash = await bcrypt.hash(this.passwordHash, BCRYPT_SALT_ROUNDS);
  next();
});

UserSchema.methods.comparePassword = async function (
  candidatePassword: string
): Promise<boolean> {
  return bcrypt.compare(candidatePassword, this.passwordHash);
};

export default mongoose.model<IUser>('User', UserSchema);