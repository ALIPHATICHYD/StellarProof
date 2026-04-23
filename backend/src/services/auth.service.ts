import jwt from 'jsonwebtoken';
import User from '../models/User.model';
import { AppError } from '../errors/AppError';
import { env } from '../config/env';

export interface LoginResult {
  token: string;
  user: {
    id: string;
    email: string;
    role: string;
    stellarPublicKey?: string;
  };
}

export class AuthService {
  async login(email: string, password: string): Promise<LoginResult> {
    if (!email || !password) {
      throw new AppError('Email and password are required', 400, 'MISSING_CREDENTIALS');
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() })
      .select('+passwordHash')
      .exec();

    if (!user) {
      throw new AppError('Invalid credentials', 401, 'INVALID_CREDENTIALS');
    }

    if (!user.isActive) {
      throw new AppError('Account is deactivated', 403, 'ACCOUNT_DEACTIVATED');
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      throw new AppError('Invalid credentials', 401, 'INVALID_CREDENTIALS');
    }

    const token = jwt.sign(
      { userId: user._id.toString() },
      env.JWT_SECRET,
      { expiresIn: env.JWT_EXPIRES_IN } as jwt.SignOptions
    );

    return {
      token,
      user: {
        id: user._id.toString(),
        email: user.email,
        role: user.role,
        ...(user.stellarPublicKey ? { stellarPublicKey: user.stellarPublicKey } : {}),
      },
    };
  }

  /**
   * ✅ NEW METHOD (fixes your CI error)
   */
  async verifyTokenAndGetUser(token: string) {
    if (!token) {
      throw new AppError('No token provided', 401, 'NO_TOKEN');
    }

    let decoded: any;

    try {
      decoded = jwt.verify(token, env.JWT_SECRET) as { userId: string };
    } catch (err) {
      throw new AppError('Invalid or expired token', 401, 'INVALID_TOKEN');
    }

    const user = await User.findById(decoded.userId).exec();

    if (!user) {
      throw new AppError('User not found', 401, 'USER_NOT_FOUND');
    }

    if (!user.isActive) {
      throw new AppError('Account is deactivated', 403, 'ACCOUNT_DEACTIVATED');
    }

    return user;
  }
}

export const authService = new AuthService();
