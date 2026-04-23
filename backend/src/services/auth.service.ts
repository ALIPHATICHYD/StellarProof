import jwt from 'jsonwebtoken';
import User, { IUser } from '../models/User.model';

interface JwtPayload {
  id: string;
  iat: number;
  exp: number;
}

class AuthService {
  async verifyTokenAndGetUser(token: string): Promise<IUser> {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
      throw new Error('JWT_SECRET environment variable is not configured');
    }

    const decoded = jwt.verify(token, secret) as JwtPayload;

    const user = await User.findById(decoded.id);
    if (!user) {
      throw new Error('USER_NOT_FOUND');
    }

    if (!user.isActive) {
      throw new Error('ACCOUNT_DEACTIVATED');
    }

    return user;
  }
}

export const authService = new AuthService();
