import { Request, Response, NextFunction } from 'express';
import { StrKey } from '@stellar/stellar-sdk';
import { userService } from '../services/user.service';
import { AppError } from '../errors/AppError';

export const connectWallet = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const { stellarPublicKey } = req.body as { stellarPublicKey?: unknown };

    if (!stellarPublicKey || typeof stellarPublicKey !== 'string') {
      return next(new AppError('stellarPublicKey is required', 400, 'MISSING_FIELD'));
    }

    if (!StrKey.isValidEd25519PublicKey(stellarPublicKey)) {
      return next(
        new AppError('Invalid Stellar public key format', 400, 'INVALID_STELLAR_KEY')
      );
    }

    const userId = req.user!._id.toString();
    const updatedUser = await userService.connectWallet(userId, stellarPublicKey);

    res.status(200).json({
      success: true,
      message: 'Stellar wallet connected successfully',
      data: {
        id: updatedUser._id,
        email: updatedUser.email,
        stellarPublicKey: updatedUser.stellarPublicKey,
        role: updatedUser.role,
      },
    });
  } catch (error) {
    next(error);
  }
};