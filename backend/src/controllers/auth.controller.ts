import { Request, Response, NextFunction } from 'express';
import { authService } from '../services/auth.service';
import { AppError } from '../errors/AppError';

export const login = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const { email, password } = req.body as { email?: unknown; password?: unknown };

    if (typeof email !== 'string' || typeof password !== 'string') {
      return next(new AppError('Email and password must be strings', 400, 'INVALID_INPUT'));
    }

    const result = await authService.login(email, password);

    res.status(200).json({
      success: true,
      message: 'Login successful',
      data: result,
    });
  } catch (error) {
    next(error);
  }
};