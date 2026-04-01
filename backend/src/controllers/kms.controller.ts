import { Request, Response } from 'express';
import * as kmsService from '../services/kms.service';
import mongoose from 'mongoose';

/**
 * KMS Controller
 * Handles HTTP requests for key management operations
 */

/**
 * POST /api/v1/kms/rotate
 * Rotates the KMS key for a user
 */
export const rotateKey = async (req: Request, res: Response): Promise<void> => {
  try {
    const { userId } = req.body;

    // Validation
    if (!userId) {
      res.status(400).json({
        status: 'error',
        message: 'userId is required in request body'
      });
      return;
    }

    // Validate ObjectId format
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      res.status(400).json({
        status: 'error',
        message: 'Invalid userId format'
      });
      return;
    }

    // Call service layer
    const result = await kmsService.rotateKey(userId);

    res.status(200).json({
      status: 'success',
      message: 'Key rotation completed successfully',
      data: {
        oldKeyVersion: result.oldKeyVersion,
        newKeyVersion: result.newKeyVersion,
        assetsReEncrypted: result.assetsReEncrypted,
        timestamp: new Date().toISOString()
      }
    });
  } catch (error: any) {
    console.error('Error in rotateKey controller:', error);

    // Handle specific error cases
    if (error.message === 'No active KMS key found for user') {
      res.status(404).json({
        status: 'error',
        message: error.message
      });
      return;
    }

    if (error.message === 'Invalid key version format') {
      res.status(400).json({
        status: 'error',
        message: error.message
      });
      return;
    }

    // Generic error response
    res.status(500).json({
      status: 'error',
      message: 'An error occurred during key rotation',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

/**
 * GET /api/v1/kms/keys/:userId
 * Gets all KMS keys for a user
 */
export const getUserKeys = async (req: Request, res: Response): Promise<void> => {
  try {
    const { userId } = req.params;

    // Validate ObjectId format
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      res.status(400).json({
        status: 'error',
        message: 'Invalid userId format'
      });
      return;
    }

    const keys = await kmsService.getAllKeys(userId);

    res.status(200).json({
      status: 'success',
      data: {
        keys: keys.map(key => ({
          id: key._id,
          keyVersion: key.keyVersion,
          algorithm: key.algorithm,
          isActive: key.isActive,
          expiresAt: key.expiresAt,
          createdAt: key.createdAt,
          updatedAt: key.updatedAt
        })),
        count: keys.length
      }
    });
  } catch (error: any) {
    console.error('Error in getUserKeys controller:', error);

    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching keys',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

/**
 * GET /api/v1/kms/keys/:userId/active
 * Gets the active KMS key for a user
 */
export const getActiveKey = async (req: Request, res: Response): Promise<void> => {
  try {
    const { userId } = req.params;

    // Validate ObjectId format
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      res.status(400).json({
        status: 'error',
        message: 'Invalid userId format'
      });
      return;
    }

    const activeKey = await kmsService.getActiveKey(userId);

    if (!activeKey) {
      res.status(404).json({
        status: 'error',
        message: 'No active key found for user'
      });
      return;
    }

    res.status(200).json({
      status: 'success',
      data: {
        id: activeKey._id,
        keyVersion: activeKey.keyVersion,
        algorithm: activeKey.algorithm,
        isActive: activeKey.isActive,
        expiresAt: activeKey.expiresAt,
        createdAt: activeKey.createdAt,
        updatedAt: activeKey.updatedAt
      }
    });
  } catch (error: any) {
    console.error('Error in getActiveKey controller:', error);

    res.status(500).json({
      status: 'error',
      message: 'An error occurred while fetching active key',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};
