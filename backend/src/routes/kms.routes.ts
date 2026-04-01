import { Router } from 'express';
import { rotateKey, getUserKeys, getActiveKey } from '../controllers/kms.controller';

const router = Router();

/**
 * POST /api/v1/kms/rotate
 * Rotate KMS key for a user
 */
router.post('/rotate', rotateKey);

/**
 * GET /api/v1/kms/keys/:userId
 * Get all KMS keys for a user
 */
router.get('/keys/:userId', getUserKeys);

/**
 * GET /api/v1/kms/keys/:userId/active
 * Get active KMS key for a user
 */
router.get('/keys/:userId/active', getActiveKey);

export default router;
