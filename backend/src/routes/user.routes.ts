import { Router } from 'express';
import { verifyJWT } from '../middlewares/jwt.middleware';
import { connectWallet } from '../controllers/user.controller';

const router = Router();

router.put('/connect-wallet', verifyJWT, connectWallet);

export default router;