import express, { Request, Response } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { connectDB } from './config/db';
import healthRoutes from './routes/health.routes';
import { validateNoDuplicateKeys } from './middlewares/validation.middleware';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;

// Middleware
app.use(cors());
// Intercepts raw JSON body stream to reject payloads with duplicate keys
app.use(validateNoDuplicateKeys);

// Connect to MongoDB
connectDB();

// Routes
app.use('/api/health', healthRoutes);

// Base route
app.get('/', (req: Request, res: Response) => {
  res.send('StellarProof Backend API is running');
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
