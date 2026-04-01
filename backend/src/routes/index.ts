/**
 * Root router.
 * Mounts the versioned API sub-routers and a health-check endpoint.
 */
import { Router, type Request, type Response } from "express";
import certificateRoutes from "./certificate.routes";
import spvRoutes from "./spv.routes";
import verificationRoutes from "./verification.routes";
import manifestRoutes from "./manifest.routes";
import developerRoutes from "./developer.routes";

const router = Router();

/**
 * GET /health
 * Unversioned health check – used by load balancers and Docker HEALTHCHECK.
 */
router.get("/health", (_req: Request, res: Response): void => {
  res.json({
    status: "ok",
    service: "stellarproof-backend",
    timestamp: new Date().toISOString(),
  });
});

router.use("/api/v1/certificates", certificateRoutes);
router.use("/api/v1/manifests", manifestRoutes);
router.use("/api/v1/spv/records", spvRoutes);
router.use("/api/v1/verification/jobs", verificationRoutes);
router.use("/api/v1/developer", developerRoutes);

export default router;
