/**
 * Manifest Controller – thin HTTP adapter layer.
 *
 * Each method:
 *  1. Extracts validated data from the request (query params are already
 *     validated by middleware before reaching here).
 *  2. Delegates to the service layer.
 *  3. Wraps the result in the standard ApiResponse envelope.
 *  4. Forwards any errors to the global error handler via `next(err)`.
 *
 * No business logic lives here.
 */
import type { Request, Response, NextFunction } from "express";
import { StatusCodes } from "http-status-codes";
import { manifestService } from "../services/manifest.service";
import type { ListManifestsQuery } from "../types/manifest.types";

export class ManifestController {
  /**
   * GET /api/v1/manifests?ownerPublicKey=G...&limit=20&skip=0
   * Returns a paginated list of manifests for the authenticated owner.
   */
  async listManifests(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const query: ListManifestsQuery = {
        ownerPublicKey: req.query.ownerPublicKey as string,
        limit: Number(req.query.limit),
        skip: Number(req.query.skip),
      };

      const result = await manifestService.listManifests(query);

      res.status(StatusCodes.OK).json({
        success: true,
        data: result,
      });
    } catch (err) {
      next(err);
    }
  }
}

export const manifestController = new ManifestController();
