/**
 * Manifest Service – business logic for retrieving a user's manifest history.
 *
 * Manifests are stored inside SPV records.  This service queries the SPV
 * collection filtered by `ownerPublicKey` and projects away the
 * `encryptedPayload` field so it is never inadvertently exposed through the
 * list endpoint.
 *
 * Pagination is implemented with MongoDB `skip` / `limit` and a parallel
 * `countDocuments` call so the caller always knows the full result-set size.
 */
import { StatusCodes } from "http-status-codes";

import { SPVModel } from "../models/spv.model";
import { AppError } from "../errors/AppError";
import type {
  IManifestEntry,
  ListManifestsQuery,
  ManifestListResult,
} from "../types/manifest.types";

// Fields to exclude from query results – never return the encrypted payload.
const EXCLUDED_FIELDS = { encryptedPayload: 0 } as const;

/**
 * Returns a paginated list of manifests owned by the given Stellar public key.
 *
 * @throws {AppError} 400 – if `limit` or `skip` values are out of range.
 */
async function listManifests(
  query: ListManifestsQuery
): Promise<ManifestListResult> {
  const { ownerPublicKey, limit, skip } = query;

  if (limit < 1 || limit > 100) {
    throw new AppError(
      "limit must be between 1 and 100",
      StatusCodes.BAD_REQUEST,
      "INVALID_PAGINATION"
    );
  }

  if (skip < 0) {
    throw new AppError(
      "skip must be a non-negative integer",
      StatusCodes.BAD_REQUEST,
      "INVALID_PAGINATION"
    );
  }

  const filter = { ownerPublicKey };

  // Run both queries in parallel to minimise round-trip latency.
  const [manifests, total] = await Promise.all([
    SPVModel.find(filter, EXCLUDED_FIELDS)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean<IManifestEntry[]>(),
    SPVModel.countDocuments(filter),
  ]);

  return { manifests, total, limit, skip };
}

// ---------------------------------------------------------------------------
// Exported service object
// ---------------------------------------------------------------------------
export const manifestService = {
  listManifests,
} as const;
