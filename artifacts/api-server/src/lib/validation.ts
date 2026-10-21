import type { Request, Response } from "express";
import type { ZodType } from "zod";

/**
 * Validates request input against one of the generated `@workspace/api-zod` schemas.
 *
 * On failure, responds 400 and returns `undefined` — so route handlers can `return` early and
 * keep their catch blocks for genuine upstream failures (which stay 502). Only the offending
 * field names go back to the client, never the submitted values (see threat_model.md: don't
 * reflect untrusted input).
 */
export function parseRequest<T>(
  schema: ZodType<T>,
  input: unknown,
  req: Request,
  res: Response,
): T | undefined {
  const result = schema.safeParse(input);
  if (result.success) return result.data;

  const fields = [...new Set(result.error.issues.map((issue) => issue.path.join(".") || "(root)"))];
  req.log.info({ fields }, "Rejected invalid request parameters");
  res.status(400).json({ error: `Invalid request parameter(s): ${fields.join(", ")}` });
  return undefined;
}
