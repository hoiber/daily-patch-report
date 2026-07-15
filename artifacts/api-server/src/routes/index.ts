import { Router, type IRouter } from "express";
import healthRouter from "./health";
import cvesRouter from "./cves";
import patchTuesdayRouter from "./patch-tuesday";
import applePatchesRouter from "./apple-patches";
import metricsRouter from "./metrics";

const router: IRouter = Router();

router.use(healthRouter);
router.use(cvesRouter);
router.use(patchTuesdayRouter);
router.use(applePatchesRouter);
router.use(metricsRouter);

export default router;
