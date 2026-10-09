import { runRemediation } from './engine.js';
import { logger } from './utils/logger.js';

runRemediation()
  .then((exitCode) => process.exit(exitCode))
  .catch((error: unknown) => {
    logger.error(`Fatal error: ${String(error)}`);
    process.exit(1);
  });
