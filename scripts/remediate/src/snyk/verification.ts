import type { RemediationAction } from './types.js';

export function verifiedFindingIds(actions: RemediationAction[]): string[] {
  return actions
    .filter((action) => action.evidence === 'snyk-cli-upgrade-path')
    .flatMap((action) => action.findingIds);
}
