import { existsSync, readFileSync, unlinkSync, writeFileSync } from 'fs';
import { join } from 'path';
import type { FixResult, PackageManager, RemediationAction, SnykIssue } from '../snyk/types.js';
import { BaseFixer } from './base-fixer.js';

const FILES: Record<PackageManager, string[]> = {
  npm: ['package.json', 'package-lock.json'],
  yarn: ['package.json', 'yarn.lock'],
  pnpm: ['package.json', 'pnpm-lock.yaml'],
  pip: ['requirements.txt'],
  poetry: ['pyproject.toml', 'poetry.lock'],
  maven: ['pom.xml'],
  gradle: ['build.gradle', 'build.gradle.kts', 'gradle/libs.versions.toml'],
  go: ['go.mod', 'go.sum'],
  composer: ['composer.json', 'composer.lock'],
};
type Snapshot = Map<string, string | null>;

export class ExactActionFixer extends BaseFixer {
  private lastSnapshot: Snapshot | undefined;
  constructor(readonly packageManager: PackageManager) {
    super();
  }

  private snapshot(cwd: string): Snapshot {
    return new Map(
      FILES[this.packageManager].map((file) => {
        const path = join(cwd, file);
        return [path, existsSync(path) ? readFileSync(path, 'utf8') : null] as const;
      }),
    );
  }
  private restore(snapshot: Snapshot): void {
    for (const [path, content] of snapshot) {
      if (content === null) {
        if (existsSync(path)) unlinkSync(path);
      } else {
        writeFileSync(path, content, 'utf8');
      }
    }
  }
  override rollback(): void {
    if (this.lastSnapshot) this.restore(this.lastSnapshot);
    this.lastSnapshot = undefined;
  }
  private editExact(cwd: string, action: RemediationAction): boolean {
    const candidates = FILES[this.packageManager].filter((f) =>
      this.packageManager === 'pip' ? f === 'requirements.txt' : this.packageManager === 'gradle',
    );
    for (const file of candidates) {
      const path = join(cwd, file);
      if (!existsSync(path)) continue;
      const before = readFileSync(path, 'utf8');
      let after: string;
      if (this.packageManager === 'pip') {
        const escaped = action.packageName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        after = before.replace(
          new RegExp(
            `^(\\\\s*${escaped}(?:\\\\[[^\\\\]]+\\\\])?)(?:\\\\s*[<>=!~^]+\\\\s*[^;\\\\s]+)?(\\\\s*(?:;.*)?)$`,
            'im',
          ),
          `$1==${action.targetVersion}$2`,
        );
      } else {
        after = before.replaceAll(
          `${action.packageName}:${action.currentVersion}`,
          `${action.packageName}:${action.targetVersion}`,
        );
      }
      if (after !== before) {
        writeFileSync(path, after, 'utf8');
        return true;
      }
    }
    return false;
  }
  private async applyAction(cwd: string, action: RemediationAction): Promise<void> {
    const exact = `${action.packageName}@${action.targetVersion}`;
    switch (this.packageManager) {
      case 'npm':
        return this.runCommand('npm', ['install', exact, '--save-exact'], cwd);
      case 'yarn':
        return this.runCommand('yarn', ['add', '--exact', exact], cwd);
      case 'pnpm':
        return this.runCommand('pnpm', ['add', '--save-exact', exact], cwd);
      case 'pip':
        if (!this.editExact(cwd, action)) throw new Error('unsupported_manifest_shape');
        return this.runCommand('pip', ['install', '-r', 'requirements.txt'], cwd);
      case 'poetry':
        return this.runCommand('poetry', ['add', exact], cwd);
      case 'maven':
        return this.runCommand(
          'mvn',
          [
            'versions:use-dep-version',
            `-Dincludes=${action.packageName}`,
            `-DdepVersion=${action.targetVersion}`,
            '-DforceVersion=true',
          ],
          cwd,
        );
      case 'gradle':
        if (!this.editExact(cwd, action)) throw new Error('unsupported_manifest_shape');
        return;
      case 'go': {
        await this.runCommand('go', ['get', `${action.packageName}@v${action.targetVersion}`], cwd);
        return this.runCommand('go', ['mod', 'tidy'], cwd);
      }
      case 'composer':
        return this.runCommand(
          'composer',
          ['require', `${action.packageName}:${action.targetVersion}`],
          cwd,
        );
    }
  }
  async applyFix(
    cwd: string,
    actions: RemediationAction[],
    findings: Map<string, SnykIssue>,
    dryRun: boolean,
  ): Promise<FixResult> {
    const relevant = actions.filter((a) => a.packageManager === this.packageManager);
    const changes = relevant.map(
      (a) => `${a.packageName}: ${a.currentVersion} -> ${a.targetVersion}`,
    );
    if (relevant.length === 0) return this.result([], findings, true, []);
    if (dryRun)
      return this.result(
        relevant,
        findings,
        true,
        changes.map((c) => `Would update ${c}`),
      );
    const snapshot = this.snapshot(cwd);
    this.lastSnapshot = snapshot;
    try {
      for (const action of relevant) await this.applyAction(cwd, action);
      const changed = [...snapshot].some(([path, before]) =>
        before === null
          ? existsSync(path)
          : existsSync(path) && readFileSync(path, 'utf8') !== before,
      );
      if (!changed) throw new Error('No relevant manifest or lockfile change');
      return this.result(relevant, findings, true, changes);
    } catch (error) {
      this.restore(snapshot);
      this.lastSnapshot = undefined;
      return this.result(relevant, findings, false, [], String(error));
    }
  }
}
