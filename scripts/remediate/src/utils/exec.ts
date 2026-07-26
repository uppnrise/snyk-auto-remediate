import { spawn } from 'child_process';
import { logger } from './logger.js';

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export interface ExecOptions {
  cwd?: string;
  env?: Record<string, string>;
  timeout?: number;
}

export function execCommand(
  command: string,
  args: string[],
  options: ExecOptions = {},
): Promise<ExecResult> {
  return new Promise((resolve, reject) => {
    const { cwd = process.cwd(), env, timeout = 300_000 } = options;

    logger.debug(`Executing: ${command} ${args.join(' ')}`);

    const child = spawn(command, args, {
      cwd,
      env: env ?? process.env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (data: Buffer) => {
      stdout += data.toString();
    });

    child.stderr.on('data', (data: Buffer) => {
      stderr += data.toString();
    });

    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      reject(new Error(`Command timed out after ${timeout}ms: ${command} ${args.join(' ')}`));
    }, timeout);

    child.on('close', (code) => {
      clearTimeout(timer);
      const exitCode = code ?? 1;

      if (exitCode !== 0) {
        const err = new Error(
          `Command failed with exit code ${exitCode}: ${command} ${args.join(' ')}\n${stderr}`,
        ) as Error & { stdout: string; stderr: string; exitCode: number };
        err.stdout = stdout;
        err.stderr = stderr;
        (err as { exitCode: number }).exitCode = exitCode;
        reject(err);
        return;
      }

      resolve({ stdout, stderr, exitCode });
    });

    child.on('error', (err) => {
      clearTimeout(timer);
      reject(new Error(`Failed to spawn command: ${err.message}`));
    });
  });
}
