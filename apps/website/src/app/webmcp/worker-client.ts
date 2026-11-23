import type { Inspection, SourceInput } from './inspect';

let running = false;
export async function runWorker(input: SourceInput, signal?: AbortSignal): Promise<Inspection> {
  if (signal?.aborted) return { status: 'error', message: 'Analysis cancelled.' };
  if (running) return { status: 'error', message: 'An analysis is already running.' };
  let worker: Worker;
  try { worker = new Worker(new URL('./inspect.worker.ts', import.meta.url), { type: 'module' }); }
  catch { return { status: 'error', message: 'A local analysis worker is unavailable.' }; }
  running = true;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let cancel: (() => void) | undefined;
  try {
    return await new Promise<Inspection>((resolve) => {
      const failure = (message: string) => resolve({ status: 'error', message });
      cancel = () => failure('Analysis cancelled.');
      signal?.addEventListener('abort', cancel, { once: true });
      timer = setTimeout(() => failure('Analysis exceeded the 10 second limit.'), 10000);
      worker.onmessage = ({ data }: MessageEvent<Inspection>) => resolve(data);
      worker.onerror = worker.onmessageerror = () => failure('The local analysis worker failed.');
      worker.postMessage(input);
    });
  } finally {
    clearTimeout(timer);
    if (cancel) signal?.removeEventListener('abort', cancel);
    worker.terminate();
    running = false;
  }
}
