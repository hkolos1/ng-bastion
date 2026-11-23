import { vi } from 'vitest';
import { runWorker } from './worker-client';

describe('analysis worker lifetime', () => {
  const input = { code: 'const a = 1;', filename: 'a.ts' };
  const terminate = vi.fn();
  const postMessage = vi.fn();

  beforeEach(() => {
    vi.useFakeTimers();
    vi.stubGlobal('Worker', class {
      terminate = terminate;
      postMessage = postMessage;
    });
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
    vi.useRealTimers();
  });

  it('honors cancellation before startup and terminates an active worker on abort', async () => {
    const cancelled = await runWorker(input, AbortSignal.abort());
    expect(cancelled).toMatchObject({ status: 'error' });
    expect(postMessage).not.toHaveBeenCalled();

    const controller = new AbortController();
    const active = runWorker(input, controller.signal);
    expect(postMessage).toHaveBeenCalledWith(input);
    expect(await runWorker(input)).toMatchObject({ status: 'error', message: expect.stringContaining('already running') });
    controller.abort();
    expect(await active).toMatchObject({ status: 'error', message: expect.stringContaining('cancelled') });
    expect(terminate).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('terminates stalled workers and releases the slot for the next request', async () => {
    for (let attempt = 0; attempt < 2; attempt++) {
      const active = runWorker(input);
      await vi.advanceTimersByTimeAsync(10000);
      expect(await active).toMatchObject({ status: 'error', message: expect.stringContaining('10 second') });
    }
    expect(terminate).toHaveBeenCalledTimes(2);
  });
});
