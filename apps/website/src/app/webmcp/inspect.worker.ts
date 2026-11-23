import { inspect, type SourceInput } from './inspect';
self.onmessage = ({ data }: MessageEvent<SourceInput>) => {
  try { self.postMessage(inspect(data)); }
  catch { self.postMessage({ status: 'error', message: 'The TypeScript parser could not process this snippet.' }); }
};
