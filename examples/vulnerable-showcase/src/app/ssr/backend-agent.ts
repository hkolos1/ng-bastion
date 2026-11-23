import https from 'node:https';

// NGB098: the SSR server accepts any certificate from the backend API.
export const backendAgent = new https.Agent({ keepAlive: true, rejectUnauthorized: false });
