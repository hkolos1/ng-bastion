import { HttpInterceptorFn } from '@angular/common/http';

/** NGB013: attaches the bearer token to every request, including third-party hosts. */
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const token = sessionStorage.getItem('access_token');
  return next(req.clone({ setHeaders: { Authorization: `Bearer ${token}` } }));
};
