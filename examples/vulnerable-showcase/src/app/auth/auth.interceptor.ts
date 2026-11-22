import { HttpInterceptorFn } from '@angular/common/http';

/** NGB013: the bearer token is attached to every request, including third-party hosts. */
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const token = localStorage.getItem('access_token');
  return next(req.clone({ setHeaders: { Authorization: `Bearer ${token}` } }));
};
