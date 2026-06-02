import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';
import { AuthService } from '../services/auth.service';

/**
 * Functional HTTP interceptor that:
 *  1. Attaches the `Token <key>` Authorization header to every outgoing
 *     request **except** login and register (to avoid sending a stale token).
 *  2. Catches any 401 Unauthorized response, clears the local session,
 *     and redirects to /login — so the user never sees a silent failure.
 */
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const auth = inject(AuthService);
  const router = inject(Router);
  const url = req.url;

  // Skip token attachment for public auth endpoints
  const isPublicAuth = url.includes('/login') || url.includes('/register');

  let outgoing = req;
  if (!isPublicAuth) {
    const token = auth.token();
    if (token) {
      outgoing = req.clone({
        setHeaders: { Authorization: `Token ${token}` },
      });
    }
  }

  return next(outgoing).pipe(
    catchError((error) => {
      // On 401 from any API, clear local auth state and redirect to login
      if (error.status === 401 && !isPublicAuth) {
        auth.clearLocal();
        void router.navigate(['/login']);
      }
      return throwError(() => error);
    })
  );
};
