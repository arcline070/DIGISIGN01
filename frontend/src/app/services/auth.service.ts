import { HttpClient } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { Observable, catchError, tap, throwError } from 'rxjs';
import { environment } from '../../environments/environment';

const TOKEN_KEY = 'ds_auth_token';
const USER_KEY = 'ds_auth_username';
const ROLE_KEY = 'ds_auth_role';
const ALGO_KEY = 'ds_auth_algo';

export type UserRole = 'admin' | 'user';
export type SignatureAlgorithm = 'RSA-SHA256' | 'ECDSA-P256-SHA256';

export interface AuthResponse {
  token: string;
  username: string;
  role: UserRole;
  signature_algorithm?: SignatureAlgorithm;
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);
  private readonly router = inject(Router);
  private readonly base = environment.apiBaseUrl;

  readonly token = signal<string | null>(null);
  readonly username = signal<string | null>(null);
  readonly role = signal<UserRole>('user');
  readonly signatureAlgorithm = signal<SignatureAlgorithm>('RSA-SHA256');

  constructor() {
    this.restoreSession();
  }

  private restoreSession(): void {
    const t = localStorage.getItem(TOKEN_KEY);
    const u = localStorage.getItem(USER_KEY);
    const r = localStorage.getItem(ROLE_KEY) as UserRole | null;
    const a = localStorage.getItem(ALGO_KEY) as SignatureAlgorithm | null;
    this.token.set(t);
    this.username.set(u);
    this.role.set(r === 'admin' ? 'admin' : 'user');
    this.signatureAlgorithm.set(a === 'ECDSA-P256-SHA256' ? 'ECDSA-P256-SHA256' : 'RSA-SHA256');
  }

  isLoggedIn(): boolean {
    return !!this.token();
  }

  clearLocal(): void {
    localStorage.clear();
    this.token.set(null);
    this.username.set(null);
    this.role.set('user');
    this.signatureAlgorithm.set('RSA-SHA256');
  }

  private persist(res: AuthResponse): void {
    localStorage.setItem(TOKEN_KEY, res.token);
    localStorage.setItem(USER_KEY, res.username);
    localStorage.setItem(ROLE_KEY, res.role);
    localStorage.setItem(ALGO_KEY, res.signature_algorithm ?? 'RSA-SHA256');
    this.token.set(res.token);
    this.username.set(res.username);
    this.role.set(res.role);
    this.signatureAlgorithm.set(res.signature_algorithm === 'ECDSA-P256-SHA256' ? 'ECDSA-P256-SHA256' : 'RSA-SHA256');
  }

  login(username: string, password: string): Observable<AuthResponse> {
    return this.http
      .post<AuthResponse>(`${this.base}/login`, { username, password })
      .pipe(
        tap((res) => this.persist(res)),
        catchError((err) => throwError(() => err))
      );
  }

  register(
    username: string,
    password: string,
    signatureAlgorithm: SignatureAlgorithm = 'RSA-SHA256'
  ): Observable<AuthResponse> {
    return this.http
      .post<AuthResponse>(`${this.base}/register`, {
        username,
        password,
        signature_algorithm: signatureAlgorithm,
      })
      .pipe(
        tap((res) => this.persist(res)),
        catchError((err) => throwError(() => err))
      );
  }

  logout(): void {
    if (!this.token()) {
      this.clearLocal();
      void this.router.navigate(['/login']);
      return;
    }
    this.http.post(`${this.base}/logout`, {}).subscribe({
      next: () => {
        this.clearLocal();
        sessionStorage.clear();
        void this.router.navigate(['/login']);
      },
      error: () => {
        this.clearLocal();
        sessionStorage.clear();
        void this.router.navigate(['/login']);
      },
    });
  }
}
