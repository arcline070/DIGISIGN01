import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';

export interface BenchmarkResult {
  crypto: {
    rsa_keygen_ms: number;
    ecdsa_keygen_ms: number;
    rsa_sign_ms: number;
    rsa_verify_ms: number;
    ecdsa_sign_ms: number;
    ecdsa_verify_ms: number;
  };
  diff: {
    diff_json_ms: number;
    diff_excel_ms: number;
  };
  chain: {
    chain_1_ms: number;
    chain_10_ms: number;
    chain_25_ms: number;
    chain_50_ms: number;
  };
}

@Injectable({
  providedIn: 'root'
})
export class BenchmarkService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = environment.apiBaseUrl;

  runDiagnostics(): Observable<BenchmarkResult> {
    return this.http.get<BenchmarkResult>(`${this.baseUrl}/system/benchmark`);
  }
}
