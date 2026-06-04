import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';

export interface DashboardSummary {
  metrics: {
    total_uploads: number;
    signatures_minted: number;
    active_users: number;
  };
  audit_ledger: {
    timestamp: string;
    user: string;
    action: string;
    status: string;
    failure_reason: string | null;
  }[];
  algorithm_split: {
    RSA: number;
    ECDSA: number;
  };
}

@Injectable({
  providedIn: 'root'
})
export class DashboardService {
  private apiUrl = `${environment.apiBaseUrl}/dashboard`;

  constructor(private http: HttpClient) { }

  getSummary(): Observable<DashboardSummary> {
    return this.http.get<DashboardSummary>(`${this.apiUrl}/summary/`);
  }

  getUsers(): Observable<any> {
    return this.http.get(`${this.apiUrl}/users/`);
  }

  getPendingDocuments(): Observable<any> {
    return this.http.get(`${this.apiUrl}/maker-checker/`);
  }

  updateDocumentStatus(documentId: string, newStatus: 'APPROVED' | 'REJECTED'): Observable<any> {
    return this.http.post(`${this.apiUrl}/maker-checker/`, {
      document_id: documentId,
      new_status: newStatus
    });
  }
}
