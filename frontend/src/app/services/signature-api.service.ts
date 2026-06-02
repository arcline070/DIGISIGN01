import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';

export interface SignatureLogRow {
  id: number;
  username: string;
  action: 'SIGN' | 'VERIFY';
  status: 'SUCCESS' | 'FAILED';
  timestamp: string;
  data_hash: string;
  signature: string;
  ip_address: string | null;
  failure_reason: string;
}

export interface VerifyResult {
  status: 'valid' | 'invalid' | 'tampered';
  message?: string;
  algorithm_used?: string;
  signed_by?: string;
  timestamp?: string;
  algorithm?: string;
  document_id?: string;
  hash?: string;
  original_filename?: string;
  certificate_owner?: string;
  certificate_valid_until?: string;
  structured_snapshot?: string;
  original_data?: string;
  verification_details?: {
    signature_status: string;
    timestamp: string;
    original_file_name: string;
    certificate_owner: string;
    certificate_expiry: string;
    signed_by: string;
    algorithm: string;
  };
  chain_verification?: {
    status: string;
    verified_versions?: number;
    broken_at_version?: number | null;
    document_id?: string;
    versions?: number;
  };
  changes?: {
    added: string[];
    deleted: string[];
    modified: { from: string; to: string }[];
  };
  tamper_report?: {
    added: string[];
    deleted: string[];
    modified: { from: string; to: string }[];
  };
  note?: string;
}

export interface IntegrityReportResult {
  status: 'valid' | 'invalid';
  crypto_verification: {
    status: 'valid' | 'invalid';
    details: Record<string, unknown>;
  };
  tamper_localization: {
    status: string;
    added_fields?: string[];
    deleted_fields?: string[];
    modified_fields?: string[];
    summary?: Record<string, number>;
    message?: string;
  };
  chain_verification: {
    status: string;
    document_id?: string;
    versions?: number;
  };
}

export interface MyCertificateResult {
  certificate: string;
  username: string;
  role: 'admin' | 'user';
  signature_algorithm?: 'RSA-SHA256' | 'ECDSA-P256-SHA256';
}

export interface SupportedAlgorithm {
  id: 'RSA-SHA256' | 'ECDSA-P256-SHA256' | (string & {});
  label: string;
}

export type ExportType = 'logs' | 'signed_data';
export type ExportFormat = 'json' | 'csv';

@Injectable({ providedIn: 'root' })
export class SignatureApiService {
  private readonly base = environment.apiBaseUrl;

  constructor(private http: HttpClient) {}

  /**
   * Sign using a pre-built FormData (file or text).
   * Returns the signed JSON package as a Blob download.
   */
  signDocumentRaw(formData: FormData): Observable<Blob> {
    return this.http.post(`${this.base}/sign-document`, formData, {
      responseType: 'blob',
    });
  }

  listDocumentIds(): Observable<{ document_ids: string[] }> {
    return this.http.get<{ document_ids: string[] }>(`${this.base}/my-document-ids`);
  }

  listDocumentIdsWithMetadata(): Observable<{ documents: { id: string; created_at: string; owner: string; filename?: string }[] }> {
    return this.http.get<{ documents: { id: string; created_at: string; owner: string; filename?: string }[] }>(`${this.base}/my-document-ids-with-metadata`);
  }

  addDocumentVersion(formData: FormData, documentId: string): Observable<Blob> {
    formData.append('document_id', documentId);
    return this.http.post(`${this.base}/add-document-version`, formData, {
      responseType: 'blob',
    });
  }

  /**
   * Verify a signed JSON package file.
   */
  verifyDocument(signedPackage: File): Observable<VerifyResult> {
    const fd = new FormData();
    fd.append('file', signedPackage, signedPackage.name);
    return this.http.post<VerifyResult>(`${this.base}/verify-document`, fd);
  }

  verifyAndWatermark(file: File): Observable<Blob> {
    const fd = new FormData();
    fd.append('file', file, file.name);
    return this.http.post(`${this.base}/verify-and-watermark`, fd, {
      responseType: 'blob',
    });
  }

  integrityReport(
    file: File,
    compareJson?: string,
    compareFile?: File | null
  ): Observable<IntegrityReportResult> {
    const fd = new FormData();
    fd.append('file', file, file.name);
    if (compareJson && compareJson.trim().length > 0) {
      fd.append('compare_json', compareJson);
    }
    if (compareFile) {
      fd.append('compare_file', compareFile, compareFile.name);
    }
    return this.http.post<IntegrityReportResult>(`${this.base}/integrity-report`, fd);
  }

  verifyChain(documentId: string): Observable<unknown> {
    return this.http.get(`${this.base}/verify-chain`, { params: { document_id: documentId } });
  }

  verifyQr(token: string): Observable<unknown> {
    return this.http.get(`${this.base}/verify-qr`, { params: { token } });
  }

  listLogs(): Observable<SignatureLogRow[]> {
    return this.http.get<SignatureLogRow[]>(`${this.base}/logs`);
  }

  myCertificate(): Observable<MyCertificateResult> {
    return this.http.get<MyCertificateResult>(`${this.base}/my-public-key`);
  }

  setSignatureAlgorithm(
    signature_algorithm: 'RSA-SHA256' | 'ECDSA-P256-SHA256'
  ): Observable<{ status: string; signature_algorithm: string; message?: string }> {
    return this.http.post<{ status: string; signature_algorithm: string; message?: string }>(
      `${this.base}/set-signature-algorithm`,
      { signature_algorithm }
    );
  }

  supportedAlgorithms(): Observable<{ algorithms: SupportedAlgorithm[] }> {
    return this.http.get<{ algorithms: SupportedAlgorithm[] }>(`${this.base}/supported-algorithms`);
  }

  exportData(type: ExportType, format: ExportFormat): Observable<Blob> {
    return this.http.get(`${this.base}/export`, {
      params: { type, format },
      responseType: 'blob',
    });
  }
}
