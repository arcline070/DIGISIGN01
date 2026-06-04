import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import * as XLSX from 'xlsx';
import { Component, ElementRef, ViewChild, inject, signal } from '@angular/core';
import { finalize } from 'rxjs/operators';
import { NavbarComponent } from '../../components/navbar/navbar.component';
import { SignatureApiService, VerifyResult } from '../../services/signature-api.service';

interface TamperReport {
  added: Record<string, any>;
  deleted: Record<string, any>;
  modified: Record<string, { old: any; new: any }>;
}

@Component({
  selector: 'app-verify',
  standalone: true,
  imports: [CommonModule, FormsModule, NavbarComponent],
  templateUrl: './verify.component.html',
  styleUrl: './verify.component.css',
})
export class VerifyComponent {
  @ViewChild('signedPackageInput') signedPackageInputRef?: ElementRef<HTMLInputElement>;

  private readonly api = inject(SignatureApiService);

  /* ── State ─────────────────────────────────────── */
  signedPackageFile: File | null = null;

  verifyLoading = signal(false);
  verifySuccess = signal(false);
  verifyError = signal<string | null>(null);
  verifyDetails = signal<VerifyResult | null>(null);
  tamperReport: TamperReport | null = null;

  /* ── Simulator State ───────────────────────────── */
  isSimulatorOpen = false;
  simulatorText = '';
  simulatorError: string | null = null;
  simulatorMode: 'json' | 'excel' = 'json';
  private simulatorOriginalPackage: any = null;

  get verificationResult(): VerifyResult | null {
    return this.verifyDetails();
  }

  get chainVerification() {
    return this.verifyDetails()?.chain_verification || null;
  }


  /* ── Verify action ─────────────────────────────── */
  verifyDocument(): void {
    this.verifySuccess.set(false);
    this.verifyError.set(null);
    this.verifyDetails.set(null);
    this.tamperReport = null;

    if (!this.signedPackageFile) {
      this.verifyError.set('Please upload signed_document.json.');
      return;
    }

    this.verifyLoading.set(true);

    this.api
      .verifyDocument(this.signedPackageFile)
      .pipe(finalize(() => this.verifyLoading.set(false)))
      .subscribe({
        next: (res: VerifyResult) => {
          if (res.status === 'valid') {
            this.verifySuccess.set(true);
            this.verifyError.set(null);
            this.verifyDetails.set(res);
          } else {
            this.verifySuccess.set(false);
            this.verifyDetails.set(res);
            this.verifyError.set(res.message || 'Invalid signature.');
          }
        },
        error: (e) => {
          if (e.status === 409 && e.error?.tamper_report) {
            this.tamperReport = e.error.tamper_report;
            this.verifyError.set(e.error.message || 'Data modifications detected.');
            this.verifySuccess.set(false);
            // We can also store chain_verification if provided
            if (e.error.chain_verification) {
                this.verifyDetails.set({ chain_verification: e.error.chain_verification } as any);
            }
          } else {
            let msg = 'Verification request failed.';
            if (e?.error) {
              try {
                const text = typeof e.error === 'string' ? e.error : '';
                if (text) {
                  const parsed = JSON.parse(text);
                  msg = parsed.message || msg;
                } else if (e.error.message) {
                  msg = e.error.message;
                }
              } catch {
                if (e.error.message) msg = e.error.message;
              }
            }
            this.verifySuccess.set(false);
            this.verifyError.set(msg);
          }
        },
      });
  }

  onSignedPackageChange(event: Event): void {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0] ?? null;
    if (file && !file.name.toLowerCase().endsWith('.json')) {
      this.verifyError.set('Signed package must be signed_document.json (.json).');
      input.value = '';
      this.signedPackageFile = null;
      return;
    }
    this.signedPackageFile = file;
    this.verifyError.set(null);
  }

  clearSignedPackage(): void {
    this.signedPackageFile = null;
    const input = this.signedPackageInputRef?.nativeElement;
    if (input) input.value = '';
  }

  downloadOriginal(): void {
    const result = this.verificationResult;
    if (!result?.original_data) {
      return;
    }

    const filename = result.verification_details?.original_file_name || 'verified_document.json';
    let blob: Blob;

    if ((result as any).original_data_is_binary) {
      // Binary file (Excel, PDF, etc.) — decode base64 to bytes
      const binary = atob(result.original_data);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      const mime = filename.endsWith('.xlsx')
        ? 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        : filename.endsWith('.pdf')
        ? 'application/pdf'
        : 'application/octet-stream';
      blob = new Blob([bytes], { type: mime });
    } else {
      // Text file (JSON, CSV, etc.) — pretty-print JSON
      let text = result.original_data;
      if (filename.endsWith('.json')) {
        try {
          text = JSON.stringify(JSON.parse(text), null, 2);
        } catch { /* keep as-is if not valid JSON */ }
      }
      blob = new Blob([text], { type: 'application/json' });
    }

    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.style.display = 'none';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  verifyButtonDisabled(): boolean {
    return this.verifyLoading() || !this.signedPackageFile || this.isSimulatorOpen;
  }

  objectKeys(obj: any): string[] {
    return obj ? Object.keys(obj) : [];
  }

  isArray(obj: any): boolean {
    return Array.isArray(obj);
  }

  /* ── UTF-8 Safe Base64 Helpers ─────────────────── */
  private encodeBase64Utf8(text: string): string {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(text);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  private decodeBase64Utf8(base64: string): string {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    const decoder = new TextDecoder('utf-8');
    return decoder.decode(bytes);
  }

  /* ── Simulator Actions ─────────────────────────── */
  async openSimulator(): Promise<void> {
    this.simulatorError = null;
    if (!this.signedPackageFile) return;

    try {
      const text = await this.signedPackageFile.text();
      const pkg = JSON.parse(text);
      this.simulatorOriginalPackage = pkg;

      // Extract the base64 string
      const b64 = pkg.original_data || pkg.signed_data || pkg.document || '';
      if (!b64) {
        this.simulatorError = 'Could not find base64 document data in the package.';
        return;
      }

      const filename = (pkg.original_filename || '').toLowerCase();
      this.simulatorMode = (filename.endsWith('.xlsx') || filename.endsWith('.xls')) ? 'excel' : 'json';

      if (this.simulatorMode === 'excel') {
        try {
          const binary = atob(b64);
          const workbook = XLSX.read(binary, { type: 'binary' });
          const jsonResult: any = {};
          workbook.SheetNames.forEach(sheetName => {
            const sheet = workbook.Sheets[sheetName];
            jsonResult[sheetName] = XLSX.utils.sheet_to_json(sheet);
          });
          this.simulatorText = JSON.stringify(jsonResult, null, 2);
        } catch (e: any) {
          this.simulatorError = 'Failed to parse Excel binary to JSON: ' + e.message;
          return;
        }
      } else {
        // Decode the payload safely
        const jsonText = this.decodeBase64Utf8(b64);
        
        // Try to format it beautifully for editing
        try {
          const parsed = JSON.parse(jsonText);
          this.simulatorText = JSON.stringify(parsed, null, 2);
        } catch {
          this.simulatorText = jsonText;
        }
      }

      this.isSimulatorOpen = true;
    } catch (e: any) {
      this.simulatorError = e.message || 'Failed to open simulator.';
    }
  }

  closeSimulator(): void {
    this.isSimulatorOpen = false;
    this.simulatorText = '';
    this.simulatorError = null;
    this.simulatorOriginalPackage = null;
  }

  simulateTampering(): void {
    this.simulatorError = null;
    if (!this.simulatorOriginalPackage) return;

    try {
      let newB64 = '';
      if (this.simulatorMode === 'excel') {
        const parsedJson = JSON.parse(this.simulatorText);
        const workbook = XLSX.utils.book_new();
        
        // Convert ISO strings directly to Excel serial floats using pure UTC math
        const fixDates = (obj: any) => {
          if (!obj) return;
          for (const key in obj) {
            if (typeof obj[key] === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(obj[key])) {
              const parts = obj[key].split('T');
              const d = parts[0].split('-');
              const t = parts[1].replace('Z', '').split(':');
              const utcTime = Date.UTC(parseInt(d[0]), parseInt(d[1])-1, parseInt(d[2]), parseInt(t[0]), parseInt(t[1]), parseInt(t[2]));
              const excelEpoch = Date.UTC(1899, 11, 30, 0, 0, 0);
              obj[key] = (utcTime - excelEpoch) / 86400000;
            } else if (typeof obj[key] === 'object') {
              fixDates(obj[key]);
            }
          }
        };
        fixDates(parsedJson);

        for (const sheetName in parsedJson) {
            const sheet = XLSX.utils.json_to_sheet(parsedJson[sheetName]);
            XLSX.utils.book_append_sheet(workbook, sheet, sheetName);
        }
        newB64 = XLSX.write(workbook, { bookType: 'xlsx', type: 'base64' });
      } else {
        // Re-encode to Base64
        newB64 = this.encodeBase64Utf8(this.simulatorText);
      }
      
      // Create new package
      const newPkg = { ...this.simulatorOriginalPackage };
      
      if (newPkg.original_data) newPkg.original_data = newB64;
      if (newPkg.document) newPkg.document = newB64;
      if (newPkg.signed_data) newPkg.signed_data = newB64;

      // Convert back to File
      const newPkgText = JSON.stringify(newPkg);
      const blob = new Blob([newPkgText], { type: 'application/json' });
      this.signedPackageFile = new File([blob], this.signedPackageFile!.name, { type: 'application/json' });

      // Close and verify
      this.closeSimulator();
      this.verifyDocument();
    } catch (e: any) {
      this.simulatorError = 'Invalid JSON: ' + (e.message || 'Check your syntax.');
    }
  }
}
