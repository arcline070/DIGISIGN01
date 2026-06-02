import { CommonModule } from '@angular/common';
import { Component, ElementRef, ViewChild, inject, signal } from '@angular/core';
import { finalize } from 'rxjs/operators';
import { NavbarComponent } from '../../components/navbar/navbar.component';
import { SignatureApiService, VerifyResult } from '../../services/signature-api.service';

@Component({
  selector: 'app-verify',
  standalone: true,
  imports: [CommonModule, NavbarComponent],
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
          } else if (res.status === 'tampered') {
            this.verifySuccess.set(false);
            this.verifyDetails.set(res);
            this.verifyError.set(null);
          } else {
            this.verifySuccess.set(false);
            this.verifyDetails.set(res);
            this.verifyError.set(res.message || 'Invalid signature.');
          }
        },
        error: (e) => {
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

    const blob = new Blob([result.original_data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = result.verification_details?.original_file_name || 'verified_document.json';
    link.style.display = 'none';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  verifyButtonDisabled(): boolean {
    return this.verifyLoading() || !this.signedPackageFile;
  }
}
