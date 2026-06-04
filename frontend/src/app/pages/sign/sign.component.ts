import { CommonModule } from '@angular/common';
import { Component, ElementRef, OnInit, ViewChild, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { finalize } from 'rxjs/operators';
import { NavbarComponent } from '../../components/navbar/navbar.component';
import { AuthService } from '../../services/auth.service';
import { SignatureApiService, SupportedAlgorithm } from '../../services/signature-api.service';
import jsPDF from 'jspdf';
import html2canvas from 'html2canvas';
import { QRCodeComponent } from 'angularx-qrcode';

@Component({
  selector: 'app-sign',
  standalone: true,
  imports: [CommonModule, FormsModule, NavbarComponent, QRCodeComponent],
  templateUrl: './sign.component.html',
  styleUrl: './sign.component.css',
})
export class SignComponent implements OnInit {
  @ViewChild('signFileInput') signFileInputRef?: ElementRef<HTMLInputElement>;

  private readonly api = inject(SignatureApiService);
  private readonly auth = inject(AuthService);

  exportToPDF(): void {
    const data = document.getElementById('pdf-content');
    if (!data) return;

    html2canvas(data, { 
      scale: 2,
      useCORS: true,
      allowTaint: true,
      logging: false,
    }).then(canvas => {
      const imgData = canvas.toDataURL('image/png');
      const pdf = new jsPDF('p', 'mm', 'a4');

      const pdfWidth = 210; // A4 width in mm
      const pdfHeight = 297; // A4 height in mm

      // Calculate ratio to fit exactly on one page
      const ratio = Math.min(pdfWidth / canvas.width, pdfHeight / canvas.height);

      const imgWidth = canvas.width * ratio;
      const imgHeight = canvas.height * ratio;

      // Center it horizontally
      const marginX = (pdfWidth - imgWidth) / 2;

      pdf.addImage(imgData, 'PNG', marginX, 10, imgWidth, imgHeight);
      pdf.save('Certified_Document.pdf');
    });
  }

  /* ── State ─────────────────────────────────────── */
  selectedFile: File | null = null;
  textData = '';

  // Not used by the simplified UI (kept so existing logic still compiles).
  documentMetadata = signal<{ id: string; created_at: string; owner: string }[]>([]);

  loading = signal(false);
  error = signal<string | null>(null);
  signSuccess = signal(false);

  // Algorithm selection modal
  algorithmModalOpen = signal(false);
  supportedAlgorithms = signal<SupportedAlgorithm[]>([]);
  selectedAlgorithm = signal<'RSA-SHA256' | 'ECDSA-P256-SHA256'>('RSA-SHA256');
  algoLoading = signal(false);
  
  // New toggles
  activeAlgorithm = signal<string>('RSA-SHA256');
  isUpdatingAlgorithm = signal(false);
  toastMessage = signal<string | null>(null);

  /** Holds the signed package Blob for download */
  private signedPackageBlob = signal<Blob | null>(null);
  private signedPackageUrl = signal<string | null>(null);
  verifyUrl = signal<string>('');
  signedPackageData = signal<any>(null);

  ngOnInit(): void {
    // Kept for backwards compatibility; UI no longer exposes the picker.
    this.loadExistingDocumentIds();
  }
  formatDocumentDate(value: string): string {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return value;
    }
    return date.toLocaleString();
  }
  private loadExistingDocumentIds(): void {
    this.api.listDocumentIdsWithMetadata().subscribe({
      next: (res) => this.documentMetadata.set(res.documents ?? []),
      error: () => this.documentMetadata.set([]),
    });
  }

  onAlgorithmChange(newAlgorithm: string): void {
    if (this.activeAlgorithm() === newAlgorithm) return;
    
    this.isUpdatingAlgorithm.set(true);
    
    this.api.updateAlgorithm(newAlgorithm).subscribe({
      next: (response) => {
        this.activeAlgorithm.set(response.algorithm);
        this.showToast(`Successfully switched to ${this.activeAlgorithm()}`);
        this.isUpdatingAlgorithm.set(false);
      },
      error: (err) => {
        console.error('Failed to update algorithm', err);
        this.showToast('Failed to change algorithm. Please try again.');
        this.isUpdatingAlgorithm.set(false);
        
        const current = this.activeAlgorithm();
        this.activeAlgorithm.set(''); 
        setTimeout(() => this.activeAlgorithm.set(current));
      }
    });
  }

  showToast(message: string): void {
    this.toastMessage.set(message);
    setTimeout(() => this.toastMessage.set(null), 3000);
  }

  /* ── File selection ────────────────────────────── */
  onFileChange(event: Event): void {
    const input = event.target as HTMLInputElement;
    this.selectedFile = input.files?.[0] ?? null;
    this.error.set(null);
    this.resetResult();
  }

  clearFile(): void {
    this.selectedFile = null;
    const input = this.signFileInputRef?.nativeElement;
    if (input) input.value = '';
    this.error.set(null);
  }

  /* ── Sign action ───────────────────────────────── */
  signDocument(): void {
    this.error.set(null);
    this.signSuccess.set(false);
    this.signedPackageBlob.set(null);
    this.revokeUrl();
    this.loading.set(true);

    const formData = new FormData();

    if (this.selectedFile) {
      formData.append('file', this.selectedFile, this.selectedFile.name);
    } else {
      formData.append('data', this.textData);
    }

    this.api
      .signDocumentRaw(formData)
      .pipe(finalize(() => this.loading.set(false)))
      .subscribe({
        next: async (blob) => {
          this.signedPackageBlob.set(blob);
          const url = URL.createObjectURL(blob);
          this.signedPackageUrl.set(url);
          this.signSuccess.set(true);
          
          try {
            const text = await blob.text();
            const pkg = JSON.parse(text);
            if (typeof pkg.structured_snapshot === 'string' && pkg.structured_snapshot) {
              try {
                pkg.structured_snapshot = JSON.parse(pkg.structured_snapshot);
              } catch (e) {
                // Ignore parse errors, fallback will catch it
              }
            }
            this.signedPackageData.set(pkg);
            if (pkg.verification_token) {
              this.verifyUrl.set(window.location.origin + '/public-verify?token=' + pkg.verification_token);
            }
          } catch (err) {
            console.error('Failed to parse package for verification token', err);
          }
        },
        error: (e) => {
          if (e?.error instanceof Blob) {
            const reader = new FileReader();
            reader.onload = () => {
              try {
                const parsed = JSON.parse(reader.result as string);
                this.error.set(parsed?.detail ?? parsed?.message ?? 'Signing failed.');
              } catch {
                this.error.set('Signing failed.');
              }
            };
            reader.onerror = () => this.error.set('Signing failed.');
            reader.readAsText(e.error);
          } else {
            const msg =
              e?.error?.detail ??
              (typeof e?.error === 'string' ? e.error : null) ??
              e?.message ??
              'Signing failed.';
            this.error.set(String(msg));
          }
        },
      });
  }

  downloadSignedDocument(): void {
    const url = this.signedPackageUrl();
    if (!url) return;
    
    let baseName = 'signed_document';
    if (this.selectedFile) {
      const originalName = this.selectedFile.name;
      const lastDot = originalName.lastIndexOf('.');
      if (lastDot > 0) {
        baseName = 'signed_document_' + originalName.substring(0, lastDot);
      } else {
        baseName = 'signed_document_' + originalName;
      }
    }
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `${baseName}.json`;
    a.click();
  }

  signButtonDisabled(): boolean {
    const hasData = this.selectedFile !== null || (this.textData || '').trim().length > 0;
    return this.loading() || !hasData;
  }


  /* ── Drag & Drop ───────────────────────────────── */
  dragOver = signal(false);

  onDragOver(event: DragEvent): void {
    event.preventDefault();
    this.dragOver.set(true);
  }

  onDragLeave(event: DragEvent): void {
    event.preventDefault();
    this.dragOver.set(false);
  }

  onDrop(event: DragEvent): void {
    event.preventDefault();
    this.dragOver.set(false);
    const file = event.dataTransfer?.files?.[0];
    if (file) {
      this.selectedFile = file;
      this.error.set(null);
      this.resetResult();
    }
  }

  /* ── Cleanup ───────────────────────────────────── */
  private revokeUrl(): void {
    const url = this.signedPackageUrl();
    if (url) {
      URL.revokeObjectURL(url);
      this.signedPackageUrl.set(null);
    }
  }



  private resetResult(): void {
    this.signSuccess.set(false);
    this.signedPackageBlob.set(null);
    this.revokeUrl();
  }
}
