import { CommonModule } from '@angular/common';
import { Component, ElementRef, ViewChild, inject, signal, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { finalize } from 'rxjs/operators';
import { NavbarComponent } from '../../components/navbar/navbar.component';
import { AuthService } from '../../services/auth.service';
import { SignatureApiService, SupportedAlgorithm } from '../../services/signature-api.service';

@Component({
  selector: 'app-add-version',
  standalone: true,
  imports: [CommonModule, FormsModule, NavbarComponent],
  templateUrl: './add-version.component.html',
  styleUrl: './add-version.component.css',
})
export class AddVersionComponent implements OnInit {
  @ViewChild('addVersionFileInput') addVersionFileInputRef?: ElementRef<HTMLInputElement>;

  private readonly api = inject(SignatureApiService);
  private readonly auth = inject(AuthService);

  selectedFile: File | null = null;
  textData = '';
  documentId = '';

  loading = signal(false);
  error = signal<string | null>(null);
  signSuccess = signal(false);

  documentMetadata = signal<{ id: string; created_at: string; owner: string; filename?: string; version_count?: number }[]>([]);
  algorithmModalOpen = signal(false);
  supportedAlgorithms = signal<SupportedAlgorithm[]>([]);
  selectedAlgorithm = signal<'RSA-SHA256' | 'ECDSA-P256-SHA256'>('RSA-SHA256');
  algoLoading = signal(false);

  private signedPackageBlob = signal<Blob | null>(null);
  private signedPackageUrl = signal<string | null>(null);

  dragOver = signal(false);

  ngOnInit(): void {
    this.loadExistingDocumentIds();
  }

  onFileChange(event: Event): void {
    const input = event.target as HTMLInputElement;
    this.selectedFile = input.files?.[0] ?? null;
    this.error.set(null);
    this.resetResult();
  }

  clearFile(): void {
    this.selectedFile = null;
    const input = this.addVersionFileInputRef?.nativeElement;
    if (input) input.value = '';
    this.error.set(null);
  }

  loadExistingDocumentIds(): void {
    this.api.listDocumentIdsWithMetadata().subscribe({
      next: (res) => this.documentMetadata.set(res.documents ?? []),
      error: () => this.documentMetadata.set([]),
    });
  }

  addVersion(): void {
    this.openAlgorithmModal();
  }

  private openAlgorithmModal(): void {
    this.error.set(null);
    this.signSuccess.set(false);
    this.signedPackageBlob.set(null);
    this.revokeUrl();
    this.selectedAlgorithm.set(this.auth.signatureAlgorithm());
    this.algorithmModalOpen.set(true);

    if (this.supportedAlgorithms().length === 0) {
      this.algoLoading.set(true);
      this.api
        .supportedAlgorithms()
        .pipe(finalize(() => this.algoLoading.set(false)))
        .subscribe({
          next: (res) => {
            const list = Array.isArray(res.algorithms) ? res.algorithms : [];
            this.supportedAlgorithms.set(list);
          },
          error: () => {
            this.supportedAlgorithms.set([
              { id: 'RSA-SHA256', label: 'RSA-SHA256' },
              { id: 'ECDSA-P256-SHA256', label: 'ECDSA-P256-SHA256' },
            ]);
          },
        });
    }
  }

  closeAlgorithmModal(): void {
    this.algorithmModalOpen.set(false);
  }

  confirmAlgorithmAndAddVersion(): void {
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

    const desired = this.selectedAlgorithm();
    const current = this.auth.signatureAlgorithm();

    const doSign = () => {
      this.api
        .addDocumentVersion(formData, this.documentId.trim())
        .pipe(finalize(() => this.loading.set(false)))
        .subscribe({
          next: (blob) => {
            this.signedPackageBlob.set(blob);
            const url = URL.createObjectURL(blob);
            this.signedPackageUrl.set(url);
            this.signSuccess.set(true);
            this.loadExistingDocumentIds();
            this.closeAlgorithmModal();
          },
          error: (e) => {
            if (e?.error instanceof Blob) {
              const reader = new FileReader();
              reader.onload = () => {
                try {
                  const parsed = JSON.parse(reader.result as string);
                  this.error.set(parsed?.detail ?? parsed?.message ?? 'Adding version failed.');
                } catch {
                  this.error.set('Adding version failed.');
                }
              };
              reader.onerror = () => this.error.set('Adding version failed.');
              reader.readAsText(e.error);
            } else {
              const msg =
                e?.error?.detail ??
                (typeof e?.error === 'string' ? e.error : null) ??
                e?.message ??
                'Adding version failed.';
              this.error.set(String(msg));
            }
          },
        });
    };

    if (desired !== current) {
      this.api
        .setSignatureAlgorithm(desired)
        .subscribe({
          next: () => {
            this.auth.signatureAlgorithm.set(desired);
            doSign();
          },
          error: () => {
            this.loading.set(false);
            this.error.set('Could not switch algorithm. Please try again.');
          },
        });
    } else {
      doSign();
    }
  }

  downloadSignedDocument(): void {
    const url = this.signedPackageUrl();
    if (!url) return;
    
    let baseName = 'signed_document';
    let nextVersion = 2;
    
    const doc = this.documentMetadata().find(d => d.id === this.documentId);
    if (doc) {
      if (doc.filename) {
        // Strip extension if it exists, e.g. "dummy.json" -> "dummy"
        const lastDot = doc.filename.lastIndexOf('.');
        if (lastDot > 0) {
          baseName = 'signed_' + doc.filename.substring(0, lastDot);
        } else {
          baseName = 'signed_' + doc.filename;
        }
      }
      if (doc.version_count) {
        nextVersion = doc.version_count; // The version count was already refreshed to include the new version
      }
    }
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `${baseName}_v${nextVersion}.json`;
    a.click();
  }

  addVersionButtonDisabled(): boolean {
    const hasData = this.selectedFile !== null || (this.textData || '').trim().length > 0;
    return this.loading() || !hasData || this.documentId.trim().length === 0;
  }

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
