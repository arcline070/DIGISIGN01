import { CommonModule } from '@angular/common';
import { Component, OnInit, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { finalize } from 'rxjs/operators';
import { NavbarComponent } from '../../components/navbar/navbar.component';
import { AuthService } from '../../services/auth.service';
import { SignatureApiService, SignatureLogRow } from '../../services/signature-api.service';

@Component({
  selector: 'app-logs',
  standalone: true,
  imports: [CommonModule, NavbarComponent],
  templateUrl: './logs.component.html',
  styleUrl: './logs.component.css',
})
export class LogsComponent implements OnInit {
  readonly auth = inject(AuthService);
  private readonly api = inject(SignatureApiService);
  private readonly router = inject(Router);

  rows = signal<SignatureLogRow[]>([]);
  loading = signal(false);
  error = signal<string | null>(null);
  myRole = signal<'admin' | 'user'>('user');

  ngOnInit(): void {
    this.refresh();
    this.api.myCertificate().subscribe({
      next: (r) => {
        this.myRole.set(r.role === 'admin' ? 'admin' : 'user');
      },
      error: () => {},
    });
  }

  refresh(): void {
    this.loading.set(true);
    this.error.set(null);
    this.api
      .listLogs()
      .pipe(finalize(() => this.loading.set(false)))
      .subscribe({
        next: (r) => this.rows.set(r),
        error: (e) => {
          if (e?.status === 401) {
            this.auth.clearLocal();
            void this.router.navigate(['/login']);
          } else {
            this.error.set('Could not load logs.');
          }
        },
      });
  }

  shortHash(value: string): string {
    const v = (value || '').trim();
    if (v.length <= 16) return v;
    return `${v.slice(0, 10)}...${v.slice(-6)}`;
  }

  isAdmin(): boolean {
    return this.myRole() === 'admin';
  }

  exportData(format: 'json' | 'csv', type: 'logs' | 'signed_data'): void {
    this.api.exportData(type, format).subscribe({
      next: (blob) => {
        const roleSuffix = type === 'logs' ? (this.isAdmin() ? 'admin' : 'user') : '';
        const name =
          type === 'logs'
            ? `logs_${roleSuffix}.${format}`
            : `signed_data.${format}`;
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = name;
        a.click();
        URL.revokeObjectURL(url);
      },
      error: () => this.error.set('Export failed.'),
    });
  }
}
