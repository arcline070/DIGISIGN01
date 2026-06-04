import { Component, OnInit, signal, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../../environments/environment';

@Component({
  selector: 'app-public-verify',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './public-verify.component.html',
  styleUrl: './public-verify.component.css'
})
export class PublicVerifyComponent implements OnInit {
  private route = inject(ActivatedRoute);
  private http = inject(HttpClient);

  loading = signal(true);
  status = signal<'authentic' | 'tampered' | null>(null);
  message = signal<string>('');
  docDetails = signal<any>(null);

  ngOnInit(): void {
    this.route.queryParams.subscribe(params => {
      const token = params['token'];
      if (!token) {
        this.status.set('tampered');
        this.message.set('No verification token provided.');
        this.loading.set(false);
        return;
      }
      this.verifyToken(token);
    });
  }

  private verifyToken(token: string): void {
    this.http.get<any>(`${environment.apiBaseUrl}/api/documents/verify/?token=${token}`)
      .subscribe({
        next: (res) => {
          this.status.set(res.status);
          if (res.status === 'authentic') {
            this.docDetails.set(res);
          } else {
            this.message.set(res.message || 'Validation failed.');
          }
          this.loading.set(false);
        },
        error: (err) => {
          this.status.set('tampered');
          this.message.set(err.error?.message || 'Verification failed due to an error.');
          this.loading.set(false);
        }
      });
  }
}
