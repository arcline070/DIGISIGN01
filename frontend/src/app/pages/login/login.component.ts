import { CommonModule } from '@angular/common';
import { Component, OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { finalize } from 'rxjs/operators';
import { AuthService, SignatureAlgorithm } from '../../services/auth.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './login.component.html',
  styleUrl: './login.component.css',
})
export class LoginComponent implements OnInit {
  username = '';
  password = '';
  registerMode = signal(false);
  loading = signal(false);
  error = signal<string | null>(null);

  constructor(
    private auth: AuthService,
    private router: Router
  ) {}

  ngOnInit(): void {
    this.username = '';
    this.password = '';
  }

  submit(): void {
    this.error.set(null);
    if (this.registerMode()) {
      this.auth.clearLocal();
    }
    const u = this.username.trim();
    if (!u || !this.password) {
      this.error.set('Enter username and password.');
      return;
    }
    this.loading.set(true);
    const req = this.registerMode()
      ? this.auth.register(u, this.password)
      : this.auth.login(u, this.password);
    req.pipe(finalize(() => this.loading.set(false))).subscribe({
      next: () => void this.router.navigate(['/']),
      error: (e) => {
        const d = e?.error?.detail;
        let msg = 'Request failed. Check credentials or try another username.';
        if (typeof d === 'string') msg = d;
        else if (Array.isArray(d)) msg = d.map((x: unknown) => String(x)).join(' ');
        this.error.set(msg);
      },
    });
  }

  toggleMode(): void {
    this.registerMode.update((v) => !v);
    this.error.set(null);
  }
}
