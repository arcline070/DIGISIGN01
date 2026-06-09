import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { BaseChartDirective } from 'ng2-charts';
import { ChartConfiguration, ChartData } from 'chart.js';
import { NavbarComponent } from '../../components/navbar/navbar.component';
import { BenchmarkService } from '../../services/benchmark.service';
import { finalize } from 'rxjs/operators';

@Component({
  selector: 'app-benchmark',
  standalone: true,
  imports: [CommonModule, NavbarComponent, BaseChartDirective],
  templateUrl: './benchmark.component.html',
  styleUrl: './benchmark.component.css'
})
export class BenchmarkComponent {
  private readonly benchmarkService = inject(BenchmarkService);

  activeTab = signal<'crypto' | 'diff' | 'chain'>('crypto');
  loading = signal(false);
  error = signal<string | null>(null);

  cryptoMetrics = signal<{ rsa_sign_tps: number, rsa_verify_tps: number, ecdsa_sign_tps: number, ecdsa_verify_tps: number } | null>(null);
  diffMetrics = signal<{ json_ms: number, excel_ms: number, overhead_ms: number } | null>(null);
  chainMetrics = signal<{ base_ms: number, stress_ms: number } | null>(null);

  // Bar Chart Options for Crypto (Logarithmic scale)
  cryptoChartOptions: ChartConfiguration<'bar'>['options'] = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: true,
        position: 'top',
        labels: {
          color: '#475569',
          font: { family: "'Inter', sans-serif", size: 14, weight: 500 }
        }
      },
      tooltip: {
        backgroundColor: 'rgba(15, 23, 42, 0.9)',
        titleFont: { family: "'Inter', sans-serif", size: 14 },
        bodyFont: { family: "'Inter', sans-serif", size: 13 },
        padding: 12,
        cornerRadius: 8,
        displayColors: true
      }
    },
    scales: {
      y: {
        type: 'logarithmic',
        grid: { color: 'rgba(0, 0, 0, 0.05)' },
        ticks: { color: '#64748b', font: { family: "'Inter', sans-serif" }, callback: (v) => v + ' ms' },
        title: { display: true, text: 'Latency (ms)', color: '#475569', font: { family: "'Inter', sans-serif", size: 13 } }
      },
      x: {
        grid: { display: false },
        ticks: { color: '#334155', font: { family: "'Inter', sans-serif", size: 14, weight: 500 } }
      }
    }
  };

  // Common Bar Chart Options (used by Tab 2)
  barChartOptions: ChartConfiguration<'bar'>['options'] = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: true,
        position: 'top',
        labels: {
          color: '#475569',
          font: { family: "'Inter', sans-serif", size: 14, weight: 500 }
        }
      },
      tooltip: {
        backgroundColor: 'rgba(15, 23, 42, 0.9)',
        titleFont: { family: "'Inter', sans-serif", size: 14 },
        bodyFont: { family: "'Inter', sans-serif", size: 13 },
        padding: 12,
        cornerRadius: 8,
        displayColors: true
      }
    },
    scales: {
      y: {
        beginAtZero: true,
        grid: { color: 'rgba(0, 0, 0, 0.05)' },
        ticks: { color: '#64748b', font: { family: "'Inter', sans-serif" }, callback: (v) => v + ' ms' },
        title: { display: true, text: 'Execution Time (ms)', color: '#475569', font: { family: "'Inter', sans-serif", size: 13 } }
      },
      x: {
        grid: { display: false },
        ticks: { color: '#334155', font: { family: "'Inter', sans-serif", size: 14, weight: 500 } }
      }
    }
  };

  // Line Chart Options (used by Tab 3)
  lineChartOptions: ChartConfiguration<'line'>['options'] = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: true,
        position: 'top',
        labels: { color: '#475569', font: { family: "'Inter', sans-serif", size: 14, weight: 500 } }
      },
      tooltip: {
        backgroundColor: 'rgba(15, 23, 42, 0.9)',
        titleFont: { family: "'Inter', sans-serif", size: 14 },
        bodyFont: { family: "'Inter', sans-serif", size: 13 },
        padding: 12,
        cornerRadius: 8,
        displayColors: true
      }
    },
    scales: {
      y: {
        beginAtZero: true,
        grid: { color: 'rgba(0, 0, 0, 0.05)' },
        ticks: { color: '#64748b', font: { family: "'Inter', sans-serif" }, callback: (v) => v + ' ms' },
        title: { display: true, text: 'Validation Latency (ms)', color: '#475569', font: { family: "'Inter', sans-serif", size: 13 } }
      },
      x: {
        grid: { color: 'rgba(0, 0, 0, 0.05)' },
        ticks: { color: '#334155', font: { family: "'Inter', sans-serif", size: 14, weight: 500 } },
        title: { display: true, text: 'Historical Document Versions', color: '#475569', font: { family: "'Inter', sans-serif", size: 13 } }
      }
    }
  };

  // Data signals
  cryptoChartData = signal<ChartData<'bar'> | null>(null);
  diffChartData = signal<ChartData<'bar'> | null>(null);
  chainChartData = signal<ChartData<'line'> | null>(null);

  setTab(tab: 'crypto' | 'diff' | 'chain'): void {
    this.activeTab.set(tab);
  }

  runDiagnostics(): void {
    this.loading.set(true);
    this.error.set(null);

    this.benchmarkService.runDiagnostics()
      .pipe(finalize(() => this.loading.set(false)))
      .subscribe({
        next: (res) => {
          // Tab 1: Crypto Metrics
          this.cryptoMetrics.set({
            rsa_sign_tps: 1000 / res.crypto.rsa_sign_ms,
            rsa_verify_tps: 1000 / res.crypto.rsa_verify_ms,
            ecdsa_sign_tps: 1000 / res.crypto.ecdsa_sign_ms,
            ecdsa_verify_tps: 1000 / res.crypto.ecdsa_verify_ms
          });

          // Tab 1: Crypto Chart
          this.cryptoChartData.set({
            labels: ['Key Generation', 'Document Signing', 'Signature Verification'],
            datasets: [
              {
                label: 'RSA-SHA256 (2048-bit)',
                data: [res.crypto.rsa_keygen_ms, res.crypto.rsa_sign_ms, res.crypto.rsa_verify_ms],
                backgroundColor: 'rgba(99, 102, 241, 0.8)',
                borderColor: 'rgba(99, 102, 241, 1)',
                borderWidth: 2,
                borderRadius: 4
              },
              {
                label: 'ECDSA-P256',
                data: [res.crypto.ecdsa_keygen_ms, res.crypto.ecdsa_sign_ms, res.crypto.ecdsa_verify_ms],
                backgroundColor: 'rgba(16, 185, 129, 0.8)',
                borderColor: 'rgba(16, 185, 129, 1)',
                borderWidth: 2,
                borderRadius: 4
              }
            ]
          });

          // Tab 2: Diff Engine
          this.diffMetrics.set({
            json_ms: res.diff.diff_json_ms,
            excel_ms: res.diff.diff_excel_ms,
            overhead_ms: res.diff.diff_excel_ms - res.diff.diff_json_ms
          });

          this.diffChartData.set({
            labels: ['Diff Engine Processing Time'],
            datasets: [
              {
                label: 'JSON Parsing & Diff',
                data: [res.diff.diff_json_ms],
                backgroundColor: 'rgba(236, 72, 153, 0.8)', // Pink
                borderColor: 'rgba(236, 72, 153, 1)',
                borderWidth: 2,
                borderRadius: 4
              },
              {
                label: 'Excel Binary Translation & openpyxl Diff',
                data: [res.diff.diff_excel_ms],
                backgroundColor: 'rgba(245, 158, 11, 0.8)', // Amber
                borderColor: 'rgba(245, 158, 11, 1)',
                borderWidth: 2,
                borderRadius: 4
              }
            ]
          });

          // Tab 3: Hash Chain
          this.chainMetrics.set({
            base_ms: res.chain.chain_1_ms,
            stress_ms: res.chain.chain_50_ms
          });

          this.chainChartData.set({
            labels: ['1 Version', '10 Versions', '25 Versions', '50 Versions'],
            datasets: [
              {
                label: 'Chain Validation Latency',
                data: [
                  res.chain.chain_1_ms,
                  res.chain.chain_10_ms,
                  res.chain.chain_25_ms,
                  res.chain.chain_50_ms
                ],
                backgroundColor: 'rgba(14, 165, 233, 0.2)', // Sky blue fill
                borderColor: 'rgba(14, 165, 233, 1)',
                borderWidth: 3,
                pointBackgroundColor: 'rgba(14, 165, 233, 1)',
                pointRadius: 5,
                fill: true,
                tension: 0.3
              }
            ]
          });
        },
        error: (err) => {
          this.error.set('Failed to run diagnostics. Ensure the backend is running.');
        }
      });
  }
}
