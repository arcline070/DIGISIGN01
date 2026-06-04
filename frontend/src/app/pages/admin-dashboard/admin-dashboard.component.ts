import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { BaseChartDirective } from 'ng2-charts';
import { ChartConfiguration, ChartData, ChartType } from 'chart.js';
import { DashboardService, DashboardSummary } from '../../services/dashboard.service';
import { HttpErrorResponse } from '@angular/common/http';
import { Router } from '@angular/router';

@Component({
  selector: 'app-admin-dashboard',
  standalone: true,
  imports: [CommonModule, BaseChartDirective],
  templateUrl: './admin-dashboard.component.html',
  styleUrls: ['./admin-dashboard.component.css']
})
export class AdminDashboardComponent implements OnInit {
  summary: DashboardSummary | null = null;
  users: any[] = [];
  pendingDocuments: any[] = [];
  error: string | null = null;

  // Chart configuration
  public pieChartOptions: ChartConfiguration['options'] = {
    responsive: true,
    plugins: {
      legend: {
        display: true,
        position: 'bottom',
        labels: { color: '#e2e8f0' } // Light color for dark theme
      }
    }
  };
  public pieChartData: ChartData<'doughnut', number[], string | string[]> = {
    labels: ['RSA-SHA256', 'ECDSA-P256-SHA256'],
    datasets: [{
      data: [0, 0],
      backgroundColor: ['#3b82f6', '#10b981'], // Blue for RSA, Green for ECDSA
      hoverBackgroundColor: ['#2563eb', '#059669'],
      borderWidth: 0
    }]
  };
  public pieChartType: ChartType = 'doughnut';

  constructor(private dashboardService: DashboardService, private router: Router) {}

  ngOnInit(): void {
    this.loadData();
  }

  loadData() {
    this.error = null;
    this.dashboardService.getSummary().subscribe({
      next: (data) => {
        this.summary = data;
        // Update chart
        this.pieChartData.datasets[0].data = [
          data.algorithm_split.RSA || 0,
          data.algorithm_split.ECDSA || 0
        ];
        // Trigger chart update hack for ng2-charts by re-assigning the object reference
        this.pieChartData = { ...this.pieChartData };
      },
      error: (err: HttpErrorResponse) => {
        if (err.status === 403) {
          this.error = "Access Denied. You must be an administrator.";
        } else {
          this.error = "Failed to load dashboard summary.";
        }
      }
    });

    this.dashboardService.getUsers().subscribe({
      next: (data) => this.users = data.users,
      error: () => {}
    });

    this.dashboardService.getPendingDocuments().subscribe({
      next: (data) => this.pendingDocuments = data.pending_documents,
      error: () => {}
    });
  }

  updateDocumentStatus(docId: string, status: 'APPROVED' | 'REJECTED') {
    if (!confirm(`Are you sure you want to ${status} document ${docId}?`)) return;
    
    this.dashboardService.updateDocumentStatus(docId, status).subscribe({
      next: () => {
        alert(`Document ${status} successfully.`);
        this.loadData(); // Reload to refresh queue
      },
      error: (err) => alert(err.error?.error || "Failed to update status")
    });
  }
}
