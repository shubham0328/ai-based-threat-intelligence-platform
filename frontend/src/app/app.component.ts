import { Component, OnDestroy } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { FormBuilder, FormGroup, Validators, AbstractControl } from '@angular/forms';
import { Subscription, interval } from 'rxjs';
import { Chart } from 'chart.js';
@Component({
  selector: 'app-root',
  template: `
  <div class="min-h-screen bg-gray-100">
    <!-- Header -->
    <header class="bg-indigo-600 text-white shadow-lg">
      <div class="max-w-7xl mx-auto py-4 px-6 flex justify-between items-center">
        <h1 class="text-2xl font-bold">AI Threat Intelligence Dashboard</h1>
        <div class="flex items-center space-x-4">
          <span class="text-sm">Last Updated: {{ lastUpdated }}</span>
          <button (click)="loadThreatHistory()" class="bg-indigo-500 hover:bg-indigo-700 text-white font-semibold py-2 px-4 rounded transition duration-200">
            Refresh
          </button>
        </div>
      </div>
    </header>

    <!-- Main Content -->
    <div class="max-w-7xl mx-auto py-6 px-6 flex flex-col lg:flex-row gap-6">
      <!-- Left Section: Dashboard (Form & Results) -->
      <div class="lg:w-2/3 space-y-6">
        <!-- Form Card -->
        <div class="bg-white shadow-lg rounded-lg p-6">
          <h2 class="text-xl font-semibold mb-4 text-gray-800">Analyze Threat</h2>
          <form [formGroup]="threatForm" (ngSubmit)="submitThreat()" class="space-y-4">
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label class="block text-sm font-medium text-gray-700">Source IP</label>
                <input formControlName="source_ip" placeholder="e.g., 192.168.1.1" class="mt-1 w-full p-2 border rounded focus:ring-indigo-500 focus:border-indigo-500">
                <div *ngIf="source_ip.invalid && source_ip.touched" class="text-red-500 text-sm mt-1">Invalid Source IP</div>
              </div>
              <div>
                <label class="block text-sm font-medium text-gray-700">Destination IP</label>
                <input formControlName="destination_ip" placeholder="e.g., 10.0.0.1" class="mt-1 w-full p-2 border rounded focus:ring-indigo-500 focus:border-indigo-500">
                <div *ngIf="destination_ip.invalid && destination_ip.touched" class="text-red-500 text-sm mt-1">Invalid Destination IP</div>
              </div>
              <div>
                <label class="block text-sm font-medium text-gray-700">Threat Type</label>
                <input formControlName="threat_type" placeholder="e.g., Malware" class="mt-1 w-full p-2 border rounded focus:ring-indigo-500 focus:border-indigo-500">
                <div *ngIf="threat_type.invalid && threat_type.touched" class="text-red-500 text-sm mt-1">Threat Type is required</div>
              </div>
              <div>
                <label class="block text-sm font-medium text-gray-700">Severity (1-10)</label>
                <input type="number" formControlName="severity" min="1" max="10" class="mt-1 w-full p-2 border rounded focus:ring-indigo-500 focus:border-indigo-500">
                <div *ngIf="severity.invalid && severity.touched" class="text-red-500 text-sm mt-1">Severity must be 1-10</div>
              </div>
              <div class="sm:col-span-2">
                <label class="block text-sm font-medium text-gray-700">Timestamp</label>
                <input formControlName="timestamp" type="datetime-local" class="mt-1 w-full p-2 border rounded focus:ring-indigo-500 focus:border-indigo-500">
                <div *ngIf="timestamp.invalid && timestamp.touched" class="text-red-500 text-sm mt-1">Valid timestamp required</div>
              </div>
            </div>
            <button type="submit" [disabled]="threatForm.invalid || loading" class="bg-indigo-600 hover:bg-indigo-700 text-white font-semibold py-2 px-4 rounded transition duration-200">
              Analyze
            </button>
          </form>
          <div *ngIf="loading" class="mt-4 text-gray-600 flex items-center">
            <svg class="animate-spin h-5 w-5 mr-2" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path></svg>
            Analyzing threat...
          </div>
        </div>

        <!-- Result Card -->
        <div *ngIf="result" class="bg-white shadow-lg rounded-lg p-6">
          <h2 class="text-xl font-semibold mb-4 text-gray-800">Analysis Result</h2>
          <div class="p-4 bg-blue-50 rounded-lg">
            <h3 class="text-lg font-medium text-blue-800">{{ result.alert }}</h3>
            <p class="text-gray-700 mt-2">{{ result.recommendation }}</p>
          </div>
        </div>
      </div>

      <!-- Right Section: Visualizations -->
      <div class="lg:w-1/3 space-y-6">
        <!-- Threat Type Distribution Chart -->
        <div class="bg-white shadow-lg rounded-lg p-6">
          <h2 class="text-lg font-semibold mb-4 text-gray-800">Threat Type Distribution</h2>
          <canvas id="threatChart" class="w-full"></canvas>
        </div>

        <!-- Threat Trend Over Time Chart -->
        <div class="bg-white shadow-lg rounded-lg p-6">
          <h2 class="text-lg font-semibold mb-4 text-gray-800">Threat Trend Over Time</h2>
          <canvas id="trendChart" class="w-full"></canvas>
        </div>
      </div>
    </div>

    <!-- Bottom Section: Threat History and Risk Scores -->
    <div class="max-w-7xl mx-auto py-6 px-6 space-y-6">
      <!-- Threat History -->
      <div class="bg-white shadow-lg rounded-lg p-6">
        <div class="flex justify-between items-center mb-4">
          <h2 class="text-xl font-semibold text-gray-800">Threat History</h2>
          <label class="flex items-center space-x-2">
            <input type="checkbox" [(ngModel)]="autoRefresh" (change)="toggleAutoRefresh()" class="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded">
            <span class="text-sm text-gray-700">Auto-refresh every 10s</span>
          </label>
        </div>
        <div *ngIf="loadingHistory" class="text-gray-600 flex items-center">
          <svg class="animate-spin h-5 w-5 mr-2" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path></svg>
          Loading threat history...
        </div>
        <div class="overflow-x-auto">
          <table *ngIf="threatHistory.length > 0" class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
              <tr>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source IP</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Destination IP</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Threat Type</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Timestamp</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Alert</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Recommendation</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">
              <tr *ngFor="let threat of threatHistory" class="hover:bg-gray-50 transition duration-150">
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{{ threat.source_ip }}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{{ threat.destination_ip }}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{{ threat.threat_type }}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{{ threat.severity }}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{{ threat.timestamp }}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{{ threat.alert }}</td>
                <td class="px-6 py-4 text-sm text-gray-900">{{ threat.recommendation }}</td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <button (click)="exportToSIEM(threat)" class="text-indigo-600 hover:text-indigo-900 text-sm font-medium">Export to SIEM</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Source IP Risk Scores -->
      <div class="bg-white shadow-lg rounded-lg p-6">
        <h2 class="text-xl font-semibold mb-4 text-gray-800">Source IP Risk Scores</h2>
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
              <tr>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source IP</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Risk Score (Max Severity)</th>
              </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">
              <tr *ngFor="let risk of riskScores" class="hover:bg-gray-50 transition duration-150">
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{{ risk.source_ip }}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{{ risk.risk_score }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
  `,
  styles: [] // Tailwind CSS is used, so inline styles are removed
})
export class AppComponent implements OnDestroy {
  threatForm: FormGroup;
  result: any = null;
  threatHistory: any[] = [];
  loading = false;
  loadingHistory = false;
  autoRefresh: boolean = false;
  autoRefreshSubscription: Subscription | null = null;
  riskScores: { source_ip: string; risk_score: number }[] = [];
  lastUpdated: string = new Date().toLocaleString();

  constructor(private http: HttpClient, private fb: FormBuilder) {
    this.threatForm = this.fb.group({
      source_ip: ['', [Validators.required, this.ipValidator]],
      destination_ip: ['', [Validators.required, this.ipValidator]],
      threat_type: ['', Validators.required],
      severity: [5, [Validators.required, Validators.min(1), Validators.max(10)]],
      timestamp: ['', Validators.required]
    });
    this.loadThreatHistory();
  }

  ngOnDestroy() {
    if (this.autoRefreshSubscription) {
      this.autoRefreshSubscription.unsubscribe();
    }
  }

  get source_ip() { return this.threatForm.get('source_ip'); }
  get destination_ip() { return this.threatForm.get('destination_ip'); }
  get threat_type() { return this.threatForm.get('threat_type'); }
  get severity() { return this.threatForm.get('severity'); }
  get timestamp() { return this.threatForm.get('timestamp'); }

  ipValidator(control: AbstractControl) {
    const ipRegex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (!control.value) return null;
    return ipRegex.test(control.value) ? null : { invalidIP: true };
  }

  submitThreat() {
    if (this.threatForm.invalid) return;

    this.loading = true;
    this.result = null;

    const formValues = this.threatForm.value;
    let timestamp = formValues.timestamp;
    if (timestamp) {
      if (timestamp.length === 16) timestamp += ':00';
      const localDate = new Date(timestamp);
      const utcTimestamp = localDate.toISOString().replace('.000Z', '');
      formValues.timestamp = utcTimestamp;
    }

    const payload = { ...formValues };
    this.http.post('http://localhost:8000/analyze-threat/', payload).subscribe({
      next: (res: any) => {
        this.result = res;
        this.loading = false;
        this.loadThreatHistory();
      },
      error: (err) => {
        alert("❌ Error analyzing threat: " + (err.error?.detail?.[0]?.msg || err.message));
        this.loading = false;
      }
    });
  }

  loadThreatHistory() {
    this.loadingHistory = true;
    this.http.get<any[]>('http://localhost:8000/threats/').subscribe({
      next: (data) => {
        this.threatHistory = data;
        this.loadingHistory = false;
        this.lastUpdated = new Date().toLocaleString();
        this.computeRiskScores();
        this.updateCharts();
      },
      error: (err) => {
        alert("❌ Error loading threat history: " + err.message);
        this.loadingHistory = false;
      }
    });
  }

  toggleAutoRefresh() {
    if (this.autoRefresh) {
      this.autoRefreshSubscription = interval(10000).subscribe(() => this.loadThreatHistory());
    } else {
      if (this.autoRefreshSubscription) {
        this.autoRefreshSubscription.unsubscribe();
        this.autoRefreshSubscription = null;
      }
    }
  }

  private computeRiskScores() {
    const riskMap = new Map<string, number>();
    this.threatHistory.forEach(threat => {
      const currentMax = riskMap.get(threat.source_ip) || 0;
      if (threat.severity > currentMax) {
        riskMap.set(threat.source_ip, threat.severity);
      }
    });
    this.riskScores = Array.from(riskMap, ([source_ip, risk_score]) => ({ source_ip, risk_score }));
  }

  private updateCharts() {
    const ctx = document.getElementById('threatChart') as HTMLCanvasElement;
    if (ctx) {
      const threatTypeCounts = new Map<string, number>();
      this.threatHistory.forEach(threat => {
        const count = threatTypeCounts.get(threat.threat_type) || 0;
        threatTypeCounts.set(threat.threat_type, count + 1);
      });
      const labels = Array.from(threatTypeCounts.keys());
      const data = Array.from(threatTypeCounts.values());
      new Chart(ctx, {
        type: 'bar',
        data: {
          labels: labels,
          datasets: [{
            label: 'Threat Count by Type',
            data: data,
            backgroundColor: ['#ff6384', '#36a2eb', '#cc65fe', '#ffce56', '#4bc0c0', '#9966ff'],
            borderWidth: 1
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            y: { beginAtZero: true, title: { display: true, text: 'Number of Threats' } },
            x: { title: { display: true, text: 'Threat Type' } }
          }
        }
      });
    }

    const trendCtx = document.getElementById('trendChart') as HTMLCanvasElement;
    if (trendCtx) {
      const dateCounts = new Map<string, number>();
      this.threatHistory.forEach(threat => {
        const date = threat.timestamp.split('T')[0];
        const count = dateCounts.get(date) || 0;
        dateCounts.set(date, count + 1);
      });
      const sortedDates = Array.from(dateCounts.keys()).sort();
      const trendData = sortedDates.map(date => dateCounts.get(date) || 0);
      new Chart(trendCtx, {
        type: 'line',
        data: {
          labels: sortedDates,
          datasets: [{
            label: 'Threats per Day',
            data: trendData,
            borderColor: '#36a2eb',
            fill: false
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            x: { type: 'category', title: { display: true, text: 'Date' } },
            y: { beginAtZero: true, title: { display: true, text: 'Number of Threats' } }
          }
        }
      });
    }
  }

  exportToSIEM(threat: any) {
    const siemPayload = {
      source_ip: threat.source_ip,
      destination_ip: threat.destination_ip,
      threat_type: threat.threat_type,
      severity: threat.severity,
      timestamp: threat.timestamp,
      alert: threat.alert,
      recommendation: threat.recommendation
    };
    console.log('Exporting to SIEM:', siemPayload);
    alert(`Simulated export to SIEM for threat from ${threat.source_ip}`);
  }
}