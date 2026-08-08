// Number Counter Animation
function initCounters() {
    const counters = document.querySelectorAll('.stats-number');
    counters.forEach(counter => {
        const target = +counter.getAttribute('data-target') || 0;
        const speed = 1000 / target; // complete in 1 sec
        
        let count = 0;
        const updateCount = () => {
            const increment = Math.ceil(target / 40);
            if (count < target) {
                count += increment;
                if (count > target) count = target;
                counter.innerText = count;
                setTimeout(updateCount, 25);
            } else {
                counter.innerText = target;
            }
        };
        updateCount();
    });
}

// Chart.js Theme Configurations
const ChartTheme = {
    gridColor: 'rgba(255, 255, 255, 0.05)',
    textColor: '#8ea0b4',
    fontFamily: "'Orbitron', sans-serif"
};

// Initialise Chart.js graphs if canvases exist
function initCharts(data) {
    // 1. Weekly Activity Line Chart
    const weeklyCanvas = document.getElementById('weeklyActivityChart');
    if (weeklyCanvas && data.weeklyDays && data.weeklyCounts) {
        const ctx = weeklyCanvas.getContext('2d');
        
        // Gradient fill
        const gradient = ctx.createLinearGradient(0, 0, 0, 300);
        gradient.addColorStop(0, 'rgba(0, 255, 136, 0.25)');
        gradient.addColorStop(1, 'rgba(0, 255, 136, 0.00)');

        new Chart(weeklyCanvas, {
            type: 'line',
            data: {
                labels: data.weeklyDays,
                datasets: [{
                    label: 'System Activity logs',
                    data: data.weeklyCounts,
                    borderColor: '#00ff88',
                    borderWidth: 2,
                    backgroundColor: gradient,
                    fill: true,
                    tension: 0.4,
                    pointBackgroundColor: '#00ff88',
                    pointBorderColor: '#060b12',
                    pointBorderWidth: 2,
                    pointRadius: 5,
                    pointHoverRadius: 7
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        grid: { color: ChartTheme.gridColor },
                        ticks: { color: ChartTheme.textColor, font: { family: 'Inter' } }
                    },
                    y: {
                        grid: { color: ChartTheme.gridColor },
                        ticks: { color: ChartTheme.textColor, stepSize: 1 }
                    }
                }
            }
        });
    }

    // 2. Threat Analysis Distribution Pie/Doughnut Chart
    const threatCanvas = document.getElementById('threatAnalysisChart');
    if (threatCanvas && data.threatLabels && data.threatCounts) {
        new Chart(threatCanvas, {
            type: 'doughnut',
            data: {
                labels: data.threatLabels,
                datasets: [{
                    data: data.threatCounts,
                    backgroundColor: [
                        'rgba(255, 62, 62, 0.85)',   // Blocked Red
                        'rgba(255, 183, 0, 0.85)',   // Warning Yellow
                        'rgba(0, 210, 255, 0.85)',   // Info Blue
                        'rgba(0, 255, 136, 0.85)'    // Allow Green
                    ],
                    borderColor: '#0b131e',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: ChartTheme.textColor,
                            font: { family: 'Inter', size: 11 },
                            padding: 15
                        }
                    }
                },
                cutout: '65%'
            }
        });
    }

    // 3. Employee Risk Scores Bar Chart
    const riskCanvas = document.getElementById('employeeRiskChart');
    if (riskCanvas && data.riskNames && data.riskScores) {
        new Chart(riskCanvas, {
            type: 'bar',
            data: {
                labels: data.riskNames,
                datasets: [{
                    label: 'Risk Rating',
                    data: data.riskScores,
                    backgroundColor: data.riskScores.map(score => {
                        if (score >= 70) return 'rgba(255, 62, 62, 0.7)'; // critical red
                        if (score >= 40) return 'rgba(255, 183, 0, 0.7)'; // warning yellow
                        return 'rgba(0, 255, 136, 0.7)'; // safe green
                    }),
                    borderColor: data.riskScores.map(score => {
                        if (score >= 70) return '#ff3e3e';
                        if (score >= 40) return '#ffb700';
                        return '#00ff88';
                    }),
                    borderWidth: 1.5,
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { color: ChartTheme.textColor, font: { family: 'Inter' } }
                    },
                    y: {
                        grid: { color: ChartTheme.gridColor },
                        ticks: { color: ChartTheme.textColor },
                        min: 0,
                        max: 100
                    }
                }
            }
        });
    }
}

// Initialise counter values on page load
document.addEventListener('DOMContentLoaded', () => {
    initCounters();
});
