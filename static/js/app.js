/* ========================================
   WEB SECURITY ANALYZER - MAIN APP JS
   ======================================== */

// Global variables
let chart = null;
let totalScans = 0;
let scanHistory = [];

// ========================================
// INITIALIZATION
// ========================================
document.addEventListener('DOMContentLoaded', function() {
    initApp();
    loadScanHistory();
    setupEventListeners();
});

function initApp() {
    // Set focus to URL input
    const urlInput = document.getElementById('url');
    if (urlInput) {
        urlInput.focus();
    }
    
    // Update stats
    updateStats();
    
    console.log('%c🔒 Web Security Analyzer Initialized', 'color: #ff4757; font-size: 16px; font-weight: bold;');
    console.log('%cProfessional Pentest Platform Ready', 'color: #2ed573; font-size: 14px;');
}

// ========================================
// EVENT LISTENERS
// ========================================
function setupEventListeners() {
    // Enter key to analyze
    const urlInput = document.getElementById('url');
    if (urlInput) {
        urlInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                analyze();
            }
        });
    }
    
    // Login button
    const loginBtn = document.getElementById('loginBtn');
    if (loginBtn) {
        loginBtn.addEventListener('click', function(e) {
            e.preventDefault();
            showLoginModal();
        });
    }
}

// ========================================
// URL FUNCTIONS
// ========================================
function setUrl(url) {
    const urlInput = document.getElementById('url');
    if (urlInput) {
        urlInput.value = url;
        urlInput.focus();
    }
}

function validateUrl(url) {
    if (!url) {
        showError('Please enter a URL');
        return false;
    }
    
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        showError('URL must start with http:// or https://');
        return false;
    }
    
    try {
        new URL(url);
        return true;
    } catch (e) {
        showError('Invalid URL format. Please enter a valid URL (e.g., https://example.com)');
        return false;
    }
}

// ========================================
// MAIN ANALYZE FUNCTION
// ========================================
async function analyze() {
    const url = document.getElementById('url').value.trim();
    
    // Validate URL
    if (!validateUrl(url)) {
        return;
    }
    
    // UI state
    showLoading(true);
    hideError();
    hideResults();
    
    const analyzeBtn = document.getElementById('analyzeBtn');
    analyzeBtn.disabled = true;
    analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i><span>Analyzing...</span>';
    
    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({ url: url })
        });
        
        const data = await response.json();
        
        if (!data.success) {
            showError(data.error || 'Analysis failed');
            return;
        }
        
        // Display results
        displayResults(data.data);
        
        // Save to history
        saveToHistory(data.data);
        
        // Update stats
        totalScans++;
        updateStats();
        
        // Scroll to results
        document.getElementById('resultsSection').scrollIntoView({
            behavior: 'smooth',
            block: 'start'
        });
        
    } catch (error) {
        console.error('Analysis error:', error);
        showError('Network error. Please check your connection and try again.');
    } finally {
        showLoading(false);
        analyzeBtn.disabled = false;
        analyzeBtn.innerHTML = '<i class="fas fa-search"></i><span>Analyze Now</span>';
    }
}

// ========================================
// DISPLAY RESULTS
// ========================================
function displayResults(data) {
    // Show results section
    const resultsSection = document.getElementById('resultsSection');
    resultsSection.style.display = 'block';
    
    // Grade
    document.getElementById('grade').textContent = data.grade;
    document.getElementById('total').textContent = data.total_score;
    
    // Grade circle color
    const gradeCircle = document.getElementById('gradeCircle');
    const gradeColors = {
        'A': 'linear-gradient(135deg, #2ed573, #7bed9f)',
        'B': 'linear-gradient(135deg, #1e90ff, #70a1ff)',
        'C': 'linear-gradient(135deg, #ffa502, #ffbe76)',
        'D': 'linear-gradient(135deg, #ff6348, #ff7f50)',
        'F': 'linear-gradient(135deg, #ff4757, #ff6b81)'
    };
    gradeCircle.style.background = gradeColors[data.grade] || gradeColors['F'];
    
    // Score fill bar
    const scoreFill = document.getElementById('scoreFill');
    scoreFill.style.width = data.total_score + '%';
    
    // Metrics
    document.getElementById('perf').textContent = data.perf_score;
    document.getElementById('sec').textContent = data.security_score;
    document.getElementById('load').textContent = data.load_time + 's';
    document.getElementById('size').textContent = data.size_kb + ' KB';
    document.getElementById('status').textContent = data.status;
    document.getElementById('title').textContent = data.title || 'No title';
    
    // Security details
    displaySecurityDetails(data.security);
    
    // Recommendations
    generateRecommendations(data);
    
    // Chart
    updateChart(data);
}

function displaySecurityDetails(security) {
    const securityGrid = document.getElementById('securityGrid');
    securityGrid.innerHTML = '';
    
    const checks = [
        { key: 'https', label: 'HTTPS', icon: 'fa-lock' },
        { key: 'hsts', label: 'HSTS', icon: 'fa-shield-alt' },
        { key: 'csp', label: 'CSP', icon: 'fa-code' },
        { key: 'x_frame', label: 'X-Frame', icon: 'fa-window-maximize' },
        { key: 'content_type', label: 'Content-Type', icon: 'fa-file' }
    ];
    
    checks.forEach(check => {
        const isPass = security[check.key];
        const div = document.createElement('div');
        div.className = `security-item ${isPass ? 'pass' : 'fail'}`;
        div.innerHTML = `
            <i class="fas ${check.icon}"></i>
            <h4>${check.label}</h4>
            <span>${isPass ? 'Enabled ✓' : 'Missing ✗'}</span>
        `;
        securityGrid.appendChild(div);
    });
    
    // Show security details section
    document.getElementById('securityDetails').style.display = 'block';
}

function generateRecommendations(data) {
    const recList = document.getElementById('recList');
    recList.innerHTML = '';
    
    const recommendations = [];
    
    if (!data.security.https) {
        recommendations.push({
            icon: 'fa-lock',
            text: 'Enable HTTPS by installing SSL/TLS certificate',
            priority: 'high'
        });
    }
    
    if (!data.security.hsts) {
        recommendations.push({
            icon: 'fa-shield-alt',
            text: 'Add Strict-Transport-Security header to prevent MITM attacks',
            priority: 'high'
        });
    }
    
    if (!data.security.csp) {
        recommendations.push({
            icon: 'fa-code',
            text: 'Implement Content-Security-Policy header to prevent XSS attacks',
            priority: 'medium'
        });
    }
    
    if (!data.security.x_frame) {
        recommendations.push({
            icon: 'fa-window-maximize',
            text: 'Add X-Frame-Options header to prevent clickjacking',
            priority: 'medium'
        });
    }
    
    if (data.load_time > 3) {
        recommendations.push({
            icon: 'fa-tachometer-alt',
            text: 'Optimize page load time (currently ' + data.load_time + 's)',
            priority: 'medium'
        });
    }
    
    if (data.size_kb > 2000) {
        recommendations.push({
            icon: 'fa-weight-hanging',
            text: 'Reduce page size (currently ' + data.size_kb + ' KB)',
            priority: 'low'
        });
    }
    
    if (recommendations.length === 0) {
        recList.innerHTML = '<p style="color: #2ed573;">✓ No critical recommendations. Site looks good!</p>';
    } else {
        recommendations.forEach(rec => {
            const div = document.createElement('div');
            div.className = 'rec-item';
            div.innerHTML = `<i class="fas ${rec.icon}"></i> ${rec.text}`;
            recList.appendChild(div);
        });
    }
}

function updateChart(data) {
    if (chart) {
        chart.destroy();
    }
    
    const ctx = document.getElementById('chart').getContext('2d');
    
    chart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Performance', 'Security'],
            datasets: [{
                label: 'Score',
                data: [data.perf_score, data.security_score],
                backgroundColor: [
                    'rgba(46, 213, 115, 0.7)',
                    'rgba(255, 71, 87, 0.7)'
                ],
                borderColor: [
                    '#2ed573',
                    '#ff4757'
                ],
                borderWidth: 2,
                borderRadius: 5,
                borderSkipped: false
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#a0a0b0'
                    }
                },
                x: {
                    grid: {
                        display: false
                    },
                    ticks: {
                        color: '#a0a0b0'
                    }
                }
            }
        }
    });
}

// ========================================
// UI FUNCTIONS
// ========================================
function showLoading(show) {
    const loader = document.getElementById('loader');
    if (show) {
        loader.style.display = 'block';
    } else {
        loader.style.display = 'none';
    }
}

function showError(message) {
    const errorDiv = document.getElementById('errorMessage');
    const errorText = document.getElementById('errorText');
    
    errorText.textContent = message;
    errorDiv.style.display = 'flex';
    
    // Auto hide after 5 seconds
    setTimeout(() => {
        hideError();
    }, 5000);
}

function hideError() {
    const errorDiv = document.getElementById('errorMessage');
    errorDiv.style.display = 'none';
}

function hideResults() {
    const resultsSection = document.getElementById('resultsSection');
    resultsSection.style.display = 'none';
}

// ========================================
// HISTORY FUNCTIONS
// ========================================
function saveToHistory(data) {
    const historyItem = {
        url: data.url,
        grade: data.grade,
        total_score: data.total_score,
        timestamp: new Date().toISOString()
    };
    
    scanHistory.unshift(historyItem);
    
    // Keep only last 10 scans
    if (scanHistory.length > 10) {
        scanHistory = scanHistory.slice(0, 10);
    }
    
    // Save to localStorage
    localStorage.setItem('scanHistory', JSON.stringify(scanHistory));
    localStorage.setItem('totalScans', totalScans);
}

function loadScanHistory() {
    const saved = localStorage.getItem('scanHistory');
    if (saved) {
        scanHistory = JSON.parse(saved);
    }
    
    const savedScans = localStorage.getItem('totalScans');
    if (savedScans) {
        totalScans = parseInt(savedScans);
    }
}

function updateStats() {
    document.getElementById('totalScans').textContent = totalScans;
    
    if (scanHistory.length > 0) {
        const avgScore = Math.round(
            scanHistory.reduce((sum, item) => sum + item.total_score, 0) / scanHistory.length
        );
        document.getElementById('avgScore').textContent = avgScore + '/100';
    }
    
    document.getElementById('threatsBlocked').textContent = scanHistory.length;
}

// ========================================
// EXPORT & SHARE
// ========================================
function exportReport() {
    const url = document.getElementById('url').value;
    const grade = document.getElementById('grade').textContent;
    const total = document.getElementById('total').textContent;
    
    const report = `
Web Security Analysis Report
=============================
URL: ${url}
Grade: ${grade}
Total Score: ${total}/100
Date: ${new Date().toLocaleString()}

Metrics:
- Performance: ${document.getElementById('perf').textContent}/100
- Security: ${document.getElementById('sec').textContent}/100
- Load Time: ${document.getElementById('load').textContent}
- Page Size: ${document.getElementById('size').textContent}
- Status: ${document.getElementById('status').textContent}

Generated by Web Security Analyzer v2.0
    `.trim();
    
    // Create and download file
    const blob = new Blob([report], { type: 'text/plain' });
    const url2 = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url2;
    a.download = 'security-report-' + new Date().getTime() + '.txt';
    a.click();
    window.URL.revokeObjectURL(url2);
}

function shareResults() {
    const url = document.getElementById('url').value;
    const grade = document.getElementById('grade').textContent;
    const total = document.getElementById('total').textContent;
    
    const shareText = `🔒 Security Analysis: ${url}\nGrade: ${grade} (${total}/100)\n#WebSecurity #Pentest`;
    
    if (navigator.share) {
        navigator.share({
            title: 'Web Security Analysis Report',
            text: shareText
        }).catch(err => {
            console.log('Share failed:', err);
        });
    } else {
        // Fallback: copy to clipboard
        navigator.clipboard.writeText(shareText).then(() => {
            alert('Report copied to clipboard!');
        });
    }
}

function showLoginModal() {
    // Simple login prompt for demo
    const username = prompt('Username:');
    if (!username) return;
    
    const password = prompt('Password:');
    if (!password) return;
    
    login(username, password);
}

async function login(username, password) {
    try {
        const response = await fetch('/pentest-login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: username,
                password: password
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert('✓ Professional access granted!');
            window.location.href = '/pentest-dashboard';
        } else {
            alert('✗ Login failed. Please check credentials.');
        }
    } catch (error) {
        alert('Login error. Please try again.');
    }
}

// ========================================
// DEBUG
// ========================================
console.log('%c✅ app.js loaded successfully', 'color: #2ed573;');