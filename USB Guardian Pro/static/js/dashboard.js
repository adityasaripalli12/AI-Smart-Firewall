// Live Cybersecurity Clock Sync
function startLiveClock() {
    const clockElement = document.getElementById('live-clock');
    if (!clockElement) return;
    
    const updateTime = () => {
        const now = new Date();
        const hrs = String(now.getHours()).padStart(2, '0');
        const mins = String(now.getMinutes()).padStart(2, '0');
        const secs = String(now.getSeconds()).padStart(2, '0');
        clockElement.textContent = `${hrs}:${mins}:${secs} UGP`;
    };
    
    updateTime();
    setInterval(updateTime, 1000);
}

// Interactive Table Row Search Filtering
function initTableSearch() {
    const searchInputs = document.querySelectorAll('.cyber-search-input');
    searchInputs.forEach(input => {
        const targetTableId = input.getAttribute('data-target-table');
        const table = document.getElementById(targetTableId);
        if (!table) return;
        
        input.addEventListener('keyup', () => {
            const filter = input.value.toLowerCase();
            const rows = table.querySelectorAll('tbody tr');
            
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                if (text.includes(filter)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        });
    });
}

// Incident Capture Image Viewer Modal Logic
function initIncidentModals() {
    const modal = document.getElementById('incident-viewer-modal');
    if (!modal) return;
    
    const modalImg = modal.querySelector('.modal-body img');
    const modalTitle = modal.querySelector('.modal-title');
    const closeBtn = modal.querySelector('.modal-close');
    
    // Attach trigger listeners to visual attachment buttons
    const triggers = document.querySelectorAll('.trigger-modal');
    triggers.forEach(trigger => {
        trigger.addEventListener('click', (e) => {
            e.preventDefault();
            const imgSrc = trigger.getAttribute('data-src');
            const imgTitle = trigger.getAttribute('data-title');
            
            if (imgSrc) {
                modalImg.src = '/' + imgSrc; // prepending root slash
                modalTitle.textContent = imgTitle || 'Incident Capture Snapshot';
                modal.classList.add('active');
            }
        });
    });
    
    // Close on clicking button or overlay background
    closeBtn.addEventListener('click', () => {
        modal.classList.remove('active');
        modalImg.src = '';
    });
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.classList.remove('active');
            modalImg.src = '';
        }
    });
}

// Dynamic Sidebar Toggler
function initSidebarToggle() {
    const toggleBtn = document.getElementById('sidebar-toggle');
    const sidebar = document.querySelector('.sidebar');
    const mainContent = document.querySelector('.main-content');
    
    if (toggleBtn && sidebar && mainContent) {
        toggleBtn.addEventListener('click', () => {
            sidebar.classList.toggle('collapsed');
            mainContent.classList.toggle('expanded');
        });
    }
}

// Notifications Dropdown Toggler
function initNotifDropdown() {
    const wrapper = document.querySelector('.notif-wrapper');
    const trigger = document.querySelector('.notif-trigger');
    const dropdown = document.querySelector('.notif-dropdown');
    
    if (trigger && dropdown) {
        trigger.addEventListener('click', (e) => {
            e.stopPropagation();
            const isVisible = dropdown.style.display === 'block';
            dropdown.style.display = isVisible ? 'none' : 'block';
        });
        
        document.addEventListener('click', () => {
            dropdown.style.display = 'none';
        });
        
        dropdown.addEventListener('click', (e) => {
            e.stopPropagation();
        });
    }
}

// Persistent Security Status Polling & Real-time Lockdown Modifiers
let lastLockdownState = null;
function startDashboardStatsPolling() {
    // Only poll if on admin or employee dashboard
    const isDashboardPage = document.getElementById('admin-dashboard-indicator') || document.getElementById('employee-dashboard-indicator');
    if (!isDashboardPage) return;
    
    const checkStatus = () => {
        fetch('/api/dashboard_stats')
            .then(res => res.json())
            .then(data => {
                if (data.lockdown_active !== undefined) {
                    const isLockdown = data.lockdown_active;
                    
                    // Trigger emergency visual modifiers if state changes
                    if (lastLockdownState !== null && lastLockdownState !== isLockdown) {
                        if (isLockdown) {
                            enableLockdownUI();
                            CyberToast.show("CRITICAL ALERT: Emergency Global USB Lockdown has been activated by Administrator!", "danger");
                        } else {
                            disableLockdownUI();
                            CyberToast.show("Security Clearance: Emergency Lockdown has been deactivated.", "success");
                        }
                    } else if (lastLockdownState === null && isLockdown) {
                        // Page loaded while lockdown was already active
                        enableLockdownUI();
                    }
                    
                    lastLockdownState = isLockdown;
                }
            })
            .catch(err => console.warn("Failed to fetch statistics:", err));
    };
    
    // Check immediately, then poll every 7 seconds
    checkStatus();
    setInterval(checkStatus, 7000);
}

function enableLockdownUI() {
    document.body.classList.add('lockdown-active-ui');
    
    // Add banner overlay if not exists
    let banner = document.getElementById('lockdown-threat-banner');
    if (!banner) {
        banner = document.createElement('div');
        banner.id = 'lockdown-threat-banner';
        banner.className = 'threat-banner-active';
        banner.innerHTML = `<i class="fas fa-radiation-alt fa-spin mr-2"></i> SYSTEM UNDER LOCKDOWN: ALL PORT CHANNELS DISABLED <i class="fas fa-radiation-alt fa-spin ml-2"></i>`;
        document.body.appendChild(banner);
        
        // Pad main body top to avoid title overlaps
        document.body.style.paddingTop = '40px';
    }
}

function disableLockdownUI() {
    document.body.classList.remove('lockdown-active-ui');
    const banner = document.getElementById('lockdown-threat-banner');
    if (banner) {
        banner.remove();
        document.body.style.paddingTop = '0px';
    }
}

// Initialise everything
document.addEventListener('DOMContentLoaded', () => {
    startLiveClock();
    initTableSearch();
    initIncidentModals();
    initSidebarToggle();
    initNotifDropdown();
    startDashboardStatsPolling();
});
