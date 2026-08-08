// Web Audio API Synth Beeps for cyber UI feedback (No external assets required!)
const CyberAudio = {
    ctx: null,
    
    init() {
        if (!this.ctx) {
            this.ctx = new (window.AudioContext || window.webkitAudioContext)();
        }
    },
    
    playBeep(type) {
        try {
            this.init();
            if (!this.ctx) return;
            
            const osc = this.ctx.createOscillator();
            const gain = this.ctx.createGain();
            
            osc.connect(gain);
            gain.connect(this.ctx.destination);
            
            const now = this.ctx.currentTime;
            
            if (type === 'success') {
                // Double high chirp
                osc.type = 'sine';
                osc.frequency.setValueAtTime(880, now);
                osc.frequency.setValueAtTime(1200, now + 0.08);
                gain.gain.setValueAtTime(0.08, now);
                gain.gain.exponentialRampToValueAtTime(0.001, now + 0.25);
                osc.start(now);
                osc.stop(now + 0.25);
            } else if (type === 'danger' || type === 'alert') {
                // Heavy alarm siren sweep
                osc.type = 'sawtooth';
                osc.frequency.setValueAtTime(150, now);
                osc.frequency.linearRampToValueAtTime(450, now + 0.3);
                gain.gain.setValueAtTime(0.12, now);
                gain.gain.exponentialRampToValueAtTime(0.001, now + 0.4);
                osc.start(now);
                osc.stop(now + 0.4);
            } else if (type === 'warning') {
                // Short mid alert beep
                osc.type = 'triangle';
                osc.frequency.setValueAtTime(440, now);
                gain.gain.setValueAtTime(0.1, now);
                gain.gain.exponentialRampToValueAtTime(0.001, now + 0.15);
                osc.start(now);
                osc.stop(now + 0.15);
            } else {
                // Default click/info click
                osc.type = 'sine';
                osc.frequency.setValueAtTime(600, now);
                gain.gain.setValueAtTime(0.05, now);
                gain.gain.exponentialRampToValueAtTime(0.001, now + 0.08);
                osc.start(now);
                osc.stop(now + 0.08);
            }
        } catch (e) {
            console.warn("Audio Context playback failed or user interaction required:", e);
        }
    }
};

// Global Toast Alert Dispatcher
const CyberToast = {
    show(message, type = 'info') {
        // Ensure container exists
        let container = document.getElementById('toast-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toast-container';
            document.body.appendChild(container);
        }
        
        // Create Toast element
        const toast = document.createElement('div');
        toast.className = `toast toast-${type} glass-panel`;
        
        let icon = 'info-circle';
        if (type === 'success') icon = 'check-circle';
        if (type === 'danger') icon = 'exclamation-triangle';
        if (type === 'warning') icon = 'exclamation-circle';
        
        toast.innerHTML = `
            <div style="display: flex; align-items: center; gap: 12px;">
                <i class="fas fa-${icon}" style="font-size: 1.1rem;"></i>
                <span>${message}</span>
            </div>
            <button onclick="this.parentElement.remove()" style="background:none; border:none; color:inherit; cursor:pointer; margin-left: 15px;">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        container.appendChild(toast);
        
        // Play corresponding synthesised alert tone
        CyberAudio.playBeep(type);
        
        // Self-dismiss toast
        setTimeout(() => {
            if (toast.parentElement) {
                toast.style.animation = 'slideIn 0.3s ease reverse forwards';
                setTimeout(() => toast.remove(), 300);
            }
        }, 5000);
    },
    
    // Updates the unread notifications count badge on topbar
    updateBadge(count) {
        const badge = document.querySelector('.notif-badge');
        if (badge) {
            if (count > 0) {
                badge.textContent = count;
                badge.style.display = 'block';
            } else {
                badge.style.display = 'none';
            }
        }
    }
};

// Hook page events on load
document.addEventListener('DOMContentLoaded', () => {
    // Initialise audio on first click anywhere (browser interaction security)
    document.addEventListener('click', () => {
        CyberAudio.init();
    }, { once: true });
});
