// Matrix background animation
const canvas = document.getElementById('matrix-bg');
const ctx = canvas.getContext('2d', { alpha: false });

// Page loader
window.addEventListener('load', function() {
    const loader = document.querySelector('.page-loader');
    if (loader) {
        setTimeout(() => {
            loader.classList.add('hidden');
        }, 300);
    }
});

const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);

function resizeCanvas() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
}

resizeCanvas();

const chars = '01';
const fontSize = 14;
let columns = Math.floor(canvas.width / fontSize);
let drops = [];

const animationInterval = isMobile ? 100 : 60;
const glowChance = isMobile ? 0.995 : 0.985;

for (let i = 0; i < columns; i++) {
    drops[i] = Math.random() * -50;
}

function drawMatrix() {
    ctx.fillStyle = 'rgba(10, 14, 27, 0.05)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    
    ctx.font = fontSize + 'px "Courier New", monospace';
    
    for (let i = 0; i < drops.length; i++) {
        const opacity = Math.min(1, Math.max(0.3, Math.random() * 0.7 + 0.3));
        ctx.fillStyle = `rgba(0, 255, 136, ${opacity})`;
        
        const text = chars[Math.floor(Math.random() * chars.length)];
        const x = i * fontSize;
        const y = drops[i] * fontSize;
        
        ctx.fillText(text, x, y);
        
        if (Math.random() > glowChance) {
            ctx.shadowBlur = 8;
            ctx.shadowColor = 'rgba(0, 255, 136, 0.8)';
            ctx.fillText(text, x, y);
            ctx.shadowBlur = 0;
        }
        
        if (y > canvas.height && Math.random() > 0.975) {
            drops[i] = 0;
        }
        
        drops[i] += Math.random() * 0.3 + 0.7;
    }
}

let lastTime = 0;
function animate(currentTime) {
    if (currentTime - lastTime > animationInterval) {
        drawMatrix();
        lastTime = currentTime;
    }
    requestAnimationFrame(animate);
}
requestAnimationFrame(animate);

let resizeTimeout;
window.addEventListener('resize', () => {
    clearTimeout(resizeTimeout);
    resizeTimeout = setTimeout(() => {
        const oldColumns = columns;
        resizeCanvas();
        columns = Math.floor(canvas.width / fontSize);
        
        if (columns > oldColumns) {
            for (let i = oldColumns; i < columns; i++) {
                drops[i] = Math.random() * canvas.height / fontSize;
            }
        } else if (columns < oldColumns) {
            drops = drops.slice(0, columns);
        }
    }, 150);
});

// OTP input validation
const otpInput = document.getElementById('otpInput');
const otpStatus = document.getElementById('otpStatus');

if (otpInput) {
    otpInput.addEventListener('input', function() {
        this.value = this.value.replace(/[^0-9]/g, '');
        
        if (this.value.length === 0) {
            otpStatus.textContent = '';
            otpStatus.className = 'status-message';
        } else if (this.value.length < 6) {
            otpStatus.textContent = `✗ Enter all 6 digits (${this.value.length}/6)`;
            otpStatus.className = 'status-message error';
        } else {
            otpStatus.textContent = '✓ Code format valid';
            otpStatus.className = 'status-message success';
        }
    });
}

// Message display
const messageBox = document.getElementById('messageBox');

function showMessage(message, type) {
    messageBox.textContent = message;
    messageBox.className = 'message-box ' + type;
    messageBox.style.display = 'block';
    
    setTimeout(() => {
        messageBox.style.display = 'none';
    }, 5000);
}

// Verify form submission
const verifyForm = document.getElementById('verifyForm');
const verifyBtn = document.getElementById('verifyBtn');

if (verifyForm) {
    verifyForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const otp = otpInput.value.trim();
        
        if (otp.length !== 6) {
            showMessage('Please enter the complete 6-digit code', 'error');
            return;
        }
        
        verifyBtn.disabled = true;
        
        fetch('/verify_otp', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                otp: otp,
                csrf_token: document.getElementById('csrfToken').value
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showMessage(data.message, 'success');
                
                // Show loading animation
                document.body.insertAdjacentHTML('beforeend', `
                    <div class="page-loader">
                        <div class="loader-spinner"></div>
                        <div class="loader-text">Verifying...</div>
                    </div>
                `);
                
                setTimeout(() => {
                    window.location.href = data.redirect || '/captcha';
                }, 1000);
            } else {
                showMessage(data.message, 'error');
                verifyBtn.disabled = false;
                
                if (data.locked || data.expired) {
                    setTimeout(() => {
                        window.location.href = '/register';
                    }, 2000);
                }
            }
        })
        .catch(error => {
            showMessage('Network error. Please try again.', 'error');
            verifyBtn.disabled = false;
        });
    });
}

// Resend OTP
const resendBtn = document.getElementById('resendBtn');

if (resendBtn) {
    resendBtn.addEventListener('click', function() {
        this.disabled = true;
        
        fetch('/resend_otp', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                csrf_token: document.getElementById('csrfToken').value
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showMessage(data.message, 'success');
                otpInput.value = '';
                otpStatus.textContent = '';
                
                setTimeout(() => {
                    this.disabled = false;
                }, 30000); // 30 seconds cooldown
            } else {
                showMessage(data.message, 'error');
                this.disabled = false;
            }
        })
        .catch(error => {
            showMessage('Network error. Please try again.', 'error');
            this.disabled = false;
        });
    });
}
