// Professional Matrix background animation with smooth performance
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

// Refresh CAPTCHA
function refreshCaptcha() {
    const img = document.getElementById('captchaImage');
    img.src = '/captcha_image?' + Date.now();
}

// Form submission
const form = document.getElementById('verificationForm');
const messageBox = document.getElementById('messageBox');

form.addEventListener('submit', function(e) {
    e.preventDefault();
    
    const captchaInput = document.getElementById('captchaInput').value;
    
    if (!captchaInput) {
        messageBox.className = 'message-box error';
        messageBox.textContent = 'Please enter the CAPTCHA characters';
        messageBox.style.display = 'block';
        return;
    }
    
    const submitBtn = form.querySelector('.submit-btn');
    submitBtn.disabled = true;
    submitBtn.style.opacity = '0.6';
    
    // Registration data is stored server-side in Flask session
    // No need to retrieve from client-side storage
    
    const formData = new FormData(form);  // This will include the hidden csrf_token field
    
    fetch('/complete_registration', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        messageBox.className = 'message-box ' + (data.success ? 'success' : 'error');
        messageBox.textContent = data.message;
        messageBox.style.display = 'block';
        
        if (data.success) {
            // Show loading animation
            document.body.insertAdjacentHTML('beforeend', `
                <div class="page-loader">
                    <div class="loader-spinner"></div>
                    <div class="loader-text">Registration complete!</div>
                </div>
            `);
            
            // Redirect to success page
            setTimeout(() => {
                window.location.href = data.redirect || '/success';
            }, 800);
        } else if (data.locked_out) {
            // Account locked - disable form and show countdown
            form.querySelector('.submit-btn').disabled = true;
            document.getElementById('captchaInput').disabled = true;
            
            // Start countdown timer
            let remaining = data.remaining_seconds || 15;
            const countdownInterval = setInterval(() => {
                remaining--;
                if (remaining > 0) {
                    messageBox.textContent = `Too many failed attempts. Please wait ${remaining} seconds before trying again.`;
                } else {
                    clearInterval(countdownInterval);
                    window.location.reload();
                }
            }, 1000);
        } else {
            // Show attempts remaining if available
            if (data.attempts_remaining !== undefined) {
                messageBox.textContent = data.message + ` (${data.attempts_remaining} attempts remaining)`;
            }
            // Refresh CAPTCHA on failure
            refreshCaptcha();
            document.getElementById('captchaInput').value = '';
        }
        
        submitBtn.disabled = false;
        submitBtn.style.opacity = '1';
    })
    .catch(error => {
        messageBox.className = 'message-box error';
        messageBox.textContent = 'Network error. Please try again.';
        messageBox.style.display = 'block';
        
        refreshCaptcha();
        document.getElementById('captchaInput').value = '';
        submitBtn.disabled = false;
        submitBtn.style.opacity = '1';
    });
});
