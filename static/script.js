// Professional Matrix background animation with smooth performance
const canvas = document.getElementById('matrix-bg');
const ctx = canvas.getContext('2d', { alpha: false }); // Better performance

// Page loader
window.addEventListener('load', function() {
    const loader = document.querySelector('.page-loader');
    if (loader) {
        setTimeout(() => {
            loader.classList.add('hidden');
        }, 300);
    }
});

// Detect if device is mobile for performance optimization
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

// Optimized animation settings
const animationInterval = isMobile ? 100 : 60;
const glowChance = isMobile ? 0.995 : 0.985;

// Initialize drops with random starting positions
for (let i = 0; i < columns; i++) {
    drops[i] = Math.random() * -50;
}

function drawMatrix() {
    // Smooth fade effect
    ctx.fillStyle = 'rgba(10, 14, 27, 0.05)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    
    ctx.font = fontSize + 'px "Courier New", monospace';
    
    // Draw characters
    for (let i = 0; i < drops.length; i++) {
        // Smooth opacity gradient
        const opacity = Math.min(1, Math.max(0.3, Math.random() * 0.7 + 0.3));
        ctx.fillStyle = `rgba(0, 255, 136, ${opacity})`;
        
        const text = chars[Math.floor(Math.random() * chars.length)];
        const x = i * fontSize;
        const y = drops[i] * fontSize;
        
        ctx.fillText(text, x, y);
        
        // Subtle glow effect on random characters
        if (Math.random() > glowChance) {
            ctx.shadowBlur = 8;
            ctx.shadowColor = 'rgba(0, 255, 136, 0.8)';
            ctx.fillText(text, x, y);
            ctx.shadowBlur = 0;
        }
        
        // Reset drop with smooth randomization
        if (y > canvas.height && Math.random() > 0.975) {
            drops[i] = 0;
        }
        
        // Smooth variable speed
        drops[i] += Math.random() * 0.3 + 0.7;
    }
}

// Use requestAnimationFrame for smoother animation
let lastTime = 0;
function animate(currentTime) {
    if (currentTime - lastTime > animationInterval) {
        drawMatrix();
        lastTime = currentTime;
    }
    requestAnimationFrame(animate);
}
requestAnimationFrame(animate);

// Optimized resize handler
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

// Toggle password visibility
function togglePassword(fieldId) {
    const field = document.getElementById(fieldId);
    field.type = field.type === 'password' ? 'text' : 'password';
}

// Real-time email validation
const emailInput = document.getElementById('email');
const emailStatus = document.getElementById('emailStatus');

if (emailInput) {
    emailInput.addEventListener('input', function() {
        const email = this.value.trim();
        const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        
        if (email.length === 0) {
            emailStatus.textContent = '';
            emailStatus.className = 'status-message';
        } else if (!emailPattern.test(email)) {
            emailStatus.textContent = '✗ Invalid email format';
            emailStatus.className = 'status-message error';
        } else {
            emailStatus.textContent = '✓ Valid email address';
            emailStatus.className = 'status-message success';
        }
    });
}

// Real-time username validation
const usernameInput = document.getElementById('username');
const usernameStatus = document.getElementById('usernameStatus');

if (usernameInput) {
    usernameInput.addEventListener('input', function() {
        const username = this.value.trim();
        
        if (username.length === 0) {
            usernameStatus.textContent = '';
            usernameStatus.className = 'status-message';
        } else if (username.length < 3) {
            usernameStatus.textContent = `✗ Too short (${username.length}/3 minimum)`;
            usernameStatus.className = 'status-message error';
        } else if (username.length > 20) {
            usernameStatus.textContent = `✗ Too long (${username.length}/20 maximum)`;
            usernameStatus.className = 'status-message error';
        } else if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            usernameStatus.textContent = '✗ Only letters, numbers, and underscores allowed';
            usernameStatus.className = 'status-message error';
        } else {
            usernameStatus.textContent = `✓ Valid username (${username.length} characters)`;
            usernameStatus.className = 'status-message success';
        }
    });
}

// Real-time confirm password validation
const confirmPasswordInput = document.getElementById('confirmPassword');
const confirmStatus = document.getElementById('confirmStatus');

if (confirmPasswordInput) {
    confirmPasswordInput.addEventListener('input', function() {
        const password = document.getElementById('password').value;
        const confirmPassword = this.value;
        
        if (confirmPassword.length === 0) {
            confirmStatus.textContent = '';
            confirmStatus.className = 'status-message';
        } else if (password !== confirmPassword) {
            confirmStatus.textContent = '✗ Passwords do not match';
            confirmStatus.className = 'status-message error';
        } else {
            confirmStatus.textContent = '✓ Passwords match';
            confirmStatus.className = 'status-message success';
        }
    });
}

// Password strength checking
const passwordInput = document.getElementById('password');
const strengthBar = document.getElementById('strengthBar');
const strengthText = document.getElementById('strengthText');
const passwordFeedback = document.getElementById('passwordFeedback');

if (passwordInput) {
    let debounceTimer;
    passwordInput.addEventListener('input', function() {
        clearTimeout(debounceTimer);
        const password = this.value;
        
        if (password.length === 0) {
            strengthBar.style.width = '0%';
            strengthBar.className = 'strength-fill';
            strengthText.textContent = '-';
            strengthText.style.color = '#6b7280';
            passwordFeedback.innerHTML = '';
            return;
        }
        
        debounceTimer = setTimeout(() => {
            fetch('/check_password_strength', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ password: password })
            })
            .then(response => response.json())
            .then(data => {
                // Calculate percentage based on score
                const percentage = (data.score / data.max_score) * 100;
                strengthBar.style.width = percentage + '%';
                strengthBar.className = 'strength-fill ' + data.strength;
                
                if (data.strength === 'weak') {
                    strengthText.textContent = 'Weak';
                    strengthText.style.color = '#ff6b6b';
                } else if (data.strength === 'medium') {
                    strengthText.textContent = 'Medium';
                    strengthText.style.color = '#ffa500';
                } else if (data.strength === 'strong') {
                    strengthText.textContent = 'Strong';
                    strengthText.style.color = '#00ff88';
                } else if (data.strength === 'very-strong') {
                    strengthText.textContent = 'Very Strong';
                    strengthText.style.color = '#00ffff';
                }
                
                // Display feedback
                passwordFeedback.innerHTML = data.feedback
                    .map(item => {
                        const icon = item.startsWith('✓') ? '✓' : '✗';
                        const className = item.startsWith('✓') ? 'pass' : 'fail';
                        return `<div class="feedback-item ${className}">${icon} ${item.substring(2)}</div>`;
                    })
                    .join('');
            });
        }, 300);
    });
}

// Form submission with loading state
const registrationForm = document.getElementById('registrationForm');
const submitBtn = document.getElementById('submitBtn');
const messageBox = document.getElementById('messageBox');

function showMessage(message, type) {
    messageBox.textContent = message;
    messageBox.className = 'message-box ' + type;
    messageBox.style.display = 'block';
    
    setTimeout(() => {
        messageBox.style.display = 'none';
    }, 5000);
}

if (registrationForm) {
    registrationForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const username = document.getElementById('username').value.trim();
        const email = document.getElementById('email').value.trim();
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirmPassword').value;
        
        // Validation
        if (username.length < 3 || username.length > 20) {
            showMessage('Username must be between 3 and 20 characters', 'error');
            return;
        }
        
        const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        if (!emailPattern.test(email)) {
            showMessage('Please enter a valid email address', 'error');
            return;
        }
        
        if (password !== confirmPassword) {
            showMessage('Passwords do not match', 'error');
            return;
        }
        
        // Show loading state
        if (submitBtn) {
            submitBtn.disabled = true;
            // The CSS will automatically show the spinner and hide the text
        }
        
        // Send registration data to server for temporary storage in server-side session
        fetch('/store_registration', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: username,
                email: email,
                password: password,
                csrf_token: document.getElementById('csrfToken').value
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Show loading animation
                showMessage(data.message, 'success');
                document.body.insertAdjacentHTML('beforeend', `
                    <div class="page-loader">
                        <div class="loader-spinner"></div>
                        <div class="loader-text">Sending verification code...</div>
                    </div>
                `);
                
                setTimeout(() => {
                    window.location.href = '/verify';
                }, 1000);
            } else {
                showMessage(data.message || 'Error storing registration data', 'error');
                submitBtn.disabled = false;
            }
        })
        .catch(error => {
            showMessage('Network error. Please try again.', 'error');
            submitBtn.disabled = false;
        });
    });
}

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Escape to clear form
    if (e.key === 'Escape') {
        const form = document.getElementById('registrationForm');
        if (form && confirm('Clear all fields?')) {
            form.reset();
            if (strengthBar) strengthBar.className = 'strength-fill';
            if (strengthText) strengthText.textContent = '-';
            if (passwordFeedback) passwordFeedback.innerHTML = '';
            if (usernameStatus) usernameStatus.textContent = '';
            if (confirmStatus) confirmStatus.textContent = '';
        }
    }
});
