/* =============================================
   Amria Mall - Interactive JavaScript
   Mouse effects, animations, and interactions
   🔒 SECURITY HARDENED VERSION 2.0
   ============================================= */

'use strict';

// ===== SECURITY CORE - IIFE to prevent global pollution =====
const AmriaSecurity = (function () {

    // Private variables - not accessible from outside
    const _config = Object.freeze({
        maxInputLength: 1000,
        maxNameLength: 100,
        maxEmailLength: 254,
        maxPhoneLength: 20,
        maxMessageLength: 5000,
        rateLimit: {
            maxAttempts: 3,
            windowMs: 60000,
            blockDurationMs: 300000 // 5 minutes block
        },
        allowedTags: [],
        dangerousPatterns: [
            /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
            /javascript:/gi,
            /on\w+\s*=/gi,
            /data:/gi,
            /vbscript:/gi,
            /expression\s*\(/gi,
            /<iframe/gi,
            /<object/gi,
            /<embed/gi,
            /<form/gi
        ]
    });

    // Private rate limiter storage
    const _rateLimiter = new Map();
    const _blockedIPs = new Map();

    // Session fingerprint for anti-tampering
    const _sessionFingerprint = generateFingerprint();

    function generateFingerprint() {
        const data = [
            navigator.userAgent,
            navigator.language,
            screen.width + 'x' + screen.height,
            new Date().getTimezoneOffset(),
            navigator.hardwareConcurrency || 'unknown'
        ].join('|');

        // Simple hash
        let hash = 0;
        for (let i = 0; i < data.length; i++) {
            const char = data.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return Math.abs(hash).toString(36);
    }

    /**
     * Advanced XSS sanitization
     * @param {string} input - User input
     * @param {string} type - Input type (name, email, phone, message)
     * @returns {string} - Sanitized input
     */
    function sanitize(input, type = 'text') {
        if (typeof input !== 'string') return '';

        // Trim and limit length based on type
        const maxLength = {
            name: _config.maxNameLength,
            email: _config.maxEmailLength,
            phone: _config.maxPhoneLength,
            message: _config.maxMessageLength,
            text: _config.maxInputLength
        }[type] || _config.maxInputLength;

        let clean = input.trim().substring(0, maxLength);

        // Remove dangerous patterns
        _config.dangerousPatterns.forEach(pattern => {
            clean = clean.replace(pattern, '');
        });

        // HTML entity encoding
        const div = document.createElement('div');
        div.textContent = clean;
        clean = div.innerHTML;

        // Additional encoding for special chars
        clean = clean
            .replace(/'/g, '&#x27;')
            .replace(/"/g, '&quot;')
            .replace(/`/g, '&#x60;')
            .replace(/\(/g, '&#40;')
            .replace(/\)/g, '&#41;');

        return clean;
    }

    /**
     * Validate email with strict regex
     */
    function isValidEmail(email) {
        if (!email || typeof email !== 'string') return false;
        if (email.length > _config.maxEmailLength) return false;

        // RFC 5322 compliant regex (simplified)
        const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        return emailRegex.test(email);
    }

    /**
     * Validate Iraqi phone number
     */
    function isValidPhone(phone) {
        if (!phone || typeof phone !== 'string') return false;
        const cleaned = phone.replace(/[\s\-\(\)]/g, '');
        if (cleaned.length > _config.maxPhoneLength) return false;

        // Iraqi mobile: +964 7XX XXX XXXX or 07XX XXX XXXX
        const phoneRegex = /^(\+964|00964|0)?7[3-9][0-9]{8}$/;
        return phoneRegex.test(cleaned);
    }

    /**
     * Validate name (no special chars except Arabic)
     */
    function isValidName(name) {
        if (!name || typeof name !== 'string') return false;
        if (name.length < 2 || name.length > _config.maxNameLength) return false;

        // Allow Arabic, English letters, spaces, and common name chars
        const nameRegex = /^[\u0600-\u06FF\u0750-\u077Fa-zA-Z\s\-'.]+$/;
        return nameRegex.test(name);
    }

    /**
     * Advanced rate limiter with blocking
     */
    function checkRateLimit(key) {
        const now = Date.now();

        // Check if blocked
        const blockRecord = _blockedIPs.get(key);
        if (blockRecord && now < blockRecord.until) {
            const remaining = Math.ceil((blockRecord.until - now) / 1000);
            return { allowed: false, blocked: true, remainingSeconds: remaining };
        }

        // Clear old block
        if (blockRecord) _blockedIPs.delete(key);

        const record = _rateLimiter.get(key);

        if (!record) {
            _rateLimiter.set(key, { count: 1, firstAttempt: now, attempts: [now] });
            return { allowed: true, remaining: _config.rateLimit.maxAttempts - 1 };
        }

        // Reset if window expired
        if (now - record.firstAttempt > _config.rateLimit.windowMs) {
            _rateLimiter.set(key, { count: 1, firstAttempt: now, attempts: [now] });
            return { allowed: true, remaining: _config.rateLimit.maxAttempts - 1 };
        }

        // Check if max attempts reached
        if (record.count >= _config.rateLimit.maxAttempts) {
            // Block the user
            _blockedIPs.set(key, { until: now + _config.rateLimit.blockDurationMs });
            return { allowed: false, blocked: true, remainingSeconds: _config.rateLimit.blockDurationMs / 1000 };
        }

        record.count++;
        record.attempts.push(now);
        return { allowed: true, remaining: _config.rateLimit.maxAttempts - record.count };
    }

    /**
     * Detect potential bot behavior
     */
    function detectBot() {
        const suspicious = [];

        // Check for common bot indicators
        if (!navigator.webdriver === undefined) suspicious.push('webdriver');
        if (navigator.languages && navigator.languages.length === 0) suspicious.push('no-languages');
        if (!window.chrome && /Chrome/.test(navigator.userAgent)) suspicious.push('fake-chrome');

        // Headless browser detection
        if (/HeadlessChrome/.test(navigator.userAgent)) suspicious.push('headless');

        return suspicious.length > 0 ? suspicious : null;
    }

    /**
     * Honeypot field detection
     */
    function checkHoneypot(form) {
        const honeypot = form.querySelector('[name="website"], [name="url"], [name="fax"], .hp-field');
        if (honeypot && honeypot.value) {
            console.warn('🚨 Bot detected via honeypot');
            return true;
        }
        return false;
    }

    /**
     * Time-based validation (form filled too fast = bot)
     */
    const _formLoadTimes = new WeakMap();

    function trackFormLoad(form) {
        _formLoadTimes.set(form, Date.now());
    }

    function checkFormTiming(form) {
        const loadTime = _formLoadTimes.get(form);
        if (!loadTime) return true; // No tracking, allow

        const fillTime = Date.now() - loadTime;
        const minFillTime = 3000; // 3 seconds minimum

        if (fillTime < minFillTime) {
            console.warn('🚨 Form submitted too quickly - possible bot');
            return false;
        }
        return true;
    }

    /**
     * CSRF Token generation (for when you have a backend)
     */
    function generateCSRFToken() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
    }

    // Public API - frozen to prevent tampering
    return Object.freeze({
        sanitize,
        isValidEmail,
        isValidPhone,
        isValidName,
        checkRateLimit,
        detectBot,
        checkHoneypot,
        trackFormLoad,
        checkFormTiming,
        generateCSRFToken,
        getFingerprint: () => _sessionFingerprint,

        // Secure form submission handler
        handleFormSubmit(form, callback) {
            if (!form || !(form instanceof HTMLFormElement)) return;

            let isSubmitting = false;

            // Track form load time
            this.trackFormLoad(form);

            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                e.stopPropagation();

                // Prevent double submission
                if (isSubmitting) return;

                // Bot detection
                const botIndicators = this.detectBot();
                if (botIndicators) {
                    console.warn('🚨 Suspicious activity detected:', botIndicators);
                    return;
                }

                // Honeypot check
                if (this.checkHoneypot(form)) return;

                // Timing check
                if (!this.checkFormTiming(form)) {
                    alert('الرجاء التأني في ملء النموذج');
                    return;
                }

                // Rate limiting
                const rateCheck = this.checkRateLimit('form-' + this.getFingerprint());
                if (!rateCheck.allowed) {
                    if (rateCheck.blocked) {
                        alert(`تم حظرك مؤقتاً. الرجاء المحاولة بعد ${Math.ceil(rateCheck.remainingSeconds / 60)} دقيقة`);
                    } else {
                        alert('الرجاء الانتظار قبل المحاولة مرة أخرى');
                    }
                    return;
                }

                // Collect and sanitize data
                const formData = new FormData(form);
                const data = {};
                let hasErrors = false;

                for (let [key, value] of formData.entries()) {
                    // Skip honeypot fields
                    if (['website', 'url', 'fax'].includes(key)) continue;

                    // Determine field type
                    const field = form.querySelector(`[name="${key}"]`);
                    const type = field?.type || 'text';

                    // Sanitize based on type
                    if (type === 'email') {
                        data[key] = this.sanitize(value, 'email');
                        if (!this.isValidEmail(value)) {
                            alert('الرجاء إدخال بريد إلكتروني صحيح');
                            field?.focus();
                            hasErrors = true;
                            break;
                        }
                    } else if (type === 'tel') {
                        data[key] = this.sanitize(value, 'phone');
                        if (value && !this.isValidPhone(value)) {
                            alert('الرجاء إدخال رقم هاتف عراقي صحيح');
                            field?.focus();
                            hasErrors = true;
                            break;
                        }
                    } else if (key === 'name' || key.includes('name')) {
                        data[key] = this.sanitize(value, 'name');
                        if (!this.isValidName(value)) {
                            alert('الرجاء إدخال اسم صحيح');
                            field?.focus();
                            hasErrors = true;
                            break;
                        }
                    } else if (key === 'message' || type === 'textarea') {
                        data[key] = this.sanitize(value, 'message');
                    } else {
                        data[key] = this.sanitize(value, 'text');
                    }
                }

                if (hasErrors) return;

                // Check required fields
                const requiredFields = form.querySelectorAll('[required]');
                for (let field of requiredFields) {
                    if (!field.value.trim()) {
                        field.focus();
                        alert('الرجاء ملء جميع الحقول المطلوبة');
                        return;
                    }
                }

                isSubmitting = true;
                const submitBtn = form.querySelector('button[type="submit"], input[type="submit"]');
                const originalText = submitBtn?.textContent || submitBtn?.value;

                if (submitBtn) {
                    submitBtn.disabled = true;
                    if (submitBtn.textContent !== undefined) {
                        submitBtn.textContent = 'جاري الإرسال...';
                    } else {
                        submitBtn.value = 'جاري الإرسال...';
                    }
                }

                try {
                    // Add security metadata
                    data._fingerprint = this.getFingerprint();
                    data._timestamp = Date.now();
                    data._csrf = this.generateCSRFToken();

                    if (typeof callback === 'function') {
                        await callback(data, form);
                    }

                    form.reset();
                    this.trackFormLoad(form); // Reset timing
                    alert('تم إرسال رسالتك بنجاح! ✅');

                } catch (error) {
                    console.error('Form submission error:', error);
                    alert('حدث خطأ. الرجاء المحاولة لاحقاً');
                } finally {
                    isSubmitting = false;
                    if (submitBtn) {
                        submitBtn.disabled = false;
                        if (submitBtn.textContent !== undefined) {
                            submitBtn.textContent = originalText;
                        } else {
                            submitBtn.value = originalText;
                        }
                    }
                }
            });
        }
    });
})();

// ===== ANTI-TAMPERING PROTECTION =====
(function () {
    // Disable right-click context menu (optional - can be removed)
    // document.addEventListener('contextmenu', e => e.preventDefault());

    // Disable certain keyboard shortcuts that could be used for inspection
    document.addEventListener('keydown', (e) => {
        // F12, Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+U (View Source)
        if (e.key === 'F12' ||
            (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'J')) ||
            (e.ctrlKey && e.key === 'U')) {
            // Uncomment to block: e.preventDefault();
            console.log('🔒 Developer tools detected');
        }
    });

    // Console warning for social engineering protection
    console.log('%c⚠️ تحذير أمني!', 'color: red; font-size: 30px; font-weight: bold;');
    console.log('%cهذا المتصفح مخصص للمطورين. إذا طلب منك شخص ما لصق كود هنا، فهذه عملية احتيال.',
        'color: red; font-size: 16px;');
    console.log('%cلا تلصق أي كود هنا أبداً!', 'color: red; font-size: 14px; font-weight: bold;');
})();

// ===== CLICKJACKING PROTECTION =====
(function () {
    // Frame busting
    if (window.self !== window.top) {
        // We're in an iframe - potential clickjacking
        try {
            window.top.location = window.self.location;
        } catch (e) {
            // Can't bust frame (cross-origin), hide content
            document.body.innerHTML = '<h1>هذا الموقع لا يمكن عرضه داخل إطار</h1>';
        }
    }
})();

// ===== END SECURITY UTILITIES =====

document.addEventListener('DOMContentLoaded', () => {
    // Initialize all components
    initMouseFollower();
    initParticles();
    initScrollAnimations();
    initMobileMenu();
    initHeaderScroll();
    initSmoothScroll();
    initCardHoverEffects();
    initSecureForms();
});

// Initialize secure form handling
function initSecureForms() {
    const contactForms = document.querySelectorAll('form');
    contactForms.forEach(form => {
        // Add honeypot field programmatically (hidden from users, visible to bots)
        const honeypot = document.createElement('input');
        honeypot.type = 'text';
        honeypot.name = 'website';
        honeypot.tabIndex = -1;
        honeypot.autocomplete = 'off';
        honeypot.style.cssText = 'position: absolute; left: -9999px; opacity: 0; pointer-events: none;';
        form.appendChild(honeypot);

        // Use the secure form handler
        AmriaSecurity.handleFormSubmit(form, async (data, formElement) => {
            // In production, send to your secure backend
            console.log('🔒 Secure form submission:', {
                sanitizedData: data,
                fingerprint: data._fingerprint,
                timestamp: new Date(data._timestamp).toISOString()
            });

            // Simulate API call (replace with actual fetch in production)
            // await fetch('/api/contact', {
            //     method: 'POST',
            //     headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': data._csrf },
            //     body: JSON.stringify(data)
            // });
        });
    });
}

// Mobile Menu Functionality
function initMobileMenu() {
    const menuToggle = document.querySelector('.menu-toggle');
    const nav = document.querySelector('nav');
    const menuOverlay = document.querySelector('.menu-overlay');
    const navLinks = document.querySelectorAll('nav a');

    if (!menuToggle || !nav || !menuOverlay) return;

    function toggleMenu() {
        menuToggle.classList.toggle('active');
        nav.classList.toggle('active');
        menuOverlay.classList.toggle('active');
        document.body.style.overflow = nav.classList.contains('active') ? 'hidden' : '';
    }

    menuToggle.addEventListener('click', toggleMenu);
    menuOverlay.addEventListener('click', toggleMenu);

    // Close menu when clicking a link
    navLinks.forEach(link => {
        link.addEventListener('click', () => {
            if (nav.classList.contains('active')) {
                toggleMenu();
            }
        });
    });
}

// Mouse Follower Effect
function initMouseFollower() {
    const follower = document.querySelector('.mouse-follower');
    if (!follower) return;

    let mouseX = 0, mouseY = 0;
    let followerX = 0, followerY = 0;

    document.addEventListener('mousemove', (e) => {
        mouseX = e.clientX;
        mouseY = e.clientY;
    });

    function animate() {
        // Smooth follow effect
        followerX += (mouseX - followerX) * 0.1;
        followerY += (mouseY - followerY) * 0.1;

        follower.style.left = followerX + 'px';
        follower.style.top = followerY + 'px';

        requestAnimationFrame(animate);
    }
    animate();
}

// Create Floating Particles
function initParticles() {
    const particlesContainer = document.querySelector('.particles');
    if (!particlesContainer) return;

    const particleCount = 30;

    for (let i = 0; i < particleCount; i++) {
        createParticle(particlesContainer, i);
    }
}

function createParticle(container, index) {
    const particle = document.createElement('div');
    particle.className = 'particle';

    // Random properties
    const size = Math.random() * 4 + 2;
    const left = Math.random() * 100;
    const delay = Math.random() * 20;
    const duration = Math.random() * 10 + 15;
    const opacity = Math.random() * 0.3 + 0.1;

    particle.style.cssText = `
        width: ${size}px;
        height: ${size}px;
        left: ${left}%;
        animation-delay: -${delay}s;
        animation-duration: ${duration}s;
        opacity: ${opacity};
        background: ${index % 3 === 0 ? '#E86F25' : index % 3 === 1 ? '#F9A825' : '#FFD54F'};
    `;

    container.appendChild(particle);
}

// Scroll Animations with Intersection Observer
function initScrollAnimations() {
    const animatedElements = document.querySelectorAll('.fade-in, .slide-right, .slide-left');

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
            }
        });
    }, {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    });

    animatedElements.forEach(el => observer.observe(el));
}

// Header Scroll Effect
function initHeaderScroll() {
    const header = document.querySelector('header');
    if (!header) return;

    let lastScroll = 0;

    window.addEventListener('scroll', () => {
        const currentScroll = window.pageYOffset;

        if (currentScroll > 100) {
            header.classList.add('scrolled');
        } else {
            header.classList.remove('scrolled');
        }

        lastScroll = currentScroll;
    });
}

// Smooth Scroll for Navigation Links
function initSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
}

// 3D Card Hover Effects
function initCardHoverEffects() {
    const cards = document.querySelectorAll('.store-card, .team-card, .about-card');

    cards.forEach(card => {
        card.addEventListener('mousemove', (e) => {
            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;

            const centerX = rect.width / 2;
            const centerY = rect.height / 2;

            const rotateX = (y - centerY) / 10;
            const rotateY = (centerX - x) / 10;

            card.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) translateY(-10px)`;
        });

        card.addEventListener('mouseleave', () => {
            card.style.transform = 'perspective(1000px) rotateX(0) rotateY(0) translateY(0)';
        });
    });
}

// Parallax Effect for Hero Section
function initParallax() {
    const hero = document.querySelector('.hero');
    if (!hero) return;

    window.addEventListener('scroll', () => {
        const scrolled = window.pageYOffset;
        const heroContent = hero.querySelector('.hero-content');

        if (heroContent && scrolled < window.innerHeight) {
            heroContent.style.transform = `translateY(${scrolled * 0.3}px)`;
            heroContent.style.opacity = 1 - (scrolled / window.innerHeight);
        }
    });
}

// Initialize Parallax
initParallax();

// Magnetic Button Effect
document.querySelectorAll('.hero-btn, .submit-btn').forEach(btn => {
    btn.addEventListener('mousemove', (e) => {
        const rect = btn.getBoundingClientRect();
        const x = e.clientX - rect.left - rect.width / 2;
        const y = e.clientY - rect.top - rect.height / 2;

        btn.style.transform = `translate(${x * 0.2}px, ${y * 0.2}px)`;
    });

    btn.addEventListener('mouseleave', () => {
        btn.style.transform = 'translate(0, 0)';
    });
});

// Typing Effect for Hero Title (Optional Enhancement)
function typeWriter(element, text, speed = 100) {
    let i = 0;
    element.textContent = '';

    function type() {
        if (i < text.length) {
            element.textContent += text.charAt(i);
            i++;
            setTimeout(type, speed);
        }
    }
    type();
}

// Wave Animation for Background
function createWaveAnimation() {
    const canvas = document.createElement('canvas');
    canvas.id = 'wave-canvas';
    canvas.style.cssText = `
        position: fixed;
        bottom: 0;
        left: 0;
        width: 100%;
        height: 200px;
        pointer-events: none;
        z-index: 0;
        opacity: 0.3;
    `;

    document.querySelector('.animated-bg')?.appendChild(canvas);

    const ctx = canvas.getContext('2d');
    let width = canvas.width = window.innerWidth;
    let height = canvas.height = 200;

    let time = 0;

    function drawWave() {
        ctx.clearRect(0, 0, width, height);

        // Draw multiple waves
        for (let wave = 0; wave < 3; wave++) {
            ctx.beginPath();
            ctx.moveTo(0, height);

            for (let x = 0; x <= width; x += 10) {
                const y = Math.sin((x * 0.01) + time + (wave * 0.5)) * 30 +
                    Math.sin((x * 0.02) + time * 1.5) * 20 +
                    height - 50 - (wave * 30);
                ctx.lineTo(x, y);
            }

            ctx.lineTo(width, height);
            ctx.closePath();

            const gradient = ctx.createLinearGradient(0, 0, width, 0);
            gradient.addColorStop(0, wave === 0 ? '#E86F25' : wave === 1 ? '#F9A825' : '#FFD54F');
            gradient.addColorStop(1, wave === 0 ? '#F9A825' : wave === 1 ? '#FFD54F' : '#E86F25');

            ctx.fillStyle = gradient;
            ctx.globalAlpha = 0.3 - (wave * 0.1);
            ctx.fill();
        }

        time += 0.02;
        requestAnimationFrame(drawWave);
    }

    drawWave();

    window.addEventListener('resize', () => {
        width = canvas.width = window.innerWidth;
    });
}

// Initialize wave animation
createWaveAnimation();

// Add ripple effect on click
document.addEventListener('click', (e) => {
    const ripple = document.createElement('div');
    ripple.style.cssText = `
        position: fixed;
        width: 20px;
        height: 20px;
        background: radial-gradient(circle, rgba(232, 111, 37, 0.5) 0%, transparent 70%);
        border-radius: 50%;
        pointer-events: none;
        left: ${e.clientX}px;
        top: ${e.clientY}px;
        transform: translate(-50%, -50%) scale(0);
        animation: rippleEffect 0.6s ease-out forwards;
        z-index: 9999;
    `;

    document.body.appendChild(ripple);

    setTimeout(() => ripple.remove(), 600);
});

// Add ripple keyframes dynamically
const style = document.createElement('style');
style.textContent = `
    @keyframes rippleEffect {
        to {
            transform: translate(-50%, -50%) scale(20);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

// Console welcome message
console.log('%c🏬 Amria Mall Website', 'font-size: 24px; color: #E86F25; font-weight: bold;');
console.log('%cDeveloped by Amria Mall Programmers - مصطفى علاء', 'font-size: 14px; color: #F9A825;');
