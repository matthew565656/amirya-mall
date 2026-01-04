/* =============================================
   Amria Mall - Interactive JavaScript
   Mouse effects, animations, and interactions
   ============================================= */

document.addEventListener('DOMContentLoaded', () => {
    // Initialize all components
    initMouseFollower();
    initParticles();
    initScrollAnimations();
    initMobileMenu();
    initHeaderScroll();
    initSmoothScroll();
    initCardHoverEffects();
});

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
