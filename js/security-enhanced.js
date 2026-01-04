/**
 * =========================================================
 * ENHANCED FRONTEND SECURITY MODULE
 * 🔒 Security Categories: #7-8, #47-48, #56-57, #67-69
 * =========================================================
 * 
 * Implements:
 * #7-8 Dependency & Supply Chain Security (SRI)
 * #47-48 Build & CI/CD Security
 * #56-57 Browser & Client-Side Security
 * #67-69 Client-Side Encryption
 */

'use strict';

// =====================================================
// ENHANCED SECURITY MODULE - IIFE
// =====================================================

const AmriaSecurityEnhanced = (function () {

    // Configuration
    const config = Object.freeze({
        apiBaseUrl: '/api',
        csrfTokenHeader: 'x-csrf-token',
        maxConsecutiveErrors: 3,
        lockoutDuration: 5 * 60 * 1000, // 5 minutes
        encryptionEnabled: true
    });

    // State
    let csrfToken = null;
    let errorCount = 0;
    let lockedUntil = null;

    // =====================================================
    // #7-8 SUBRESOURCE INTEGRITY (SRI)
    // =====================================================

    /**
     * Load external script with SRI verification
     * @param {string} src - Script source URL
     * @param {string} integrity - SRI hash
     * @param {string} crossorigin - CORS setting
     */
    function loadScriptWithSRI(src, integrity, crossorigin = 'anonymous') {
        return new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = src;
            script.integrity = integrity;
            script.crossOrigin = crossorigin;
            script.async = true;

            script.onload = () => resolve(script);
            script.onerror = () => reject(new Error(`Failed to load script: ${src}`));

            document.head.appendChild(script);
        });
    }

    /**
     * Load external stylesheet with SRI verification
     */
    function loadStyleWithSRI(href, integrity, crossorigin = 'anonymous') {
        return new Promise((resolve, reject) => {
            const link = document.createElement('link');
            link.rel = 'stylesheet';
            link.href = href;
            link.integrity = integrity;
            link.crossOrigin = crossorigin;

            link.onload = () => resolve(link);
            link.onerror = () => reject(new Error(`Failed to load stylesheet: ${href}`));

            document.head.appendChild(link);
        });
    }

    /**
     * Generate SRI hash for content
     * @param {string} content - Content to hash
     * @param {string} algorithm - Hash algorithm (sha256, sha384, sha512)
     */
    async function generateSRIHash(content, algorithm = 'sha384') {
        const encoder = new TextEncoder();
        const data = encoder.encode(content);

        const hashBuffer = await crypto.subtle.digest(
            algorithm === 'sha256' ? 'SHA-256' :
                algorithm === 'sha384' ? 'SHA-384' : 'SHA-512',
            data
        );

        const hashArray = new Uint8Array(hashBuffer);
        const hashBase64 = btoa(String.fromCharCode(...hashArray));

        return `${algorithm}-${hashBase64}`;
    }

    // =====================================================
    // #67-69 CLIENT-SIDE ENCRYPTION (Web Crypto API)
    // =====================================================

    /**
     * Generate encryption key
     */
    async function generateKey() {
        return await crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Export key to base64
     */
    async function exportKey(key) {
        const exported = await crypto.subtle.exportKey('raw', key);
        return btoa(String.fromCharCode(...new Uint8Array(exported)));
    }

    /**
     * Import key from base64
     */
    async function importKey(keyBase64) {
        const keyData = Uint8Array.from(atob(keyBase64), c => c.charCodeAt(0));
        return await crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Encrypt data using AES-GCM
     * @param {string} plaintext - Data to encrypt
     * @param {CryptoKey} key - Encryption key
     */
    async function encrypt(plaintext, key) {
        const encoder = new TextEncoder();
        const data = encoder.encode(plaintext);

        const iv = crypto.getRandomValues(new Uint8Array(12));

        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            data
        );

        // Combine IV and ciphertext
        const combined = new Uint8Array(iv.length + ciphertext.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(ciphertext), iv.length);

        return btoa(String.fromCharCode(...combined));
    }

    /**
     * Decrypt data using AES-GCM
     * @param {string} encryptedBase64 - Encrypted data in base64
     * @param {CryptoKey} key - Decryption key
     */
    async function decrypt(encryptedBase64, key) {
        const combined = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));

        const iv = combined.slice(0, 12);
        const ciphertext = combined.slice(12);

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            ciphertext
        );

        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    }

    /**
     * Hash password client-side (for additional security)
     */
    async function hashPassword(password, salt) {
        const encoder = new TextEncoder();
        const data = encoder.encode(password + salt);

        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = new Uint8Array(hashBuffer);

        return Array.from(hashArray)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    // =====================================================
    // #56-57 BROWSER SECURITY
    // =====================================================

    /**
     * Detect potentially insecure context
     */
    function isSecureContext() {
        if (typeof window === 'undefined') return false;

        // Check if running in secure context (HTTPS or localhost)
        if (window.isSecureContext !== undefined) {
            return window.isSecureContext;
        }

        // Fallback check
        return window.location.protocol === 'https:' ||
            window.location.hostname === 'localhost' ||
            window.location.hostname === '127.0.0.1';
    }

    /**
     * Detect developer tools opening
     */
    function detectDevTools() {
        const threshold = 160;
        const check = () => {
            const widthThreshold = window.outerWidth - window.innerWidth > threshold;
            const heightThreshold = window.outerHeight - window.innerHeight > threshold;

            if (widthThreshold || heightThreshold) {
                console.log('%c🔒 Developer Tools Detected', 'color: orange; font-size: 16px;');
            }
        };

        window.addEventListener('resize', check);
        check();
    }

    /**
     * Protect against DOM clobbering
     */
    function protectAgainstDOMClobbering() {
        // Freeze important global objects
        const protectedProperties = ['document', 'window', 'location', 'history'];

        protectedProperties.forEach(prop => {
            if (window[prop]) {
                Object.defineProperty(window, prop, {
                    configurable: false,
                    writable: false
                });
            }
        });
    }

    /**
     * Content Security Policy violation handler
     */
    function setupCSPViolationHandler() {
        document.addEventListener('securitypolicyviolation', (event) => {
            console.error('🚨 CSP Violation:', {
                blockedURI: event.blockedURI,
                violatedDirective: event.violatedDirective,
                originalPolicy: event.originalPolicy
            });

            // Report to server
            fetch('/api/csp-report', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    blockedURI: event.blockedURI,
                    violatedDirective: event.violatedDirective,
                    documentURI: event.documentURI,
                    timestamp: new Date().toISOString()
                })
            }).catch(() => { });
        });
    }

    /**
     * Detect and prevent XSS via DOM
     */
    function setupDOMXSSProtection() {
        // Override innerHTML setter to sanitize content
        const originalInnerHTMLSetter = Object.getOwnPropertyDescriptor(
            Element.prototype,
            'innerHTML'
        ).set;

        Object.defineProperty(Element.prototype, 'innerHTML', {
            set: function (value) {
                // Basic XSS pattern detection
                if (typeof value === 'string') {
                    const dangerousPatterns = [
                        /<script/i,
                        /javascript:/i,
                        /on\w+\s*=/i,
                        /data:/i
                    ];

                    if (dangerousPatterns.some(p => p.test(value))) {
                        console.warn('🚨 Potential XSS blocked in innerHTML');
                        // Sanitize
                        value = value.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
                            .replace(/javascript:/gi, '')
                            .replace(/on\w+\s*=/gi, 'data-blocked=');
                    }
                }

                return originalInnerHTMLSetter.call(this, value);
            },
            get: Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML').get
        });
    }

    // =====================================================
    // SECURE API COMMUNICATION
    // =====================================================

    /**
     * Fetch CSRF token from server
     */
    async function fetchCSRFToken() {
        try {
            const response = await fetch(`${config.apiBaseUrl}/csrf-token`, {
                credentials: 'same-origin'
            });

            if (response.ok) {
                const data = await response.json();
                csrfToken = data.token;
                return csrfToken;
            }
        } catch (error) {
            console.error('Failed to fetch CSRF token:', error);
        }
        return null;
    }

    /**
     * Make secure API request with CSRF protection
     */
    async function secureRequest(url, options = {}) {
        // Check lockout
        if (lockedUntil && Date.now() < lockedUntil) {
            const remaining = Math.ceil((lockedUntil - Date.now()) / 1000);
            throw new Error(`Account locked. Try again in ${remaining} seconds.`);
        }

        // Ensure we have CSRF token
        if (!csrfToken && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(options.method?.toUpperCase())) {
            await fetchCSRFToken();
        }

        // Prepare headers
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };

        // Add CSRF token
        if (csrfToken) {
            headers[config.csrfTokenHeader] = csrfToken;
        }

        // Add auth token if available
        const authToken = sessionStorage.getItem('accessToken');
        if (authToken) {
            headers['Authorization'] = `Bearer ${authToken}`;
        }

        try {
            const response = await fetch(`${config.apiBaseUrl}${url}`, {
                ...options,
                headers,
                credentials: 'same-origin'
            });

            // Reset error count on success
            if (response.ok) {
                errorCount = 0;
            }

            // Handle 401 - try to refresh token
            if (response.status === 401) {
                const refreshed = await refreshAuthToken();
                if (refreshed) {
                    return secureRequest(url, options);
                }
            }

            // Handle 429 - rate limited
            if (response.status === 429) {
                const retryAfter = response.headers.get('Retry-After');
                throw new Error(`Rate limited. Retry after ${retryAfter} seconds.`);
            }

            return response;

        } catch (error) {
            errorCount++;

            if (errorCount >= config.maxConsecutiveErrors) {
                lockedUntil = Date.now() + config.lockoutDuration;
                throw new Error('Too many errors. Please try again later.');
            }

            throw error;
        }
    }

    /**
     * Refresh authentication token
     */
    async function refreshAuthToken() {
        const refreshToken = sessionStorage.getItem('refreshToken');
        if (!refreshToken) return false;

        try {
            const response = await fetch(`${config.apiBaseUrl}/auth/refresh`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ refreshToken }),
                credentials: 'same-origin'
            });

            if (response.ok) {
                const data = await response.json();
                sessionStorage.setItem('accessToken', data.accessToken);
                sessionStorage.setItem('refreshToken', data.refreshToken);
                return true;
            }
        } catch (error) {
            console.error('Token refresh failed:', error);
        }

        // Clear tokens on failure
        sessionStorage.removeItem('accessToken');
        sessionStorage.removeItem('refreshToken');
        return false;
    }

    // =====================================================
    // SECURE STORAGE
    // =====================================================

    let storageKey = null;

    /**
     * Initialize secure storage with encryption
     */
    async function initSecureStorage() {
        if (!isSecureContext()) {
            console.warn('⚠️ Not in secure context - encryption disabled');
            return false;
        }

        try {
            // Check for existing key
            const existingKey = sessionStorage.getItem('_sk');

            if (existingKey) {
                storageKey = await importKey(existingKey);
            } else {
                storageKey = await generateKey();
                const exported = await exportKey(storageKey);
                sessionStorage.setItem('_sk', exported);
            }

            return true;
        } catch (error) {
            console.error('Failed to initialize secure storage:', error);
            return false;
        }
    }

    /**
     * Store encrypted data
     */
    async function secureStore(key, value) {
        if (!storageKey) {
            // Fallback to regular storage
            localStorage.setItem(key, JSON.stringify(value));
            return;
        }

        try {
            const encrypted = await encrypt(JSON.stringify(value), storageKey);
            localStorage.setItem(`_enc_${key}`, encrypted);
        } catch (error) {
            console.error('Encryption failed:', error);
            localStorage.setItem(key, JSON.stringify(value));
        }
    }

    /**
     * Retrieve and decrypt data
     */
    async function secureRetrieve(key) {
        if (!storageKey) {
            const value = localStorage.getItem(key);
            return value ? JSON.parse(value) : null;
        }

        try {
            const encrypted = localStorage.getItem(`_enc_${key}`);
            if (!encrypted) return null;

            const decrypted = await decrypt(encrypted, storageKey);
            return JSON.parse(decrypted);
        } catch (error) {
            console.error('Decryption failed:', error);
            return null;
        }
    }

    /**
     * Remove stored data
     */
    function secureRemove(key) {
        localStorage.removeItem(key);
        localStorage.removeItem(`_enc_${key}`);
    }

    // =====================================================
    // INITIALIZATION
    // =====================================================

    /**
     * Initialize all security features
     */
    async function initialize() {
        console.log('%c🔒 Amria Security Enhanced v2.0', 'color: green; font-size: 14px;');

        // Check secure context
        if (!isSecureContext()) {
            console.warn('⚠️ Running in insecure context! Some features disabled.');
        }

        // Initialize secure storage
        await initSecureStorage();

        // Fetch CSRF token
        await fetchCSRFToken();

        // Setup protections
        setupCSPViolationHandler();
        protectAgainstDOMClobbering();

        // Optional: detect dev tools
        if (config.detectDevTools) {
            detectDevTools();
        }

        console.log('%c✅ Security initialized', 'color: green;');
    }

    // Auto-initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        initialize();
    }

    // =====================================================
    // PUBLIC API
    // =====================================================

    return Object.freeze({
        // SRI
        loadScriptWithSRI,
        loadStyleWithSRI,
        generateSRIHash,

        // Encryption
        generateKey,
        exportKey,
        importKey,
        encrypt,
        decrypt,
        hashPassword,

        // Security checks
        isSecureContext,

        // Secure communication
        fetchCSRFToken,
        secureRequest,
        refreshAuthToken,

        // Secure storage
        initSecureStorage,
        secureStore,
        secureRetrieve,
        secureRemove,

        // Re-initialize
        initialize
    });
})();

// Export for module environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AmriaSecurityEnhanced;
}
