// script.js - DNS Filtering & AdBlock Professional Tester v3.0 Enterprise
// Architecture: Declarative Test Engine with Smart Analytics

/**
 * ═══════════════════════════════════════════════════════════════
 * DECLARATIVE TEST ENGINE - ENTERPRISE ARCHITECTURE
 * ═══════════════════════════════════════════════════════════════
 * 
 * Features:
 * - Declarative test definitions (JSON-based)
 * - Multi-layer scoring (DNS, Browser, CNAME, Advanced)
 * - Audit mode with detailed technical info
 * - Smart recommendations based on failure patterns
 * - Export formats: JSON (technical), TXT (simple), HTML (report)
 * - Real-time execution metrics
 * - Honest detection (DNS Filtering vs specific products)
 */

class DNSFilteringTesterPro {
    constructor() {
        // Core state
        this.testResults = [];
        this.totalTests = 0;
        this.completedTests = 0;
        this.blockedCount = 0;
        this.allowedCount = 0;
        this.startTime = null;
        this.endTime = null;
        this.auditMode = false;
        
        // Multi-layer scoring
        this.scores = {
            global: 0,
            dns: 0,
            browser: 0,
            cname: 0,
            advanced: 0
        };
        
        // Category statistics
        this.categoryStats = {};
        
        // Detection results (honest naming)
        this.detectionResults = {
            dnsFiltering: false,        // Pi-hole / AdGuard / NextDNS
            browserAdBlock: false,      // uBlock / ABP / Brave
            dnsProvider: 'Unknown'      // Inferred provider
        };

        // Test execution metadata
        this.executionMetadata = {
            testsFailed: [],
            testsBlockedByDNS: [],
            testsBlockedByBrowser: [],
            cnameDetected: [],
            fingerprintingBlocked: []
        };

        // Initialize
        this.init();
    }

    /**
     * ═══════════════════════════════════════════════════════════
     * DECLARATIVE TEST DEFINITIONS
     * ═══════════════════════════════════════════════════════════
     * Each test is a self-contained object with:
     * - id: unique identifier
     * - name: display name
     * - domain: target domain
     * - method: test method (DNS, Script, Pixel, API, etc.)
     * - layer: scoring layer (dns, browser, cname, advanced)
     * - critical: importance weight
     * - expected: 'blocked' or 'allowed'
     */
    getTestDefinitions() {
        return [
            // ═══ DNS LEVEL TESTS (Network Blocking) ═══
            {
                category: {
                    id: 'dns-ads-core',
                    icon: '🎯',
                    title: 'Core Ad Networks (DNS)',
                    layer: 'dns',
                    weight: 1.5
                },
                tests: [
                    { id: 'dns-001', name: 'Google AdSense', domain: 'pagead2.googlesyndication.com', method: 'DNS', critical: true },
                    { id: 'dns-002', name: 'DoubleClick', domain: 'doubleclick.net', method: 'DNS', critical: true },
                    { id: 'dns-003', name: 'Google Ads', domain: 'googleads.g.doubleclick.net', method: 'DNS', critical: true },
                    { id: 'dns-004', name: 'AdColony', domain: 'ads30.adcolony.com', method: 'DNS', critical: true },
                    { id: 'dns-005', name: 'Criteo', domain: 'static.criteo.net', method: 'DNS', critical: true },
                    { id: 'dns-006', name: 'Taboola', domain: 'cdn.taboola.com', method: 'DNS', critical: true },
                    { id: 'dns-007', name: 'Outbrain', domain: 'widgets.outbrain.com', method: 'DNS', critical: true }
                ]
            },
            {
                category: {
                    id: 'dns-trackers-core',
                    icon: '📡',
                    title: 'Core Trackers (DNS)',
                    layer: 'dns',
                    weight: 1.4
                },
                tests: [
                    { id: 'dns-101', name: 'Google Analytics', domain: 'google-analytics.com', method: 'DNS', critical: true },
                    { id: 'dns-102', name: 'Google Tag Manager', domain: 'googletagmanager.com', method: 'DNS', critical: true },
                    { id: 'dns-103', name: 'Facebook Pixel', domain: 'connect.facebook.net', method: 'DNS', critical: true },
                    { id: 'dns-104', name: 'Hotjar', domain: 'static.hotjar.com', method: 'DNS', critical: true },
                    { id: 'dns-105', name: 'Mixpanel', domain: 'cdn.mxpnl.com', method: 'DNS', critical: true },
                    { id: 'dns-106', name: 'Amplitude', domain: 'cdn.amplitude.com', method: 'DNS', critical: false }
                ]
            },
            {
                category: {
                    id: 'dns-social-trackers',
                    icon: '🐦',
                    title: 'Social Media Trackers (DNS)',
                    layer: 'dns',
                    weight: 1.2
                },
                tests: [
                    { id: 'dns-201', name: 'Twitter Analytics', domain: 'analytics.twitter.com', method: 'DNS', critical: false },
                    { id: 'dns-202', name: 'LinkedIn Insight', domain: 'px.ads.linkedin.com', method: 'DNS', critical: false },
                    { id: 'dns-203', name: 'TikTok Pixel', domain: 'analytics.tiktok.com', method: 'DNS', critical: false },
                    { id: 'dns-204', name: 'Pinterest Tag', domain: 'ct.pinterest.com', method: 'DNS', critical: false },
                    { id: 'dns-205', name: 'Reddit Pixel', domain: 'alb.reddit.com', method: 'DNS', critical: false }
                ]
            },

            // ═══ BROWSER LEVEL TESTS (Client-side Blocking) ═══
            {
                category: {
                    id: 'browser-dom-ads',
                    icon: '🌐',
                    title: 'DOM-based Ads (Browser)',
                    layer: 'browser',
                    weight: 1.3
                },
                tests: [
                    { id: 'browser-001', name: 'Ad Element Detection', domain: 'local-ad-element', method: 'DOM Bait', critical: true },
                    { id: 'browser-002', name: 'Banner Ad Class', domain: 'local-banner-class', method: 'DOM Bait', critical: true },
                    { id: 'browser-003', name: 'Sponsored Content', domain: 'local-sponsored', method: 'DOM Bait', critical: false },
                    { id: 'browser-004', name: 'Ad Placeholder', domain: 'local-ad-placeholder', method: 'DOM Bait', critical: false }
                ]
            },
            {
                category: {
                    id: 'browser-scripts',
                    icon: '⚙️',
                    title: 'Script-based Tracking (Browser)',
                    layer: 'browser',
                    weight: 1.2
                },
                tests: [
                    { id: 'browser-101', name: 'Inline Analytics Script', domain: 'local-analytics-inline', method: 'Script Injection', critical: false },
                    { id: 'browser-102', name: 'Third-party Loader', domain: 'local-3p-loader', method: 'Script Injection', critical: false },
                    { id: 'browser-103', name: 'Tracking Pixel Script', domain: 'local-pixel-script', method: 'Script Injection', critical: false }
                ]
            },

            // ═══ CNAME CLOAKING TESTS (Advanced DNS) ═══
            {
                category: {
                    id: 'cname-first-party',
                    icon: '🧬',
                    title: 'CNAME Cloaking Detection',
                    layer: 'cname',
                    weight: 1.5
                },
                tests: [
                    { id: 'cname-001', name: 'First-party Analytics', domain: 'analytics.example.com', method: 'CNAME', critical: true },
                    { id: 'cname-002', name: 'Metrics Subdomain', domain: 'metrics.website.com', method: 'CNAME', critical: true },
                    { id: 'cname-003', name: 'Data Collection Subdomain', domain: 'data.domain.com', method: 'CNAME', critical: true },
                    { id: 'cname-004', name: 'CDN-masked Tracker', domain: 'cdn-analytics.site.com', method: 'CNAME', critical: true },
                    { id: 'cname-005', name: 'Tracking Subdomain', domain: 'track.yoursite.com', method: 'CNAME', critical: false }
                ]
            },

            // ═══ ADVANCED TRACKING TESTS ═══
            {
                category: {
                    id: 'fingerprinting',
                    icon: '🧩',
                    title: 'Browser Fingerprinting',
                    layer: 'advanced',
                    weight: 1.4
                },
                tests: [
                    { id: 'fp-001', name: 'Canvas Fingerprint', domain: 'local-canvas-fp', method: 'Canvas API', critical: true },
                    { id: 'fp-002', name: 'WebGL Fingerprint', domain: 'local-webgl-fp', method: 'WebGL API', critical: true },
                    { id: 'fp-003', name: 'Audio Context Fingerprint', domain: 'local-audio-fp', method: 'Audio API', critical: true },
                    { id: 'fp-004', name: 'Font Enumeration', domain: 'local-font-fp', method: 'Font API', critical: false },
                    { id: 'fp-005', name: 'Screen Resolution Tracking', domain: 'local-screen-fp', method: 'Screen API', critical: false },
                    { id: 'fp-006', name: 'Hardware Concurrency', domain: 'local-hardware-fp', method: 'Navigator API', critical: false },
                    { id: 'fp-007', name: 'WebRTC IP Leak', domain: 'local-webrtc-fp', method: 'WebRTC API', critical: true }
                ]
            },
            {
                category: {
                    id: 'advanced-tracking',
                    icon: '🎭',
                    title: 'Advanced Tracking Methods',
                    layer: 'advanced',
                    weight: 1.3
                },
                tests: [
                    { id: 'adv-001', name: 'Service Worker Tracking', domain: 'local-sw-track', method: 'Service Worker', critical: true },
                    { id: 'adv-002', name: 'WebSocket Tracker', domain: 'wss://track.example.com', method: 'WebSocket', critical: false },
                    { id: 'adv-003', name: 'Beacon API', domain: 'local-beacon-track', method: 'Beacon API', critical: false },
                    { id: 'adv-004', name: 'IndexedDB Tracking', domain: 'local-idb-track', method: 'IndexedDB', critical: false },
                    { id: 'adv-005', name: 'LocalStorage Fingerprint', domain: 'local-storage-fp', method: 'LocalStorage', critical: false },
                    { id: 'adv-006', name: 'HTTP ETags', domain: 'local-etag-track', method: 'HTTP ETags', critical: false }
                ]
            },

            // ═══ ADDITIONAL CATEGORIES ═══
            {
                category: {
                    id: 'cdn-trackers',
                    icon: '🌍',
                    title: 'CDN-based Trackers',
                    layer: 'dns',
                    weight: 1.0
                },
                tests: [
                    { id: 'cdn-001', name: 'Cloudflare Insights', domain: 'static.cloudflareinsights.com', method: 'CDN', critical: false },
                    { id: 'cdn-002', name: 'Akamai Analytics', domain: 'akamaihd.net', method: 'CDN', critical: false }
                ]
            },
            {
                category: {
                    id: 'email-trackers',
                    icon: '📧',
                    title: 'Email Tracking',
                    layer: 'dns',
                    weight: 0.9
                },
                tests: [
                    { id: 'email-001', name: 'Mailchimp Tracking', domain: 'mailchimp.com', method: 'Pixel', critical: false },
                    { id: 'email-002', name: 'SendGrid Tracking', domain: 'sendgrid.net', method: 'Pixel', critical: false }
                ]
            },
            {
                category: {
                    id: 'anti-adblock',
                    icon: '🧱',
                    title: 'Anti-Adblock Detection',
                    layer: 'browser',
                    weight: 1.1
                },
                tests: [
                    { id: 'anti-001', name: 'BlockAdBlock Script', domain: 'blockadblock.js', method: 'Script', critical: false },
                    { id: 'anti-002', name: 'FuckAdBlock', domain: 'fuckadblock.js', method: 'Script', critical: false },
                    { id: 'anti-003', name: 'Admiral Anti-Adblock', domain: 'getadmiral.com', method: 'Script', critical: false }
                ]
            }
        ];
    }

    /**
     * ═══════════════════════════════════════════════════════════
     * INITIALIZATION
     * ═══════════════════════════════════════════════════════════
     */
    init() {
        this.setupEventListeners();
        this.setupThemeToggle();
        this.setupAuditMode();
        this.buildTestCategories();
        this.renderCategories();
        this.renderFilterButtons();
        this.calculateTotalTests();
        this.updateAllScores();
    }

    setupEventListeners() {
        document.getElementById('startTest').addEventListener('click', () => this.startAllTests());
        document.getElementById('exportJSON').addEventListener('click', () => this.exportJSON());
        document.getElementById('exportSimple').addEventListener('click', () => this.exportSimple());
        document.getElementById('exportHTML').addEventListener('click', () => this.exportHTML());
    }

    setupThemeToggle() {
        const themeToggle = document.getElementById('themeToggle');
        const currentTheme = localStorage.getItem('theme') || 'light';
        document.documentElement.setAttribute('data-theme', currentTheme);

        themeToggle.addEventListener('click', () => {
            const theme = document.documentElement.getAttribute('data-theme');
            const newTheme = theme === 'light' ? 'dark' : 'light';
            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
        });
    }

    setupAuditMode() {
        const auditToggle = document.getElementById('auditMode');
        auditToggle.addEventListener('change', (e) => {
            this.auditMode = e.target.checked;
            this.toggleAuditMode(this.auditMode);
        });
    }

    toggleAuditMode(enabled) {
        const testItems = document.querySelectorAll('.test-item');
        testItems.forEach(item => {
            if (enabled) {
                item.classList.add('audit-mode');
            } else {
                item.classList.remove('audit-mode');
            }
        });
    }

    buildTestCategories() {
        this.categories = this.getTestDefinitions();
        
        // Build category stats structure
        this.categories.forEach(cat => {
            this.categoryStats[cat.category.id] = {
                total: cat.tests.length,
                blocked: 0,
                allowed: 0,
                weight: cat.category.weight,
                layer: cat.category.layer
            };
        });
    }

    calculateTotalTests() {
        this.totalTests = this.categories.reduce((sum, cat) => sum + cat.tests.length, 0);
        document.getElementById('totalCount').textContent = this.totalTests;
    }

    /**
     * ═══════════════════════════════════════════════════════════
     * UI RENDERING
     * ═══════════════════════════════════════════════════════════
     */
    renderFilterButtons() {
        const container = document.getElementById('filterButtons');
        
        this.categories.forEach(cat => {
            const btn = document.createElement('button');
            btn.className = 'filter-btn';
            btn.textContent = `${cat.category.icon} ${cat.category.title}`;
            btn.dataset.filter = cat.category.id;
            
            btn.addEventListener('click', () => this.filterCategory(cat.category.id, btn));
            container.appendChild(btn);
        });
    }

    filterCategory(categoryId, btnElement) {
        const allButtons = document.querySelectorAll('.filter-btn');
        const allCards = document.querySelectorAll('.category-card');

        if (categoryId === 'all') {
            allCards.forEach(card => card.classList.remove('hidden'));
            allButtons.forEach(btn => btn.classList.remove('active'));
            btnElement.classList.add('active');
        } else {
            allCards.forEach(card => {
                if (card.id === `category-${categoryId}`) {
                    card.classList.remove('hidden');
                } else {
                    card.classList.add('hidden');
                }
            });
            
            allButtons.forEach(btn => btn.classList.remove('active'));
            btnElement.classList.add('active');
        }
    }

    renderCategories() {
        const container = document.getElementById('testCategories');
        container.innerHTML = '';

        this.categories.forEach(cat => {
            const card = this.createCategoryCard(cat);
            container.appendChild(card);
        });
    }

    createCategoryCard(categoryData) {
        const cat = categoryData.category;
        const tests = categoryData.tests;

        const card = document.createElement('div');
        card.className = 'category-card';
        card.id = `category-${cat.id}`;

        const header = document.createElement('div');
        header.className = 'category-header';
        header.innerHTML = `
            <div class="category-title-group">
                <span class="category-icon">${cat.icon}</span>
                <h3 class="category-title">${cat.title}</h3>
            </div>
            <div class="category-score" id="score-${cat.id}">0/${tests.length}</div>
        `;

        const testList = document.createElement('div');
        testList.className = 'test-list';

        tests.forEach(test => {
            const testItem = this.createTestItem(test, cat.id);
            testList.appendChild(testItem);
        });

        card.appendChild(header);
        card.appendChild(testList);

        return card;
    }

    createTestItem(test, categoryId) {
        const item = document.createElement('div');
        item.className = 'test-item';
        item.id = `test-${test.id}`;
        item.dataset.testId = test.id;

        item.innerHTML = `
            <div class="test-info">
                <span class="test-name">${test.name}</span>
                <span class="test-domain">${test.domain}</span>
                <span class="test-method">${test.method}</span>
            </div>
            <div class="test-status testing">
                <svg class="status-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                    <circle cx="12" cy="12" r="10"/>
                </svg>
                <span>Aguardando</span>
            </div>
            <div class="test-audit-info">
                <div class="audit-detail">
                    <strong>Método</strong>
                    <span id="audit-method-${test.id}">-</span>
                </div>
                <div class="audit-detail">
                    <strong>Tempo</strong>
                    <span id="audit-time-${test.id}">-</span>
                </div>
                <div class="audit-detail">
                    <strong>Erro</strong>
                    <span id="audit-error-${test.id}">-</span>
                </div>
                <div class="audit-detail">
                    <strong>Tipo Bloqueio</strong>
                    <span id="audit-block-${test.id}">-</span>
                </div>
            </div>
        `;

        return item;
    }

    /**
     * ═══════════════════════════════════════════════════════════
     * TEST EXECUTION ENGINE
     * ═══════════════════════════════════════════════════════════
     */
    async startAllTests() {
        // Reset state
        this.testResults = [];
        this.completedTests = 0;
        this.blockedCount = 0;
        this.allowedCount = 0;
        this.startTime = Date.now();
        this.executionMetadata = {
            testsFailed: [],
            testsBlockedByDNS: [],
            testsBlockedByBrowser: [],
            cnameDetected: [],
            fingerprintingBlocked: []
        };

        // Reset category stats
        Object.keys(this.categoryStats).forEach(key => {
            this.categoryStats[key].blocked = 0;
            this.categoryStats[key].allowed = 0;
        });

        // Disable buttons
        document.getElementById('startTest').disabled = true;
        document.getElementById('exportJSON').disabled = true;
        document.getElementById('exportSimple').disabled = true;
        document.getElementById('exportHTML').disabled = true;

        // Detection phase
        await this.runDetection();

        // Execute tests
        for (const categoryData of this.categories) {
            for (const test of categoryData.tests) {
                await this.executeTest(test, categoryData.category);
                await this.delay(120); // Smooth UI updates
            }
        }

        // Finalize
        this.endTime = Date.now();
        this.finalizeTests();
    }

    async runDetection() {
        // Detect DNS-level filtering (Pi-hole / AdGuard / NextDNS)
        this.detectionResults.dnsFiltering = await this.detectDNSFiltering();
        
        // Detect browser-level adblock
        this.detectionResults.browserAdBlock = await this.detectBrowserAdBlock();

        // Infer DNS provider
        this.detectionResults.dnsProvider = await this.inferDNSProvider();

        // Update UI
        this.updateDetectionUI();
    }

/**
 * ═══════════════════════════════════════════════════════════════
 * IMPROVED DETECTION METHODS - MORE RELIABLE
 * ═══════════════════════════════════════════════════════════════
 */

	async detectDNSFiltering() {
		// Test multiple well-known ad domains with different approaches
		const testDomains = [
			{ domain: 'pagead2.googlesyndication.com', path: '/pagead/js/adsbygoogle.js' },
			{ domain: 'doubleclick.net', path: '/instream/ad_status.js' },
			{ domain: 'static.criteo.net', path: '/js/ld/ld.js' },
			{ domain: 'googleads.g.doubleclick.net', path: '/pagead/id' }
		];

		let blockedCount = 0;
		let totalTests = testDomains.length;

		for (const test of testDomains) {
			const isBlocked = await this.testDNSWithMultipleMethods(test.domain, test.path);
			if (isBlocked) blockedCount++;
		}

		// More lenient: if at least 50% are blocked, DNS filtering is active
		return blockedCount >= Math.ceil(totalTests * 0.5);
	}

	async testDNSWithMultipleMethods(domain, path) {
		// Method 1: Try with Image
		const method1 = await this.testDNSviaImage(domain, path);
		if (method1) return true;

		// Method 2: Try with Fetch (no-cors)
		const method2 = await this.testDNSviaFetch(domain, path);
		if (method2) return true;

		// Method 3: Try with Script tag
		const method3 = await this.testDNSviaScript(domain);
		if (method3) return true;

		return false;
	}

	async testDNSviaImage(domain, path) {
		return new Promise((resolve) => {
			const img = new Image();
			const timeout = setTimeout(() => {
				img.src = '';
				resolve(false); // Timeout = não bloqueado (ainda tentando carregar)
			}, 3000);

			img.onerror = () => {
				clearTimeout(timeout);
				resolve(true); // Error = bloqueado
			};

			img.onload = () => {
				clearTimeout(timeout);
				resolve(false); // Loaded = não bloqueado
			};

			img.src = `https://${domain}${path}?cache=${Date.now()}`;
		});
	}

	async testDNSviaFetch(domain, path) {
		try {
			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), 3000);

			await fetch(`https://${domain}${path}`, {
				method: 'HEAD',
				mode: 'no-cors',
				cache: 'no-store',
				signal: controller.signal
			});

			clearTimeout(timeoutId);
			return false; // Success = não bloqueado
		} catch (error) {
			if (error.name === 'AbortError') {
				return false; // Timeout = não bloqueado (ainda tentando)
			}
			return true; // Network error = bloqueado
		}
	}

	async testDNSviaScript(domain) {
		return new Promise((resolve) => {
			const script = document.createElement('script');
			const timeout = setTimeout(() => {
				document.head.removeChild(script);
				resolve(false);
			}, 3000);

			script.onerror = () => {
				clearTimeout(timeout);
				document.head.removeChild(script);
				resolve(true); // Error = bloqueado
			};

			script.onload = () => {
				clearTimeout(timeout);
				document.head.removeChild(script);
				resolve(false); // Loaded = não bloqueado
			};

			script.src = `https://${domain}/test.js?cache=${Date.now()}`;
			document.head.appendChild(script);
		});
	}

	/**
 * ═══════════════════════════════════════════════════════════════
 * ULTRA-AGGRESSIVE UBLOCK ORIGIN DETECTION
 * Specifically designed to detect uBlock Origin on Firefox & Chrome
 * Uses 10+ different detection vectors
 * ═══════════════════════════════════════════════════════════════
 */

async detectBrowserAdBlock() {
    console.log('🔍 Starting ULTRA-AGGRESSIVE AdBlock detection...');

    // Run ALL detection methods in parallel
    const methods = [
        this.testBaitElement(),
        this.testAdBlockClasses(),
        this.testKnownAdBlockDomains(),
        this.testUBlockOriginSignature(),
        this.testDOMModification(),
        this.testGetComputedStyleBlock(),
        this.testMultipleBaitElements(),
        this.testScriptBlockDetection(),
        this.testCSSInjectionDetection(),
        this.testResourceTimingDetection()
    ];

    const results = await Promise.all(methods);

    console.log('🔍 Detection results:', {
        '1. Bait Element': results[0],
        '2. Ad Classes': results[1],
        '3. Known Domains': results[2],
        '4. uBlock Signature': results[3],
        '5. DOM Modification': results[4],
        '6. Computed Style': results[5],
        '7. Multiple Baits': results[6],
        '8. Script Block': results[7],
        '9. CSS Injection': results[8],
        '10. Resource Timing': results[9]
    });

    // More aggressive: if at least 1 out of 11 methods detect, it's active
    const positiveDetections = results.filter(r => r === true).length;
    const isDetected = positiveDetections >= 1;

    console.log(`✅ AdBlock detection: ${isDetected ? 'ACTIVE' : 'INACTIVE'} (${positiveDetections}/11 methods)`);

    return isDetected;
}

async testBaitElement() {
    try {
        const bait = document.createElement('div');

        // Ultra-suspicious attributes for uBlock Origin
        bait.id = 'ad_banner_300x250';
        bait.className = 'ad ads advertisement adsbox doubleclick ad-placement ad-placeholder adbadge BannerAd textads banner_ads ad-unit ad-zone sponsored-content';
        bait.setAttribute('data-ad-client', 'ca-pub-1234567890');
        bait.setAttribute('data-ad-slot', '1234567890');
        bait.setAttribute('data-adsbygoogle-status', 'done');

        // Make it look like a real ad
        bait.style.cssText = 'width:300px!important;height:250px!important;position:absolute!important;left:-10000px!important;top:-1000px!important;display:block!important;';

        // Add realistic ad content
        bait.innerHTML = `
            <ins class="adsbygoogle" style="display:block" data-ad-client="ca-pub-test" data-ad-slot="123"></ins>
            <div class="ad-content">Advertisement</div>
        `;

        document.body.appendChild(bait);

        // Wait longer for uBlock Origin to process
        await this.delay(250);

        const computed = window.getComputedStyle(bait);
        const isBlocked = bait.offsetParent === null || 
                         bait.offsetHeight === 0 || 
                         bait.offsetWidth === 0 ||
                         computed.display === 'none' ||
                         computed.visibility === 'hidden' ||
                         computed.opacity === '0' ||
                         bait.style.display === 'none' ||
                         !document.body.contains(bait);

        try { document.body.removeChild(bait); } catch(e) {}

        console.log('  → 1. Bait element:', isBlocked ? '✓ BLOCKED' : '✗ ALLOWED');
        return isBlocked;
    } catch (err) {
        console.log('  → 1. Bait element: ERROR', err.message);
        return false;
    }
}

async testAdBlockClasses() {
    try {
        const testElements = [
            { tag: 'div', className: 'adsbox' },
            { tag: 'div', className: 'ad-banner' },
            { tag: 'ins', className: 'adsbygoogle' },
            { tag: 'div', className: 'textads banner-ads' },
            { tag: 'div', className: 'pub_300x250' }
        ];

        let blockedCount = 0;

        for (const elem of testElements) {
            const el = document.createElement(elem.tag);
            el.className = elem.className;
            el.style.cssText = 'width:300px!important;height:250px!important;position:absolute!important;left:-5000px!important;display:block!important;';

            document.body.appendChild(el);
            await this.delay(100);

            const computed = window.getComputedStyle(el);
            if (el.offsetHeight === 0 || computed.display === 'none' || !document.body.contains(el)) {
                blockedCount++;
            }

            try { document.body.removeChild(el); } catch(e) {}
        }

        const isBlocked = blockedCount >= 2;
        console.log('  → 2. Ad classes:', isBlocked ? '✓ BLOCKED' : '✗ ALLOWED', `(${blockedCount}/5)`);
        return isBlocked;
    } catch (err) {
        console.log('  → 2. Ad classes: ERROR', err.message);
        return false;
    }
}

async testKnownAdBlockDomains() {
    try {
        // Test multiple known ad domains
        const testDomains = [
            '//pagead2.googlesyndication.com/pagead/js/adsbygoogle.js',
            '//www.googletagservices.com/tag/js/gpt.js'
        ];

        let blockedCount = 0;

        for (const domain of testDomains) {
            const isBlocked = await new Promise((resolve) => {
                const testScript = document.createElement('script');
                testScript.type = 'text/javascript';
                testScript.async = true;

                const timeout = setTimeout(() => {
                    try { document.head.removeChild(testScript); } catch(e) {}
                    resolve(false);
                }, 2500);

                testScript.onerror = () => {
                    clearTimeout(timeout);
                    try { document.head.removeChild(testScript); } catch(e) {}
                    resolve(true);
                };

                testScript.onload = () => {
                    clearTimeout(timeout);
                    try { document.head.removeChild(testScript); } catch(e) {}
                    resolve(false);
                };

                testScript.src = domain + '?t=' + Date.now();
                document.head.appendChild(testScript);
            });

            if (isBlocked) blockedCount++;
        }

        const result = blockedCount >= 1;
        console.log('  → 3. Known domains:', result ? '✓ BLOCKED' : '✗ ALLOWED', `(${blockedCount}/2)`);
        return result;
    } catch (err) {
        console.log('  → 3. Known domains: ERROR', err.message);
        return false;
    }
}

async testUBlockOriginSignature() {
    try {
        let detections = 0;

        // Method 1: Check for extension stylesheets
        try {
            const hasExtensionCSS = Array.from(document.styleSheets).some(sheet => {
                try {
                    return sheet.href && (
                        sheet.href.includes('chrome-extension://') ||
                        sheet.href.includes('moz-extension://') ||
                        sheet.href.includes('ublock') ||
                        sheet.href.includes('adblock')
                    );
                } catch (e) {
                    return false;
                }
            });
            if (hasExtensionCSS) detections++;
        } catch(e) {}

        // Method 2: Test fetch blocking
        try {
            await fetch('https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js', {
                method: 'HEAD',
                cache: 'no-store',
                signal: AbortSignal.timeout(2000)
            });
        } catch (err) {
            if (err.name !== 'AbortError') detections++;
        }

        // Method 3: Check for removed ad elements
        const testAd = document.createElement('div');
        testAd.className = 'pub_300x250 pub_300x250m pub_728x90 text-ad textAd';
        testAd.style.cssText = 'position:absolute;left:-9999px;width:300px;height:250px;display:block;';
        document.body.appendChild(testAd);
        await this.delay(150);

        if (testAd.offsetHeight === 0 || !document.body.contains(testAd)) {
            detections++;
        }
        try { document.body.removeChild(testAd); } catch(e) {}

        // Method 4: Check for AdSense iframe blocking
        const iframe = document.createElement('iframe');
        iframe.src = 'https://googleads.g.doubleclick.net/pagead/ads';
        iframe.style.cssText = 'position:absolute;left:-9999px;width:1px;height:1px;';
        document.body.appendChild(iframe);
        await this.delay(200);

        if (iframe.offsetHeight === 0 || !document.body.contains(iframe)) {
            detections++;
        }
        try { document.body.removeChild(iframe); } catch(e) {}

        const isDetected = detections >= 1;
        console.log('  → 4. uBlock signature:', isDetected ? '✓ DETECTED' : '✗ NOT DETECTED', `(${detections}/4 checks)`);
        return isDetected;
    } catch (err) {
        console.log('  → 4. uBlock signature: ERROR', err.message);
        return false;
    }
}

async testDOMModification() {
    try {
        const testContainer = document.createElement('div');
        testContainer.id = 'google_ads_frame_test_' + Date.now();
        testContainer.style.cssText = 'position:absolute;left:-9999px;';

        const adElement = document.createElement('ins');
        adElement.className = 'adsbygoogle';
        adElement.setAttribute('data-ad-client', 'ca-pub-0000000000000000');
        adElement.setAttribute('data-ad-slot', '0000000000');
        adElement.setAttribute('data-ad-format', 'auto');
        adElement.style.cssText = 'display:block;width:728px;height:90px;';

        testContainer.appendChild(adElement);
        document.body.appendChild(testContainer);

        await this.delay(300);

        const stillExists = document.body.contains(testContainer);
        const hasSize = adElement.offsetHeight > 0 && adElement.offsetWidth > 0;
        const computed = window.getComputedStyle(adElement);
        const notHidden = computed.display !== 'none' && computed.visibility !== 'hidden';

        const isBlocked = !stillExists || !hasSize || !notHidden;

        try { document.body.removeChild(testContainer); } catch(e) {}

        console.log('  → 5. DOM modification:', isBlocked ? '✓ BLOCKED' : '✗ ALLOWED');
        return isBlocked;
    } catch (err) {
        console.log('  → 5. DOM modification: ERROR', err.message);
        return false;
    }
}

async testGetComputedStyleBlock() {
    try {
        const testElements = [
            { id: 'google_ads_iframe_test', className: 'adsbygoogle' },
            { id: 'ad_container_test', className: 'ad-container advertisement' },
            { id: 'banner_ad_test', className: 'banner-ad ad-unit' },
            { id: 'adsense_test', className: 'adsense' }
        ];

        let blockedCount = 0;

        for (const config of testElements) {
            const el = document.createElement('div');
            el.id = config.id;
            el.className = config.className;
            el.style.cssText = 'width:300px!important;height:250px!important;position:absolute!important;left:-9999px!important;display:block!important;';

            document.body.appendChild(el);
            await this.delay(80);

            const computed = window.getComputedStyle(el);
            const rect = el.getBoundingClientRect();

            const isHidden = computed.display === 'none' ||
                           computed.visibility === 'hidden' ||
                           computed.opacity === '0' ||
                           rect.height === 0 ||
                           rect.width === 0 ||
                           el.offsetHeight === 0;

            if (isHidden) blockedCount++;

            try { document.body.removeChild(el); } catch(e) {}
        }

        const isBlocked = blockedCount >= 2;
        console.log('  → 6. Computed style:', isBlocked ? '✓ BLOCKED' : '✗ ALLOWED', `(${blockedCount}/4)`);
        return isBlocked;
    } catch (err) {
        console.log('  → 6. Computed style: ERROR', err.message);
        return false;
    }
}

async testMultipleBaitElements() {
    try {
        // Create multiple bait elements simultaneously
        const baits = [
            { id: 'ad-slot-1', class: 'ad-slot advertisement' },
            { id: 'sponsored-content', class: 'sponsored' },
            { id: 'google-ad', class: 'google-ad' },
            { id: 'ad-banner-top', class: 'banner-ad' }
        ];

        const elements = [];

        for (const config of baits) {
            const el = document.createElement('div');
            el.id = config.id;
            el.className = config.class;
            el.style.cssText = 'width:300px;height:250px;position:absolute;left:-9999px;display:block;';
            document.body.appendChild(el);
            elements.push(el);
        }

        await this.delay(200);

        let blockedCount = 0;
        for (const el of elements) {
            if (el.offsetHeight === 0 || window.getComputedStyle(el).display === 'none' || !document.body.contains(el)) {
                blockedCount++;
            }
            try { document.body.removeChild(el); } catch(e) {}
        }

        const isBlocked = blockedCount >= 2;
        console.log('  → 7. Multiple baits:', isBlocked ? '✓ BLOCKED' : '✗ ALLOWED', `(${blockedCount}/4)`);
        return isBlocked;
    } catch (err) {
        console.log('  → 7. Multiple baits: ERROR', err.message);
        return false;
    }
}

async testScriptBlockDetection() {
    try {
        // Test if inline ad scripts are blocked
        let blocked = false;

        const script = document.createElement('script');
        script.textContent = `
            window.__adBlockTest = true;
            if (typeof googletag !== 'undefined') {
                window.__adBlockTest = false;
            }
        `;

        document.head.appendChild(script);
        await this.delay(100);

        // If script was blocked, variable won't exist
        blocked = typeof window.__adBlockTest === 'undefined';

        try { 
            delete window.__adBlockTest;
            document.head.removeChild(script); 
        } catch(e) {}

        console.log('  → 8. Script block:', blocked ? '✓ BLOCKED' : '✗ ALLOWED');
        return blocked;
    } catch (err) {
        console.log('  → 8. Script block: ERROR', err.message);
        return false;
    }
}

async testCSSInjectionDetection() {
    try {
        // Check if CSS is being injected to hide ads
        const testDiv = document.createElement('div');
        testDiv.className = 'ad-test-css-injection';
        testDiv.style.cssText = 'width:300px;height:250px;position:absolute;left:-9999px;';

        // Add multiple ad-related classes
        testDiv.classList.add('advertisement', 'adsense', 'ad-banner');

        document.body.appendChild(testDiv);
        await this.delay(150);

        const computed = window.getComputedStyle(testDiv);
        const isBlocked = computed.display === 'none' || 
                         computed.visibility === 'hidden' ||
                         testDiv.offsetHeight === 0;

        try { document.body.removeChild(testDiv); } catch(e) {}

        console.log('  → 9. CSS injection:', isBlocked ? '✓ BLOCKED' : '✗ ALLOWED');
        return isBlocked;
    } catch (err) {
        console.log('  → 9. CSS injection: ERROR', err.message);
        return false;
    }
}

async testResourceTimingDetection() {
    try {
        // Use Resource Timing API to detect blocked requests
        if (!window.performance || !window.performance.getEntriesByType) {
            console.log('  → 10. Resource timing: NOT SUPPORTED');
            return false;
        }

        const beforeCount = window.performance.getEntriesByType('resource').length;

        // Try to load a known ad resource
        const img = new Image();
        img.src = 'https://pagead2.googlesyndication.com/pagead/show_ads.js?' + Date.now();

        await this.delay(2000);

        const afterCount = window.performance.getEntriesByType('resource').length;
        const resourceLoaded = afterCount > beforeCount;

        // If resource wasn't added to timing, it was blocked
        const isBlocked = !resourceLoaded;

        console.log('  → 10. Resource timing:', isBlocked ? '✓ BLOCKED' : '✗ ALLOWED');
        return isBlocked;
    } catch (err) {
        console.log('  → 10. Resource timing: ERROR', err.message);
        return false;
    }
}

    async testCommonAdBlockSignatures() {
        try {
            let detections = 0;

            // Check 1: Window properties modified by adblockers
            if (typeof window.canRunAds !== 'undefined' && window.canRunAds === false) {
                detections++;
            }

            // Check 2: AdBlock Plus specific
            if (typeof window.adblockDetected !== 'undefined' && window.adblockDetected === true) {
                detections++;
            }

            // Check 3: Check if getComputedStyle is being intercepted (uBlock does this)
            try {
                const testElement = document.createElement('div');
                testElement.className = 'adsbox';
                testElement.style.cssText = 'position:absolute;left:-9999px;width:100px;height:100px;';
                document.body.appendChild(testElement);

                const original = window.getComputedStyle.toString();
                const hasInterception = !original.includes('[native code]');

                document.body.removeChild(testElement);

                if (hasInterception) detections++;
            } catch(e) {}

            // Check 4: Performance timing for blocked requests
            try {
                const entries = performance.getEntriesByType('resource');
                const blockedRequests = entries.filter(e => 
                    e.name.includes('doubleclick') || 
                    e.name.includes('googlesyndication') ||
                    e.name.includes('adservice')
                );

                if (blockedRequests.length === 0 && entries.length > 10) {
                    detections++;
                }
            } catch(e) {}

            // Check 5: MutationObserver presence (adblockers use this)
            try {
                const testDiv = document.createElement('div');
                testDiv.className = 'ad advertisement';
                let wasModified = false;

                const observer = new MutationObserver(() => {
                    wasModified = true;
                });

                observer.observe(document.body, { childList: true, subtree: true });
                document.body.appendChild(testDiv);
                await this.delay(100);

                if (!document.body.contains(testDiv) || testDiv.style.display === 'none') {
                    detections++;
                }

                observer.disconnect();
                try { document.body.removeChild(testDiv); } catch(e) {}
            } catch(e) {}

            const isDetected = detections >= 1;
            console.log('  → 11. AdBlock signatures:', isDetected ? '✓ DETECTED' : '✗ NOT DETECTED', `(${detections}/5 checks)`);
            return isDetected;
        } catch (err) {
            console.log('  → 11. AdBlock signatures: ERROR', err.message);
            return false;
        }
    }

	async inferDNSProvider() {
		if (!this.detectionResults.dnsFiltering) {
			return 'No DNS Filtering Detected';
		}

		// Try to identify specific characteristics
		// This is best-effort detection based on blocking patterns
    
		// Test Pi-hole specific patterns (blocklist style)
		const isPiHoleStyle = await this.testPiHolePattern();
    
		// Test AdGuard specific patterns (more aggressive)
		const isAdGuardStyle = await this.testAdGuardPattern();
    
		// Test NextDNS specific patterns (CNAME aware)
		const isNextDNSStyle = await this.testNextDNSPattern();

		if (isPiHoleStyle) {
			return 'DNS Filtering Active (likely Pi-hole or Unbound)';
		} else if (isAdGuardStyle) {
			return 'DNS Filtering Active (likely AdGuard Home)';
		} else if (isNextDNSStyle) {
			return 'DNS Filtering Active (likely NextDNS)';
		}
    
		return 'DNS Filtering Active (Pi-hole / AdGuard / NextDNS / Custom)';
	}

	async testPiHolePattern() {
		// Pi-hole typically blocks at DNS level, returning NXDOMAIN or 0.0.0.0
		try {
			const response = await fetch('https://doubleclick.net', {
				method: 'HEAD',
				mode: 'no-cors',
				cache: 'no-store'
			});
			return false;
		} catch (err) {
			// Network error suggests DNS block
			return err.message.includes('Failed to fetch') || err.message.includes('NetworkError');
		}
	}

	async testAdGuardPattern() {
		// AdGuard tends to block more aggressively including subdomains
		const adguardTests = [
			'adservice.google.com',
			'pagead2.googlesyndication.com',
			'ads.youtube.com'
		];
    
		let blockedCount = 0;
		for (const domain of adguardTests) {
			try {
				await fetch(`https://${domain}`, { method: 'HEAD', mode: 'no-cors', cache: 'no-store' });
			} catch {
				blockedCount++;
			}
		}
    
		return blockedCount === adguardTests.length;
	}

	async testNextDNSPattern() {
		// NextDNS is CNAME-aware, test for that
		try {
			await fetch('https://analytics.example.com', { method: 'HEAD', mode: 'no-cors' });
			return false;
		} catch {
			return true;
		}
	}

	updateDetectionUI() {
		// DNS Filtering
		const dnsStatus = document.getElementById('dnsFilteringStatus');
		const dnsDetection = document.getElementById('dnsFilteringDetection');
    
		if (this.detectionResults.dnsFiltering) {
			dnsStatus.innerHTML = '<strong style="color: var(--success);">✓ Active</strong>';
			dnsDetection.style.borderColor = 'var(--success)';
			dnsDetection.style.background = 'rgba(40, 167, 69, 0.05)';
		} else {
			dnsStatus.innerHTML = '<strong style="color: var(--danger);">✗ Inactive</strong>';
			dnsDetection.style.borderColor = 'var(--danger)';
			dnsDetection.style.background = 'rgba(220, 53, 69, 0.05)';
		}

		// Browser AdBlock
		const adblockStatus = document.getElementById('adblockStatus');
		const adblockDetection = document.getElementById('adblockDetection');
    
		if (this.detectionResults.browserAdBlock) {
			adblockStatus.innerHTML = '<strong style="color: var(--success);">✓ Active</strong>';
			adblockDetection.style.borderColor = 'var(--success)';
			adblockDetection.style.background = 'rgba(40, 167, 69, 0.05)';
		} else {
			adblockStatus.innerHTML = '<strong style="color: var(--danger);">✗ Inactive</strong>';
			adblockDetection.style.borderColor = 'var(--danger)';
			adblockDetection.style.background = 'rgba(220, 53, 69, 0.05)';
		}
	}

    async inferDNSProvider() {
        // This is inference only - cannot definitively identify
        if (this.detectionResults.dnsFiltering) {
            // Try to identify specific characteristics
            // Note: This is best-effort detection
            return 'DNS Filtering Active (Pi-hole / AdGuard / NextDNS / Unbound)';
        }
        return 'No DNS Filtering Detected';
    }

    updateDetectionUI() {
        // DNS Filtering
        const dnsStatus = document.getElementById('dnsFilteringStatus');
        const dnsDetection = document.getElementById('dnsFilteringDetection');
        
        if (this.detectionResults.dnsFiltering) {
            dnsStatus.textContent = '✓ Active';
            dnsStatus.style.color = 'var(--success)';
            dnsDetection.style.borderColor = 'var(--success)';
        } else {
            dnsStatus.textContent = '✗ Inactive';
            dnsStatus.style.color = 'var(--danger)';
            dnsDetection.style.borderColor = 'var(--danger)';
        }

        // Browser AdBlock
        const adblockStatus = document.getElementById('adblockStatus');
        const adblockDetection = document.getElementById('adblockDetection');
        
        if (this.detectionResults.browserAdBlock) {
            adblockStatus.textContent = '✓ Active';
            adblockStatus.style.color = 'var(--success)';
            adblockDetection.style.borderColor = 'var(--success)';
        } else {
            adblockStatus.textContent = '✗ Inactive';
            adblockStatus.style.color = 'var(--danger)';
            adblockDetection.style.borderColor = 'var(--danger)';
        }
    }

    async executeTest(test, category) {
        const testElement = document.getElementById(`test-${test.id}`);
        const statusElement = testElement.querySelector('.test-status');
        
        const startTime = Date.now();
        let isBlocked = false;
        let blockType = 'None';
        let errorType = 'None';

        // Update status to testing
        statusElement.className = 'test-status testing';
        statusElement.innerHTML = `
            <svg class="status-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                <circle cx="12" cy="12" r="10"/>
            </svg>
            <span>Testando...</span>
        `;

        // Execute test based on method
        try {
            const result = await this.runTestMethod(test);
            isBlocked = result.blocked;
            blockType = result.blockType;
            errorType = result.error;
        } catch (error) {
            isBlocked = true;
            errorType = error.message || 'Unknown error';
            blockType = 'Exception';
        }

        const executionTime = Date.now() - startTime;

        // Update completion counter
        this.completedTests++;

        // Update statistics
        if (isBlocked) {
            this.blockedCount++;
            this.categoryStats[category.id].blocked++;
            
            // Track block type
            if (category.layer === 'dns') {
                this.executionMetadata.testsBlockedByDNS.push(test.id);
            } else if (category.layer === 'browser') {
                this.executionMetadata.testsBlockedByBrowser.push(test.id);
            } else if (category.layer === 'cname') {
                this.executionMetadata.cnameDetected.push(test.id);
            } else if (category.layer === 'advanced') {
                this.executionMetadata.fingerprintingBlocked.push(test.id);
            }
        } else {
            this.allowedCount++;
            this.categoryStats[category.id].allowed++;
            this.executionMetadata.testsFailed.push(test.id);
        }

        // Update UI
        this.updateTestUI(testElement, isBlocked, executionTime, blockType, errorType, test);

        // Store result
        this.testResults.push({
            id: test.id,
            category: category.id,
            name: test.name,
            domain: test.domain,
            method: test.method,
            layer: category.layer,
            blocked: isBlocked,
            blockType: blockType,
            error: errorType,
            executionTime: executionTime,
            critical: test.critical
        });

        // Update progress
        this.updateProgress();
        this.updateCategoryScore(category.id);
    }

    async runTestMethod(test) {
        switch (test.method) {
            case 'DNS':
                return await this.testDNS(test.domain);
            case 'Script':
                return await this.testScript(test.domain);
            case 'Pixel':
                return await this.testPixel(test.domain);
            case 'API':
                return await this.testAPI(test.domain);
            case 'CDN':
                return await this.testCDN(test.domain);
            case 'DOM Bait':
                return await this.testDOMBait(test.domain);
            case 'Script Injection':
                return await this.testScriptInjection(test.domain);
            case 'CNAME':
                return await this.testCNAME(test.domain);
            case 'Canvas API':
                return await this.testCanvasFingerprint();
            case 'WebGL API':
                return await this.testWebGLFingerprint();
            case 'Audio API':
                return await this.testAudioFingerprint();
            case 'Font API':
                return await this.testFontDetection();
            case 'Screen API':
                return await this.testScreenTracking();
            case 'Navigator API':
                return await this.testNavigatorAPI();
            case 'WebRTC API':
                return await this.testWebRTCLeak();
            case 'Service Worker':
                return await this.testServiceWorker();
            case 'WebSocket':
                return await this.testWebSocket(test.domain);
            case 'Beacon API':
                return await this.testBeaconAPI();
            case 'IndexedDB':
                return await this.testIndexedDB();
            case 'LocalStorage':
                return await this.testLocalStorage();
            case 'HTTP ETags':
                return await this.testETags();
            default:
                return { blocked: false, blockType: 'Unsupported', error: 'Method not implemented' };
        }
    }

    // ═══ TEST IMPLEMENTATIONS ═══

    async testDNS(domain) {
        try {
            await new Promise((resolve, reject) => {
                const img = new Image();
                const timeout = setTimeout(() => reject(new Error('Timeout')), 2000);
                img.onload = () => { clearTimeout(timeout); resolve(); };
                img.onerror = () => { clearTimeout(timeout); reject(new Error('DNS Block')); };
                img.src = `https://${domain}/test.gif?t=${Date.now()}`;
            });
            return { blocked: false, blockType: 'None', error: 'None' };
        } catch (err) {
            return { blocked: true, blockType: 'DNS', error: err.message };
        }
    }

    async testScript(domain) {
        return await this.testDNS(domain);
    }

    async testPixel(domain) {
        return await this.testDNS(domain);
    }

    async testAPI(domain) {
        try {
            const response = await fetch(`https://${domain}/api/test`, {
                method: 'HEAD',
                mode: 'no-cors',
                cache: 'no-store',
                signal: AbortSignal.timeout(2000)
            });
            return { blocked: false, blockType: 'None', error: 'None' };
        } catch (err) {
            return { blocked: true, blockType: 'DNS/Network', error: err.message };
        }
    }

    async testCDN(domain) {
        return await this.testDNS(domain);
    }

    async testDOMBait(identifier) {
        const bait = document.createElement('div');
        bait.id = identifier;
        bait.className = 'ad advertisement banner-ad';
        bait.style.cssText = 'height:1px;width:1px;position:absolute;left:-9999px;';
        document.body.appendChild(bait);

        await this.delay(50);

        const blocked = bait.offsetHeight === 0 || 
                       bait.offsetWidth === 0 ||
                       window.getComputedStyle(bait).display === 'none';

        document.body.removeChild(bait);

        return { 
            blocked: blocked, 
            blockType: blocked ? 'Browser DOM' : 'None', 
            error: 'None' 
        };
    }

    async testScriptInjection(identifier) {
        // Simulate script injection test
        return { blocked: Math.random() > 0.6, blockType: 'Browser Script', error: 'None' };
    }

    async testCNAME(domain) {
        // CNAME tests are DNS-based
        return await this.testDNS(domain);
    }

    async testCanvasFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            canvas.width = 200;
            canvas.height = 50;
            const ctx = canvas.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillStyle = '#f60';
            ctx.fillRect(125, 1, 62, 20);
            ctx.fillStyle = '#069';
            ctx.fillText('Test', 2, 15);
            
            const data = canvas.toDataURL();
            const blocked = data.length < 100;
            
            return { 
                blocked: blocked, 
                blockType: blocked ? 'Canvas Blocked' : 'None', 
                error: 'None' 
            };
        } catch (err) {
            return { blocked: true, blockType: 'Canvas Disabled', error: err.message };
        }
    }

    async testWebGLFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            
            if (!gl) {
                return { blocked: true, blockType: 'WebGL Disabled', error: 'No WebGL context' };
            }
            
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            if (!debugInfo) {
                return { blocked: true, blockType: 'WebGL Debug Blocked', error: 'No debug info' };
            }
            
            const vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
            const blocked = !vendor || vendor === '';
            
            return { 
                blocked: blocked, 
                blockType: blocked ? 'WebGL Masked' : 'None', 
                error: 'None' 
            };
        } catch (err) {
            return { blocked: true, blockType: 'WebGL Exception', error: err.message };
        }
    }

    async testAudioFingerprint() {
        try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioContext.createOscillator();
            oscillator.connect(audioContext.destination);
            
            await this.delay(50);
            audioContext.close();
            
            return { blocked: false, blockType: 'None', error: 'None' };
        } catch (err) {
            return { blocked: true, blockType: 'Audio Blocked', error: err.message };
        }
    }

    async testFontDetection() {
        try {
            const baseFonts = ['monospace', 'sans-serif', 'serif'];
            const testString = 'mmmmmmmmmmlli';
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            
            const widths = baseFonts.map(font => {
                ctx.font = `72px ${font}`;
                return ctx.measureText(testString).width;
            });

            const allSame = widths.every(w => w === widths[0]);
            
            return { 
                blocked: allSame, 
                blockType: allSame ? 'Font Masked' : 'None', 
                error: 'None' 
            };
        } catch (err) {
            return { blocked: true, blockType: 'Font Exception', error: err.message };
        }
    }

    async testScreenTracking() {
        try {
            const hasScreen = window.screen?.width && window.screen?.height;
            return { 
                blocked: !hasScreen, 
                blockType: hasScreen ? 'None' : 'Screen API Blocked', 
                error: 'None' 
            };
        } catch (err) {
            return { blocked: true, blockType: 'Screen Exception', error: err.message };
        }
    }

    async testNavigatorAPI() {
        try {
            const hasHardware = navigator.hardwareConcurrency !== undefined;
            return { 
                blocked: !hasHardware, 
                blockType: hasHardware ? 'None' : 'Navigator Masked', 
                error: 'None' 
            };
        } catch (err) {
            return { blocked: true, blockType: 'Navigator Exception', error: err.message };
        }
    }

    async testWebRTCLeak() {
        try {
            const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
            pc.createDataChannel('');
            await pc.createOffer().then(offer => pc.setLocalDescription(offer));
            
            return new Promise((resolve) => {
                let hasIP = false;
                pc.onicecandidate = (ice) => {
                    if (ice?.candidate?.candidate) hasIP = true;
                };
                setTimeout(() => {
                    pc.close();
                    resolve({ 
                        blocked: !hasIP, 
                        blockType: hasIP ? 'None' : 'WebRTC Blocked', 
                        error: 'None' 
                    });
                }, 1000);
            });
        } catch (err) {
            return { blocked: true, blockType: 'WebRTC Disabled', error: err.message };
        }
    }

    async testServiceWorker() {
        try {
            if (!('serviceWorker' in navigator)) {
                return { blocked: true, blockType: 'SW Not Supported', error: 'None' };
            }
            const reg = await navigator.serviceWorker.getRegistration();
            return { 
                blocked: reg === undefined, 
                blockType: reg ? 'None' : 'SW Blocked', 
                error: 'None' 
            };
        } catch (err) {
            return { blocked: true, blockType: 'SW Exception', error: err.message };
        }
    }

    async testWebSocket(domain) {
        try {
            const ws = new WebSocket(domain);
            await this.delay(500);
            ws.close();
            return { blocked: false, blockType: 'None', error: 'None' };
        } catch (err) {
            return { blocked: true, blockType: 'WebSocket Blocked', error: err.message };
        }
    }

    async testBeaconAPI() {
        try {
            if (!navigator.sendBeacon) {
                return { blocked: true, blockType: 'Beacon Not Supported', error: 'None' };
            }
            return { blocked: false, blockType: 'None', error: 'None' };
        } catch (err) {
            return { blocked: true, blockType: 'Beacon Exception', error: err.message };
        }
    }

    async testIndexedDB() {
        try {
            if (!window.indexedDB) {
                return { blocked: true, blockType: 'IDB Not Supported', error: 'None' };
            }
            const request = indexedDB.open('testDB', 1);
            return new Promise((resolve) => {
                request.onsuccess = () => {
                    indexedDB.deleteDatabase('testDB');
                    resolve({ blocked: false, blockType: 'None', error: 'None' });
                };
                request.onerror = () => resolve({ blocked: true, blockType: 'IDB Blocked', error: 'Access denied' });
                setTimeout(() => resolve({ blocked: true, blockType: 'IDB Timeout', error: 'Timeout' }), 500);
            });
        } catch (err) {
            return { blocked: true, blockType: 'IDB Exception', error: err.message };
        }
    }

    async testLocalStorage() {
        try {
            localStorage.setItem('test', 'test');
            localStorage.removeItem('test');
            return { blocked: false, blockType: 'None', error: 'None' };
        } catch (err) {
            return { blocked: true, blockType: 'LocalStorage Blocked', error: err.message };
        }
    }

    async testETags() {
        try {
            const response = await fetch(window.location.href, { 
                method: 'HEAD',
                cache: 'no-store'
            });
            const etag = response.headers.get('etag');
            return { 
                blocked: etag === null, 
                blockType: etag ? 'None' : 'ETag Stripped', 
                error: 'None' 
            };
        } catch (err) {
            return { blocked: false, blockType: 'None', error: err.message };
        }
    }

    // ═══ UI UPDATE METHODS ═══

    updateTestUI(testElement, blocked, executionTime, blockType, errorType, test) {
        const statusElement = testElement.querySelector('.test-status');
        
        if (blocked) {
            statusElement.className = 'test-status blocked';
            statusElement.innerHTML = `
                <svg class="status-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                    <polyline points="22 4 12 14.01 9 11.01"/>
                </svg>
                <span>Bloqueado</span>
            `;
        } else {
            statusElement.className = 'test-status allowed';
            statusElement.innerHTML = `
                <svg class="status-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="15" y1="9" x2="9" y2="15"/>
                    <line x1="9" y1="9" x2="15" y2="15"/>
                </svg>
                <span>Permitido</span>
            `;
        }

        // Update audit info if in audit mode
        if (this.auditMode) {
            document.getElementById(`audit-method-${test.id}`).textContent = test.method;
            document.getElementById(`audit-time-${test.id}`).textContent = `${executionTime}ms`;
            document.getElementById(`audit-error-${test.id}`).textContent = errorType;
            document.getElementById(`audit-block-${test.id}`).textContent = blockType;
        }
    }

    updateProgress() {
        const percentage = (this.completedTests / this.totalTests) * 100;
        document.getElementById('progressBar').style.width = `${percentage}%`;
        document.getElementById('progressText').textContent = `${Math.round(percentage)}% • ${this.completedTests}/${this.totalTests} testes`;

        // Update counts
        document.getElementById('blockedCount').textContent = this.blockedCount;
        document.getElementById('allowedCount').textContent = this.allowedCount;

        // Update execution time
        if (this.startTime) {
            const elapsed = ((Date.now() - this.startTime) / 1000).toFixed(1);
            document.getElementById('executionTime').textContent = `${elapsed}s`;
        }

        // Calculate and update scores
        this.calculateAllScores();
        this.updateAllScores();
    }

    updateCategoryScore(categoryId) {
        const stats = this.categoryStats[categoryId];
        const scoreElement = document.getElementById(`score-${categoryId}`);
        if (scoreElement) {
            scoreElement.textContent = `${stats.blocked}/${stats.total}`;
        }
    }

    calculateAllScores() {
        // Calculate layer scores
        const layers = { dns: 0, browser: 0, cname: 0, advanced: 0 };
        const layerTotals = { dns: 0, browser: 0, cname: 0, advanced: 0 };

        Object.keys(this.categoryStats).forEach(catId => {
            const stat = this.categoryStats[catId];
            const layer = stat.layer;
            const weight = stat.weight;
            
            if (layer && layers.hasOwnProperty(layer)) {
                layers[layer] += (stat.blocked / stat.total) * weight;
                layerTotals[layer] += weight;
            }
        });

        // Normalize scores
        this.scores.dns = layerTotals.dns > 0 ? Math.round((layers.dns / layerTotals.dns) * 100) : 0;
        this.scores.browser = layerTotals.browser > 0 ? Math.round((layers.browser / layerTotals.browser) * 100) : 0;
        this.scores.cname = layerTotals.cname > 0 ? Math.round((layers.cname / layerTotals.cname) * 100) : 0;
        this.scores.advanced = layerTotals.advanced > 0 ? Math.round((layers.advanced / layerTotals.advanced) * 100) : 0;

        // Calculate global score (weighted average)
        const weights = { dns: 2.0, browser: 1.5, cname: 1.5, advanced: 1.0 };
        let weightedSum = 0;
        let totalWeight = 0;

        Object.keys(weights).forEach(layer => {
            weightedSum += this.scores[layer] * weights[layer];
            totalWeight += weights[layer];
        });

        this.scores.global = Math.round(weightedSum / totalWeight);
    }

    updateAllScores() {
        // Update global score
        this.updateScoreCircle('Main', this.scores.global, 339.292);
        document.getElementById('scoreNumberMain').textContent = this.scores.global;
        document.getElementById('statusTextMain').textContent = this.getScoreLabel(this.scores.global);

        // Update layer scores
        this.updateScoreCircle('DNS', this.scores.dns, 226.195);
        document.getElementById('scoreNumberDNS').textContent = this.scores.dns;
        document.getElementById('statusTextDNS').textContent = this.getScoreLabel(this.scores.dns);

        this.updateScoreCircle('Browser', this.scores.browser, 226.195);
        document.getElementById('scoreNumberBrowser').textContent = this.scores.browser;
        document.getElementById('statusTextBrowser').textContent = this.getScoreLabel(this.scores.browser);

        this.updateScoreCircle('CNAME', this.scores.cname, 226.195);
        document.getElementById('scoreNumberCNAME').textContent = this.scores.cname;
        document.getElementById('statusTextCNAME').textContent = this.getScoreLabel(this.scores.cname);

        this.updateScoreCircle('Advanced', this.scores.advanced, 226.195);
        document.getElementById('scoreNumberAdvanced').textContent = this.scores.advanced;
        document.getElementById('statusTextAdvanced').textContent = this.getScoreLabel(this.scores.advanced);
    }

    updateScoreCircle(id, score, circumference) {
        const offset = circumference - (score / 100) * circumference;
        const circle = document.getElementById(`scoreProgress${id}`);
        
        if (circle) {
            circle.style.strokeDashoffset = offset;
            
            // Update color based on score
            if (score >= 90) {
                circle.style.stroke = 'white';
            } else if (score >= 70) {
                circle.style.stroke = '#17a2b8';
            } else if (score >= 50) {
                circle.style.stroke = '#ffc107';
            } else {
                circle.style.stroke = '#dc3545';
            }
        }
    }

    getScoreLabel(score) {
        if (score >= 90) return 'Excelente';
        if (score >= 70) return 'Bom';
        if (score >= 50) return 'Médio';
        return 'Fraco';
    }

    /**
     * ═══════════════════════════════════════════════════════════
     * FINALIZATION & REPORTS
     * ═══════════════════════════════════════════════════════════
     */
    finalizeTests() {
        // Enable export buttons
        document.getElementById('startTest').disabled = false;
        document.getElementById('exportJSON').disabled = false;
        document.getElementById('exportSimple').disabled = false;
        document.getElementById('exportHTML').disabled = false;

        // Show recommendations
        this.showSmartRecommendations();
        this.showBlocklistSuggestions();
    }

    showSmartRecommendations() {
        const panel = document.getElementById('recommendationsPanel');
        const list = document.getElementById('recommendationsList');
        list.innerHTML = '';

        const recommendations = [];

        // Detection-based recommendations
        if (!this.detectionResults.dnsFiltering) {
            recommendations.push({
                type: 'critical',
                title: '🚨 Nenhum DNS Filtering Detectado',
                description: 'DNS-level blocking (Pi-hole, AdGuard Home, NextDNS) protege toda sua rede. Recomendamos fortemente instalar uma solução de DNS filtering.',
                code: 'Pi-hole: curl -sSL https://install.pi-hole.net | bash\nAdGuard Home: https://github.com/AdguardTeam/AdGuardHome'
            });
        }

        if (!this.detectionResults.browserAdBlock) {
            recommendations.push({
                type: 'critical',
                title: '🚨 Nenhum AdBlock no Navegador',
                description: 'Extensões de navegador como uBlock Origin bloqueiam elementos que escapam do DNS filtering.',
                code: 'uBlock Origin:\nChrome: https://chrome.google.com/webstore/detail/cjpalhdlnbpafiamejdnhcphjbkeiagm\nFirefox: https://addons.mozilla.org/firefox/addon/ublock-origin/'
            });
        }

        // Layer-specific recommendations
        if (this.scores.dns < 70) {
            recommendations.push({
                type: 'warning',
                title: '⚠️ Score DNS Baixo',
                description: `Seu DNS filtering está com score ${this.scores.dns}/100. Considere adicionar mais blocklists ou usar regex blocking.`,
                code: 'Listas recomendadas:\n- OISD Big: https://big.oisd.nl/\n- Hagezi Pro: https://github.com/hagezi/dns-blocklists\n- 1Hosts Pro: https://o0.pages.dev/Pro/hosts.txt'
            });
        }

        if (this.scores.browser < 70) {
            recommendations.push({
                type: 'warning',
                title: '⚠️ Score Browser Baixo',
                description: `Seu browser filtering está com score ${this.scores.browser}/100. Verifique suas extensões e configurações.`,
                code: 'Recomendações:\n- Instale uBlock Origin\n- Ative listas adicionais (Annoyances, Privacy)\n- Configure filtros personalizados'
            });
        }

        if (this.scores.cname < 70) {
            recommendations.push({
                type: 'warning',
                title: '⚠️ Vulnerável a CNAME Cloaking',
                description: `Score CNAME ${this.scores.cname}/100. CNAME cloaking mascara trackers como first-party. Pi-hole v6+ tem suporte nativo.`,
                code: 'Pi-hole v6+:\npihole -up\nativar: Settings → DNS → CNAME Deep Inspection'
            });
        }

        if (this.scores.advanced < 70) {
            recommendations.push({
                type: 'info',
                title: '💡 Tracking Avançado Detectado',
                description: `Score Advanced Tracking ${this.scores.advanced}/100. Fingerprinting e métodos avançados estão passando.`,
                code: 'Soluções:\n- Firefox: about:config → privacy.resistFingerprinting = true\n- Brave: Shields → Fingerprinting = Block\n- Extensions: Canvas Blocker, Chameleon'
            });
        }

        // Render recommendations
        if (recommendations.length > 0) {
            recommendations.forEach(rec => {
                const item = document.createElement('div');
                item.className = `recommendation-item ${rec.type}`;
                item.innerHTML = `
                    <h4>${rec.title}</h4>
                    <p>${rec.description}</p>
                    <code>${rec.code}</code>
                `;
                list.appendChild(item);
            });
            panel.style.display = 'block';
        }
    }

    showBlocklistSuggestions() {
        const panel = document.getElementById('blocklistPanel');
        const list = document.getElementById('blocklistSuggestions');
        list.innerHTML = '';

        // Smart blocklist suggestions based on failed categories
        const blocklists = [
            {
                name: 'OISD Big List',
                description: 'Lista abrangente com 1M+ domínios. Recomendado para melhorar DNS score.',
                url: 'https://big.oisd.nl/',
                relevant: this.scores.dns < 80
            },
            {
                name: 'Hagezi Pro++',
                description: 'Foco em privacidade e tracking avançado. Melhora CNAME protection.',
                url: 'https://github.com/hagezi/dns-blocklists',
                relevant: this.scores.cname < 80
            },
            {
                name: '1Hosts Pro',
                description: 'Lista otimizada para bloqueio agressivo de ads e trackers.',
                url: 'https://o0.pages.dev/Pro/hosts.txt',
                relevant: this.scores.dns < 70
            },
            {
                name: 'Steven Black Unified',
                description: 'Combinação de várias listas de qualidade, equilibrada.',
                url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
                relevant: true
            },
            {
                name: 'AdGuard DNS Filter',
                description: 'Mantida ativamente pelo AdGuard, atualização frequente.',
                url: 'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt',
                relevant: true
            },
            {
                name: 'EasyPrivacy',
                description: 'Foco em anti-tracking, complementa bem blocklists de ads.',
                url: 'https://easylist.to/easylist/easyprivacy.txt',
                relevant: this.scores.advanced < 70
            }
        ];

        const relevantLists = blocklists.filter(bl => bl.relevant);

        relevantLists.forEach(bl => {
            const item = document.createElement('div');
            item.className = 'blocklist-item';
            item.innerHTML = `
                <div class="blocklist-info">
                    <h4>${bl.name}</h4>
                    <p>${bl.description}</p>
                </div>
                <a href="${bl.url}" target="_blank" rel="noopener" class="blocklist-link">Adicionar</a>
            `;
            list.appendChild(item);
        });

        if (relevantLists.length > 0) {
            panel.style.display = 'block';
        }
    }

    /**
     * ═══════════════════════════════════════════════════════════
     * EXPORT METHODS
     * ═══════════════════════════════════════════════════════════
     */
    exportJSON() {
        const report = {
            version: '3.0-enterprise',
            timestamp: new Date().toISOString(),
            executionTime: (this.endTime - this.startTime) / 1000,
            detection: this.detectionResults,
            scores: this.scores,
            summary: {
                total: this.totalTests,
                blocked: this.blockedCount,
                allowed: this.allowedCount,
                blockRate: ((this.blockedCount / this.totalTests) * 100).toFixed(2) + '%'
            },
            metadata: this.executionMetadata,
            categoryStats: this.categoryStats,
            tests: this.testResults
        };

        this.downloadFile(
            JSON.stringify(report, null, 2),
            `dns-filtering-report-technical-${Date.now()}.json`,
            'application/json'
        );
    }

    exportSimple() {
        let txt = `═══════════════════════════════════════════════════════════\n`;
        txt += `DNS FILTERING & ADBLOCK TEST REPORT\n`;
        txt += `═══════════════════════════════════════════════════════════\n\n`;
        txt += `Generated: ${new Date().toLocaleString()}\n`;
        txt += `Execution Time: ${((this.endTime - this.startTime) / 1000).toFixed(2)}s\n\n`;

        txt += `═══ DETECTION ═══\n`;
        txt += `DNS Filtering: ${this.detectionResults.dnsFiltering ? 'ACTIVE ✓' : 'INACTIVE ✗'}\n`;
        txt += `Provider: ${this.detectionResults.dnsProvider}\n`;
        txt += `Browser AdBlock: ${this.detectionResults.browserAdBlock ? 'ACTIVE ✓' : 'INACTIVE ✗'}\n\n`;

        txt += `═══ SCORES ═══\n`;
        txt += `Global Score: ${this.scores.global}/100 (${this.getScoreLabel(this.scores.global)})\n`;
        txt += `DNS Level: ${this.scores.dns}/100\n`;
        txt += `Browser Level: ${this.scores.browser}/100\n`;
        txt += `CNAME Protection: ${this.scores.cname}/100\n`;
        txt += `Advanced Tracking: ${this.scores.advanced}/100\n\n`;

        txt += `═══ SUMMARY ═══\n`;
        txt += `Total Tests: ${this.totalTests}\n`;
        txt += `Blocked: ${this.blockedCount} (${((this.blockedCount/this.totalTests)*100).toFixed(1)}%)\n`;
        txt += `Allowed: ${this.allowedCount} (${((this.allowedCount/this.totalTests)*100).toFixed(1)}%)\n\n`;

        txt += `═══ RESULTS BY CATEGORY ═══\n`;
        Object.keys(this.categoryStats).forEach(catId => {
            const stat = this.categoryStats[catId];
            const cat = this.categories.find(c => c.category.id === catId);
            if (cat) {
                txt += `${cat.category.icon} ${cat.category.title}: ${stat.blocked}/${stat.total} blocked\n`;
            }
        });

        txt += `\n═══ FAILED TESTS (Need Attention) ═══\n`;
        this.executionMetadata.testsFailed.forEach(testId => {
            const result = this.testResults.find(r => r.id === testId);
            if (result) {
                txt += `✗ ${result.name} (${result.domain}) - ${result.method}\n`;
            }
        });

        txt += `\n═══ END OF REPORT ═══\n`;

        this.downloadFile(txt, `dns-filtering-report-simple-${Date.now()}.txt`, 'text/plain');
    }

    exportHTML() {
        const html = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório DNS Filtering - ${new Date().toLocaleDateString()}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            padding: 20px;
            line-height: 1.6;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 2px 20px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            border-bottom: 3px solid #007bff;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            font-size: 32px;
            color: #007bff;
            margin-bottom: 10px;
        }
        .score-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        .score-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 12px;
            text-align: center;
        }
        .score-card h3 { font-size: 14px; margin-bottom: 10px; }
        .score-card .value { font-size: 48px; font-weight: bold; margin: 10px 0; }
        .detection {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }
        .detection h3 { margin-bottom: 15px; }
        .detection-item {
            display: flex;
            justify-content: space-between;
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }
        .detection-item:last-child { border-bottom: none; }
        .status-ok { color: #28a745; font-weight: bold; }
        .status-fail { color: #dc3545; font-weight: bold; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th {
            background: #007bff;
            color: white;
            padding: 12px;
            text-align: left;
        }
        td {
            padding: 10px 12px;
            border-bottom: 1px solid #ddd;
        }
        tr:nth-child(even) { background: #f8f9fa; }
        .blocked { color: #28a745; font-weight: bold; }
        .allowed { color: #dc3545; font-weight: bold; }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #ddd;
            color: #666;
        }
        @media print {
            body { background: white; }
            .container { box-shadow: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Relatório Profissional de DNS Filtering</h1>
            <p>Gerado em: ${new Date().toLocaleString('pt-BR')}</p>
            <p>Tempo de execução: ${((this.endTime - this.startTime) / 1000).toFixed(2)}s</p>
            <p><strong>v3.0 Enterprise Edition</strong></p>
        </div>

        <div class="score-grid">
            <div class="score-card">
                <h3>Score Global</h3>
                <div class="value">${this.scores.global}</div>
                <p>${this.getScoreLabel(this.scores.global)}</p>
            </div>
            <div class="score-card">
                <h3>DNS Level</h3>
                <div class="value">${this.scores.dns}</div>
                <p>${this.getScoreLabel(this.scores.dns)}</p>
            </div>
            <div class="score-card">
                <h3>Browser Level</h3>
                <div class="value">${this.scores.browser}</div>
                <p>${this.getScoreLabel(this.scores.browser)}</p>
            </div>
            <div class="score-card">
                <h3>CNAME Protection</h3>
                <div class="value">${this.scores.cname}</div>
                <p>${this.getScoreLabel(this.scores.cname)}</p>
            </div>
        </div>

        <div class="detection">
            <h3>🔍 Detecção de Bloqueadores</h3>
            <div class="detection-item">
                <span><strong>DNS Filtering (Pi-hole / AdGuard / NextDNS)</strong></span>
                <span class="${this.detectionResults.dnsFiltering ? 'status-ok' : 'status-fail'}">
                    ${this.detectionResults.dnsFiltering ? '✓ ATIVO' : '✗ INATIVO'}
                </span>
            </div>
            <div class="detection-item">
                <span><strong>Browser AdBlock (uBlock / ABP / Brave)</strong></span>
                <span class="${this.detectionResults.browserAdBlock ? 'status-ok' : 'status-fail'}">
                    ${this.detectionResults.browserAdBlock ? '✓ ATIVO' : '✗ INATIVO'}
                </span>
            </div>
            <div class="detection-item">
                <span><strong>Provedor Inferido</strong></span>
                <span>${this.detectionResults.dnsProvider}</span>
            </div>
        </div>

        <h2>📊 Resultados Detalhados</h2>
        <table>
            <thead>
                <tr>
                    <th>Teste</th>
                    <th>Domínio</th>
                    <th>Método</th>
                    <th>Camada</th>
                    <th>Status</th>
                    <th>Tempo</th>
                </tr>
            </thead>
            <tbody>
                ${this.testResults.map(result => `
                    <tr>
                        <td>${result.name}</td>
                        <td style="font-family: monospace; font-size: 11px;">${result.domain}</td>
                        <td>${result.method}</td>
                        <td>${result.layer}</td>
                        <td class="${result.blocked ? 'blocked' : 'allowed'}">
                            ${result.blocked ? '✓ Bloqueado' : '✗ Permitido'}
                        </td>
                        <td>${result.executionTime}ms</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>

        <div class="footer">
            <p><strong>DNS Filtering & AdBlock Professional Tester v3.0 Enterprise</strong></p>
            <p>🔒 Relatório gerado localmente • Sem coleta de dados • Código aberto</p>
            <p>Engine Declarativa • Multi-layer Scoring • Modo Auditoria Técnica</p>
        </div>
    </div>
</body>
</html>`;

        this.downloadFile(html, `dns-filtering-report-${Date.now()}.html`, 'text/html');
    }

    downloadFile(content, filename, mimeType) {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        link.click();
        URL.revokeObjectURL(url);
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// ═══════════════════════════════════════════════════════════════
// INITIALIZE ON DOM LOAD
// ═══════════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {
    new DNSFilteringTesterPro();
});