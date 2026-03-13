/* VAPT Scanner Pro - Layout Injector (Flask version) */
(function () {

    // ── Inject notification panel styles once ─────────────────────────────
    function _injectStyles() {
        if (document.getElementById('_notif-styles')) return;
        var s = document.createElement('style');
        s.id = '_notif-styles';
        s.textContent = `
/* ── Notification panel — White / Light theme ─────────── */
.notif-panel {
    position: absolute;
    top: calc(100% + 10px);
    right: 0;
    width: 370px;
    background: #ffffff;
    border: 1px solid #e8ecf2;
    border-radius: 16px;
    box-shadow: 0 8px 32px rgba(30,60,120,0.10), 0 2px 8px rgba(30,60,120,0.06);
    overflow: hidden;
    z-index: 9999;
    opacity: 0;
    transform: translateY(-8px) scale(0.98);
    pointer-events: none;
    transition: opacity 0.22s ease, transform 0.22s cubic-bezier(.34,1.3,.64,1);
    font-family: 'Segoe UI', system-ui, sans-serif;
}
.notif-panel.open {
    opacity: 1;
    transform: translateY(0) scale(1);
    pointer-events: all;
}

/* Header */
.np-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 18px 13px;
    border-bottom: 1px solid #f0f3f8;
    background: linear-gradient(135deg, #f5f8ff 0%, #ffffff 70%);
}
.np-head-left {
    display: flex;
    align-items: center;
    gap: 9px;
}
.np-head-icon {
    width: 32px; height: 32px;
    background: #e8f0fe;
    border-radius: 9px;
    display: flex; align-items: center; justify-content: center;
    color: #3b7de8;
    font-size: 13px;
}
.np-head-title {
    font-size: 14px;
    font-weight: 700;
    color: #1a2236;
    letter-spacing: 0.01em;
}
.np-head-count {
    font-size: 10.5px;
    font-weight: 700;
    background: #e53e3e;
    color: #fff;
    padding: 2px 7px;
    border-radius: 20px;
    letter-spacing: 0.02em;
    min-width: 20px;
    text-align: center;
    line-height: 1.6;
    transition: all 0.2s;
}
.np-head-count.zero { background: #edf1f7; color: #9aa5b8; }
.np-head-actions {
    display: flex;
    align-items: center;
    gap: 4px;
}
.np-btn {
    background: none;
    border: none;
    color: #9aa5b8;
    cursor: pointer;
    padding: 5px 9px;
    border-radius: 8px;
    font-size: 12px;
    display: flex;
    align-items: center;
    gap: 5px;
    transition: background 0.15s, color 0.15s;
    white-space: nowrap;
    font-family: inherit;
    font-weight: 500;
}
.np-btn:hover { background: #f0f3f8; color: #4a5568; }
.np-btn.clear-btn:hover { background: #fff0f0; color: #e53e3e; }
.np-btn i { font-size: 11px; }

/* Filter tabs */
.np-tabs {
    display: flex;
    gap: 2px;
    padding: 10px 14px 0;
    border-bottom: 1px solid #f0f3f8;
    background: #fafbfd;
}
.np-tab {
    padding: 7px 13px;
    border-radius: 8px 8px 0 0;
    font-size: 11px;
    font-weight: 600;
    color: #9aa5b8;
    cursor: pointer;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    border: none;
    background: none;
    position: relative;
    transition: color 0.15s, background 0.15s;
    font-family: inherit;
}
.np-tab:hover { color: #4a5568; background: #f0f3f8; }
.np-tab.active {
    color: #3b7de8;
    background: #eef3fd;
}
.np-tab.active::after {
    content: '';
    position: absolute;
    bottom: -1px; left: 0; right: 0;
    height: 2px;
    background: #3b7de8;
    border-radius: 2px 2px 0 0;
}

/* Scroll list */
.np-list {
    max-height: 340px;
    overflow-y: auto;
    scrollbar-width: thin;
    scrollbar-color: #e2e8f0 transparent;
    background: #fff;
}
.np-list::-webkit-scrollbar { width: 4px; }
.np-list::-webkit-scrollbar-thumb { background: #e2e8f0; border-radius: 2px; }

/* Individual notification item */
.np-item {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 13px 18px 13px 22px;
    text-decoration: none;
    border-bottom: 1px solid #f5f7fb;
    position: relative;
    cursor: pointer;
    transition: background 0.15s;
    animation: npSlideIn 0.28s ease both;
}
@keyframes npSlideIn {
    from { opacity: 0; transform: translateX(-10px); }
    to   { opacity: 1; transform: translateX(0); }
}
.np-item:hover { background: #f8faff; }
.np-item.read { opacity: 0.6; }
.np-item:last-child { border-bottom: none; }

/* Unread indicator bar */
.np-item::before {
    content: '';
    position: absolute;
    left: 0; top: 10px; bottom: 10px;
    width: 3px;
    background: #3b7de8;
    border-radius: 0 3px 3px 0;
    transition: opacity 0.2s;
}
.np-item.read::before { opacity: 0; }

/* Icon bubble */
.np-ico {
    width: 38px; height: 38px;
    border-radius: 11px;
    display: flex; align-items: center; justify-content: center;
    font-size: 15px;
    flex-shrink: 0;
    margin-top: 1px;
}
.np-ico.critical { background: #fff0f0; color: #e53e3e; }
.np-ico.high     { background: #fff8f0; color: #dd6b20; }
.np-ico.scan     { background: #eef3fd; color: #3b7de8; }
.np-ico.target   { background: #f0faf4; color: #2f855a; }
.np-ico.info     { background: #f5f0ff; color: #6b46c1; }

/* Text area */
.np-text { flex: 1; min-width: 0; }
.np-text strong {
    display: block;
    font-size: 13px;
    font-weight: 600;
    color: #1a2236;
    line-height: 1.35;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}
.np-text .np-body {
    font-size: 11.5px;
    color: #6b7a94;
    margin-top: 2px;
    line-height: 1.45;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}
.np-text .np-time {
    font-size: 10.5px;
    color: #b0b9c8;
    margin-top: 5px;
    display: flex;
    align-items: center;
    gap: 4px;
}
.np-time i { font-size: 9px; }

/* Severity chip */
.np-chip {
    display: inline-block;
    font-size: 9.5px;
    font-weight: 700;
    padding: 1.5px 6px;
    border-radius: 4px;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    margin-right: 5px;
    vertical-align: middle;
}
.np-chip.critical { background: #fff0f0; color: #c53030; border: 1px solid #fed7d7; }
.np-chip.high     { background: #fffaf0; color: #c05621; border: 1px solid #feebc8; }
.np-chip.scan     { background: #ebf4ff; color: #2b6cb0; border: 1px solid #bee3f8; }
.np-chip.target   { background: #f0fff4; color: #276749; border: 1px solid #c6f6d5; }

/* Empty state */
.np-empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 44px 20px;
    color: #b0b9c8;
    gap: 10px;
}
.np-empty i { font-size: 30px; color: #dde3ee; }
.np-empty span { font-size: 13px; color: #9aa5b8; }

/* Loading state */
.np-loading {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    padding: 36px 20px;
    color: #9aa5b8;
    font-size: 13px;
}

/* Footer */
.np-footer {
    padding: 11px 18px;
    border-top: 1px solid #f0f3f8;
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: #fafbfd;
}
.np-footer-info {
    font-size: 11px;
    color: #b0b9c8;
}
.np-view-all {
    font-size: 11.5px;
    color: #3b7de8;
    text-decoration: none;
    font-weight: 600;
    padding: 4px 10px;
    border-radius: 7px;
    transition: background 0.15s;
}
.np-view-all:hover { background: #eef3fd; }

/* Badge on bell button */
.nb-bx {
    position: absolute;
    top: -3px; right: -3px;
    min-width: 17px; height: 17px;
    background: #e53e3e;
    color: #fff;
    font-size: 10px;
    font-weight: 700;
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    padding: 0 4px;
    border: 2px solid #fff;
    pointer-events: none;
    transition: transform 0.2s cubic-bezier(.34,1.5,.64,1);
}
.nb-bx.bump { transform: scale(1.35); }

/* ── Sidebar NEW badge ─────────────────────────────────── */
.sb-badge {
    display: inline-flex;
    align-items: center;
    padding: 1px 6px;
    border-radius: 5px;
    font-size: 9px;
    font-weight: 800;
    letter-spacing: .06em;
    text-transform: uppercase;
    background: linear-gradient(135deg, #2563eb, #06b6d4);
    color: #fff;
    margin-left: auto;
    flex-shrink: 0;
    line-height: 1.6;
    box-shadow: 0 1px 4px rgba(37,99,235,.35);
    pointer-events: none;
}
.sb.col .sb-badge { display: none; }

/* ── Responsive: tablet (≤ 900px) ─────────────────────── */
@media (max-width: 900px) {
    .sb { width: 56px !important; }
    .sb .sb-logo-text,
    .sb .ni span,
    .sb .col-btn span { display: none !important; }
    .sb .sb-logo { justify-content: center; padding: .75rem 0; }
    .sb .ni { justify-content: center; padding: .55rem 0; }
    .sb-badge { display: none !important; }
    .sb .col-btn { justify-content: center; }
    :root { --ml: 56px !important; }
}

/* ── Responsive: mobile (≤ 600px) ─────────────────────── */
@media (max-width: 600px) {
    .sb { transform: translateX(-100%); position: fixed; z-index: 1100; width: 220px !important; transition: transform .25s ease; }
    .sb.mob-open { transform: translateX(0); }
    .sb .sb-logo-text,
    .sb .ni span,
    .sb .col-btn span { display: block !important; }
    .sb .sb-logo { justify-content: flex-start; padding: 1rem 1.125rem; }
    .sb .ni { justify-content: flex-start; padding: .55rem 1rem; }
    .sb-badge { display: inline-flex !important; }
    .sb .col-btn { justify-content: flex-start; }
    :root { --ml: 0px !important; }
    .main, #main { margin-left: 0 !important; }
    .hdr { left: 0 !important; }
    .sb-overlay { display: block !important; }
}

/* ── Responsive: small mobile (≤ 440px) ───────────────── */
@media (max-width: 440px) {
    .hdr .srch { display: none; }
    .hdr { padding: 0 .75rem; }
    .content { padding: .625rem .625rem 1rem; }
    .g2 { grid-template-columns: 1fr !important; gap: .625rem !important; }
    .pt h1 { font-size: 1.1rem; }
    .pt p  { font-size: .75rem; }
}

/* ── Mobile sidebar overlay ────────────────────────────── */
.sb-overlay {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,.45);
    z-index: 1099;
    backdrop-filter: blur(2px);
}

/* ── Mobile hamburger btn (injected on small screens) ─── */
.mob-menu-btn {
    display: none;
    background: none;
    border: none;
    font-size: 1.1rem;
    color: var(--text, #111827);
    cursor: pointer;
    padding: .4rem .5rem;
    border-radius: 8px;
    transition: background .15s;
    margin-right: .25rem;
}
.mob-menu-btn:hover { background: var(--border, #e5e7eb); }
@media (max-width: 600px) { .mob-menu-btn { display: flex; align-items: center; } }
`;
        document.head.appendChild(s);
    }

    // ── State ─────────────────────────────────────────────────────────────
    var _notifData   = [];
    var _unreadCount = 0;
    var _activeFilter = 'all'; // 'all' | 'vulnerability' | 'scan' | 'target'
    var _POLL_MS = 30000;

    // ── Sidebar ───────────────────────────────────────────────────────────
    function renderSidebar(active) {
        const items = [
            ['/dashboard',          'fa-solid fa-table-cells-large',  'Dashboard',       null],
            ['/targets',            'fa-solid fa-crosshairs',          'Targets',         null],
            ['/scanning',           'fa-solid fa-magnifying-glass',    'Scanning',        null],
            ['/bulk-ip-scanning',   'fa-solid fa-network-wired',       'Bulk IP Scanner', 'NEW'],
            ['/vulnerabilities',    'fa-solid fa-bug',                 'Vulnerabilities', null],
            ['/reports',            'fa-regular fa-file-lines',        'Reports',         null],
            ['/scheduled',          'fa-solid fa-calendar-check',      'Scheduled',       null],
            ['/features',           'fa-solid fa-bolt',                'Features',        null],
            ['/documentation',      'fa-solid fa-book-open',           'Documentation',   null],
            ['/about',              'fa-solid fa-circle-info',         'About',           null],
            ['/settings',           'fa-solid fa-gear',                'Settings',        null],
        ];
        return `<aside class="sb" id="sb">
            <div class="sb-logo">
                <i class="fa-solid fa-shield-halved"></i>
                <div class="sb-logo-text"><strong>VAPT Scanner</strong><small>Enterprise Security</small></div>
            </div>
            <nav class="sb-nav">
                ${items.map(([h, ic, l, badge]) => `<a href="${h}" class="ni${active === h ? ' on' : ''}" title="${l}"><i class="${ic}"></i><span>${l}</span>${badge ? `<span class="sb-badge">${badge}</span>` : ''}</a>`).join('')}
            </nav>
            <div class="sb-foot">
                <button class="col-btn" onclick="toggleSB()"><i class="fa-solid fa-chevron-left" id="cbI"></i><span>Collapse</span></button>
            </div>
        </aside>`;
    }

    // ── Header ────────────────────────────────────────────────────────────
    function renderHeader() {
        return `<header class="hdr" id="hdr">
            <button class="mob-menu-btn" id="mobMenuBtn" onclick="toggleMobileSB()" title="Menu"><i class="fa-solid fa-bars"></i></button>
            <div class="srch"><i class="fa-solid fa-magnifying-glass"></i><input placeholder="Search targets, scans, vulnerabilities..."></div>
            <div class="hr">
                <div class="nb" style="position:relative">
                    <button class="nb-btn" id="notif-bell-btn" onclick="_toggleNotifPanel(event)" style="position:relative">
                        <i class="fa-regular fa-bell"></i>
                        <span class="nb-bx" id="notif-badge" style="display:none">0</span>
                    </button>
                    <!-- Notification panel -->
                    <div class="notif-panel" id="notif-panel">
                        <div class="np-head">
                            <div class="np-head-left">
                                <div class="np-head-icon"><i class="fa-solid fa-bell"></i></div>
                                <span class="np-head-title">Notifications</span>
                                <span class="np-head-count zero" id="np-count">0</span>
                            </div>
                            <div class="np-head-actions">
                                <button class="np-btn" onclick="_refreshNotifPanel()" title="Refresh">
                                    <i class="fa-solid fa-arrows-rotate"></i>
                                </button>
                                <button class="np-btn clear-btn" onclick="_clearAllNotifs(event)" title="Clear all">
                                    <i class="fa-solid fa-trash-can"></i> Clear
                                </button>
                            </div>
                        </div>
                        <div class="np-tabs">
                            <button class="np-tab active" data-filter="all"            onclick="_setFilter(this,'all')">All</button>
                            <button class="np-tab"        data-filter="vulnerability"  onclick="_setFilter(this,'vulnerability')">Vulns</button>
                            <button class="np-tab"        data-filter="scan"           onclick="_setFilter(this,'scan')">Scans</button>
                            <button class="np-tab"        data-filter="target"         onclick="_setFilter(this,'target')">Targets</button>
                        </div>
                        <div class="np-list" id="np-list">
                            <div class="np-loading"><i class="fa-solid fa-spinner fa-spin"></i> Loading notifications\u2026</div>
                        </div>
                        <div class="np-footer">
                            <span class="np-footer-info" id="np-footer-info">Auto-refreshes every 30s</span>
                            <a href="/vulnerabilities" class="np-view-all">View all &rarr;</a>
                        </div>
                    </div>
                </div>
                <div class="ub" onclick="toggleDrop('ud')">
                    <div class="ua"><i class="fa-regular fa-user"></i></div>
                    <div class="ui"><strong>${(window.__user && window.__user.name) || 'User'}</strong><small>${(window.__user && window.__user.email) || ''}</small></div>
                    <div class="drop ud" id="ud">
                        <div class="ud-hd"><strong>${(window.__user && window.__user.name) || 'User'}</strong><small>${(window.__user && window.__user.email) || ''}</small></div>
                        <a href="/settings"><i class="fa-regular fa-user"></i> Profile Settings</a>
                        <a href="/logout" class="lout"><i class="fa-solid fa-right-from-bracket"></i> Logout</a>
                    </div>
                </div>
            </div>
        </header>`;
    }

    // ── Helpers ───────────────────────────────────────────────────────────
    function _esc(str) {
        return String(str || '')
            .replace(/&/g,'&amp;').replace(/</g,'&lt;')
            .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    function _iconForItem(n) {
        var sev = (n.dot_color || '');
        if (sev === 'r') return { cls: 'critical', icon: 'fa-solid fa-triangle-exclamation' };
        if (sev === 'o') return { cls: 'high',     icon: 'fa-solid fa-circle-exclamation' };
        if (n.type === 'scan')   return { cls: 'scan',   icon: 'fa-solid fa-magnifying-glass' };
        if (n.type === 'target') return { cls: 'target', icon: 'fa-solid fa-crosshairs' };
        return { cls: 'info', icon: 'fa-solid fa-bell' };
    }

    function _chipForItem(n) {
        var sev = n.dot_color;
        if (sev === 'r') return '<span class="np-chip critical">Critical</span>';
        if (sev === 'o') return '<span class="np-chip high">High</span>';
        if (n.type === 'scan')   return '<span class="np-chip scan">Scan</span>';
        if (n.type === 'target') return '<span class="np-chip target">Target</span>';
        return '';
    }

    function _itemHTML(n, delay) {
        var ico  = _iconForItem(n);
        var read = n.read ? ' read' : '';
        var ds   = delay ? ' style="animation-delay:' + delay + 'ms"' : '';
        return '<a href="' + _esc(n.href || '#') + '" class="np-item' + read + '" data-nid="' + _esc(n.id) + '" onclick="_markRead(event,this)"' + ds + '>'
            + '<div class="np-ico ' + ico.cls + '"><i class="' + ico.icon + '"></i></div>'
            + '<div class="np-text">'
            +   '<strong>' + _esc(n.title) + '</strong>'
            +   '<div class="np-body">' + _chipForItem(n) + _esc(n.body) + '</div>'
            +   '<div class="np-time"><i class="fa-regular fa-clock"></i>' + _esc(n.time_label) + '</div>'
            + '</div>'
            + '</a>';
    }

    // ── Render list ───────────────────────────────────────────────────────
    function _renderList() {
        var el = document.getElementById('np-list');
        if (!el) return;
        var filtered = _activeFilter === 'all'
            ? _notifData
            : _notifData.filter(function(n){ return n.type === _activeFilter; });
        if (!filtered.length) {
            el.innerHTML = '<div class="np-empty"><i class="fa-regular fa-bell-slash"></i><span>No notifications here</span></div>';
        } else {
            el.innerHTML = filtered.map(function(n, i){ return _itemHTML(n, i * 40); }).join('');
        }
        // footer info
        var fi = document.getElementById('np-footer-info');
        if (fi) {
            var total = _notifData.length;
            fi.textContent = total ? total + ' notification' + (total !== 1 ? 's' : '') + ' \u00b7 auto-refresh 30s' : 'Auto-refreshes every 30s';
        }
    }

    // ── Badge ─────────────────────────────────────────────────────────────
    function _updateBadge() {
        var badge = document.getElementById('notif-badge');
        var count = document.getElementById('np-count');
        if (badge) {
            if (_unreadCount > 0) {
                badge.textContent  = _unreadCount > 9 ? '9+' : _unreadCount;
                badge.style.display = '';
                badge.classList.add('bump');
                setTimeout(function(){ badge.classList.remove('bump'); }, 400);
            } else {
                badge.style.display = 'none';
            }
        }
        if (count) {
            count.textContent = _unreadCount;
            count.className   = 'np-head-count' + (_unreadCount ? '' : ' zero');
        }
    }

    // ── Panel open/close ──────────────────────────────────────────────────
    window._toggleNotifPanel = function (e) {
        e && e.stopPropagation();
        // close user dropdown
        var ud = document.getElementById('ud');
        if (ud) ud.classList.remove('open');
        var panel = document.getElementById('notif-panel');
        if (!panel) return;
        panel.classList.toggle('open');
    };

    // ── Filter tab ────────────────────────────────────────────────────────
    window._setFilter = function (btn, filter) {
        _activeFilter = filter;
        document.querySelectorAll('.np-tab').forEach(function(t){ t.classList.remove('active'); });
        btn.classList.add('active');
        _renderList();
    };

    // ── Mark single read ──────────────────────────────────────────────────
    window._markRead = function (e, el) {
        var nid = el.getAttribute('data-nid');
        var n   = _notifData.find(function(x){ return x.id === nid; });
        if (n && !n.read) {
            n.read = true;
            el.classList.add('read');
            _unreadCount = Math.max(0, _unreadCount - 1);
            _updateBadge();
        }
    };

    // ── Clear all ─────────────────────────────────────────────────────────
    window._clearAllNotifs = function (e) {
        e && e.stopPropagation();
        _notifData   = [];
        _unreadCount = 0;
        _renderList();
        _updateBadge();
    };

    // ── Refresh ───────────────────────────────────────────────────────────
    window._refreshNotifPanel = function () {
        var el = document.getElementById('np-list');
        if (el) el.innerHTML = '<div class="np-loading"><i class="fa-solid fa-spinner fa-spin"></i> Refreshing\u2026</div>';
        _fetch(false);
    };

    // ── Fetch ─────────────────────────────────────────────────────────────
    function _fetch(silent) {
        fetch('/api/notifications', { credentials: 'same-origin' })
            .then(function(r){ return r.ok ? r.json() : Promise.reject(r.status); })
            .then(function(data) {
                // Preserve already-read state
                var prevRead = {};
                _notifData.forEach(function(n){ if (n.read) prevRead[n.id] = true; });
                _notifData = (data.notifications || []).map(function(n){
                    if (prevRead[n.id]) n.read = true;
                    return n;
                });
                _unreadCount = _notifData.filter(function(n){ return !n.read; }).length;
                _renderList();
                _updateBadge();
            })
            .catch(function() {
                if (!silent) {
                    var el = document.getElementById('np-list');
                    if (el) el.innerHTML = '<div class="np-empty"><i class="fa-solid fa-triangle-exclamation" style="color:#e53e3e"></i><span style="color:#fc8181">Failed to load notifications</span></div>';
                }
            });
    }

    // ── Close panel on outside click ──────────────────────────────────────
    document.addEventListener('click', function(e) {
        if (!e.target.closest('.nb')) {
            var panel = document.getElementById('notif-panel');
            if (panel) panel.classList.remove('open');
        }
        if (!e.target.closest('.ub')) {
            var ud = document.getElementById('ud');
            if (ud) ud.classList.remove('open');
        }
    });

    // ── Init layout ───────────────────────────────────────────────────────
    window.initLayout = function (active) {
        _injectStyles();
        document.body.insertAdjacentHTML('afterbegin', renderSidebar(active));
        document.body.insertAdjacentHTML('afterbegin', renderHeader());
        // Inject mobile overlay
        if (!document.getElementById('sb-overlay')) {
            var ov = document.createElement('div');
            ov.className = 'sb-overlay';
            ov.id        = 'sb-overlay';
            ov.onclick   = function() { closeMobileSB(); };
            document.body.appendChild(ov);
        }
        const mEl = document.getElementById('_main');
        if (mEl) {
            mEl.classList.add('main');
            mEl.id = 'main';
            mEl.style.removeProperty('margin-left');
            mEl.style.removeProperty('transition');
        }
        document.documentElement.style.setProperty('--ml', '220px');
        // Initial fetch + polling
        _fetch(false);
        setInterval(function(){ _fetch(true); }, _POLL_MS);
    };

    // ── Sidebar toggle ────────────────────────────────────────────────────
    window.toggleSB = function () {
        const s  = document.getElementById('sb');
        const i  = document.getElementById('cbI');
        const collapsed = !s.classList.contains('col');
        s.classList.toggle('col');
        i.className = collapsed ? 'fa-solid fa-chevron-right' : 'fa-solid fa-chevron-left';
        const ml = collapsed ? '56px' : '220px';
        document.documentElement.style.setProperty('--ml', ml);
        setTimeout(() => window.dispatchEvent(new Event('resize')), 260);
    };

    // ── Legacy toggleDrop (ud only now) ──────────────────────────────────
    window.toggleDrop = function (id) {
        if (id !== 'ud') return;
        var panel = document.getElementById('notif-panel');
        if (panel) panel.classList.remove('open');
        var el = document.getElementById(id);
        if (el) el.classList.toggle('open');
    };

    // ── Mobile sidebar toggle ─────────────────────────────────────────────
    window.toggleMobileSB = function () {
        var sb = document.getElementById('sb');
        var ov = document.getElementById('sb-overlay');
        if (!sb) return;
        var isOpen = sb.classList.contains('mob-open');
        if (isOpen) { closeMobileSB(); } else { openMobileSB(); }
    };

    window.openMobileSB = function () {
        var sb = document.getElementById('sb');
        var ov = document.getElementById('sb-overlay');
        if (sb) sb.classList.add('mob-open');
        if (ov) ov.style.display = 'block';
        document.body.style.overflow = 'hidden';
    };

    window.closeMobileSB = function () {
        var sb = document.getElementById('sb');
        var ov = document.getElementById('sb-overlay');
        if (sb) sb.classList.remove('mob-open');
        if (ov) ov.style.display = 'none';
        document.body.style.overflow = '';
    };

    // Close sidebar on nav link click (mobile)
    document.addEventListener('click', function(e) {
        var link = e.target.closest('.ni');
        if (link && window.innerWidth <= 600) {
            closeMobileSB();
        }
    });

})();