/* VAPT Scanner Pro - Layout Injector (Flask version) */
(function () {
    // ── Notification state ────────────────────────────────────────────────
    var _notifData   = [];   // cached list from last fetch
    var _unreadCount = 0;
    var _pollTimer   = null;
    var _POLL_MS     = 30000; // refresh every 30 s

    // ── Sidebar ───────────────────────────────────────────────────────────
    function renderSidebar(active) {
        const items = [
            ['/dashboard',      'fa-solid fa-table-cells-large',  'Dashboard'],
            ['/targets',        'fa-solid fa-crosshairs',          'Targets'],
            ['/scanning',       'fa-solid fa-magnifying-glass',    'Scanning'],
            ['/vulnerabilities','fa-solid fa-bug',                 'Vulnerabilities'],
            ['/reports',        'fa-regular fa-file-lines',        'Reports'],
            ['/scheduled',      'fa-solid fa-calendar-check',      'Scheduled'],
            ['/features',       'fa-solid fa-bolt',                'Features'],
            ['/documentation',  'fa-solid fa-book-open',           'Documentation'],
            ['/about',          'fa-solid fa-circle-info',         'About'],
            ['/settings',       'fa-solid fa-gear',                'Settings'],
        ];
        return `<aside class="sb" id="sb">
            <div class="sb-logo">
                <i class="fa-solid fa-shield-halved"></i>
                <div class="sb-logo-text"><strong>VAPT Scanner</strong><small>Enterprise Security</small></div>
            </div>
            <nav class="sb-nav">
                ${items.map(([h, ic, l]) => `<a href="${h}" class="ni${active === h ? ' on' : ''}" title="${l}"><i class="${ic}"></i><span>${l}</span></a>`).join('')}
            </nav>
            <div class="sb-foot">
                <button class="col-btn" onclick="toggleSB()"><i class="fa-solid fa-chevron-left" id="cbI"></i><span>Collapse</span></button>
            </div>
        </aside>`;
    }

    // ── Header (notification panel rendered empty; JS fills it) ──────────
    function renderHeader() {
        return `<header class="hdr" id="hdr">
            <div class="srch"><i class="fa-solid fa-magnifying-glass"></i><input placeholder="Search targets, scans, vulnerabilities..."></div>
            <div class="hr">
                <div class="nb">
                    <button class="nb-btn" onclick="toggleDrop('nd')">
                        <i class="fa-regular fa-bell"></i>
                        <span class="nb-bx" id="notif-badge" style="display:none">0</span>
                    </button>
                    <div class="drop nd" id="nd">
                        <h4><i class="fa-regular fa-bell" style="color:var(--blue)"></i> Notifications
                            <span id="notif-refresh-btn"
                                  onclick="refreshNotifications()"
                                  title="Refresh"
                                  style="float:right;cursor:pointer;font-size:12px;font-weight:400;color:var(--blue)">
                                <i class="fa-solid fa-arrows-rotate"></i>
                            </span>
                        </h4>
                        <div id="notif-list"><div class="nd-loading" style="padding:14px 16px;font-size:13px;color:var(--muted,#888)"><i class="fa-solid fa-spinner fa-spin"></i> Loading\u2026</div></div>
                        <div class="nd-ft"><a href="#" onclick="markAllRead(event)">Mark all as read</a> \u00b7 <a href="#">View all</a></div>
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

    // ── Build HTML for a single notification item ─────────────────────────
    function _notifItemHTML(n) {
        var dotClass = 'nd-dot ' + (n.dot_color || 'b');
        var readClass = n.read ? ' read' : '';
        return '<a href="' + _esc(n.href || '#') + '" class="ni2' + readClass + '" data-nid="' + _esc(n.id) + '" onclick="_onNotifClick(event,this)">'
            + '<div class="' + dotClass + '"></div>'
            + '<div>'
            + '<strong>' + _esc(n.title) + '</strong>'
            + '<small>' + _esc(n.body) + '<br>' + _esc(n.time_label) + '</small>'
            + '</div>'
            + '</a>';
    }

    function _esc(str) {
        return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    // ── Render notification list into the panel ───────────────────────────
    function _renderList() {
        var el = document.getElementById('notif-list');
        if (!el) return;
        if (!_notifData.length) {
            el.innerHTML = '<div style="padding:14px 16px;color:var(--muted,#888);font-size:13px;text-align:center"><i class="fa-regular fa-bell-slash"></i> No notifications</div>';
            return;
        }
        el.innerHTML = _notifData.map(_notifItemHTML).join('');
    }

    // ── Update badge ──────────────────────────────────────────────────────
    function _updateBadge() {
        var badge = document.getElementById('notif-badge');
        if (!badge) return;
        if (_unreadCount > 0) {
            badge.textContent = _unreadCount > 9 ? '9+' : _unreadCount;
            badge.style.display = '';
        } else {
            badge.style.display = 'none';
        }
    }

    // ── Fetch notifications from API ──────────────────────────────────────
    function _fetchNotifications(silent) {
        fetch('/api/notifications', { credentials: 'same-origin' })
            .then(function(r){ return r.ok ? r.json() : Promise.reject(r.status); })
            .then(function(data) {
                // Preserve read state for items already seen
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
                    var el = document.getElementById('notif-list');
                    if (el) el.innerHTML = '<div style="padding:14px 16px;color:#e74c3c;font-size:13px;text-align:center"><i class="fa-solid fa-triangle-exclamation"></i> Could not load notifications</div>';
                }
            });
    }

    // ── Public: manual refresh ────────────────────────────────────────────
    window.refreshNotifications = function () {
        var el = document.getElementById('notif-list');
        if (el) el.innerHTML = '<div style="padding:14px 16px;font-size:13px;color:var(--muted,#888)"><i class="fa-solid fa-spinner fa-spin"></i> Refreshing\u2026</div>';
        _fetchNotifications(false);
    };

    // ── Mark all as read ──────────────────────────────────────────────────
    window.markAllRead = function (e) {
        e.preventDefault();
        _notifData.forEach(function(n){ n.read = true; });
        _unreadCount = 0;
        _renderList();
        _updateBadge();
    };

    // ── Mark single notification read on click ────────────────────────────
    window._onNotifClick = function (e, el) {
        var nid = el.getAttribute('data-nid');
        var n   = _notifData.find(function(x){ return x.id === nid; });
        if (n && !n.read) {
            n.read = true;
            _unreadCount = Math.max(0, _unreadCount - 1);
            el.classList.add('read');
            _updateBadge();
        }
    };

    // ── Start polling ─────────────────────────────────────────────────────
    function _startPolling() {
        _fetchNotifications(false);
        _pollTimer = setInterval(function(){ _fetchNotifications(true); }, _POLL_MS);
    }

    // ── Init layout ───────────────────────────────────────────────────────
    window.initLayout = function (active) {
        document.body.insertAdjacentHTML('afterbegin', renderSidebar(active));
        document.body.insertAdjacentHTML('afterbegin', renderHeader());
        const mEl = document.getElementById('_main');
        if (mEl) {
            mEl.classList.add('main');
            mEl.id = 'main';
            mEl.style.removeProperty('margin-left');
            mEl.style.removeProperty('transition');
        }
        document.documentElement.style.setProperty('--ml', '220px');
        _startPolling();
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

    // ── Dropdown toggle ───────────────────────────────────────────────────
    window.toggleDrop = function (id) {
        ['nd', 'ud'].forEach(d => {
            const el = document.getElementById(d);
            if (el && d !== id) el.classList.remove('open');
        });
        const el = document.getElementById(id);
        if (el) el.classList.toggle('open');
    };

    document.addEventListener('click', e => {
        if (!e.target.closest('.nb') && !e.target.closest('.ub')) {
            ['nd', 'ud'].forEach(d => {
                const el = document.getElementById(d);
                if (el) el.classList.remove('open');
            });
        }
    });
})();