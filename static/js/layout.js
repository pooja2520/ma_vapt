/* VAPT Scanner Pro - Layout Injector (Flask version) */
(function () {
    function renderSidebar(active) {
        const items = [
            ['/dashboard', 'fa-solid fa-table-cells-large', 'Dashboard'],
            ['/targets', 'fa-solid fa-crosshairs', 'Targets'],
            ['/scanning', 'fa-solid fa-magnifying-glass', 'Scanning'],
            ['/vulnerabilities', 'fa-solid fa-bug', 'Vulnerabilities'],
            ['/reports', 'fa-regular fa-file-lines', 'Reports'],
            ['/features', 'fa-solid fa-bolt', 'Features'],
            ['/documentation', 'fa-solid fa-book-open', 'Documentation'],
            ['/about', 'fa-solid fa-circle-info', 'About'],
            ['/settings', 'fa-solid fa-gear', 'Settings'],
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

    function renderHeader() {
        return `<header class="hdr" id="hdr">
            <div class="srch"><i class="fa-solid fa-magnifying-glass"></i><input placeholder="Search targets, scans, vulnerabilities..."></div>
            <div class="hr">
                <div class="nb">
                    <button class="nb-btn" onclick="toggleDrop('nd')"><i class="fa-regular fa-bell"></i><span class="nb-bx">3</span></button>
                    <div class="drop nd" id="nd">
                        <h4><i class="fa-regular fa-bell" style="color:var(--blue)"></i> Notifications</h4>
                        <div class="ni2"><div class="nd-dot r"></div><div><strong>Critical vulnerability found</strong><small>SQL Injection in login endpoint<br>2 min ago</small></div></div>
                        <div class="ni2"><div class="nd-dot b"></div><div><strong>Scan completed</strong><small>Production Web App scan finished<br>15 min ago</small></div></div>
                        <div class="ni2"><div class="nd-dot b"></div><div><strong>New target added</strong><small>staging.example.com was added<br>1 hour ago</small></div></div>
                        <div class="nd-ft"><a href="#">View all notifications</a></div>
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

    window.initLayout = function (active) {
        document.body.insertAdjacentHTML('afterbegin', renderSidebar(active));
        document.body.insertAdjacentHTML('afterbegin', renderHeader());
        const mEl = document.getElementById('_main');
        if (mEl) {
            mEl.classList.add('main');
            mEl.id = 'main';
            // Remove any inline margin — layout is controlled by --ml CSS variable
            mEl.style.removeProperty('margin-left');
            mEl.style.removeProperty('transition');
        }
        // Set initial CSS variable value
        document.documentElement.style.setProperty('--ml', '220px');
    };

    window.toggleSB = function () {
        const s  = document.getElementById('sb');
        const i  = document.getElementById('cbI');
        const collapsed = !s.classList.contains('col');
        s.classList.toggle('col');
        i.className = collapsed ? 'fa-solid fa-chevron-right' : 'fa-solid fa-chevron-left';
        // Update CSS variable — this moves BOTH header and main simultaneously
        const ml = collapsed ? '56px' : '220px';
        document.documentElement.style.setProperty('--ml', ml);
        // Dispatch resize so Chart.js and other responsive elements reflow
        setTimeout(() => window.dispatchEvent(new Event('resize')), 260);
    };

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