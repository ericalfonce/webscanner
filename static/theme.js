/* MulikaScans — shared dark/light theme toggle */
(function () {
    function getTheme() {
        return localStorage.getItem('ms-theme') || 'dark';
    }

    function applyTheme(t) {
        document.documentElement.setAttribute('data-theme', t);
        localStorage.setItem('ms-theme', t);
        var btn = document.getElementById('theme-toggle');
        if (btn) {
            var icon = btn.querySelector('i');
            if (icon) icon.className = t === 'light' ? 'fas fa-moon' : 'fas fa-sun';
            btn.title = t === 'light' ? 'Dark mode' : 'Light mode';
            btn.setAttribute('aria-label', t === 'light' ? 'Switch to dark mode' : 'Switch to light mode');
        }
    }

    window.toggleTheme = function () {
        applyTheme(getTheme() === 'dark' ? 'light' : 'dark');
    };

    document.addEventListener('DOMContentLoaded', function () {
        applyTheme(getTheme());
    });
})();
