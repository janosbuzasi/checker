function copyJson() {
    const jsonElement = document.getElementById('jsonOutput');
    const statusElement = document.getElementById('copyStatus');

    if (!jsonElement) {
        return;
    }

    const jsonText = jsonElement.textContent || '';

    navigator.clipboard.writeText(jsonText).then(() => {
        if (statusElement) {
            statusElement.style.display = 'block';

            setTimeout(() => {
                statusElement.style.display = 'none';
            }, 1800);
        }
    }).catch(() => {
        if (statusElement) {
            statusElement.textContent = 'Copy failed.';
            statusElement.style.display = 'block';

            setTimeout(() => {
                statusElement.style.display = 'none';
                statusElement.textContent = 'JSON copied.';
            }, 1800);
        }
    });
}

document.addEventListener('DOMContentLoaded', function () {
    const menuButton = document.querySelector('.menu-toggle');
    const menu = document.querySelector('.main-menu');
    const submenuButtons = document.querySelectorAll('.submenu-toggle');

    if (!menuButton || !menu) {
        return;
    }

    function closeMenu() {
        menu.classList.remove('active');
        menuButton.setAttribute('aria-expanded', 'false');
        menuButton.querySelector('.sr-only').textContent = 'Menu open';
    }

    menuButton.addEventListener('click', function () {
        const isOpen = menu.classList.toggle('active');
        menuButton.setAttribute('aria-expanded', String(isOpen));
        menuButton.querySelector('.sr-only').textContent = isOpen ? 'Menu close' : 'Menu open';
    });

    submenuButtons.forEach(function (submenuButton) {
        submenuButton.addEventListener('click', function () {
            const group = submenuButton.closest('.menu-group');
            const isOpen = group.classList.toggle('open');
            submenuButton.setAttribute('aria-expanded', String(isOpen));
        });
    });

    document.addEventListener('click', function (event) {
        if (!menu.contains(event.target) && !menuButton.contains(event.target)) {
            closeMenu();
        }
    });

    document.addEventListener('keydown', function (event) {
        if (event.key === 'Escape') {
            closeMenu();
            menuButton.focus();
        }
    });
});
