/* BHRAM Technologies — Main JS */
'use strict';

// ── Mobile Navigation Toggle ─────────────────────────────────────────────────
const navToggle = document.getElementById('nav-toggle');
const navLinks  = document.getElementById('nav-links');
if (navToggle && navLinks) {
    navToggle.addEventListener('click', () => {
        navLinks.classList.toggle('open');
    });
}

// ── Navbar scroll effect ─────────────────────────────────────────────────────
const navbar = document.getElementById('navbar');
if (navbar) {
    window.addEventListener('scroll', () => {
        navbar.style.borderBottomColor = window.scrollY > 10
            ? 'rgba(30,45,74,0.8)'
            : 'rgba(30,45,74,0.4)';
    }, { passive: true });
}

// ── Auto-dismiss flash messages ───────────────────────────────────────────────
document.querySelectorAll('.flash').forEach(el => {
    setTimeout(() => {
        el.style.transition = 'opacity 0.5s';
        el.style.opacity = '0';
        setTimeout(() => el.remove(), 500);
    }, 6000);
});
