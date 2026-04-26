/* ═══════════════════════════════════════════════════
   BitR1FT Portfolio — Interactivity (Pure JS)
   ═══════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {

  // ── Navbar scroll effect ──
  const nav = document.querySelector('nav');
  if (nav) {
    window.addEventListener('scroll', () => {
      nav.classList.toggle('scrolled', window.scrollY > 50);
    });
  }

  // ── Mobile menu toggle ──
  const hamburger = document.getElementById('nav-hamburger');
  const mobileMenu = document.getElementById('mobile-menu');
  if (hamburger && mobileMenu) {
    hamburger.addEventListener('click', () => {
      mobileMenu.classList.toggle('open');
    });
    // Close menu on link click
    mobileMenu.querySelectorAll('a').forEach(link => {
      link.addEventListener('click', () => {
        mobileMenu.classList.remove('open');
      });
    });
  }

  // ── Typing animation ──
  const typingEl = document.getElementById('typing-text');
  if (typingEl) {
    const text = typingEl.getAttribute('data-text') || '';
    const cursor = typingEl.querySelector('.cursor-blink');
    let i = 0;

    setTimeout(() => {
      const interval = setInterval(() => {
        if (i < text.length) {
          typingEl.childNodes[0].textContent = text.slice(0, i + 1);
          i++;
        } else {
          clearInterval(interval);
        }
      }, 70);
    }, 400);
  }

});
