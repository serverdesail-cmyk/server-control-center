(() => {
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduced) return;
  const cards = document.querySelectorAll('.feature-card');
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.classList.add('is-visible');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.12 });
  cards.forEach((card) => observer.observe(card));
  const visual = document.querySelector('.hero-visual');
  if (visual && window.matchMedia('(pointer:fine)').matches) {
    document.addEventListener('pointermove', (event) => {
      const x = (event.clientX / window.innerWidth - 0.5) * 5;
      const y = (event.clientY / window.innerHeight - 0.5) * 5;
      visual.style.setProperty('--tilt-x', `${-y}deg`);
      visual.style.setProperty('--tilt-y', `${x}deg`);
    }, { passive: true });
  }
})();
