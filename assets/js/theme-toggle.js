document.addEventListener('DOMContentLoaded', () => {
  const toggleButton = document.getElementById('theme-toggle');
  const body = document.body;
  const currentTheme = localStorage.getItem('theme');

  if (currentTheme) {
    body.setAttribute('data-theme', currentTheme);
  } else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
    body.setAttribute('data-theme', 'dark');
  }

  if (toggleButton) {
    toggleButton.addEventListener('click', () => {
      if (body.getAttribute('data-theme') === 'dark') {
        body.setAttribute('data-theme', 'light');
        localStorage.setItem('theme', 'light');
      } else {
        body.setAttribute('data-theme', 'dark');
        localStorage.setItem('theme', 'dark');
      }
    });
  }
});
