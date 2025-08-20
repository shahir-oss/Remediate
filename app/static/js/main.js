// Placeholder for custom JS
console.log('ConiferRemediate loaded');


document.querySelectorAll('.result-link').forEach(link => {
  link.addEventListener('click', e => {
    e.preventDefault();
    window.open(link.href, '_blank', 'width=600,height=400');
  });
});
