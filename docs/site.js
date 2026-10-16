'use strict';

const lightbox = document.querySelector('.lightbox');
const siteShell = document.querySelector('.site-shell');
const closeButton = lightbox.querySelector('.lightbox-close');
const expandedImage = lightbox.querySelector('img');
const caption = lightbox.querySelector('figcaption');
let activeTrigger = null;

function closeFigure() {
  lightbox.hidden = true;
  siteShell.inert = false;
  document.body.classList.remove('is-modal-open');
  if (activeTrigger) {
    activeTrigger.setAttribute('aria-expanded', 'false');
    activeTrigger.focus();
  }
}

for (const trigger of document.querySelectorAll('[data-lightbox]')) {
  trigger.addEventListener('click', () => {
    activeTrigger = trigger;
    expandedImage.src = trigger.dataset.lightbox;
    expandedImage.alt = trigger.querySelector('img').alt;
    caption.textContent = trigger.dataset.caption;
    lightbox.setAttribute('aria-label', expandedImage.alt);
    trigger.setAttribute('aria-expanded', 'true');
    lightbox.hidden = false;
    siteShell.inert = true;
    document.body.classList.add('is-modal-open');
    closeButton.focus();
  });
}

closeButton.addEventListener('click', closeFigure);
lightbox.addEventListener('click', event => {
  if (event.target === lightbox) closeFigure();
});
lightbox.addEventListener('keydown', event => {
  if (event.key === 'Escape') closeFigure();
  if (event.key === 'Tab') {
    event.preventDefault();
    closeButton.focus();
  }
});
