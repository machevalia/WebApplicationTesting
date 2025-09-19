Encounter Cliff Notes

- Basic clickjacking (CSRF-protected action)
  - Framed the site with transparent iframe. Aligned a bait "click" over the dangerous button (delete/change). One click executed action despite CSRF token in-page.

- Prefilled form data via URL param
  - Target page prefilled email from `?email=...`. Iframed that URL and aligned user click to submit → changed victim email.

- Frame buster bypass (sandbox)
  - Page tried to detect `top != self`. Used `<iframe sandbox="allow-forms">` without `allow-top-navigation` to neutralize busting and still submit forms.

- Clickjacking to trigger DOM XSS
  - Feedback page reflected `name` unsafely. Iframed a URL with `name=<img onerror=print()>` and aligned click to submit.

- Multi-step clickjacking
  - Two overlay elements positioned over two separate buttons. First click triggers step 1, second click triggers confirmation.


