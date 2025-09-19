Encounter Cliff Notes

- Basic SSTI in query param (ERB)
  - Message reflected through a template engine. ERB payloads worked: `<%= 7*7 %>`, then file read and `system()` to delete target file.

- Code-context SSTI (Tornado)
  - Comment author display field was templated. Injected Tornado template to import `os` and run `os.system('rm ...')` via crafted value.

- Admin template editor (Freemarker)
  - Logged in to template editor. Used Freemarker execute utility to run commands.

- Unknown engine → induce error → Handlebars
  - Triggered error in out-of-stock message to leak engine. Switched to documented handlebars exploit to execute.

- Framework info disclosure via template objects (Django)
  - Used `{% debug %}` and `{{ settings.SECRET_KEY }}` to dump secrets once template context accessible.


