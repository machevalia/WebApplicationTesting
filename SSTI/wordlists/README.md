### SSTI Payload Lists

Engine-specific payload files:
- jinja2.txt
- tornado.txt
- twig.txt
- smarty.txt
- freemarker.txt
- spring_spel_thymeleaf.txt
- velocity.txt
- erb_ejs.txt
- jsp_el.txt
- mako.txt
- handlebars.txt

Tips
- Start with math probes (e.g., `{{7*7}}`, `${7*7}`, `*{7*7}`) to fingerprint engines.
- Escalate to environment/file read and finally command exec where applicable.
- Use the URL-encoded variants file if injecting into URLs.

