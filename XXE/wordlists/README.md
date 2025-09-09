### XXE Wordlists and PoCs

Use with `XXE/Hunt Methodology.md`. Start with minimal read-file/OOB probes, then escalate to parameter entities and external DTDs.

Lists
- read-file.txt: internal subset file exfil payloads.
- ssrf.txt: external entity SSRF targets (metadata endpoints).
- blind-oob.txt: OAST callbacks (entity and parameter-entity variants).
- param-entities.txt: `%`-style entity and inclusion patterns.
- external-dtd.txt: DTD snippets for stacked exfil.
- xinclude.txt: XInclude probes.
- svg-xxe.txt: SVG-based XXE samples.

PoCs (see `../pocs/`)
- inline_entity.xml: single-request internal subset XXE.
- external_dtd.xml: references hosted DTD for stacked exfil.
- error_exfil.xml: forces error including file content.
- svg_read.svg: in-band file read via SVG entity.

Tool
- `../tools/xxepost.sh`: send XML with curl including custom headers.

