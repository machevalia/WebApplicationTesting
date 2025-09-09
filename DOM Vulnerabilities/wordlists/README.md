### DOM Wordlists and PoCs

Use with `DOM Vulnerabilities/Hunt Methodology.md`. Start by mapping sources and sinks, then pick the list/PoC that matches the flow.

Lists
- sources.txt: common controllable sources.
- sinks.txt: risky sinks to grep for.
- postmessage.txt: payloads for message handlers (HTML/nav/JSON.parse).
- clobbering.txt: `id/name` patterns to override globals/properties.
- sanitizer-bypass.txt: patterns for attribute clobbering and focus triggers.
- cookies.txt: patterns for cookie seed and navigation.

PoCs (see `../pocs/`)
- pm_html.html: postMessage → innerHTML.
- pm_nav.html: postMessage → location navigation.
- pm_json.html: postMessage JSON.parse loader.
- cookie_seed_iframe.html: cookie-set then render.
- clobber_default_avatar.html: DOM clobbering defaultAvatar.
- janitor_attr_clobber.html: HTMLJanitor attr clobber + focus.

