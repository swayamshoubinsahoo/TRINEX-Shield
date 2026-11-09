const $ = id => document.getElementById(id);
chrome.tabs.query({ active: true, currentWindow: true }, t => {
  const url = (t[0] && t[0].url) || '', a = analyse(url), u = $('u'), f = $('f');
  const span = (cls, txt) => { const s = document.createElement('span'); s.className = cls; s.textContent = txt; return s };
  u.textContent = '';
  if (!a) { u.textContent = 'Open a website (http or https) to analyse it.'; $('go').disabled = true; return }
  u.append(span('p', a.sc));
  if (a.sub) { u.append(span('sub', a.sub), span('p', '.')) }
  u.append(span('dom', a.dom));
  if (a.tld) u.append(span('p', '.'), span('tld', a.tld));
  u.append(span('p', a.rest));
  if (a.fl.length) a.fl.forEach(x => { const d = document.createElement('span'); d.className = 'fl'; d.textContent = x; f.append(d) });
  else { const d = document.createElement('div'); d.className = 'ok'; d.textContent = 'No URL red flags. This is not proof the site is safe.'; f.append(d) }
  $('go').onclick = () => chrome.tabs.create({ url: 'http://127.0.0.1:8000/?url=' + encodeURIComponent(url) });
});
