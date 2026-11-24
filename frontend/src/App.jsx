import { useCallback, useEffect, useState } from 'react';

const GOOGLE_CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID;
const GOOGLE_PROJECT_NUMBER = GOOGLE_CLIENT_ID?.split('-')[0];
const GMAIL_API_ENABLE_URL = `https://console.cloud.google.com/apis/library/gmail.googleapis.com?project=${GOOGLE_PROJECT_NUMBER}`;
const GMAIL_SCOPE = 'https://www.googleapis.com/auth/gmail.readonly';
const GMAIL_API = 'https://gmail.googleapis.com/gmail/v1/users/me';
const emptyForm = { subject: '', sender: '', body: '', rawEmail: '' };

async function api(path, options = {}) {
  const response = await fetch(`/api${path}`, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = typeof payload.detail === 'string' ? payload.detail : 'The API request failed.';
    throw new Error(detail);
  }
  return payload;
}

async function gmailGet(path, accessToken) {
  const response = await fetch(`${GMAIL_API}${path}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401) throw new Error('Gmail authorization expired. Disconnect and connect Gmail again.');
    if (response.status === 403 && /has not been used|disabled/i.test(payload.error?.message || '')) {
      throw new Error('GMAIL_API_DISABLED');
    }
    throw new Error(payload.error?.message || 'Gmail could not return the requested message.');
  }
  return payload;
}

function decodeBase64Url(value = '') {
  if (!value) return '';
  try {
    const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/'));
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return new TextDecoder('utf-8').decode(bytes);
  } catch {
    return '';
  }
}

function htmlToText(value) {
  const documentNode = new DOMParser().parseFromString(value, 'text/html');
  return documentNode.body?.textContent || '';
}

function getMessageBody(payload) {
  const plain = [];
  const html = [];
  function visit(part) {
    if (!part || part.filename) return;
    const data = decodeBase64Url(part.body?.data);
    if (part.mimeType === 'text/plain' && data) plain.push(data);
    if (part.mimeType === 'text/html' && data) html.push(data);
    (part.parts || []).forEach(visit);
  }
  visit(payload);
  return (plain.length ? plain.join('\n') : html.map(htmlToText).join('\n')).slice(0, 200_000);
}

function getHeader(headers = [], name) {
  return headers.find((header) => header.name?.toLowerCase() === name.toLowerCase())?.value || '';
}

function classify(result) {
  if (result?.model?.status !== 'ready' || result.model.spam_score == null) return 'Needs review';
  return result.model.spam_score >= 0.5 ? 'Likely spam' : 'Not flagged as spam';
}

function Verdict({ children, level = 'neutral' }) {
  return <span className={`verdict verdict-${level}`}>{children}</span>;
}

function ResultPanel({ result }) {
  if (!result) {
    return <section className="panel result-panel empty-result"><h2>Scan result</h2><p>Your findings will appear here after you scan a message.</p></section>;
  }

  const verdict = result.classification || classify(result);
  const verdictLevel = verdict === 'Likely spam' || result.risk_level === 'high' ? 'high' : verdict === 'Needs review' || result.risk_level === 'medium' ? 'review' : 'good';
  const auth = result.authentication || {};

  return (
    <section className="panel result-panel">
      <div className="result-heading">
        <div><span className="section-kicker">SCAN RESULT</span><h2>{result.subject || '(no subject)'}</h2><p className="byline">{result.sender || 'Unknown sender'}</p></div>
        <Verdict level={verdictLevel}>{verdict}</Verdict>
      </div>
      {result.model?.spam_score != null && <div className="model-result">Spam model score <strong>{Math.round(result.model.spam_score * 100)}%</strong><span>Model output is an estimate; review the findings before deciding.</span></div>}
      <div className="result-block"><h3>Findings</h3>
        {result.findings?.length ? <ul className="findings">{result.findings.map((item, index) => <li key={`${item.title}-${index}`}><span className={`finding-dot dot-${item.severity}`} /><div><strong>{item.title}</strong><p>{item.detail}</p></div></li>)}</ul> : <p className="muted-copy">No configured risk indicators matched. That does not guarantee the message is safe.</p>}
      </div>
      {result.urls?.length > 0 && <div className="result-block"><h3>Links found</h3><ul className="plain-list">{result.urls.map((item, index) => <li key={`${item.url}-${index}`}><code>{item.url}</code>{item.flags?.length > 0 && <small>{item.flags.join(' · ')}</small>}</li>)}</ul><p className="muted-copy">Links were inspected as text and never opened.</p></div>}
      {auth.sender_domain && <div className="result-block"><h3>Sender checks</h3><p className="muted-copy">From domain: <strong>{auth.sender_domain}</strong></p><p className="muted-copy">{auth.note}</p></div>}
      <p className="privacy-note">Email body and raw headers are not stored in scan history.</p>
    </section>
  );
}

export default function App() {
  const [form, setForm] = useState(emptyForm);
  const [options, setOptions] = useState({ checkDns: false });
  const [stats, setStats] = useState({ total: 0, high: 0, medium: 0, low: 0 });
  const [history, setHistory] = useState([]);
  const [result, setResult] = useState(null);
  const [health, setHealth] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [fileName, setFileName] = useState('');
  const [gmail, setGmail] = useState(null);
  const [googleReady, setGoogleReady] = useState(Boolean(window.google?.accounts?.oauth2));
  const [gmailMessages, setGmailMessages] = useState([]);
  const [gmailBusy, setGmailBusy] = useState(false);
  const [gmailProgress, setGmailProgress] = useState('');

  const refreshDashboard = useCallback(async () => {
    try {
      const [nextStats, nextHistory, nextHealth] = await Promise.all([
        api('/stats'), api('/history?limit=8'), api('/health'),
      ]);
      setStats(nextStats);
      setHistory(nextHistory.items || []);
      setHealth(nextHealth);
    } catch (requestError) {
      setError(`${requestError.message} Make sure the backend is running.`);
    }
  }, []);

  useEffect(() => { refreshDashboard(); }, [refreshDashboard]);

  useEffect(() => {
    if (googleReady) return undefined;
    const timer = window.setInterval(() => {
      if (window.google?.accounts?.oauth2) {
        setGoogleReady(true);
        window.clearInterval(timer);
      }
    }, 150);
    return () => window.clearInterval(timer);
  }, [googleReady]);

  function changeField(name, value) {
    setForm((current) => ({ ...current, [name]: value, rawEmail: '' }));
    setFileName('');
  }

  async function loadEmailFile(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    if (file.size > 1_000_000) {
      setError('Choose a text-based .eml file smaller than 1 MB.');
      event.target.value = '';
      return;
    }
    try {
      setForm({ ...emptyForm, rawEmail: await file.text() });
      setFileName(file.name);
      setError('');
    } catch {
      setError('Could not read this file. Choose a text-based .eml file.');
    }
    event.target.value = '';
  }

  async function submitAnalysis(event) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const payload = {
        ...(form.rawEmail ? { raw_email: form.rawEmail } : { subject: form.subject, sender: form.sender, body: form.body }),
        check_dns: options.checkDns,
      };
      const nextResult = await api('/analyze', { method: 'POST', body: JSON.stringify(payload) });
      setResult(nextResult);
      await refreshDashboard();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  async function connectGmail() {
    setError('');
    if (!GOOGLE_CLIENT_ID) {
      setError('Google OAuth client ID is missing. Set VITE_GOOGLE_CLIENT_ID in frontend/.env.local and restart Vite.');
      return;
    }
    if (!window.google?.accounts?.oauth2) {
      setError('Google sign-in did not load. Check your internet connection and reload the page.');
      return;
    }
    setGmailBusy(true);
    try {
      const token = await new Promise((resolve, reject) => {
        const client = window.google.accounts.oauth2.initTokenClient({
          client_id: GOOGLE_CLIENT_ID,
          scope: GMAIL_SCOPE,
          callback: (response) => response.error ? reject(new Error(response.error_description || response.error)) : resolve(response.access_token),
          error_callback: (response) => reject(new Error(response.message || 'Google sign-in was closed or blocked.')),
        });
        client.requestAccessToken({ prompt: 'select_account' });
      });
      const profile = await gmailGet('/profile', token);
      setGmail({ accessToken: token, email: profile.emailAddress || 'Gmail connected' });
      setGmailProgress('Connected. Choose “Sync and scan inbox” to analyze the 10 newest messages.');
    } catch (requestError) {
      setError(requestError.message === 'GMAIL_API_DISABLED' ? requestError.message : `Gmail connection failed: ${requestError.message}. Check the Google Cloud OAuth setup.`);
    } finally {
      setGmailBusy(false);
    }
  }

  function disconnectGmail() {
    setGmail(null);
    setGmailMessages([]);
    setGmailProgress('Session cleared from this browser. To revoke the Google app grant, remove Mailwatch from your Google Account security settings.');
  }

  async function syncAndScanGmail() {
    if (!gmail?.accessToken) return;
    setGmailBusy(true);
    setError('');
    setGmailProgress('Loading the 10 newest Inbox messages…');
    try {
      const params = new URLSearchParams({ maxResults: '10', labelIds: 'INBOX' });
      const listed = await gmailGet(`/messages?${params.toString()}`, gmail.accessToken);
      const ids = listed.messages || [];
      if (ids.length === 0) {
        setGmailMessages([]);
        setGmailProgress('No messages found in Inbox.');
        return;
      }

      const messages = [];
      for (let index = 0; index < ids.length; index += 4) {
        const batch = ids.slice(index, index + 4);
        const loaded = await Promise.all(batch.map(async ({ id }) => {
          const message = await gmailGet(`/messages/${encodeURIComponent(id)}?format=full`, gmail.accessToken);
          const headers = message.payload?.headers || [];
          const body = getMessageBody(message.payload) || message.snippet || '';
          const headerBlock = headers.map((header) => `${header.name}: ${header.value}`).join('\r\n');
          return {
            id: message.id,
            subject: getHeader(headers, 'subject') || '(no subject)',
            sender: getHeader(headers, 'from') || 'Unknown sender',
            body,
            snippet: message.snippet || '',
            rawHeaders: `${headerBlock}\r\n\r\n`,
            date: message.internalDate ? new Date(Number(message.internalDate)).toLocaleString() : getHeader(headers, 'date'),
            analysis: null,
            scanError: '',
          };
        }));
        messages.push(...loaded);
      }
      setGmailMessages(messages);

      for (let index = 0; index < messages.length; index += 1) {
        const message = messages[index];
        setGmailProgress(`Analyzing message ${index + 1} of ${messages.length}… The first model run may download files.`);
        try {
          const analysis = await api('/analyze', {
            method: 'POST',
            body: JSON.stringify({
              subject: message.subject,
              sender: message.sender,
              body: message.body,
              raw_email: message.rawHeaders,
            }),
          });
          message.analysis = analysis;
          setGmailMessages((current) => current.map((item) => item.id === message.id ? { ...item, analysis } : item));
        } catch (requestError) {
          message.scanError = requestError.message;
          setGmailMessages((current) => current.map((item) => item.id === message.id ? { ...item, scanError: requestError.message } : item));
        }
      }
      setGmailProgress(`Finished. Scanned ${messages.length} recent Inbox messages. No Gmail messages were changed.`);
      await refreshDashboard();
    } catch (requestError) {
      setError(requestError.message === 'GMAIL_API_DISABLED' ? requestError.message : `Gmail sync failed: ${requestError.message}`);
      setGmailProgress('');
    } finally {
      setGmailBusy(false);
    }
  }

  async function selectHistory(item) {
    try { setResult(await api(`/history/${item.id}`)); }
    catch (requestError) { setError(requestError.message); }
  }

  async function removeHistory(event, id) {
    event.stopPropagation();
    try {
      await api(`/history/${id}`, { method: 'DELETE' });
      if (result?.id === id) setResult(null);
      await refreshDashboard();
    } catch (requestError) { setError(requestError.message); }
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="header-inner">
          <a className="brand" href="#top"><span className="brand-mark">M</span><span>Mailwatch<small>Email review</small></span></a>
          <div className="header-right"><span className={`api-state ${health ? 'connected' : ''}`}><i />{health ? 'Local scanner connected' : 'Connecting to scanner…'}</span></div>
        </div>
      </header>

      <main className="page-container" id="top">
        <section className="intro">
          <div><p className="eyebrow">EMAIL SECURITY</p><h1>Review your email</h1><p className="intro-copy">Scan a message or connect Gmail to check recent Inbox messages for spam signals.</p></div>
          <div className="summary"><span>{stats.total}</span><small>messages scanned</small></div>
        </section>

        {error && <div className="error-banner" role="alert"><span>{error === 'GMAIL_API_DISABLED' ? 'Google sign-in succeeded, but the Gmail API is disabled for this Cloud project. Enable the Gmail API, wait a few minutes, then connect again.' : error}{error === 'GMAIL_API_DISABLED' && <> <a href={GMAIL_API_ENABLE_URL} target="_blank" rel="noreferrer">Open Gmail API settings</a></>}</span><button onClick={() => setError('')} aria-label="Dismiss">×</button></div>}

        <section className="panel gmail-panel">
          <div className="gmail-panel-copy"><div className="gmail-icon" aria-hidden="true">G</div><div><h2>{gmail ? 'Gmail is connected' : 'Connect your Gmail'}</h2><p>{gmail ? gmail.email : 'Read-only access. We scan recent messages and never change your mailbox.'}</p></div></div>
          <div className="gmail-actions">{gmail ? <><button className="button button-primary" onClick={syncAndScanGmail} disabled={gmailBusy}>{gmailBusy ? 'Scanning…' : 'Sync and scan inbox'}</button><button className="button button-link" onClick={disconnectGmail} disabled={gmailBusy}>Clear session</button></> : <button className="button button-secondary" onClick={connectGmail} disabled={gmailBusy || !googleReady}>{gmailBusy ? 'Connecting…' : googleReady ? 'Sign in with Google' : 'Loading sign-in…'}</button>}</div>
          {gmailProgress && <p className="gmail-progress" role="status">{gmailProgress}</p>}
          <p className="privacy-note gmail-privacy">Gmail access is read-only. The sign-in token stays in this browser session; email text is sent to your local scanner for analysis and is not saved in history.</p>
        </section>

        {gmailMessages.length > 0 && <section className="panel inbox-panel"><div className="panel-heading"><div><p className="eyebrow">GMAIL INBOX</p><h2>Recent messages</h2></div><span className="count-label">{gmailMessages.length} scanned</span></div><div className="gmail-message-list">{gmailMessages.map((message) => {
          const verdict = message.analysis ? classify(message.analysis) : message.scanError ? 'Scan failed' : 'Waiting';
          const level = verdict === 'Likely spam' ? 'high' : verdict === 'Not flagged as spam' ? 'good' : 'review';
          return <article className="gmail-message" key={message.id}><div className="message-main"><div className="message-meta"><strong>{message.sender}</strong><span>{message.date}</span></div><h3>{message.subject}</h3><p>{message.analysis?.findings?.[0]?.title || message.snippet || message.body.slice(0, 180) || 'No preview available.'}</p>{message.scanError && <small className="scan-error">{message.scanError}</small>}</div><div className="message-verdict"><Verdict level={level}>{verdict}</Verdict>{message.analysis?.model?.spam_score != null && <small>Spam score {Math.round(message.analysis.model.spam_score * 100)}%</small>}{message.analysis && <button className="text-button" onClick={() => setResult(message.analysis)}>View report</button>}</div></article>;
        })}</div><p className="muted-copy inbox-note">“Not flagged as spam” means the model did not flag it; it is not a safety guarantee. Emails are only read and analyzed.</p></section>}

        <section className="workspace">
          <section className="panel form-panel"><div className="panel-heading"><div><p className="eyebrow">MANUAL SCAN</p><h2>Scan a message</h2></div><span className="optional-label">PASTE OR LOAD .EML</span></div>
            <form onSubmit={submitAnalysis}>
              <label htmlFor="subject">Subject <span>optional</span></label><input id="subject" value={form.subject} disabled={Boolean(form.rawEmail)} onChange={(event) => changeField('subject', event.target.value)} placeholder="Email subject" />
              <label htmlFor="sender">Sender <span>optional</span></label><input id="sender" value={form.sender} disabled={Boolean(form.rawEmail)} onChange={(event) => changeField('sender', event.target.value)} placeholder="name@example.com" />
              <label htmlFor="body">Message body</label><textarea id="body" value={form.body} disabled={Boolean(form.rawEmail)} maxLength={200000} onChange={(event) => changeField('body', event.target.value)} placeholder="Paste the email text here…" rows={7} />
              <div className="file-row"><label className="file-control"><input type="file" accept=".eml,message/rfc822,text/plain" onChange={loadEmailFile} /><span>{fileName || 'Choose a .eml file (up to 1 MB)'}</span></label>{fileName && <button type="button" className="clear-file" onClick={() => { setForm(emptyForm); setFileName(''); }}>Clear file</button>}</div>
              <p className="classifier-note">Spam classification always runs with DistilBERT. The first scan downloads the model and runs it on CPU.</p>
              <details className="advanced-options"><summary>Optional checks</summary><div className="checkboxes"><label><input type="checkbox" checked={options.checkDns} onChange={(event) => setOptions((old) => ({ ...old, checkDns: event.target.checked }))} />Check sender DNS records</label></div></details>
              <button className="button button-primary analyze-button" type="submit" disabled={busy || (!form.rawEmail && !form.subject.trim() && !form.body.trim())}>{busy ? 'Analyzing…' : 'Analyze message'}</button>
              <p className="muted-copy form-note">Links are inspected but never opened. Attachments are not executed or analyzed.</p>
            </form>
          </section>
          <ResultPanel result={result} />
        </section>

        <section className="panel history-panel"><div className="panel-heading"><div><p className="eyebrow">SAVED LOCALLY</p><h2>Recent scan history</h2></div><span className="count-label">{stats.total} total</span></div>{history.length ? <div className="history-list">{history.map((item) => <article className="history-row" key={item.id} onClick={() => selectHistory(item)}><div><strong>{item.subject || '(no subject)'}</strong><small>{item.sender} · {new Date(item.created_at).toLocaleString()}</small></div><div className="history-actions"><Verdict level={item.classification === 'Likely spam' ? 'high' : item.classification === 'Not flagged as spam' ? 'good' : item.risk_level === 'high' ? 'high' : 'review'}>{item.classification || item.risk_level}</Verdict><button className="delete-button" onClick={(event) => removeHistory(event, item.id)} aria-label={`Delete scan ${item.id}`}>Delete</button></div></article>)}</div> : <p className="muted-copy no-history">Scanned messages will appear here. Email bodies are not stored.</p>}</section>

        <footer className="footer-note">The classifier is experimental. Use its result as a review aid, not a guarantee that an email is safe.</footer>
      </main>
    </div>
  );
}
