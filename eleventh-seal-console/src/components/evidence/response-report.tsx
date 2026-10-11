import { useState } from 'react';
import { Check, Copy, FileText } from 'lucide-react';
import { Button } from '@/components/ui/button';
import type { ApiResult, Json } from '@/types/api';
export function CopyValue({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  const [failed, setFailed] = useState(false);
  const copy = async () => { try { await navigator.clipboard.writeText(value); setCopied(true); setFailed(false); setTimeout(() => setCopied(false), 1800); } catch { setFailed(true); } };
  return <span className="copy-control"><Button variant="ghost" size="icon" onClick={copy} aria-label="Copy response" title="Copy response">{copied ? <Check/> : <Copy/>}</Button>{failed && <span role="status">Copy unavailable</span>}</span>;
}
function JsonValue({ data }: { data: Json }) {
  if (data && typeof data === 'object' && !Array.isArray(data)) return <div className="response-fields">{Object.entries(data).map(([key, value]) => <section className="response-field" key={key}><h4>{key.replace(/_/g, ' ')}</h4><pre>{typeof value === 'string' ? value : JSON.stringify(value, null, 2)}</pre></section>)}</div>;
  return <pre className="raw-response">{typeof data === 'string' ? data : JSON.stringify(data, null, 2)}</pre>;
}
export function ResponseReport({ result }: { result?: ApiResult | undefined }) {
  if (!result) return <div className="result-empty"><FileText size={28} strokeWidth={1}/><span>NO REQUEST RESULTS</span><p>No server response has been received.</p></div>;
  return <div className="response-report" aria-live="polite"><div className="response-meta"><span className="text-primary">HTTP {result.status}</span><time>{result.receivedAt}</time><CopyValue value={typeof result.data === 'string' ? result.data : JSON.stringify(result.data, null, 2)}/></div>{result.data === null ? <p className="empty-copy">The server returned an empty response.</p> : <JsonValue data={result.data}/>}<details className="technical-details"><summary>Response details</summary><dl><dt>Content type</dt><dd>{result.contentType || 'Not supplied'}</dd><dt>Received</dt><dd>{result.receivedAt}</dd></dl></details></div>;
}
