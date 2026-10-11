import { useState } from 'react';
import { Eye, EyeOff, Fingerprint } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useApi } from '@/components/layout/api-context';
import type { Contract } from '@/types/api';
export function SessionPanel({ contract }: { contract?: Contract | undefined }) {
  const { token, setToken } = useApi();
  const [visible, setVisible] = useState(false);
  const toggle = () => setVisible(value => !value);
  const clear = () => setToken('');
  return <aside className="session-panel"><div className="section-heading"><span>01 / AUTHORIZATION</span><Fingerprint size={15}/></div><h3>Session credentials</h3><div className="session-status"><span className="status-dot muted"/>{token ? 'Token supplied · not verified' : 'No authorized session'}</div><div className="form-field"><label htmlFor="authorization-token">Bearer token</label><div className="token-input"><input id="authorization-token" type={visible ? 'text' : 'password'} value={token} onChange={event => setToken(event.target.value)} maxLength={16384} autoComplete="off" spellCheck={false} placeholder="Authorization token"/><Button variant="ghost" size="icon" onClick={toggle} aria-label={visible ? 'Hide token' : 'Show token'}>{visible ? <EyeOff/> : <Eye/>}</Button></div><p className="field-help">{contract ? contract.bearer ? 'Bearer authorization required by the server.' : 'No bearer requirement is declared for this operation.' : 'Authorization requirements are unverified.'}</p></div>{token && <Button variant="outline" size="sm" onClick={clear}>Clear token</Button>}<dl className="session-facts"><dt>Credential storage</dt><dd>Memory only</dd><dt>Session verification</dt><dd>Server-authoritative</dd><dt>Case binding</dt><dd>Not supplied</dd></dl></aside>;
}
