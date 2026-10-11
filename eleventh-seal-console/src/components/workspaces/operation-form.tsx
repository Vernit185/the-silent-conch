import { useRef, useState, type FormEvent } from 'react';
import { ArrowRight, Download, LoaderCircle, AlertCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useApi } from '@/components/layout/api-context';
import { ApiError, describeError, execute } from '@/services/api';
import type { ApiResult, Contract } from '@/types/api';
export function OperationForm({ contract, label, onResult, download = false }: { contract?: Contract | undefined; label: string; onResult: (result: ApiResult) => void; download?: boolean }) {
  const { token, catalog, loading } = useApi();
  const [values, setValues] = useState<Record<string, string>>({});
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string>();
  const [status, setStatus] = useState<number>();
  const lock = useRef(false);
  const submit = async (event: FormEvent) => {
    event.preventDefault(); if (!contract || lock.current) return;
    lock.current = true; setPending(true); setError(undefined); setStatus(undefined);
    try { const result = await execute(contract, values, token, download); onResult(result); }
    catch (error) { setError(describeError(error)); if (error instanceof ApiError) setStatus(error.status); }
    finally { setPending(false); lock.current = false; }
  };
  const unavailable = !contract || !contract.supported;
  return <form className="operation-form" onSubmit={submit}>
    {contract?.fields.map(field => {
      const id = `${contract.method}-${field.location}-${field.name}`;
      const isLong = /query|question|prompt|message|instruction/i.test(field.name);
      return <div className="form-field" key={id}><label htmlFor={id}>{field.name.replace(/_/g, ' ')}{field.required && <span className="required-mark"> *</span>}</label>{field.schema.enum || field.schema.type === 'boolean' ? <select id={id} value={values[field.name] ?? ''} required={field.required} disabled={pending} onChange={event => setValues(previous => ({ ...previous, [field.name]: event.target.value }))}><option value="">Select value</option>{(field.schema.enum ?? [true, false]).map(option => <option value={String(option)} key={String(option)}>{String(option)}</option>)}</select> : isLong ? <textarea id={id} value={values[field.name] ?? ''} required={field.required} maxLength={Math.min(field.schema.maxLength ?? 32768, 32768)} minLength={field.schema.minLength} disabled={pending} rows={9} onChange={event => setValues(previous => ({ ...previous, [field.name]: event.target.value }))} placeholder="Enter intelligence query…"/> : <input id={id} value={values[field.name] ?? ''} type={/ticket|token/i.test(field.name) ? 'password' : 'text'} autoComplete="off" spellCheck={false} required={field.required} maxLength={Math.min(field.schema.maxLength ?? 32768, 32768)} disabled={pending} onChange={event => setValues(previous => ({ ...previous, [field.name]: event.target.value }))}/>}{field.description && <p className="field-help">{field.description}</p>}<span className="field-source">{field.location.toUpperCase()} / {field.schema.type}</span></div>;
    })}
    {unavailable && <div className="unavailable-form"><label>{download ? 'Record request' : label === 'Submit query' ? 'Intelligence query' : 'Archive ticket'}</label>{label === 'Submit query' ? <textarea disabled rows={8} placeholder="Query workspace awaiting a verified server contract"/> : <input disabled placeholder="Awaiting verified request fields"/>}<p className="field-help">{loading ? 'Reading server contract…' : contract?.reason ?? (catalog ? 'This operation is not exposed by the server contract.' : 'Request fields and authorization requirements are not yet verified.')}</p></div>}
    {error && <div className="request-error" role="alert"><AlertCircle size={16}/><div>{status && <strong>HTTP {status} {status === 401 ? '· AUTHORIZATION REJECTED' : ''}</strong>}<p>{error}</p></div></div>}
    <div className="form-actions"><span>{pending ? 'REQUEST IN PROGRESS' : 'SERVER-VALIDATED REQUEST'}</span><Button type="submit" disabled={unavailable || pending} variant="default">{pending ? <LoaderCircle className="animate-spin"/> : download ? <Download/> : null}{pending ? 'Processing…' : label}{!pending && !download && <ArrowRight/>}</Button></div>
  </form>;
}
