import { z } from 'zod';
import type { ApiCatalog, ApiResult, Contract, Field, Json, OpenApi, Operation, Schema } from '@/types/api';

const configuredBase = (import.meta.env['VITE_API_BASE_URL'] ?? '').trim();
export const apiBaseLabel = configuredBase || 'Same-origin';
function endpoint(path: string) {
  if (!configuredBase) return path;
  const base = new URL(configuredBase);
  if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password) throw new Error('API URL must use HTTP or HTTPS and contain no credentials.');
  return `${configuredBase.replace(/\/$/, '')}${path}`;
}
export class ApiError extends Error {
  constructor(message: string, public status?: number, public data?: Json) { super(message); this.name = 'ApiError'; }
}
export function describeError(error: unknown) { return error instanceof Error ? error.message : 'The request could not be completed.'; }
function messageFrom(data: Json): string {
  if (typeof data === 'string') return data.slice(0, 2000);
  if (data && !Array.isArray(data) && typeof data === 'object') {
    if (typeof data['detail'] === 'string') return data['detail'];
    if (typeof data['message'] === 'string') return data['message'];
    if (data['detail']) return JSON.stringify(data['detail']);
  }
  return 'The server rejected this request.';
}
async function readResponse(response: Response): Promise<Json> {
  const text = await response.text();
  if (!text) return null;
  try { return JSON.parse(text) as Json; } catch { return text; }
}
export function resolveSchema(schema: Schema, doc: OpenApi, seen = new Set<string>()): Schema {
  if (schema.$ref) {
    if (!schema.$ref.startsWith('#/components/schemas/') || seen.has(schema.$ref)) return { type: 'unsupported' };
    const name = schema.$ref.split('/').at(-1) ?? '';
    const next = doc.components?.schemas?.[name];
    return next ? resolveSchema(next, doc, new Set([...seen, schema.$ref])) : { type: 'unsupported' };
  }
  if (schema.anyOf) {
    const nonNull = schema.anyOf.filter(s => s.type !== 'null');
    return nonNull.length === 1 ? resolveSchema(nonNull[0] ?? { type: 'unsupported' }, doc, seen) : { type: 'unsupported' };
  }
  if (schema.allOf?.length === 1) return resolveSchema(schema.allOf[0] ?? { type: 'unsupported' }, doc, seen);
  return schema;
}
export function makeContract(path: string, method: 'GET' | 'POST', operation: Operation, doc: OpenApi): Contract {
  const fields: Field[] = [];
  let reason: string | undefined;
  const security = operation.security ?? doc.security ?? [];
  const bearer = security.some(group => Object.keys(group).some(key => {
    const scheme = doc.components?.securitySchemes?.[key];
    return scheme?.type === 'http' && scheme.scheme?.toLowerCase() === 'bearer';
  }));
  if (security.some(group => Object.keys(group).some(key => {
    const scheme = doc.components?.securitySchemes?.[key];
    return !(scheme?.type === 'http' && scheme.scheme?.toLowerCase() === 'bearer');
  }))) reason = 'This operation uses an authorization method not described by the supported bearer-token contract.';
  for (const parameter of operation.parameters ?? []) {
    if (parameter.in !== 'query') { reason = `This operation requires a ${parameter.in} parameter; a verified adapter is needed.`; continue; }
    fields.push({ name: parameter.name, location: 'query', required: !!parameter.required, schema: resolveSchema(parameter.schema ?? {}, doc), description: parameter.description });
  }
  if (operation.requestBody) {
    const raw = operation.requestBody.content?.['application/json']?.schema;
    const schema = raw ? resolveSchema(raw, doc) : undefined;
    if (!schema || schema.type !== 'object' || !schema.properties) reason = 'A verified JSON object request contract is required for this operation.';
    else for (const [name, value] of Object.entries(schema.properties)) fields.push({ name, location: 'body', required: schema.required?.includes(name) ?? false, schema: resolveSchema(value, doc), description: value.description });
  }
  if (fields.some(field => !['string', 'integer', 'number', 'boolean'].includes(field.schema.type ?? ''))) reason = 'The server exposes complex request fields; a contract-specific adapter is required.';
  return { path, method, operation, fields, bearer, supported: !reason, reason };
}
export async function discoverApi(signal?: AbortSignal): Promise<ApiCatalog> {
  let response: Response;
  try { response = await fetch(endpoint('/openapi.json'), { signal: signal ?? null, credentials: 'same-origin', headers: { Accept: 'application/json' } }); }
  catch (error) { if (signal?.aborted) throw error; throw new ApiError('The challenge server could not be reached. Check its URL and cross-origin access.'); }
  const data = await readResponse(response);
  if (!response.ok) throw new ApiError(`API contract unavailable (HTTP ${response.status}). No challenge requests have been sent.`, response.status, data);
  if (!data || typeof data !== 'object' || Array.isArray(data) || !('paths' in data) || !data['paths'] || typeof data['paths'] !== 'object' || !('openapi' in data)) throw new ApiError('No FastAPI contract was returned. The challenge server connection remains unverified.');
  const doc = data as unknown as OpenApi;
  const find = (path: string, method: 'GET' | 'POST') => {
    const operation = doc.paths[path]?.[method.toLowerCase()];
    return operation ? makeContract(path, method, operation, doc) : undefined;
  };
  const recordPath = Object.keys(doc.paths).find(path => /^\/api\/diagnostics\/(records|list)$/.test(path) && doc.paths[path]?.['get']);
  return { document: doc, diagnostics: find('/api/diagnostics/download', 'GET'), oracle: find('/api/oracle/query', 'POST'), archive: find('/api/archive/redeem', 'POST'), records: recordPath ? find(recordPath, 'GET') : undefined };
}
export function validateFields(contract: Contract, values: Record<string, string>): Record<string, Json> {
  const result: Record<string, Json> = {};
  for (const field of contract.fields) {
    const raw = values[field.name] ?? '';
    if (!raw && !field.required) continue;
    let schema: z.ZodTypeAny;
    const limits = field.schema;
    if (limits.type === 'string') {
      let text = z.string().min(field.required ? Math.max(1, limits.minLength ?? 1) : (limits.minLength ?? 0)).max(Math.min(limits.maxLength ?? 32768, 32768));
      if (limits.format === 'email') text = text.email();
      if (limits.format === 'uuid') text = text.uuid();
      schema = text;
    } else if (limits.type === 'boolean') schema = z.enum(['true', 'false']).transform(v => v === 'true');
    else {
      if (!raw.trim()) throw new ApiError(`${field.name}: a numeric value is required.`);
      let number = z.coerce.number().finite();
      if (limits.type === 'integer') number = number.int();
      if (limits.minimum !== undefined) number = number.min(limits.minimum);
      if (limits.maximum !== undefined) number = number.max(limits.maximum);
      schema = number;
    }
    const parsed = schema.safeParse(raw);
    if (!parsed.success) throw new ApiError(`${field.name}: ${parsed.error.issues[0]?.message ?? 'invalid value'}`);
    if (limits.enum && !limits.enum.some(value => value === parsed.data)) throw new ApiError(`${field.name}: select a value permitted by the server.`);
    result[field.name] = parsed.data as Json;
  }
  return result;
}
export async function execute(contract: Contract, values: Record<string, string>, token: string, download = false): Promise<ApiResult> {
  if (!contract.supported) throw new ApiError(contract.reason ?? 'Unsupported request contract.');
  const validated = validateFields(contract, values);
  const params = new URLSearchParams();
  const body: Record<string, Json> = {};
  contract.fields.forEach(field => {
    if (!(field.name in validated)) return;
    if (field.location === 'query') params.append(field.name, String(validated[field.name]));
    else { const value = validated[field.name]; if (value !== undefined) body[field.name] = value; }
  });
  const headers: Record<string, string> = { Accept: download ? '*/*' : 'application/json' };
  if (contract.bearer) {
    const parsedToken = z.string().min(1, 'An authorization token is required.').max(16384).regex(/^[^\s\x00-\x1f\x7f]+$/, 'Token must not contain whitespace or control characters.').safeParse(token.trim());
    if (!parsedToken.success) throw new ApiError(parsedToken.error.issues[0]?.message ?? 'Invalid authorization token.');
    headers['Authorization'] = `Bearer ${parsedToken.data}`;
  }
  if (contract.method === 'POST') headers['Content-Type'] = 'application/json';
  let response: Response;
  try { response = await fetch(`${endpoint(contract.path)}${params.size ? `?${params}` : ''}`, { method: contract.method, headers, credentials: 'same-origin', body: contract.method === 'POST' ? JSON.stringify(body) : null }); }
  catch { throw new ApiError('Network request failed. No result was received from the challenge server.'); }
  const contentType = response.headers.get('content-type') ?? '';
  if (!response.ok) { const data = await readResponse(response); throw new ApiError(messageFrom(data), response.status, data); }
  if (download && !contentType.includes('json')) {
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    const match = response.headers.get('content-disposition')?.match(/filename="?([^";]+)"?/);
    link.href = url; link.download = (match?.[1] ?? 'diagnostic-record').replace(/[\\/\x00-\x1f]/g, '_');
    link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    return { status: response.status, data: { download: link.download, bytes: blob.size }, contentType, receivedAt: new Date().toISOString() };
  }
  return { status: response.status, data: await readResponse(response), contentType, receivedAt: new Date().toISOString() };
}
