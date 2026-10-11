export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export interface Schema { type?: string; format?: string; description?: string | undefined; title?: string; properties?: Record<string, Schema>; required?: string[]; items?: Schema; enum?: Json[]; $ref?: string; allOf?: Schema[]; anyOf?: Schema[]; maxLength?: number; minLength?: number; minimum?: number; maximum?: number; default?: Json; }
export interface Parameter { name: string; in: string; required?: boolean; description?: string | undefined; schema?: Schema; }
export interface Operation { operationId?: string; summary?: string; description?: string | undefined; parameters?: Parameter[]; requestBody?: { required?: boolean; content?: Record<string, { schema?: Schema }> }; security?: Record<string, string[]>[]; responses?: Record<string, unknown>; }
export interface OpenApi { openapi?: string; paths: Record<string, Record<string, Operation>>; components?: { schemas?: Record<string, Schema>; securitySchemes?: Record<string, { type?: string; scheme?: string }> }; security?: Record<string, string[]>[]; }
export interface Contract { path: string; method: 'GET' | 'POST'; operation: Operation; fields: Field[]; bearer: boolean; supported: boolean; reason?: string | undefined; }
export interface Field { name: string; location: 'query' | 'body'; required: boolean; schema: Schema; description?: string | undefined; }
export interface ApiCatalog { document: OpenApi; diagnostics?: Contract | undefined; records?: Contract | undefined; oracle?: Contract | undefined; archive?: Contract | undefined; }
export interface ApiResult { status: number; data: Json; contentType: string; receivedAt: string; }
