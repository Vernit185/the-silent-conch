import { createFileRoute } from '@tanstack/react-router';
import { useState } from 'react';
import { Radio } from 'lucide-react';
import { useApi } from '@/components/layout/api-context';
import { PageHeading } from '@/components/workspaces/page-heading';
import { ConnectionNotice } from '@/components/workspaces/connection-notice';
import { SessionPanel } from '@/components/workspaces/session-panel';
import { OperationForm } from '@/components/workspaces/operation-form';
import { ResponseReport } from '@/components/evidence/response-report';
import type { ApiResult } from '@/types/api';
export const Route = createFileRoute('/oracle')({ head: () => ({ meta: [{ title: 'Oracle Console — The Silent Conch' }, { name: 'description', content: 'Authorized intelligence query workspace with server-derived retrieval and execution reports.' }, { property: 'og:title', content: 'Oracle Console — The Silent Conch' }, { property: 'og:description', content: 'Inspect real intelligence query results and execution records.' }, { property: 'og:type', content: 'website' }, { name: 'twitter:card', content: 'summary_large_image' }] }), component: Oracle });
function Oracle() {
 const { catalog } = useApi(); const [result, setResult] = useState<ApiResult>();
 return <div className="page-container"><PageHeading number="03" title="ORACLE CONSOLE" subtitle="INTELLIGENCE QUERY SYSTEM" description="Submit an authorized intelligence request. Retrieved records and execution details are reported as returned by the relay."/><ConnectionNotice/><div className="oracle-layout"><SessionPanel contract={catalog?.oracle}/><section className="query-panel"><div className="section-heading"><span>02 / QUERY WORKSPACE</span><Radio size={15}/></div><h3>Intelligence request</h3><OperationForm contract={catalog?.oracle} label="Submit query" onResult={setResult}/>{catalog?.oracle && <details className="technical-details"><summary>Verified request contract</summary><pre>{JSON.stringify(catalog.oracle.operation, null, 2)}</pre></details>}</section><section className="execution-panel"><div className="section-heading"><span>03 / RESULTS & EXECUTION</span><span>{result ? `HTTP ${result.status}` : 'NO RESPONSE'}</span></div><h3>Execution record</h3><ResponseReport result={result}/></section></div></div>;
}
