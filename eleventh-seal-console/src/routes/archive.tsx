import { createFileRoute } from '@tanstack/react-router';
import { useState } from 'react';
import { LockKeyhole } from 'lucide-react';
import { useApi } from '@/components/layout/api-context';
import { PageHeading } from '@/components/workspaces/page-heading';
import { ConnectionNotice } from '@/components/workspaces/connection-notice';
import { SessionPanel } from '@/components/workspaces/session-panel';
import { OperationForm } from '@/components/workspaces/operation-form';
import { ResponseReport } from '@/components/evidence/response-report';
import type { ApiResult } from '@/types/api';
export const Route = createFileRoute('/archive')({ head: () => ({ meta: [{ title: 'Sealed Archive — The Silent Conch' }, { name: 'description', content: 'Server-authorized archive ticket redemption for The Eleventh Seal.' }, { property: 'og:title', content: 'Sealed Archive — The Silent Conch' }, { property: 'og:description', content: 'Submit an archive ticket for authorization and redemption.' }, { property: 'og:type', content: 'website' }, { name: 'twitter:card', content: 'summary_large_image' }] }), component: Archive });
function Archive() {
 const { catalog } = useApi(); const [result, setResult] = useState<ApiResult>();
 return <div className="page-container"><PageHeading number="04" title="SEALED ARCHIVE" subtitle="AUTHORIZATION & REDEMPTION" description="Establish the validity of an archive request. Ticket authorization and redemption are determined exclusively by the challenge server."/><ConnectionNotice/><div className="archive-layout"><SessionPanel contract={catalog?.archive}/><section className="archive-request"><div className="section-heading"><span>02 / ARCHIVE REQUEST</span><LockKeyhole size={15}/></div><h3>Redeem archive ticket</h3><OperationForm contract={catalog?.archive} label="Redeem ticket" onResult={setResult}/><div className="archive-policy"><span className="eyebrow">AUTHORIZATION POLICY</span><p>Only a server-accepted request can release an archive response. No archive content is stored in this application.</p></div></section><section className="execution-panel"><div className="section-heading"><span>03 / REDEMPTION RECORD</span><span>{result ? `HTTP ${result.status}` : 'NO RESPONSE'}</span></div><h3>Archive response</h3><ResponseReport result={result}/></section></div></div>;
}
