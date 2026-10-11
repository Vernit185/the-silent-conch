import { RefreshCw, Unplug, CheckCircle2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useApi } from '@/components/layout/api-context';
export function ConnectionNotice({ compact = false }: { compact?: boolean }) {
 const { catalog, loading, error, refresh } = useApi();
 return <div className={compact ? 'connection-notice compact' : 'connection-notice'} role="status">{catalog ? <CheckCircle2 size={17}/> : <Unplug size={17}/>}<div><strong>{loading ? 'VERIFYING SERVER CONNECTION' : catalog ? 'API CONTRACT AVAILABLE' : 'CHALLENGE SERVER UNVERIFIED'}</strong>{!compact && <p>{loading ? 'Reading the challenge server’s published API contract.' : catalog ? 'Operations are available only where declared by the challenge server.' : error ?? 'No challenge server contract is available.'}</p>}</div><Button variant="ghost" size="icon" onClick={refresh} disabled={loading} aria-label="Retry server connection" title="Retry server connection"><RefreshCw className={loading ? 'animate-spin' : ''}/></Button></div>;
}
