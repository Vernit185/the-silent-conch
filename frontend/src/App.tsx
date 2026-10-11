import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Terminal, 
  Database, 
  Lock, 
  Unlock, 
  Download, 
  Activity, 
  Cpu, 
  AlertTriangle, 
  CheckCircle2, 
  Copy, 
  RefreshCw,
  Eye,
  Send,
  Radio,
  FileText
} from 'lucide-react';

interface DiagnosticRecord {
  id: string;
  name: string;
  classification: string;
  timestamp: string;
  description: string;
  access: string;
  download_url: string | null;
  mac: string | null;
  ref: string;
}

export function App() {
  const [activeTab, setActiveTab] = useState<'overview' | 'diagnostics' | 'oracle' | 'archive'>('overview');
  const [records, setRecords] = useState<DiagnosticRecord[]>([]);
  const [loadingRecords, setLoadingRecords] = useState(false);
  const [selectedRecord, setSelectedRecord] = useState<DiagnosticRecord | null>(null);
  const [manifestContent, setManifestContent] = useState<string | null>(null);

  // Download form state
  const [downloadRef, setDownloadRef] = useState('diagnostic-pub-01');
  const [downloadMac, setDownloadMac] = useState('');
  const [downloadMsg, setDownloadMsg] = useState<{ type: 'info' | 'error' | 'success'; text: string } | null>(null);

  // Oracle state
  const [oracleToken, setOracleToken] = useState('');
  const [oracleQuery, setOracleQuery] = useState('query_intel: seal-11 status');
  const [oracleResponses, setOracleResponses] = useState<Array<{ query: string; response: any; time: string }>>([]);
  const [oracleLoading, setOracleLoading] = useState(false);

  // Archive state
  const [ticketInput, setTicketInput] = useState('');
  const [caseIdInput, setCaseIdInput] = useState('CASE-KURUKSHETRA-SEAL11');
  const [redeemLoading, setRedeemLoading] = useState(false);
  const [redeemResult, setRedeemResult] = useState<{ status: 'success' | 'error'; message: string; flag?: string } | null>(null);

  // Anti-Inspect security protections
  useEffect(() => {
    const handleContextMenu = (e: MouseEvent) => {
      e.preventDefault();
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      if (
        e.key === 'F12' ||
        (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'i' || e.key === 'J' || e.key === 'j' || e.key === 'C' || e.key === 'c')) ||
        (e.ctrlKey && (e.key === 'U' || e.key === 'u' || e.key === 'S' || e.key === 's'))
      ) {
        e.preventDefault();
      }
    };

    document.addEventListener('contextmenu', handleContextMenu);
    window.addEventListener('keydown', handleKeyDown);

    return () => {
      document.removeEventListener('contextmenu', handleContextMenu);
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, []);

  // Fetch diagnostics
  const fetchRecords = async () => {
    setLoadingRecords(true);
    try {
      const res = await fetch('/api/diagnostics/records');
      if (res.ok) {
        const data = await res.json();
        const items = data.records || data.manifests || [];
        setRecords(items);
        if (items.length > 0 && !downloadMac) {
          const first = items.find((i: DiagnosticRecord) => i.mac);
          if (first) {
            setDownloadRef(first.id);
            setDownloadMac(first.mac || '');
          }
        }
      }
    } catch {
      // Fallback sample data if standalone
      setRecords([
        {
          id: 'diagnostic-pub-01',
          name: 'Perimeter Relay Gateway Status - Day 11',
          classification: 'PUBLIC',
          timestamp: 'Year 3138 BCE, Day 11, Hour 21:00',
          description: 'Standard perimeter sync report. All relays operating under protocol KRP/1.1.',
          access: 'PUBLIC',
          download_url: '/api/diagnostics/download?ref=diagnostic-pub-01',
          mac: '659a8c1f01691a329dbe05ba55b6c31f',
          ref: 'diagnostic-pub-01'
        },
        {
          id: 'diagnostic-pub-02',
          name: 'KRP/1.1 Protocol Specifications & Signature Standards',
          classification: 'PUBLIC',
          timestamp: 'Year 3138 BCE, Day 11, Hour 22:15',
          description: 'Cryptographic specification memo for automated relay message validation.',
          access: 'PUBLIC',
          download_url: '/api/diagnostics/download?ref=diagnostic-pub-02',
          mac: '7bfa37346618e76da4a7037ce6d81ce4',
          ref: 'diagnostic-pub-02'
        },
        {
          id: 'diagnostic-pub-03',
          name: 'Night Watch Incident Alert - Seal XI Anomaly',
          classification: 'PUBLIC',
          timestamp: 'Year 3138 BCE, Day 11, Hour 23:45',
          description: 'Notice of unauthorized archive query during night watch.',
          access: 'PUBLIC',
          download_url: '/api/diagnostics/download?ref=diagnostic-pub-03',
          mac: '9f658097bb326e5539ab426649f874bc',
          ref: 'diagnostic-pub-03'
        },
        {
          id: 'seal11-relay-telemetry.pcap',
          name: 'Raw Protocol Telemetry Capture (KRP/1.1)',
          classification: 'RESTRICTED (LEVEL 4)',
          timestamp: 'Year 3138 BCE, Day 11, Hour 23:45',
          description: 'Full TCP network packet stream from Perimeter Relay XI.',
          access: 'RESTRICTED (LEVEL 4)',
          download_url: null,
          mac: null,
          ref: 'seal11-relay-telemetry.pcap'
        }
      ]);
    } finally {
      setLoadingRecords(false);
    }
  };

  useEffect(() => {
    fetchRecords();
  }, []);

  const viewManifest = async (record: DiagnosticRecord) => {
    setSelectedRecord(record);
    setManifestContent('Loading record details...');
    try {
      const res = await fetch(`/api/diagnostics/view?ref=${encodeURIComponent(record.ref)}`);
      const data = await res.json();
      if (res.ok && data.data) {
        setManifestContent(data.data.content || JSON.stringify(data.data, null, 2));
      } else {
        setManifestContent(data.message || 'RESTRICTED: Insufficient permissions to view raw record content.');
      }
    } catch {
      setManifestContent('Network error while retrieving manifest.');
    }
  };

  const handleDownloadSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!downloadRef) {
      setDownloadMsg({ type: 'error', text: 'Reference identifier cannot be empty.' });
      return;
    }
    const targetUrl = `/api/diagnostics/download?ref=${encodeURIComponent(downloadRef)}${downloadMac ? `&mac=${encodeURIComponent(downloadMac)}` : ''}`;
    setDownloadMsg({ type: 'info', text: `Initiating download from: ${targetUrl}` });
    window.location.href = targetUrl;
  };

  const handleOracleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!oracleQuery.trim()) return;

    setOracleLoading(true);
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (oracleToken.trim()) {
      headers['Authorization'] = `Bearer ${oracleToken.trim()}`;
    }

    try {
      const res = await fetch('/api/oracle/query', {
        method: 'POST',
        headers,
        body: JSON.stringify({ query: oracleQuery.trim() })
      });
      const data = await res.json();
      setOracleResponses(prev => [
        {
          query: oracleQuery.trim(),
          response: data,
          time: new Date().toLocaleTimeString()
        },
        ...prev
      ]);
    } catch {
      setOracleResponses(prev => [
        {
          query: oracleQuery.trim(),
          response: { status: 'error', message: 'Failed to communicate with Oracle agent.' },
          time: new Date().toLocaleTimeString()
        },
        ...prev
      ]);
    } finally {
      setOracleLoading(false);
    }
  };

  const handleRedeemSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ticketInput.trim() || !caseIdInput.trim()) {
      setRedeemResult({ status: 'error', message: 'Ticket and Case ID are both required.' });
      return;
    }

    setRedeemLoading(true);
    setRedeemResult(null);
    try {
      const res = await fetch('/api/archive/redeem', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ticket: ticketInput.trim(), case_id: caseIdInput.trim() })
      });
      const data = await res.json();
      if (res.ok && data.status === 'success') {
        setRedeemResult({
          status: 'success',
          message: data.message || 'Authorization ratified! Seal XI unsealed.',
          flag: data.resolution?.flag || data.flag
        });
      } else {
        setRedeemResult({
          status: 'error',
          message: data.message || 'Invalid or revoked archive ticket.'
        });
      }
    } catch {
      setRedeemResult({ status: 'error', message: 'Network error connecting to Archive redemption service.' });
    } finally {
      setRedeemLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div className="min-h-screen bg-[#07090e] text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Banner Navigation */}
      <header className="border-b border-slate-800/80 bg-[#0c101a]/90 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 ring-1 ring-cyan-400/30">
              <Shield className="h-5 w-5 text-white" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-lg tracking-wider text-white">THE SILENT CONCH</span>
                <span className="text-xs px-2 py-0.5 rounded font-mono bg-cyan-950/80 text-cyan-400 border border-cyan-800/60">SEAL XI</span>
              </div>
              <p className="text-[11px] font-mono text-slate-400">KURUKSHETRA RELAY GATEWAY // PROTOCOL KRP/1.1</p>
            </div>
          </div>

          {/* Right Status */}
          <div className="hidden md:flex items-center space-x-3">
            <div className="flex items-center space-x-2 px-3 py-1.5 rounded-full bg-emerald-950/40 border border-emerald-800/50 text-emerald-400 text-xs font-mono">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></span>
              <span>GATEWAY ACTIVE</span>
            </div>
            <div className="text-xs font-mono text-slate-500 border border-slate-800 px-3 py-1.5 rounded-md bg-slate-900/50">
              PORT: 8000 / ES256
            </div>
          </div>
        </div>

        {/* Tab Bar */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex space-x-1 border-t border-slate-800/40 overflow-x-auto">
          <button
            onClick={() => setActiveTab('overview')}
            className={`flex items-center space-x-2 py-3 px-4 border-b-2 font-medium text-sm transition-colors whitespace-nowrap ${
              activeTab === 'overview'
                ? 'border-cyan-400 text-cyan-400 bg-cyan-950/20'
                : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/30'
            }`}
          >
            <Activity className="h-4 w-4" />
            <span>Command Overview</span>
          </button>

          <button
            onClick={() => setActiveTab('diagnostics')}
            className={`flex items-center space-x-2 py-3 px-4 border-b-2 font-medium text-sm transition-colors whitespace-nowrap ${
              activeTab === 'diagnostics'
                ? 'border-cyan-400 text-cyan-400 bg-cyan-950/20'
                : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/30'
            }`}
          >
            <Database className="h-4 w-4" />
            <span>Diagnostic Records</span>
          </button>

          <button
            onClick={() => setActiveTab('oracle')}
            className={`flex items-center space-x-2 py-3 px-4 border-b-2 font-medium text-sm transition-colors whitespace-nowrap ${
              activeTab === 'oracle'
                ? 'border-cyan-400 text-cyan-400 bg-cyan-950/20'
                : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/30'
            }`}
          >
            <Cpu className="h-4 w-4" />
            <span>Oracle Console</span>
          </button>

          <button
            onClick={() => setActiveTab('archive')}
            className={`flex items-center space-x-2 py-3 px-4 border-b-2 font-medium text-sm transition-colors whitespace-nowrap ${
              activeTab === 'archive'
                ? 'border-cyan-400 text-cyan-400 bg-cyan-950/20'
                : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/30'
            }`}
          >
            <Lock className="h-4 w-4" />
            <span>Sealed Archive</span>
          </button>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8">
        {/* ============================================================= */}
        {/* VIEW 1: COMMAND OVERVIEW */}
        {/* ============================================================= */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Status Grid */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="p-4 rounded-xl bg-[#0f1422] border border-slate-800 hover:border-slate-700 transition">
                <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-2">
                  <span>RELAY STATUS</span>
                  <Radio className="h-4 w-4 text-emerald-400 animate-pulse" />
                </div>
                <div className="text-xl font-bold text-white tracking-wide">OPERATIONAL</div>
                <div className="text-xs text-slate-400 mt-1 font-mono">Node: Relay Seal XI (Oregon)</div>
              </div>

              <div className="p-4 rounded-xl bg-[#0f1422] border border-slate-800 hover:border-slate-700 transition">
                <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-2">
                  <span>PROTOCOL SPEC</span>
                  <Terminal className="h-4 w-4 text-cyan-400" />
                </div>
                <div className="text-xl font-bold text-cyan-400 font-mono tracking-wide">KRP/1.1</div>
                <div className="text-xs text-slate-400 mt-1 font-mono">Framed TCP & ECDSA P-256</div>
              </div>

              <div className="p-4 rounded-xl bg-[#0f1422] border border-slate-800 hover:border-slate-700 transition">
                <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-2">
                  <span>KEY IDENTIFIER</span>
                  <Shield className="h-4 w-4 text-amber-400" />
                </div>
                <div className="text-lg font-bold text-amber-400 font-mono truncate">relay-seal-eleven</div>
                <div className="text-xs text-slate-400 mt-1 font-mono">Curve: NIST P-256 (secp256r1)</div>
              </div>

              <div className="p-4 rounded-xl bg-[#0f1422] border border-slate-800 hover:border-slate-700 transition">
                <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-2">
                  <span>ORACLE GATEWAY</span>
                  <Lock className="h-4 w-4 text-purple-400" />
                </div>
                <div className="text-xl font-bold text-purple-400 tracking-wide font-mono">ES256 AUTH</div>
                <div className="text-xs text-slate-400 mt-1 font-mono">Audience: oracle.seal11.internal</div>
              </div>
            </div>

            {/* Night Watch Alert Banner */}
            <div className="p-5 rounded-xl bg-gradient-to-r from-amber-950/40 via-red-950/20 to-slate-900 border border-amber-800/60 shadow-lg">
              <div className="flex items-start space-x-3">
                <AlertTriangle className="h-6 w-6 text-amber-400 flex-shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <div className="flex items-center space-x-3">
                    <h3 className="font-semibold text-amber-300 text-base">NIGHT WATCH INCIDENT: CASE-KURUKSHETRA-SEAL11</h3>
                    <span className="px-2 py-0.5 text-[10px] font-mono bg-red-950 text-red-400 border border-red-800 rounded">RESTRICTED LEVEL 4</span>
                  </div>
                  <p className="text-sm text-slate-300">
                    At Hour 23:42 on Day 11, perimeter telemetry captured an unverified archive unseal attempt. Full network capture stream was persisted to <span className="font-mono text-cyan-300">seal11-relay-telemetry.pcap</span>. Access to raw packet captures requires presigned authorization.
                  </p>
                  <div className="pt-2 flex flex-wrap gap-2">
                    <button
                      onClick={() => setActiveTab('diagnostics')}
                      className="px-3 py-1.5 rounded-md bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-amber-300 text-xs font-medium transition"
                    >
                      Inspect Diagnostic Records →
                    </button>
                    <button
                      onClick={() => setActiveTab('oracle')}
                      className="px-3 py-1.5 rounded-md bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-cyan-300 text-xs font-medium transition"
                    >
                      Query Oracle Assistant →
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {/* Cryptographic Architecture Chain */}
            <div className="p-6 rounded-xl bg-[#0f1422] border border-slate-800">
              <h3 className="text-base font-semibold text-white mb-4 flex items-center space-x-2">
                <Cpu className="h-5 w-5 text-cyan-400" />
                <span>Verification Pipeline & Cryptographic Hierarchy</span>
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800 relative">
                  <div className="text-xs font-mono text-cyan-400 mb-1">STAGE 1 // TELEMETRY</div>
                  <h4 className="font-bold text-sm text-white mb-2">Presigned Manifests</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Perimeter download gateway validates presigned HMAC-SHA256 signatures for diagnostic artifacts.
                  </p>
                </div>

                <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800 relative">
                  <div className="text-xs font-mono text-cyan-400 mb-1">STAGE 2 // PCAP ANALYSIS</div>
                  <h4 className="font-bold text-sm text-white mb-2">ECDSA Nonce Anomaly</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Restricted telemetry capture contains framed KRP/1.1 signed payloads sharing identical signature scalar nonces.
                  </p>
                </div>

                <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800 relative">
                  <div className="text-xs font-mono text-cyan-400 mb-1">STAGE 3 // TOKEN FORGERY</div>
                  <h4 className="font-bold text-sm text-white mb-2">ES256 Delegation</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Recovered relay private key signs authorized ES256 JWT tokens for internal Oracle intelligence queries.
                  </p>
                </div>

                <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800 relative">
                  <div className="text-xs font-mono text-cyan-400 mb-1">STAGE 4 // RATIFICATION</div>
                  <h4 className="font-bold text-sm text-white mb-2">Archive Unsealing</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Single-use delegation ticket redeems ratified resolution for Case XI to reveal the verified secret flag.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ============================================================= */}
        {/* VIEW 2: DIAGNOSTIC RECORDS */}
        {/* ============================================================= */}
        {activeTab === 'diagnostics' && (
          <div className="space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h2 className="text-xl font-bold text-white flex items-center space-x-2">
                  <Database className="h-5 w-5 text-cyan-400" />
                  <span>Diagnostic Manifest Registry</span>
                </h2>
                <p className="text-xs text-slate-400 font-mono mt-1">
                  Perimeter telemetry records and cryptographically authenticated gateway manifests.
                </p>
              </div>

              <button
                onClick={fetchRecords}
                disabled={loadingRecords}
                className="inline-flex items-center space-x-2 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 transition border border-slate-700"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${loadingRecords ? 'animate-spin' : ''}`} />
                <span>Refresh Records</span>
              </button>
            </div>

            {/* Records Table */}
            <div className="rounded-xl border border-slate-800 overflow-hidden bg-[#0f1422]">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-900/90 text-slate-400 font-mono uppercase tracking-wider border-b border-slate-800">
                    <tr>
                      <th className="py-3 px-4">Identifier / Ref</th>
                      <th className="py-3 px-4">Record Title</th>
                      <th className="py-3 px-4">Timestamp</th>
                      <th className="py-3 px-4">Classification</th>
                      <th className="py-3 px-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-slate-300">
                    {records.map((rec) => (
                      <tr key={rec.id} className="hover:bg-slate-800/30 transition">
                        <td className="py-3 px-4 font-mono font-medium text-cyan-300">
                          {rec.id}
                        </td>
                        <td className="py-3 px-4">
                          <div className="font-semibold text-slate-100">{rec.name}</div>
                          <div className="text-[11px] text-slate-400 line-clamp-1">{rec.description}</div>
                        </td>
                        <td className="py-3 px-4 font-mono text-slate-400 whitespace-nowrap">
                          {rec.timestamp}
                        </td>
                        <td className="py-3 px-4 whitespace-nowrap">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                            rec.classification.includes('RESTRICTED')
                              ? 'bg-red-950/80 text-red-400 border border-red-800/60'
                              : 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/60'
                          }`}>
                            {rec.classification}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-right space-x-2 whitespace-nowrap">
                          <button
                            onClick={() => viewManifest(rec)}
                            className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 transition border border-slate-700"
                          >
                            <Eye className="h-3 w-3" />
                            <span>View</span>
                          </button>
                          {rec.download_url && (
                            <a
                              href={rec.download_url}
                              className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-cyan-900/60 hover:bg-cyan-800 text-cyan-200 transition border border-cyan-700"
                            >
                              <Download className="h-3 w-3" />
                              <span>Get</span>
                            </a>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Record Detail Modal / Panel */}
            {selectedRecord && (
              <div className="p-5 rounded-xl bg-[#0f1422] border border-cyan-800/60 space-y-3 shadow-xl">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div>
                    <h3 className="font-bold text-white text-sm flex items-center space-x-2">
                      <FileText className="h-4 w-4 text-cyan-400" />
                      <span>{selectedRecord.name}</span>
                    </h3>
                    <p className="text-xs font-mono text-slate-400">{selectedRecord.id} // {selectedRecord.timestamp}</p>
                  </div>
                  <button
                    onClick={() => setSelectedRecord(null)}
                    className="text-slate-400 hover:text-white text-xs px-2 py-1 rounded bg-slate-800 border border-slate-700"
                  >
                    Close
                  </button>
                </div>
                <div className="p-3 rounded bg-[#090b12] border border-slate-800 font-mono text-xs text-slate-300 whitespace-pre-wrap max-h-60 overflow-y-auto">
                  {manifestContent}
                </div>
              </div>
            )}

            {/* Presigned Artifact Download Form */}
            <div className="p-6 rounded-xl bg-[#0f1422] border border-slate-800 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-semibold text-white flex items-center space-x-2">
                    <Download className="h-5 w-5 text-cyan-400" />
                    <span>Presigned Gateway Artifact Dispatcher</span>
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Direct endpoint: <code className="text-cyan-300 font-mono">/api/diagnostics/download?ref=&lt;target&gt;&amp;mac=&lt;signature&gt;</code>
                  </p>
                </div>
              </div>

              <form onSubmit={handleDownloadSubmit} className="grid grid-cols-1 md:grid-cols-12 gap-3">
                <div className="md:col-span-5">
                  <label className="block text-xs font-mono text-slate-400 mb-1">TARGET REFERENCE (`ref`)</label>
                  <input
                    type="text"
                    value={downloadRef}
                    onChange={(e) => setDownloadRef(e.target.value)}
                    placeholder="e.g. diagnostic-pub-01 or seal11-relay-telemetry.pcap"
                    className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-sm font-mono text-white focus:outline-none focus:border-cyan-400"
                  />
                </div>

                <div className="md:col-span-5">
                  <label className="block text-xs font-mono text-slate-400 mb-1">PRESIGNED HMAC SIGNATURE (`mac`)</label>
                  <input
                    type="text"
                    value={downloadMac}
                    onChange={(e) => setDownloadMac(e.target.value)}
                    placeholder="HMAC-SHA256 32-char hex token"
                    className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-sm font-mono text-white focus:outline-none focus:border-cyan-400"
                  />
                </div>

                <div className="md:col-span-2 flex items-end">
                  <button
                    type="submit"
                    className="w-full py-2 px-4 rounded-lg bg-cyan-600 hover:bg-cyan-500 font-medium text-sm text-white transition flex items-center justify-center space-x-2"
                  >
                    <Download className="h-4 w-4" />
                    <span>Download</span>
                  </button>
                </div>
              </form>

              {downloadMsg && (
                <div className={`p-3 rounded-lg text-xs font-mono border ${
                  downloadMsg.type === 'error'
                    ? 'bg-red-950/40 border-red-800 text-red-300'
                    : 'bg-cyan-950/40 border-cyan-800 text-cyan-300'
                }`}>
                  {downloadMsg.text}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ============================================================= */}
        {/* VIEW 3: ORACLE CONSOLE */}
        {/* ============================================================= */}
        {activeTab === 'oracle' && (
          <div className="space-y-6">
            <div>
              <h2 className="text-xl font-bold text-white flex items-center space-x-2">
                <Cpu className="h-5 w-5 text-cyan-400" />
                <span>Kurukshetra Oracle Autonomous Agent</span>
              </h2>
              <p className="text-xs text-slate-400 font-mono mt-1">
                Internal intelligence query agent. Enforces ECDSA ES256 JSON Web Token authorization.
              </p>
            </div>

            {/* Oracle Token Input */}
            <div className="p-5 rounded-xl bg-[#0f1422] border border-slate-800 space-y-3">
              <label className="block text-xs font-mono text-slate-300 flex items-center justify-between">
                <span>ORACLE AUTHORIZATION BEARER TOKEN (ES256 JWT)</span>
                <span className="text-[10px] text-cyan-400">Required scopes: intel:read oracle:query archive:delegate case:reconcile</span>
              </label>
              <textarea
                value={oracleToken}
                onChange={(e) => setOracleToken(e.target.value)}
                placeholder="eyJhbGciOiJFUzI1NiIsImtpZCI6InJlbGF5LXNlYWwtZWxldmVuIn0... (Paste forged or recovered JWT token here)"
                rows={2}
                className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono text-white focus:outline-none focus:border-cyan-400"
              />
            </div>

            {/* Query Form */}
            <form onSubmit={handleOracleSubmit} className="p-5 rounded-xl bg-[#0f1422] border border-slate-800 space-y-4">
              <div>
                <label className="block text-xs font-mono text-slate-300 mb-2">QUERY COMMAND</label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={oracleQuery}
                    onChange={(e) => setOracleQuery(e.target.value)}
                    placeholder="e.g. query_intel: seal-11 status, delegate_archive: get sealed ticket"
                    className="flex-1 px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-sm font-mono text-white focus:outline-none focus:border-cyan-400"
                  />
                  <button
                    type="submit"
                    disabled={oracleLoading}
                    className="px-5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 font-medium text-sm text-white transition flex items-center space-x-2"
                  >
                    {oracleLoading ? (
                      <RefreshCw className="h-4 w-4 animate-spin" />
                    ) : (
                      <Send className="h-4 w-4" />
                    )}
                    <span>Execute</span>
                  </button>
                </div>
              </div>

              {/* Quick Preset Buttons */}
              <div className="flex flex-wrap gap-2 text-xs font-mono">
                <span className="text-slate-500 self-center">Presets:</span>
                <button
                  type="button"
                  onClick={() => setOracleQuery('query_intel: seal-11 status')}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
                >
                  query_intel: seal-11 status
                </button>
                <button
                  type="button"
                  onClick={() => setOracleQuery('delegate_archive: get sealed ticket')}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
                >
                  delegate_archive: get sealed ticket
                </button>
                <button
                  type="button"
                  onClick={() => setOracleQuery('reconcile_case: confirm case')}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
                >
                  reconcile_case: confirm case
                </button>
              </div>
            </form>

            {/* Oracle Execution Logs / Terminal Output */}
            <div className="p-5 rounded-xl bg-[#090b12] border border-slate-800 space-y-4 font-mono">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <div className="flex items-center space-x-2 text-xs text-slate-400">
                  <Terminal className="h-4 w-4 text-cyan-400" />
                  <span>ORACLE AUDIT TRAIL & LOGS</span>
                </div>
                {oracleResponses.length > 0 && (
                  <button
                    onClick={() => setOracleResponses([])}
                    className="text-[11px] text-slate-500 hover:text-slate-300"
                  >
                    Clear History
                  </button>
                )}
              </div>

              {oracleResponses.length === 0 ? (
                <div className="text-xs text-slate-600 italic py-6 text-center">
                  No commands executed in current session. Enter a query above to dispatch to Oracle agent.
                </div>
              ) : (
                <div className="space-y-4 max-h-96 overflow-y-auto">
                  {oracleResponses.map((item, idx) => (
                    <div key={idx} className="p-3 rounded-lg bg-[#0e121d] border border-slate-800/80 space-y-2">
                      <div className="flex items-center justify-between text-xs text-cyan-400 border-b border-slate-800 pb-1">
                        <span>&gt; {item.query}</span>
                        <span className="text-[10px] text-slate-500">{item.time}</span>
                      </div>
                      <pre className="text-xs text-slate-300 overflow-x-auto whitespace-pre-wrap">
                        {JSON.stringify(item.response, null, 2)}
                      </pre>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ============================================================= */}
        {/* VIEW 4: SEALED ARCHIVE REDEMPTION */}
        {/* ============================================================= */}
        {activeTab === 'archive' && (
          <div className="max-w-2xl mx-auto space-y-6">
            <div className="text-center space-y-2">
              <div className="h-12 w-12 rounded-xl bg-purple-950/60 border border-purple-800/60 mx-auto flex items-center justify-center text-purple-400 shadow-lg shadow-purple-950/30">
                <Lock className="h-6 w-6" />
              </div>
              <h2 className="text-2xl font-bold text-white tracking-wide">Sealed Archive Ratification</h2>
              <p className="text-xs text-slate-400 font-mono">
                Redeem your single-use delegation authorization ticket to ratify Case XI and claim the final resolution.
              </p>
            </div>

            <form onSubmit={handleRedeemSubmit} className="p-6 rounded-xl bg-[#0f1422] border border-slate-800 space-y-4">
              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">ARCHIVE CASE IDENTIFIER</label>
                <input
                  type="text"
                  value={caseIdInput}
                  onChange={(e) => setCaseIdInput(e.target.value)}
                  placeholder="CASE-KURUKSHETRA-SEAL11"
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-sm font-mono text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">SINGLE-USE DELEGATION TICKET</label>
                <input
                  type="text"
                  value={ticketInput}
                  onChange={(e) => setTicketInput(e.target.value)}
                  placeholder="TICKET-KURUKSHETRA-..."
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-sm font-mono text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <button
                type="submit"
                disabled={redeemLoading}
                className="w-full py-2.5 px-4 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 font-semibold text-sm text-white transition flex items-center justify-center space-x-2 shadow-lg shadow-purple-950/40"
              >
                {redeemLoading ? (
                  <RefreshCw className="h-4 w-4 animate-spin" />
                ) : (
                  <Unlock className="h-4 w-4" />
                )}
                <span>Unseal Archive & Ratify Case</span>
              </button>
            </form>

            {/* Redemption Output */}
            {redeemResult && (
              <div className={`p-6 rounded-xl border space-y-3 ${
                redeemResult.status === 'success'
                  ? 'bg-emerald-950/40 border-emerald-700/80'
                  : 'bg-red-950/40 border-red-800'
              }`}>
                <div className="flex items-center space-x-2">
                  {redeemResult.status === 'success' ? (
                    <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                  ) : (
                    <AlertTriangle className="h-5 w-5 text-red-400" />
                  )}
                  <h3 className={`font-bold text-sm ${
                    redeemResult.status === 'success' ? 'text-emerald-300' : 'text-red-300'
                  }`}>
                    {redeemResult.status === 'success' ? 'CASE RESOLUTION RATIFIED' : 'REDEMPTION REJECTED'}
                  </h3>
                </div>

                <p className="text-xs text-slate-300 font-mono">
                  {redeemResult.message}
                </p>

                {redeemResult.flag && (
                  <div className="mt-4 p-4 rounded-lg bg-[#090b12] border border-emerald-500/50 space-y-2">
                    <div className="text-[11px] font-mono text-emerald-400 font-bold uppercase tracking-wider">
                      ★ RATIFIED CASE FLAG:
                    </div>
                    <div className="flex items-center justify-between gap-2 p-2 rounded bg-black/60 border border-emerald-900">
                      <code className="text-sm font-bold font-mono text-emerald-300 select-all">
                        {redeemResult.flag}
                      </code>
                      <button
                        onClick={() => copyToClipboard(redeemResult.flag!)}
                        className="p-1.5 rounded bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-700 transition"
                        title="Copy Flag"
                      >
                        <Copy className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-[#0c101a] py-4 text-center text-xs font-mono text-slate-500">
        The Silent Conch: The Eleventh Seal // Kurukshetra Gateway Security
      </footer>
    </div>
  );
}

export default App;
