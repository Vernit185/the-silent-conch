import { Link, useRouterState } from '@tanstack/react-router';
import { useState } from 'react';
import { ArrowUpRight, Menu, X, Fingerprint } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useApi } from './api-context';
export const sections = [
  { to: '/', label: 'Command Overview', short: 'Overview', number: '01' },
  { to: '/diagnostics', label: 'Diagnostic Records', short: 'Diagnostics', number: '02' },
  { to: '/oracle', label: 'Oracle Console', short: 'Oracle', number: '03' },
  { to: '/archive', label: 'Archive Redemption', short: 'Archive', number: '04' },
] as const;
export function RelayMark({ large = false }: { large?: boolean }) {
  return <svg className={large ? 'relay-mark relay-mark-large' : 'relay-mark'} viewBox="0 0 44 44" fill="none" aria-hidden="true"><path d="M22 3 39 12.5v19L22 41 5 31.5v-19L22 3Z" stroke="currentColor" strokeWidth="1.2"/><path d="m13 16 9-5 9 5v12l-9 5-9-5V16Z" stroke="currentColor" strokeWidth="1.2"/><path d="M22 11v22m-9-17 18 12m0-12L13 28" stroke="currentColor" strokeWidth="1.2"/><path d="M22 3v8m17 1.5-8 3.5m8 15.5L31 28M22 41v-8M5 31.5l8-3.5M5 12.5l8 3.5" stroke="currentColor" strokeWidth="1.2"/></svg>;
}
export function Shell({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const pathname = useRouterState({ select: state => state.location.pathname });
  const { token } = useApi();
  const toggleMenu = () => setOpen(value => !value);
  const closeMenu = () => setOpen(false);
  return <div className="application-shell">
    <header className="global-header"><div className="authority"><RelayMark/><div><span className="authority-name">KURUKSHETRA RELAY AUTHORITY</span><span className="authority-subtitle">SEALED INTELLIGENCE SYSTEM</span></div></div><div className="header-right"><span className="header-classification">RESTRICTED ACCESS</span><span className="day-tag">DAY <strong>XI</strong></span><Button variant="ghost" size="icon" className="mobile-menu" onClick={toggleMenu} aria-label={open ? 'Close navigation' : 'Open navigation'} aria-expanded={open}>{open ? <X/> : <Menu/>}</Button></div></header>
    <div className="navigation-band"><nav aria-label="Primary navigation" className={open ? 'main-nav is-open' : 'main-nav'}>{sections.map(section => <Link key={section.to} to={section.to} className={pathname === section.to ? 'nav-item active' : 'nav-item'} onClick={closeMenu}><span className="nav-number">{section.number}</span>{section.label}{pathname === section.to && <span className="nav-current"/>}</Link>)}</nav><span className="session-indicator"><Fingerprint size={14}/>{token ? 'TOKEN PRESENT · UNVERIFIED' : 'NO AUTHORIZED SESSION'}</span></div>
    <main id="main-content">{children}</main>
    <footer className="global-footer"><span><span className="footer-square"/>KRA / INTERNAL INVESTIGATION ENVIRONMENT</span><span>THE ELEVENTH SEAL <span className="footer-divider">/</span> DAY XI <ArrowUpRight size={12}/></span></footer>
  </div>;
}
