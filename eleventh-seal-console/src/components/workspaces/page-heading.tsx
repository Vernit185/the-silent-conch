export function PageHeading({ number, title, subtitle, description }: { number: string; title: string; subtitle: string; description: string }) {
 return <header className="page-heading"><div className="eyebrow">INVESTIGATION WORKSPACE <span>/ {number}</span></div><div className="page-title-line"><div><h1>{title}</h1><p className="page-subtitle">{subtitle}</p></div><span className="workspace-code">KRA / XI / {number}</span></div><p className="page-description">{description}</p></header>;
}
