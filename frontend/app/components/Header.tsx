"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
export default function Header(){const path=usePathname();return <header className="site-header"><Link href="/" className="brand"><span className="brand-symbol">TS</span><span><b>TRUSTSPLIT</b><small>SECURITY BENCHMARK</small></span></Link><nav className="main-nav" aria-label="Main navigation"><Link className={path==="/"?"active":""} href="/">Benchmark</Link><Link className={path==="/architecture"?"active":""} href="/architecture">System map</Link></nav><div className="header-model"><span className="status-dot green"/> LOCAL GUARD <b>GEMMA 3 · 1B</b></div></header>}
