import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata = { title: "TrustSplit · Security Benchmark", description: "Compare raw and locally screened model proposals against deterministic policy enforcement." };
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) { return <html lang="en"><body>{children}</body></html>; }
