import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "CTF Agent Dashboard",
  description: "Live trace and human-in-the-loop control for the autonomous CTF-solving agent.",
};

// Runs before paint so the correct theme class is on <html> for the very first frame --
// shadcn's generated globals.css uses a `.dark` class selector (@custom-variant dark),
// not the `prefers-color-scheme` media query the pre-shadcn styles relied on, so without
// this the app would always render light regardless of the OS theme.
const themeInitScript = `(function(){try{var d=window.matchMedia("(prefers-color-scheme: dark)").matches;document.documentElement.classList.toggle("dark",d);}catch(e){}})();`;

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
      suppressHydrationWarning
    >
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeInitScript }} />
      </head>
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
