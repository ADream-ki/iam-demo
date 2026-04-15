import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Emit a self-contained production server for Docker deployment.
  output: "standalone",
  // Prevent server-side bundling of browser-only WebAuthn packages.
  // Without this, Next.js may try to SSR @simplewebauthn/browser which
  // references `window` and crashes the RSC render with a production error.
  serverExternalPackages: ['@simplewebauthn/browser'],
  experimental: {
    serverActions: {
      bodySizeLimit: "2mb"
    }
  }
};

export default nextConfig;
