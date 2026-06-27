import type { NextConfig } from "next";
import path from "node:path";

/* 生成构建ID：日期 + 短时间戳哈希，格式如 250214-a3f8 */
const now = new Date();
const datePart = now.toISOString().slice(2, 10).replace(/-/g, '');
const hashPart = Math.floor(now.getTime() % 0xFFFF).toString(16).padStart(4, '0');
const buildId = `${datePart}-${hashPart}`;

const nextConfig: NextConfig = {
  output: "export",
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
  generateBuildId: () => buildId,
  env: {
    NEXT_PUBLIC_BUILD_ID: buildId,
  },
  /* 性能优化 */
  poweredByHeader: false,
  reactStrictMode: true,
  compress: true,
  webpack: (config) => {
    config.resolve = config.resolve || {};
    config.resolve.alias = {
      ...(config.resolve.alias || {}),
      '@': path.resolve(process.cwd()),
    };
    return config;
  },
  /* Turbopack 兼容（Next.js 16 默认） */
  turbopack: {
    root: process.cwd(),
  },
  /* 跳过 Next 内置类型检查；scripts/build.js 已先执行 tsc --noEmit */
  typescript: {
    ignoreBuildErrors: true,
  },
};

export default nextConfig;
