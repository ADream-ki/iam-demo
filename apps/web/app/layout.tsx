import './globals.css';
import type { ReactNode } from 'react';

export const metadata = {
  title: 'Secure Hub IAM',
  description: 'Multi-subject authentication and session management demo',
};

/**
 * 根布局：注入全局样式并包裹所有页面内容。
 */
export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="zh-CN">
      <body>{children}</body>
    </html>
  );
}
