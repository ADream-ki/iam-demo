import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';

const ACCESS_COOKIE = process.env.SESSION_COOKIE_NAME || 'session_token';
const REFRESH_COOKIE = process.env.REFRESH_COOKIE_NAME || 'refresh_token';

export function middleware(request: NextRequest) {
  if (request.nextUrl.pathname.startsWith('/dashboard')) {
    const accessToken = request.cookies.get(ACCESS_COOKIE)?.value;
    const refreshToken = request.cookies.get(REFRESH_COOKIE)?.value;
    if (!accessToken && !refreshToken) {
      const subject = request.nextUrl.pathname.split('/')[2];
      const target = subject ? `/auth/${subject}` : '/';
      const url = new URL(target, request.url);
      return NextResponse.redirect(url);
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/dashboard/:path*'],
};
