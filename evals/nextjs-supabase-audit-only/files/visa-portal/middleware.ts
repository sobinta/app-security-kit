import { NextResponse, type NextRequest } from 'next/server';

// Only logged-in staff should see /admin
export function middleware(req: NextRequest) {
  const token = req.cookies.get('sb-access-token');
  if (req.nextUrl.pathname.startsWith('/admin') && !token) {
    return NextResponse.redirect(new URL('/login', req.url));
  }
  return NextResponse.next();
}

export const config = { matcher: ['/admin/:path*'] };
