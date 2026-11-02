/** @type {import('next').NextConfig} */
module.exports = {
  reactStrictMode: true,
  productionBrowserSourceMaps: true,
  images: { remotePatterns: [{ protocol: 'https', hostname: '**' }] },
};
