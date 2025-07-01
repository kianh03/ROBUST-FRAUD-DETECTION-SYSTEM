/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  env: {
    PRIMARY_API_URL: process.env.PRIMARY_API_URL || 'http://localhost:5001',
    BACKUP_API_URL: process.env.BACKUP_API_URL || 'http://localhost:5001',
    PRIMARY_TOKEN: process.env.PRIMARY_TOKEN || '',
    BACKUP_TOKEN: process.env.BACKUP_TOKEN || '',
  },
  images: {
    domains: ['localhost'],
  },
}

module.exports = nextConfig 