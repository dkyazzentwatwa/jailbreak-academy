# 🚀 Deployment Guide - Jailbreak Training Simulator

## Prerequisites

- Node.js 18+ and npm/yarn installed
- Git installed
- A hosting service account (Vercel, Netlify, or similar)

## Quick Deploy

### Option 1: Deploy to Vercel (Recommended)

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/yourusername/llm-sanitizer-59)

1. Click the button above
2. Connect your GitHub account
3. Configure environment variables (see below)
4. Deploy!

### Option 2: Deploy to Netlify

[![Deploy to Netlify](https://www.netlify.com/img/deploy/button.svg)](https://app.netlify.com/start/deploy?repository=https://github.com/yourusername/llm-sanitizer-59)

1. Click the button above
2. Connect your GitHub account
3. Configure build settings:
   - Build command: `npm run build`
   - Publish directory: `dist`
4. Add environment variables
5. Deploy!

## Manual Deployment

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/llm-sanitizer-59.git
cd llm-sanitizer-59
```

### 2. Install Dependencies

```bash
npm install
# or
yarn install
```

### 3. Configure Environment Variables

Copy `.env.example` to `.env` and update the values:

```bash
cp .env.example .env
```

Edit `.env` with your production values:

```env
VITE_APP_ENV=production
VITE_API_URL=https://your-api-url.com
VITE_API_KEY=your-production-api-key
VITE_ENABLE_ANALYTICS=true
VITE_ANALYTICS_ID=your-analytics-id
VITE_ENABLE_LEADERBOARD=true
VITE_ENABLE_CERTIFICATES=true
```

### 4. Build for Production

```bash
npm run build
```

This creates an optimized production build in the `dist` folder.

### 5. Test Production Build Locally

```bash
npm run preview
```

Visit `http://localhost:4173` to test the production build.

## Deployment Options

### Static Hosting (Recommended)

The app is a static SPA and can be hosted on any static hosting service:

#### Vercel
```bash
npm i -g vercel
vercel
```

#### Netlify
```bash
npm i -g netlify-cli
netlify deploy --prod
```

#### GitHub Pages
```bash
npm run build
git add dist -f
git commit -m "Deploy to GitHub Pages"
git subtree push --prefix dist origin gh-pages
```

#### AWS S3 + CloudFront
1. Build the project: `npm run build`
2. Upload `dist` folder to S3 bucket
3. Configure CloudFront distribution
4. Set up custom domain (optional)

### Docker Deployment

Create a `Dockerfile`:

```dockerfile
FROM node:18-alpine as builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

Build and run:
```bash
docker build -t jailbreak-sim .
docker run -p 80:80 jailbreak-sim
```

## Configuration

### Security Headers

Ensure your hosting provider sets these headers:

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
```

### CORS Configuration

If using a backend API, configure CORS:

```javascript
// Backend CORS settings
cors({
  origin: ['https://yourdomain.com'],
  credentials: true
})
```

### SSL/TLS

Always use HTTPS in production. Most hosting providers offer free SSL certificates.

## Performance Optimization

### CDN Setup

1. Enable CDN on your hosting provider
2. Configure cache headers for static assets:
   - HTML: no-cache
   - JS/CSS: max-age=31536000
   - Images: max-age=86400

### Monitoring

Set up monitoring for:
- Uptime monitoring (UptimeRobot, Pingdom)
- Error tracking (Sentry)
- Analytics (Google Analytics, Plausible)
- Performance monitoring (Lighthouse CI)

## Troubleshooting

### Build Failures

```bash
# Clear cache and reinstall
rm -rf node_modules package-lock.json
npm install
npm run build
```

### Environment Variables Not Working

- Ensure all env vars start with `VITE_`
- Rebuild after changing env vars
- Check hosting provider's env var configuration

### PWA Not Installing

- Ensure HTTPS is enabled
- Check manifest.json is accessible
- Verify service worker registration

## Maintenance

### Updating Dependencies

```bash
npm update
npm audit fix
npm run build
npm test
```

### Database Backup (if using backend)

Set up automated backups for any backend database.

### Monitoring Checklist

- [ ] SSL certificate expiration
- [ ] Domain renewal
- [ ] API rate limits
- [ ] Storage usage
- [ ] Error rates
- [ ] Performance metrics

## Support

For deployment issues:
- Email: littlehakr@protonmail.com
- GitHub Issues: [Create an issue](https://github.com/yourusername/llm-sanitizer-59/issues)

## License

This project is for educational purposes. See LICENSE file for details.