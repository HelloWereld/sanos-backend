# SANOS Backend

Production backend for SANOS skills verification platform.

## Deployment

Deployed to Railway with automatic deployments from main branch.

## Environment Variables

Copy from .env.example and set in Railway dashboard.

## API Endpoints

- GET /health - Health check
- POST /api/auth/register - User registration
- POST /api/auth/login - User login
- GET /api/auth/verify-email - Email verification
- POST /api/badges - Create badge
- GET /api/badges/:id/verify - Verify badge
- GET /api/admin/users - Admin: List users
- GET /api/admin/badges - Admin: List badges
