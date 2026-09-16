# Ticket System API

Small Go backend for the Backend Intern ticket system assignment.

## Features

- User registration and login
- JWT-protected ticket APIs
- Password hashing with PBKDF2-HMAC-SHA256
- Users can only view and update their own tickets
- Ticket status flow: `open -> in_progress -> closed`
- Closed tickets cannot be reopened
- Docker-ready deployment

## API

| Method | Endpoint | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `/health` | No | Health check |
| POST | `/auth/register` | No | Register user |
| POST | `/auth/login` | No | Login and receive JWT |
| POST | `/tickets` | Yes | Create ticket |
| GET | `/tickets` | Yes | List current user's tickets |
| GET | `/tickets/{id}` | Yes | Get current user's ticket |
| PATCH | `/tickets/{id}/status` | Yes | Update current user's ticket status |

## Local Run

```bash
go run .
```

Health check:

```bash
curl http://localhost:8080/health
```

Expected response:

```json
{"status":"ok"}
```

## Docker Run

```bash
docker build -t ticket-system .
docker run -p 8080:8080 ticket-system
curl http://localhost:8080/health
```

## Example Requests

Register:

```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secret123"}'
```

Login:

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secret123"}'
```

Create ticket:

```bash
curl -X POST http://localhost:8080/tickets \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"title":"Cannot login","description":"Login fails on submit."}'
```

Update status:

```bash
curl -X PATCH http://localhost:8080/tickets/1/status \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"status":"in_progress"}'
```

## Environment Variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `8080` | HTTP port. Render sets this automatically. |
| `JWT_SECRET` | `change-me-in-production` | Secret used to sign JWTs. |
| `DATA_FILE` | `data.json` | File used for simple JSON persistence. |

## Render Deployment

1. Push this repository to GitHub.
2. In Render, create a new Web Service from the GitHub repository.
3. Choose Docker as the runtime/environment.
4. Add environment variable `JWT_SECRET` with a long random value.
5. Deploy.
6. Confirm the public health endpoint:

```bash
curl https://YOUR-RENDER-SERVICE.onrender.com/health
```

## Deployment URL

- API base URL: https://ticket-system-d2j7.onrender.com
- Health check URL: https://ticket-system-d2j7.onrender.com/health

## Assumptions

- The assignment allows a simple persistent store, so this implementation uses a JSON file.
- Ticket creation always starts with status `open`.
- Users must move tickets from `open` to `in_progress`, then from `in_progress` to `closed`.
- Repeating the same status is treated as valid and leaves the ticket in that status.
