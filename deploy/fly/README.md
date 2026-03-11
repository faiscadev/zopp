# Deploy zopp-server on Fly

Deploy a zopp-server instance on [Fly.io](https://fly.io) with PostgreSQL.

## Prerequisites

- [Fly CLI](https://fly.io/docs/flyctl/install/) installed and authenticated (`fly auth login`)
- A Fly account with billing configured

## Quick Start

### 1. Launch the app

From the repository root:

```bash
fly launch --config deploy/fly/fly.toml --no-deploy
```

Fly will prompt you to set the app name and region. Choose a region close to your team.

### 2. Create a PostgreSQL database

```bash
fly postgres create --name zopp-db
```

Choose the same region as your app. For development, the "Development" plan is sufficient.

### 3. Attach the database

```bash
fly postgres attach zopp-db --app <your-app-name>
```

This automatically sets the `DATABASE_URL` secret on your app.

### 4. Deploy

```bash
fly deploy --config deploy/fly/fly.toml
```

The first deploy takes a few minutes to build the Docker image.

### 5. Verify the deployment

```bash
fly status --app <your-app-name>
```

Check that the Machine is running and healthy.

## Generate an Invite Token

After deploying, create the first invite token to bootstrap your workspace:

```bash
fly ssh console --app <your-app-name> -C "/usr/local/bin/zopp-server invite create"
```

This outputs an invite token. Save it securely — you'll use it to join the server from the CLI.

## Connect the CLI

With the invite token from the previous step:

```bash
zopp join <invite-token> <your-email> --server https://<your-app-name>.fly.dev
```

This registers your device as a principal on the server. You can then create workspaces and manage secrets:

```bash
zopp workspace create my-workspace
zopp project create my-project
zopp environment create production
zopp secret set API_KEY "my-secret-value"
```

## Environment Variables

### Set automatically

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string (set by `fly postgres attach`) |

### Configured in fly.toml

| Variable | Default | Description |
|---|---|---|
| `ZOPP_EMAIL_VERIFICATION_REQUIRED` | `false` | Set to `true` once email is configured |

### Optional (set as Fly secrets)

Set these with `fly secrets set`:

```bash
# Enable email verification with Resend
fly secrets set \
  ZOPP_EMAIL_VERIFICATION_REQUIRED=true \
  ZOPP_EMAIL_PROVIDER=resend \
  ZOPP_EMAIL_FROM=noreply@yourdomain.com \
  RESEND_API_KEY=re_xxxxx

# Or use SMTP
fly secrets set \
  ZOPP_EMAIL_VERIFICATION_REQUIRED=true \
  ZOPP_EMAIL_PROVIDER=smtp \
  ZOPP_EMAIL_FROM=noreply@yourdomain.com \
  SMTP_HOST=smtp.example.com \
  SMTP_PORT=587 \
  SMTP_USERNAME=user \
  SMTP_PASSWORD=pass
```

## TLS

Fly automatically terminates TLS at the edge. The zopp-server runs plain gRPC internally — no TLS certificate configuration is needed.

Your CLI connects via `https://<your-app-name>.fly.dev` and Fly handles the TLS termination.

## Scaling

The default configuration uses a shared CPU with 256MB RAM and auto-stop enabled. To adjust:

```bash
# Scale VM size
fly scale vm shared-cpu-2x --memory 512 --app <your-app-name>

# Keep at least one Machine running (disable auto-stop)
fly scale count 1 --app <your-app-name>
```

## Troubleshooting

### Check server logs

```bash
fly logs --app <your-app-name>
```

### Check health

```bash
curl https://<your-app-name>.fly.dev/healthz
```

### SSH into the Machine

```bash
fly ssh console --app <your-app-name>
```
