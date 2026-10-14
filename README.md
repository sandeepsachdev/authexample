# authexample — Spring Boot + Auth0 on Railway

A minimal Spring Boot 3 web app that shows how to add **Auth0** login to a Java web app
with Spring Security's built-in OpenID Connect support, packaged to deploy on
**[Railway](https://railway.com)** with one click.

| Page | Access | What it shows |
|------|--------|---------------|
| `/` | public | Welcome page; greets you by name once signed in |
| `/profile` | **requires login** | Your name, email, avatar and all ID token claims |
| `/logout` (POST) | signed in | Ends the local session *and* the Auth0 session |
| `/actuator/health` | public | Health check used by Railway |

## How it works

- `spring-boot-starter-oauth2-client` does the whole OIDC Authorization Code flow.
  Auth0 is configured as a provider in `application.yml` using its issuer URL, so
  endpoints and signing keys are discovered automatically.
- `SecurityConfig` makes `/` public, protects everything else, and adds a logout
  handler that redirects to Auth0's `/v2/logout` so the user is signed out of Auth0 too.
- `HomeController` reads the signed-in user as an `OidcUser` and passes claims to
  Thymeleaf templates.
- `server.forward-headers-strategy=framework` makes the app trust Railway's
  `X-Forwarded-*` headers, so the redirect URIs it sends to Auth0 use `https://`.

```
src/main/java/com/example/authexample/
├── AuthExampleApplication.java
├── config/SecurityConfig.java   # route protection, login, Auth0 logout
└── web/HomeController.java      # "/" and "/profile"
src/main/resources/
├── application.yml              # Auth0 + PORT config (from env vars)
└── templates/                   # Thymeleaf pages
```

## 1. Set up Auth0

1. Sign up / log in at <https://manage.auth0.com>.
2. **Applications → Applications → Create Application** → choose
   **Regular Web Applications**.
3. On the **Settings** tab note the **Domain**, **Client ID** and **Client Secret**.
4. Fill in these fields (comma-separate local and Railway URLs) and **Save**:

   | Field | Value |
   |-------|-------|
   | Allowed Callback URLs | `http://localhost:8080/login/oauth2/code/auth0, https://YOUR-APP.up.railway.app/login/oauth2/code/auth0` |
   | Allowed Logout URLs | `http://localhost:8080/, https://YOUR-APP.up.railway.app/` |
   | Allowed Web Origins | `http://localhost:8080, https://YOUR-APP.up.railway.app` |

You'll come back and fill in the Railway URL after the first deploy.

## 2. Run locally

Requires Java 21 (the Maven wrapper downloads Maven for you).

```bash
export AUTH0_DOMAIN=dev-xxxxxxxx.us.auth0.com   # no https://, no trailing slash
export AUTH0_CLIENT_ID=...
export AUTH0_CLIENT_SECRET=...
./mvnw spring-boot:run
```

Open <http://localhost:8080>, click **Log in with Auth0**, then visit **Profile**.

Run the tests (no Auth0 tenant needed):

```bash
./mvnw test
```

## 3. Deploy to Railway

The repo includes a `Dockerfile` and `railway.json` (build with Docker, health check
on `/actuator/health`), so there's nothing else to configure.

1. Push this repo to GitHub.
2. In Railway: **New Project → Deploy from GitHub repo** → pick this repo.
3. In the service's **Variables** tab add:
   - `AUTH0_DOMAIN`
   - `AUTH0_CLIENT_ID`
   - `AUTH0_CLIENT_SECRET`

   (Railway sets `PORT` itself; the app listens on it automatically.)
4. **Settings → Networking → Generate Domain** to get a public
   `https://<name>.up.railway.app` URL.
5. Add that URL to the Auth0 **Allowed Callback / Logout URLs / Web Origins**
   (see step 1) and save.
6. Open the Railway URL and log in. 🎉

Or, with the Railway CLI:

```bash
railway init
railway variables --set AUTH0_DOMAIN=... --set AUTH0_CLIENT_ID=... --set AUTH0_CLIENT_SECRET=...
railway up
railway domain
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| App fails at startup with `Could not resolve placeholder 'AUTH0_DOMAIN'` | Set the three `AUTH0_*` variables. |
| App fails at startup with an issuer / discovery error | `AUTH0_DOMAIN` must be just the host, e.g. `dev-abc.us.auth0.com`. |
| Auth0 shows *Callback URL mismatch* | Add `https://<your-domain>/login/oauth2/code/auth0` exactly to Allowed Callback URLs. |
| Callback URL starts with `http://` on Railway | Make sure `server.forward-headers-strategy: framework` is still in `application.yml`. |
| Logout shows an Auth0 error page | Add `https://<your-domain>/` to Allowed Logout URLs. |
