# authexample — Spring Boot + Auth0 on Railway

A minimal Spring Boot 3 web app that shows how to add **Auth0** login to a Java web app
with Spring Security's built-in OpenID Connect support, packaged to deploy on
**[Railway](https://railway.com)** with one click.

| Page | Access | What it shows |
|------|--------|---------------|
| `/` | public | Welcome page; greets you by name once signed in |
| `/profile` | **requires login** | Your name, email, avatar, roles and all ID token claims |
| `/members` | **`member` or `admin` role** | Members-only page |
| `/admin` | **`admin` role** | Admin-only page |
| `/logout` (POST) | signed in | Ends the local session *and* the Auth0 session |
| `/actuator/health` | public | Health check used by Railway |

## How it works

- `spring-boot-starter-oauth2-client` does the whole OIDC Authorization Code flow.
  Auth0 is configured as a provider in `application.yml` using its issuer URL, so
  endpoints and signing keys are discovered automatically.
- `SecurityConfig` makes `/` public, protects everything else, and adds a logout
  handler that redirects to Auth0's `/v2/logout` so the user is signed out of Auth0 too.
- `Auth0RolesMapper` turns the roles Auth0 puts in the ID token (via a Post-Login
  Action, see [Access levels](#4-access-levels-roles)) into `ROLE_MEMBER` / `ROLE_ADMIN`.
  `SecurityConfig` guards `/members/**` and `/admin/**` with them, and a role
  hierarchy makes `ADMIN` imply `MEMBER`.
- `HomeController` reads the signed-in user as an `OidcUser` and passes claims to
  Thymeleaf templates.
- `server.forward-headers-strategy=framework` makes the app trust Railway's
  `X-Forwarded-*` headers, so the redirect URIs it sends to Auth0 use `https://`.

```
src/main/java/com/example/authexample/
├── AuthExampleApplication.java
├── config/SecurityConfig.java   # route protection, login, Auth0 logout, role hierarchy
├── config/Auth0RolesMapper.java # Auth0 roles claim -> Spring Security roles
├── web/HomeController.java      # "/" and "/profile"
└── web/AccessController.java    # "/members", "/admin", "/access-denied"
auth0/add-roles-to-tokens.js     # Post-Login Action to paste into Auth0
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

## 4. Access levels (roles)

The app has four levels:

| Level | Who | Can open |
|-------|-----|----------|
| Anonymous | anyone | `/` |
| Signed in | any Auth0 user | `/`, `/profile` |
| Member | users with the `member` role | above + `/members` |
| Admin | users with the `admin` role | everything (admin implies member) |

Auth0 doesn't put roles in tokens by default, so there are three things to set up
in the Auth0 dashboard: the roles, who has them, and an Action that adds them to
the ID token.

### 4a. Create the roles

1. **User Management → Roles → + Create Role**.
2. Name: `member`, Description: `Can open the members area` → **Create**.
3. Repeat with Name: `admin`, Description: `Can open the admin area`.

Role names are case-insensitive in the app (`Admin` becomes `ROLE_ADMIN` too).

### 4b. Assign roles to users

1. **User Management → Users** → click a user (log in to the app once first so
   your user exists, or **+ Create User**).
2. Open the **Roles** tab → **Assign Roles** → pick `member` and/or `admin` → **Assign**.

You can also do it from the role's side: **Roles → admin → Users → Add Users**.

### 4c. Add roles to the ID token with an Action

1. **Actions → Library → Create Action → Build from scratch**.
2. Name: `Add roles to tokens`, Trigger: **Login / Post Login**, Runtime: the
   recommended Node version → **Create**.
3. Replace the code with the contents of
   [`auth0/add-roles-to-tokens.js`](auth0/add-roles-to-tokens.js):

   ```js
   exports.onExecutePostLogin = async (event, api) => {
     const namespace = 'https://authexample.demo';
     const roles = (event.authorization && event.authorization.roles) || [];
     api.idToken.setCustomClaim(`${namespace}/roles`, roles);
     api.accessToken.setCustomClaim(`${namespace}/roles`, roles);
   };
   ```
4. Click **Deploy**.
5. **Actions → Triggers → post-login**. Drag **Add roles to tokens** from the
   *Custom* panel on the right into the flow between **Start** and **Complete**,
   then click **Apply**.

The claim name is namespaced (a URL) so it can't clash with standard OIDC claims; the
URL doesn't have to exist. If you change it, set the app's `AUTH0_ROLES_CLAIM`
variable to the full claim name (e.g. `https://myapp.example.com/roles`).

### 4d. Try it

1. **Log out** of the app and log back in. Roles are read at login, so changes in
   Auth0 only apply after a fresh login.
2. Open **Profile**: the *Roles* line and the *Your access* table show what you can open,
   and the ID token claims include `https://authexample.demo/roles`.
3. Open **Members** / **Admin**. Without the role you get an *Access denied* page (HTTP 403).

To protect a new page, add a rule in `SecurityConfig`, e.g.
`.requestMatchers("/reports/**").hasRole("ADMIN")`, or put
`@PreAuthorize("hasRole('ADMIN')")` on a controller method (after adding
`@EnableMethodSecurity`). To show or hide parts of a page, use
`sec:authorize="hasRole('ADMIN')"` in a Thymeleaf template.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| App fails at startup with `Could not resolve placeholder 'AUTH0_DOMAIN'` | Set the three `AUTH0_*` variables. |
| App fails at startup with an issuer / discovery error | `AUTH0_DOMAIN` must be just the host, e.g. `dev-abc.us.auth0.com`. |
| Auth0 shows *Callback URL mismatch* | Add `https://<your-domain>/login/oauth2/code/auth0` exactly to Allowed Callback URLs. |
| Callback URL starts with `http://` on Railway | Make sure `server.forward-headers-strategy: framework` is still in `application.yml`. |
| Logout shows an Auth0 error page | Add `https://<your-domain>/` to Allowed Logout URLs. |
| Profile says *Roles: none* although roles are assigned | Check the Action is **deployed** and in the **post-login** flow, then log out and back in. |
| Roles claim is in the token but still *none* | The claim name must equal `AUTH0_ROLES_CLAIM` (default `https://authexample.demo/roles`). |
