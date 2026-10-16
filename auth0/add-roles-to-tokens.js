/**
 * Auth0 Post-Login Action: adds the user's RBAC roles to the ID token.
 *
 * Paste this into Auth0 Dashboard → Actions → Library → Create Action
 * (trigger: "Login / Post Login"), Deploy it, then add it to the Login flow
 * (Actions → Triggers → post-login).
 *
 * The namespace must match app.auth0.roles-claim / AUTH0_ROLES_CLAIM in the app.
 */
exports.onExecutePostLogin = async (event, api) => {
  const namespace = 'https://authexample.demo';
  const roles = (event.authorization && event.authorization.roles) || [];

  api.idToken.setCustomClaim(`${namespace}/roles`, roles);
  api.accessToken.setCustomClaim(`${namespace}/roles`, roles);
};
