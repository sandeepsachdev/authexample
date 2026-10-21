/**
 * Auth0 Post-Login Action: require MFA when the app asks for it (step-up authentication).
 *
 * The app requests this by sending
 *   acr_values=http://schemas.openid.net/pape/policies/2007/06/multi-factor
 * (it does so before an admin adds a role to a user). Ordinary logins are unaffected.
 *
 * Paste into Auth0 Dashboard → Actions → Library → Create Action (trigger: "Login / Post Login"),
 * Deploy it, then add it to the Login flow (Actions → Triggers → post-login).
 */
exports.onExecutePostLogin = async (event, api) => {
  const MFA_ACR = 'http://schemas.openid.net/pape/policies/2007/06/multi-factor';
  const requested = (event.transaction && event.transaction.acr_values) || [];

  if (requested.includes(MFA_ACR)) {
    // Challenge with any factor the user has enrolled (or let them enroll one),
    // and don't let "remember this browser" skip the challenge.
    api.multifactor.enable('any', { allowRememberBrowser: false });
  }
};
