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
  if (!requested.includes(MFA_ACR)) {
    return;
  }

  const enrolled = (event.user.enrolledFactors || []).map((factor) => ({ type: factor.type }));
  if (enrolled.length > 0) {
    // Always challenge in this login, even if MFA was already done earlier in the
    // Auth0 session (api.multifactor.enable would accept that and not ask again).
    api.authentication.challengeWithAny(enrolled);
  } else {
    // No factor enrolled yet: make the user set one up (e.g. scan a QR code).
    api.multifactor.enable('any', { allowRememberBrowser: false });
  }

  // Tells the app this login passed the step-up challenge. Auth0 only issues the
  // token after the challenge succeeds. Must match AUTH0_STEP_UP_CLAIM in the app.
  api.idToken.setCustomClaim('https://authexample.demo/step_up_mfa', true);
};
