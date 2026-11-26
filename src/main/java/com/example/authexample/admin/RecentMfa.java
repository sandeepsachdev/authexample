package com.example.authexample.admin;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import org.springframework.security.oauth2.core.oidc.user.OidcUser;

/**
 * Checks that the user's current ID token came from a recent step-up MFA challenge.
 *
 * The step-up Action (auth0/require-mfa-for-step-up.js) challenges the user for MFA and
 * adds a custom claim (e.g. "https://authexample.demo/step_up_mfa": true). Auth0 only issues
 * the token once the challenge is passed, so the claim proves MFA happened in that login.
 * The standard {@code amr} claim isn't used: Auth0 also sets it when MFA was done earlier in
 * the session without a new challenge.
 *
 * Freshness uses {@code iat} (when the token was issued), not {@code auth_time}: a step-up
 * that reuses the Auth0 session skips the password, so {@code auth_time} may still be the
 * original login hours ago, while the token from the step-up round trip is always new.
 */
final class RecentMfa {

    private RecentMfa() {
    }

    static boolean verified(OidcUser user, String stepUpClaim, Duration maxAge, Clock clock) {
        Instant issuedAt = user.getIssuedAt();
        return Boolean.TRUE.equals(user.getClaimAsBoolean(stepUpClaim))
            && issuedAt != null
            && !issuedAt.isBefore(clock.instant().minus(maxAge));
    }
}
