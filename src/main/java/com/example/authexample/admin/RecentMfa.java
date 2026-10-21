package com.example.authexample.admin;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.springframework.security.oauth2.core.oidc.user.OidcUser;

/**
 * Checks the ID token from the user's latest login for a recent MFA challenge:
 * Auth0 lists "mfa" in the {@code amr} (authentication methods) claim when MFA was done.
 *
 * Freshness uses {@code iat} (when the token was issued), not {@code auth_time}: a step-up
 * that reuses the Auth0 session skips the password, so {@code auth_time} may still be the
 * original login hours ago, while the token from the step-up round trip is always new.
 */
final class RecentMfa {

    private RecentMfa() {
    }

    static boolean verified(OidcUser user, Duration maxAge, Clock clock) {
        List<String> methods = user.getAuthenticationMethods();
        Instant issuedAt = user.getIssuedAt();
        return methods != null && methods.contains("mfa")
            && issuedAt != null
            && !issuedAt.isBefore(clock.instant().minus(maxAge));
    }
}
