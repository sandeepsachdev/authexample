package com.example.authexample.admin;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.springframework.security.oauth2.core.oidc.user.OidcUser;

/**
 * Checks the ID token from the user's latest login for a recent MFA challenge:
 * Auth0 lists "mfa" in the {@code amr} (authentication methods) claim when MFA was done,
 * and {@code auth_time} says when the user actually logged in.
 */
final class RecentMfa {

    private RecentMfa() {
    }

    static boolean verified(OidcUser user, Duration maxAge, Clock clock) {
        List<String> methods = user.getAuthenticationMethods();
        Instant authenticatedAt = user.getAuthenticatedAt();
        return methods != null && methods.contains("mfa")
            && authenticatedAt != null
            && !authenticatedAt.isBefore(clock.instant().minus(maxAge));
    }
}
