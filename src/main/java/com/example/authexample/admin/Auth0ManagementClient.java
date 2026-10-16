package com.example.authexample.admin;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;

/**
 * Minimal client for the Auth0 Management API (https://auth0.com/docs/api/management/v2),
 * used by admins to list users and change which roles they have.
 *
 * It signs in as a Machine-to-Machine application using the client credentials grant,
 * caches the resulting access token until shortly before it expires, and sends it as a
 * Bearer token on each call.
 */
public class Auth0ManagementClient {

    private static final int PAGE_SIZE = 100;

    private final RestClient rest;
    private final String clientId;
    private final String clientSecret;
    private final String audience;
    private final Clock clock;

    private String accessToken;
    private Instant accessTokenExpiry = Instant.MIN;

    public Auth0ManagementClient(RestClient.Builder builder, String domain, String clientId, String clientSecret,
            Clock clock) {
        this.rest = builder.baseUrl("https://" + domain).build();
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.audience = "https://" + domain + "/api/v2/";
        this.clock = clock;
    }

    /** False until AUTH0_MGMT_CLIENT_ID and AUTH0_MGMT_CLIENT_SECRET are set. */
    public boolean isConfigured() {
        return !clientId.isBlank() && !clientSecret.isBlank();
    }

    /** One page of users, most recent login first. Needs scope read:users. */
    public Auth0Models.UserPage listUsers(int page, int perPage) {
        return rest.get()
            .uri("/api/v2/users?page={page}&per_page={perPage}&include_totals=true&sort=last_login:-1",
                page, perPage)
            .headers(h -> h.setBearerAuth(token()))
            .retrieve()
            .body(Auth0Models.UserPage.class);
    }

    /** Needs scope read:users. */
    public Auth0Models.User getUser(String userId) {
        return rest.get()
            .uri("/api/v2/users/{id}", userId)
            .headers(h -> h.setBearerAuth(token()))
            .retrieve()
            .body(Auth0Models.User.class);
    }

    /** All roles defined in the tenant. Needs scope read:roles. */
    public List<Auth0Models.Role> listRoles() {
        return rest.get()
            .uri("/api/v2/roles?per_page={perPage}", PAGE_SIZE)
            .headers(h -> h.setBearerAuth(token()))
            .retrieve()
            .body(new ParameterizedTypeReference<>() {});
    }

    /** IDs of every user that has the role. Needs scopes read:roles and read:role_members. */
    public List<String> roleMemberIds(String roleId) {
        List<String> ids = new ArrayList<>();
        for (int page = 0; ; page++) {
            List<Auth0Models.User> members = rest.get()
                .uri("/api/v2/roles/{id}/users?page={page}&per_page={perPage}", roleId, page, PAGE_SIZE)
                .headers(h -> h.setBearerAuth(token()))
                .retrieve()
                .body(new ParameterizedTypeReference<>() {});
            members.forEach(m -> ids.add(m.userId()));
            if (members.size() < PAGE_SIZE) {
                return ids;
            }
        }
    }

    /** Needs scopes read:users and read:roles. */
    public List<Auth0Models.Role> getUserRoles(String userId) {
        return rest.get()
            .uri("/api/v2/users/{id}/roles?per_page={perPage}", userId, PAGE_SIZE)
            .headers(h -> h.setBearerAuth(token()))
            .retrieve()
            .body(new ParameterizedTypeReference<>() {});
    }

    /** Needs scope create:role_members. */
    public void assignRoles(String userId, Collection<String> roleIds) {
        if (roleIds.isEmpty()) {
            return;
        }
        rest.post()
            .uri("/api/v2/users/{id}/roles", userId)
            .headers(h -> h.setBearerAuth(token()))
            .contentType(MediaType.APPLICATION_JSON)
            .body(Map.of("roles", roleIds))
            .retrieve()
            .toBodilessEntity();
    }

    /** Needs scope delete:role_members. */
    public void removeRoles(String userId, Collection<String> roleIds) {
        if (roleIds.isEmpty()) {
            return;
        }
        rest.method(HttpMethod.DELETE)
            .uri("/api/v2/users/{id}/roles", userId)
            .headers(h -> h.setBearerAuth(token()))
            .contentType(MediaType.APPLICATION_JSON)
            .body(Map.of("roles", roleIds))
            .retrieve()
            .toBodilessEntity();
    }

    /**
     * Creates a user in a database connection (email + password login). Needs scope create:users.
     * Auth0 rejects passwords that don't meet the connection's password policy with HTTP 400,
     * and emails that already exist with HTTP 409.
     */
    public Auth0Models.User createUser(String connection, String email, String name, String password) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("connection", connection);
        body.put("email", email);
        body.put("password", password);
        if (name != null && !name.isBlank()) {
            body.put("name", name.trim());
        }
        return rest.post()
            .uri("/api/v2/users")
            .headers(h -> h.setBearerAuth(token()))
            .contentType(MediaType.APPLICATION_JSON)
            .body(body)
            .retrieve()
            .body(Auth0Models.User.class);
    }

    /**
     * Creates a one-time link that lets the user choose their own password (an Auth0
     * "password change ticket"). After setting it they are sent to {@code resultUrl}.
     * Opening the link also proves they own the email, so it is marked verified.
     * Needs scope create:user_tickets.
     */
    public String createPasswordSetupLink(String userId, String resultUrl, Duration validFor) {
        Auth0Models.Ticket ticket = rest.post()
            .uri("/api/v2/tickets/password-change")
            .headers(h -> h.setBearerAuth(token()))
            .contentType(MediaType.APPLICATION_JSON)
            .body(Map.of(
                "user_id", userId,
                "result_url", resultUrl,
                "ttl_sec", validFor.toSeconds(),
                "mark_email_as_verified", true))
            .retrieve()
            .body(Auth0Models.Ticket.class);
        return ticket.ticket();
    }

    /** Fetches a Management API token with the client credentials grant, reusing it until it's about to expire. */
    private synchronized String token() {
        if (accessToken == null || clock.instant().isAfter(accessTokenExpiry)) {
            Auth0Models.TokenResponse response = rest.post()
                .uri("/oauth/token")
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of(
                    "grant_type", "client_credentials",
                    "client_id", clientId,
                    "client_secret", clientSecret,
                    "audience", audience))
                .retrieve()
                .body(Auth0Models.TokenResponse.class);
            accessToken = response.accessToken();
            accessTokenExpiry = clock.instant().plusSeconds(Math.max(0, response.expiresIn() - 60));
        }
        return accessToken;
    }
}
