package com.example.authexample.admin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

class Auth0ManagementClientTests {

    private MockRestServiceServer server;
    private Auth0ManagementClient client;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        client = new Auth0ManagementClient(builder, "example.auth0.com", "mgmt-id", "mgmt-secret",
            Clock.fixed(Instant.parse("2026-10-16T00:00:00Z"), ZoneOffset.UTC));
    }

    private void expectTokenRequest() {
        server.expect(requestTo("https://example.auth0.com/oauth/token"))
            .andExpect(method(HttpMethod.POST))
            .andExpect(content().json("""
                {"grant_type":"client_credentials","client_id":"mgmt-id","client_secret":"mgmt-secret",
                 "audience":"https://example.auth0.com/api/v2/"}"""))
            .andRespond(withSuccess("""
                {"access_token":"tok","expires_in":86400,"token_type":"Bearer"}""", MediaType.APPLICATION_JSON));
    }

    @Test
    void listsUsersWithBearerTokenAndReusesToken() {
        expectTokenRequest();
        server.expect(requestTo("https://example.auth0.com/api/v2/users?page=0&per_page=25&include_totals=true&sort=last_login:-1"))
            .andExpect(header("Authorization", "Bearer tok"))
            .andRespond(withSuccess("""
                {"start":0,"limit":25,"length":1,"total":1,"users":[
                  {"user_id":"auth0|1","email":"ada@example.com","name":"Ada","logins_count":3,
                   "last_login":"2026-10-15T09:30:00.000Z","identities":[]}]}""", MediaType.APPLICATION_JSON));
        server.expect(requestTo("https://example.auth0.com/api/v2/roles?per_page=100"))
            .andExpect(header("Authorization", "Bearer tok"))
            .andRespond(withSuccess("""
                [{"id":"rol_1","name":"admin","description":"Admins"}]""", MediaType.APPLICATION_JSON));

        var page = client.listUsers(0, 25);
        var roles = client.listRoles();

        assertThat(page.total()).isEqualTo(1);
        assertThat(page.users()).extracting(Auth0Models.User::userId, Auth0Models.User::loginsCount)
            .containsExactly(org.assertj.core.groups.Tuple.tuple("auth0|1", 3));
        assertThat(roles).extracting(Auth0Models.Role::name).containsExactly("admin");
        server.verify();
    }

    @Test
    void encodesUserIdAndSendsRoleChanges() {
        expectTokenRequest();
        server.expect(requestTo("https://example.auth0.com/api/v2/users/auth0%7C1/roles"))
            .andExpect(method(HttpMethod.POST))
            .andExpect(content().json("""
                {"roles":["rol_1"]}"""))
            .andRespond(withSuccess());
        server.expect(requestTo("https://example.auth0.com/api/v2/users/auth0%7C1/roles"))
            .andExpect(method(HttpMethod.DELETE))
            .andExpect(content().json("""
                {"roles":["rol_2"]}"""))
            .andRespond(withSuccess());

        client.assignRoles("auth0|1", List.of("rol_1"));
        client.removeRoles("auth0|1", List.of("rol_2"));
        client.assignRoles("auth0|1", List.of()); // no-op: no request sent

        server.verify();
    }

    @Test
    void pagesThroughRoleMembers() {
        expectTokenRequest();
        String fullPage = "[" + String.join(",", java.util.stream.IntStream.range(0, 100)
            .mapToObj(i -> "{\"user_id\":\"auth0|" + i + "\"}").toList()) + "]";
        server.expect(requestTo("https://example.auth0.com/api/v2/roles/rol_1/users?page=0&per_page=100"))
            .andRespond(withSuccess(fullPage, MediaType.APPLICATION_JSON));
        server.expect(requestTo("https://example.auth0.com/api/v2/roles/rol_1/users?page=1&per_page=100"))
            .andRespond(withSuccess("[{\"user_id\":\"auth0|100\"}]", MediaType.APPLICATION_JSON));

        assertThat(client.roleMemberIds("rol_1")).hasSize(101).contains("auth0|0", "auth0|100");
        server.verify();
    }

    @Test
    void isConfiguredOnlyWithCredentials() {
        assertThat(client.isConfigured()).isTrue();
        assertThat(new Auth0ManagementClient(RestClient.builder(), "example.auth0.com", "", "", Clock.systemUTC())
            .isConfigured()).isFalse();
    }
}
