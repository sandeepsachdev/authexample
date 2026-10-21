package com.example.authexample.admin;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
import static org.hamcrest.Matchers.not;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.web.client.HttpClientErrorException;

import com.example.authexample.TestAuth0Config;

@SpringBootTest(properties = {
    "AUTH0_DOMAIN=example.auth0.com",
    "AUTH0_CLIENT_ID=test-client",
    "AUTH0_CLIENT_SECRET=test-secret"
})
@AutoConfigureMockMvc
@Import(TestAuth0Config.class)
class UserAdminControllerTests {

    private static final Auth0Models.Role ADMIN = new Auth0Models.Role("rol_admin", "admin", "Admins");
    private static final Auth0Models.Role MEMBER = new Auth0Models.Role("rol_member", "member", "Members");
    private static final Auth0Models.User ADA =
        new Auth0Models.User("auth0|ada", "ada@example.com", "Ada Lovelace", null, "2026-10-15T09:30:00.000Z", 4, false);

    @Autowired
    MockMvc mvc;

    @MockitoBean
    Auth0ManagementClient auth0;

    @BeforeEach
    void setUp() {
        when(auth0.isConfigured()).thenReturn(true);
        when(auth0.listRoles()).thenReturn(List.of(ADMIN, MEMBER));
    }

    /** An admin whose last login did not include MFA. */
    private static RequestPostProcessor admin(String subject) {
        return oidcLogin()
            .idToken(t -> t.subject(subject))
            .authorities(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }

    /** An admin who logged in with MFA {@code ago} ago (Auth0 sets amr=["mfa"] and auth_time). */
    private static RequestPostProcessor adminWithMfa(String subject, java.time.Duration ago) {
        return oidcLogin()
            .idToken(t -> t.subject(subject)
                .claim("amr", List.of("mfa"))
                .claim("auth_time", java.time.Instant.now().minus(ago)))
            .authorities(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }

    @Test
    void onlyAdminsCanOpenUserManagement() throws Exception {
        mvc.perform(get("/admin/users").with(oidcLogin().authorities(new SimpleGrantedAuthority("ROLE_MEMBER"))))
            .andExpect(status().isForbidden());
        mvc.perform(post("/admin/users/auth0|ada/roles").param("roleIds", "rol_admin")
                .with(oidcLogin().authorities(new SimpleGrantedAuthority("ROLE_MEMBER"))).with(csrf()))
            .andExpect(status().isForbidden());
        verify(auth0, never()).assignRoles(any(), any());
    }

    @Test
    void listsUsersWithTheirRoles() throws Exception {
        when(auth0.roleMemberIds("rol_admin")).thenReturn(List.of());
        when(auth0.roleMemberIds("rol_member")).thenReturn(List.of("auth0|ada"));
        when(auth0.listUsers(0, UserAdminController.PER_PAGE))
            .thenReturn(new Auth0Models.UserPage(0, 25, 1, List.of(ADA)));

        mvc.perform(get("/admin/users").with(admin("auth0|me")))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("Ada Lovelace")))
            .andExpect(content().string(containsString(">member<")))
            .andExpect(content().string(containsString("2026-10-15 09:30")))
            .andExpect(content().string(containsString("/admin/users/auth0%7Cada")));
    }

    @Test
    void editPageShowsCheckedRoles() throws Exception {
        when(auth0.getUser("auth0|ada")).thenReturn(ADA);
        when(auth0.getUserRoles("auth0|ada")).thenReturn(List.of(MEMBER));

        mvc.perform(get("/admin/users/{id}", "auth0|ada").with(admin("auth0|me")))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("value=\"rol_member\" checked")))
            .andExpect(content().string(containsString("value=\"rol_admin\">")));
    }

    @Test
    void savingRolesAddsAndRemovesTheDifference() throws Exception {
        when(auth0.getUserRoles("auth0|ada")).thenReturn(List.of(MEMBER));

        mvc.perform(post("/admin/users/{id}/roles", "auth0|ada").param("roleIds", "rol_admin")
                .with(adminWithMfa("auth0|me", java.time.Duration.ofMinutes(1))).with(csrf()))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("/admin/users/auth0%7Cada"))
            .andExpect(flash().attribute("message", containsString("Roles updated")));

        verify(auth0).assignRoles("auth0|ada", List.of("rol_admin"));
        verify(auth0).removeRoles("auth0|ada", List.of("rol_member"));
    }

    @Test
    void uncheckingEverythingRemovesAllRoles() throws Exception {
        when(auth0.getUserRoles("auth0|ada")).thenReturn(List.of(ADMIN, MEMBER));

        mvc.perform(post("/admin/users/{id}/roles", "auth0|ada").with(admin("auth0|me")).with(csrf()))
            .andExpect(status().is3xxRedirection());

        verify(auth0).assignRoles("auth0|ada", List.of());
        verify(auth0).removeRoles("auth0|ada", List.of("rol_admin", "rol_member"));
    }

    @Test
    void adminCannotRemoveOwnAdminRole() throws Exception {
        when(auth0.getUserRoles("auth0|me")).thenReturn(List.of(ADMIN));

        mvc.perform(post("/admin/users/{id}/roles", "auth0|me").param("roleIds", "rol_member")
                .with(admin("auth0|me")).with(csrf()))
            .andExpect(status().is3xxRedirection())
            .andExpect(flash().attribute("error", containsString("can't remove your own admin role")));

        verify(auth0, never()).assignRoles(any(), any());
        verify(auth0, never()).removeRoles(any(), any());
    }

    @Test
    void showsSetupInstructionsWhenNotConfigured() throws Exception {
        when(auth0.isConfigured()).thenReturn(false);

        mvc.perform(get("/admin/users").with(admin("auth0|me")))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("AUTH0_MGMT_CLIENT_ID")));
    }

    @Test
    void showsAuth0ErrorsInsteadOfFailing() throws Exception {
        when(auth0.listUsers(anyInt(), eq(UserAdminController.PER_PAGE))).thenThrow(HttpClientErrorException.create(
            HttpStatus.FORBIDDEN, "Forbidden", HttpHeaders.EMPTY,
            "{\"message\":\"Insufficient scope, expected any of: read:users\"}".getBytes(StandardCharsets.UTF_8),
            StandardCharsets.UTF_8));

        mvc.perform(get("/admin/users").with(admin("auth0|me")))
            .andExpect(status().isBadGateway())
            .andExpect(content().string(containsString("Insufficient scope")));
    }

    private static final Auth0Models.User GRACE =
        new Auth0Models.User("auth0|grace", "grace@example.com", "Grace Hopper", null, null, 0, false);

    @Test
    void newUserFormListsRoles() throws Exception {
        mvc.perform(get("/admin/users/new").with(admin("auth0|me")))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("New user")))
            .andExpect(content().string(containsString("value=\"rol_member\"")));
    }

    @Test
    void membersCannotCreateUsers() throws Exception {
        mvc.perform(post("/admin/users").param("email", "x@example.com")
                .with(oidcLogin().authorities(new SimpleGrantedAuthority("ROLE_MEMBER"))).with(csrf()))
            .andExpect(status().isForbidden());
        verify(auth0, never()).createUser(any(), any(), any(), any());
    }

    @Test
    void createsUserWithRolesAndSetupLink() throws Exception {
        when(auth0.createUser(eq("Username-Password-Authentication"), eq("grace@example.com"), eq("Grace Hopper"),
            anyString())).thenReturn(GRACE);
        when(auth0.createPasswordSetupLink("auth0|grace", "http://localhost/", UserAdminController.SETUP_LINK_VALIDITY))
            .thenReturn("https://example.auth0.com/lo/reset?ticket=abc");

        mvc.perform(post("/admin/users")
                .param("email", " grace@example.com ")
                .param("name", "Grace Hopper")
                .param("password", "")
                .param("roleIds", "rol_member", "rol_unknown")
                .with(admin("auth0|me")).with(csrf()))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("/admin/users/auth0%7Cgrace"))
            .andExpect(flash().attribute("message", "User created."))
            .andExpect(flash().attribute("setupLink", "https://example.auth0.com/lo/reset?ticket=abc"));

        // Unknown role IDs are dropped; a strong random password is generated.
        verify(auth0).assignRoles("auth0|grace", List.of("rol_member"));
        verify(auth0).createUser(any(), any(), any(), org.mockito.ArgumentMatchers.argThat(p -> p.length() >= 32));
    }

    @Test
    void createsUserWithAdminChosenPasswordAndNoLink() throws Exception {
        when(auth0.createUser(any(), eq("grace@example.com"), any(), eq("Chosen-Pa55word!"))).thenReturn(GRACE);

        mvc.perform(post("/admin/users")
                .param("email", "grace@example.com")
                .param("password", "Chosen-Pa55word!")
                .with(admin("auth0|me")).with(csrf()))
            .andExpect(status().is3xxRedirection())
            .andExpect(flash().attributeCount(1));

        verify(auth0, never()).createPasswordSetupLink(any(), any(), any());
    }

    @Test
    void showsAuth0ValidationErrorsOnTheFormWithoutEchoingPassword() throws Exception {
        when(auth0.createUser(any(), any(), any(), any())).thenThrow(HttpClientErrorException.create(
            HttpStatus.BAD_REQUEST, "Bad Request", HttpHeaders.EMPTY,
            "{\"statusCode\":400,\"message\":\"PasswordStrengthError: Password is too weak\"}"
                .getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8));

        mvc.perform(post("/admin/users")
                .param("email", "grace@example.com")
                .param("password", "weakpass123")
                .param("roleIds", "rol_member")
                .with(admin("auth0|me")).with(csrf()))
            .andExpect(status().isOk())
            .andExpect(view().name("admin/user-new"))
            .andExpect(content().string(containsString("PasswordStrengthError: Password is too weak")))
            .andExpect(content().string(containsString("value=\"grace@example.com\"")))
            .andExpect(content().string(containsString("value=\"rol_member\" checked")))
            .andExpect(content().string(not(containsString("weakpass123"))));

        verify(auth0, never()).assignRoles(any(), any());
    }

    @Test
    void rejectsInvalidEmailBeforeCallingAuth0() throws Exception {
        mvc.perform(post("/admin/users").param("email", "not-an-email").with(admin("auth0|me")).with(csrf()))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("Enter a valid email address.")));
        verify(auth0, never()).createUser(any(), any(), any(), any());
    }

    // ---- Step-up MFA when adding roles ----

    @Test
    void addingRoleWithoutMfaParksChangeAndAsksForVerification() throws Exception {
        when(auth0.getUserRoles("auth0|ada")).thenReturn(List.of(MEMBER));
        var session = new org.springframework.mock.web.MockHttpSession();

        mvc.perform(post("/admin/users/{id}/roles", "auth0|ada").param("roleIds", "rol_member", "rol_admin")
                .session(session).with(admin("auth0|me")).with(csrf()))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("/admin/users/auth0%7Cada/roles/verify"));

        assertThat(session.getAttribute(PendingRoleChange.SESSION_KEY))
            .isEqualTo(new PendingRoleChange("auth0|ada", java.util.Set.of("rol_member", "rol_admin")));
        verify(auth0, never()).assignRoles(any(), any());
        verify(auth0, never()).removeRoles(any(), any());
    }

    @Test
    void mfaFromAnOldLoginDoesNotCount() throws Exception {
        when(auth0.getUserRoles("auth0|ada")).thenReturn(List.of());

        mvc.perform(post("/admin/users/{id}/roles", "auth0|ada").param("roleIds", "rol_admin")
                .with(adminWithMfa("auth0|me", java.time.Duration.ofHours(1))).with(csrf()))
            .andExpect(redirectedUrl("/admin/users/auth0%7Cada/roles/verify"));

        verify(auth0, never()).assignRoles(any(), any());
    }

    @Test
    void removingRolesDoesNotNeedMfa() throws Exception {
        when(auth0.getUserRoles("auth0|ada")).thenReturn(List.of(MEMBER));

        mvc.perform(post("/admin/users/{id}/roles", "auth0|ada").with(admin("auth0|me")).with(csrf()))
            .andExpect(redirectedUrl("/admin/users/auth0%7Cada"));

        verify(auth0).removeRoles("auth0|ada", List.of("rol_member"));
    }

    @Test
    void verifyWithoutMfaSendsAdminToStepUpLoginAndRemembersWhereToComeBack() throws Exception {
        var session = new org.springframework.mock.web.MockHttpSession();
        session.setAttribute(PendingRoleChange.SESSION_KEY, new PendingRoleChange("auth0|ada", java.util.Set.of("rol_admin")));

        mvc.perform(get("/admin/users/{id}/roles/verify", "auth0|ada").session(session).with(admin("auth0|me")))
            .andExpect(redirectedUrl("/oauth2/authorization/auth0?mfa"));

        var saved = (org.springframework.security.web.savedrequest.SavedRequest)
            session.getAttribute("SPRING_SECURITY_SAVED_REQUEST");
        assertThat(saved.getRedirectUrl()).contains("/admin/users/auth0%7Cada/roles/verify");
    }

    @Test
    void stepUpLoginAsksAuth0ForAFreshLoginWithMfa() throws Exception {
        String stepUp = mvc.perform(get("/oauth2/authorization/auth0").param("mfa", ""))
            .andExpect(status().is3xxRedirection())
            .andReturn().getResponse().getRedirectedUrl();
        String normal = mvc.perform(get("/oauth2/authorization/auth0"))
            .andReturn().getResponse().getRedirectedUrl();

        assertThat(stepUp).startsWith("https://example.auth0.com/authorize?")
            .contains("prompt=login")
            .contains("acr_values=http://schemas.openid.net/pape/policies/2007/06/multi-factor");
        assertThat(normal).doesNotContain("prompt=").doesNotContain("acr_values");
    }

    @Test
    void verifyWithFreshMfaShowsConfirmation() throws Exception {
        when(auth0.getUser("auth0|ada")).thenReturn(ADA);
        when(auth0.getUserRoles("auth0|ada")).thenReturn(List.of(MEMBER));
        var session = new org.springframework.mock.web.MockHttpSession();
        session.setAttribute(PendingRoleChange.SESSION_KEY, new PendingRoleChange("auth0|ada", java.util.Set.of("rol_admin")));

        mvc.perform(get("/admin/users/{id}/roles/verify", "auth0|ada").session(session)
                .with(adminWithMfa("auth0|me", java.time.Duration.ofSeconds(10))))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("Identity verified")))
            .andExpect(content().string(containsString("Add <span class=\"badge admin\">admin</span>")))
            .andExpect(content().string(containsString("Remove <span class=\"badge blocked\">member</span>")));

        verify(auth0, never()).assignRoles(any(), any());
    }

    @Test
    void applyWithFreshMfaMakesTheChangeOnce() throws Exception {
        when(auth0.getUserRoles("auth0|ada")).thenReturn(List.of(MEMBER));
        var session = new org.springframework.mock.web.MockHttpSession();
        session.setAttribute(PendingRoleChange.SESSION_KEY,
            new PendingRoleChange("auth0|ada", java.util.Set.of("rol_member", "rol_admin")));

        mvc.perform(post("/admin/users/{id}/roles/apply", "auth0|ada").session(session)
                .with(adminWithMfa("auth0|me", java.time.Duration.ofMinutes(1))).with(csrf()))
            .andExpect(redirectedUrl("/admin/users/auth0%7Cada"))
            .andExpect(flash().attribute("message", containsString("Roles updated")));

        verify(auth0).assignRoles("auth0|ada", List.of("rol_admin"));
        assertThat(session.getAttribute(PendingRoleChange.SESSION_KEY)).isNull();
    }

    @Test
    void applyWithoutMfaGoesBackToVerification() throws Exception {
        var session = new org.springframework.mock.web.MockHttpSession();
        session.setAttribute(PendingRoleChange.SESSION_KEY, new PendingRoleChange("auth0|ada", java.util.Set.of("rol_admin")));

        mvc.perform(post("/admin/users/{id}/roles/apply", "auth0|ada").session(session)
                .with(admin("auth0|me")).with(csrf()))
            .andExpect(redirectedUrl("/admin/users/auth0%7Cada/roles/verify"));

        verify(auth0, never()).assignRoles(any(), any());
    }

    @Test
    void applyIgnoresAChangeParkedForAnotherUser() throws Exception {
        var session = new org.springframework.mock.web.MockHttpSession();
        session.setAttribute(PendingRoleChange.SESSION_KEY, new PendingRoleChange("auth0|other", java.util.Set.of("rol_admin")));

        mvc.perform(post("/admin/users/{id}/roles/apply", "auth0|ada").session(session)
                .with(adminWithMfa("auth0|me", java.time.Duration.ofMinutes(1))).with(csrf()))
            .andExpect(redirectedUrl("/admin/users/auth0%7Cada"))
            .andExpect(flash().attribute("error", containsString("Nothing to apply")));

        verify(auth0, never()).assignRoles(any(), any());
    }

    @Test
    void cancelDropsTheParkedChange() throws Exception {
        var session = new org.springframework.mock.web.MockHttpSession();
        session.setAttribute(PendingRoleChange.SESSION_KEY, new PendingRoleChange("auth0|ada", java.util.Set.of("rol_admin")));

        mvc.perform(post("/admin/users/{id}/roles/cancel", "auth0|ada").session(session)
                .with(admin("auth0|me")).with(csrf()))
            .andExpect(redirectedUrl("/admin/users/auth0%7Cada"));

        assertThat(session.getAttribute(PendingRoleChange.SESSION_KEY)).isNull();
        verify(auth0, never()).assignRoles(any(), any());
    }
}
