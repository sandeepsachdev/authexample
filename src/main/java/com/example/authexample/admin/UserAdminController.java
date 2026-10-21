package com.example.authexample.admin;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.example.authexample.config.StepUpAuthorizationRequestResolver;

/**
 * Lets admins see every user in the Auth0 tenant and change their roles ("groups").
 * Lives under /admin/**, so SecurityConfig already restricts it to ROLE_ADMIN.
 */
@Controller
@RequestMapping("/admin/users")
public class UserAdminController {

    private static final Logger log = LoggerFactory.getLogger(UserAdminController.class);

    static final int PER_PAGE = 25;
    private static final String ADMIN_ROLE = "admin";
    static final Duration SETUP_LINK_VALIDITY = Duration.ofDays(7);
    /** Session flag: we've sent the admin to Auth0 for step-up and are waiting for them back. */
    static final String STEP_UP_ATTEMPTED = UserAdminController.class.getName() + ".STEP_UP_ATTEMPTED";

    private final Auth0ManagementClient auth0;
    private final String connection;
    private final ObjectMapper json;
    private final Duration stepUpMaxAge;
    private final String stepUpClaim;
    private final Clock clock = Clock.systemUTC();
    private final RequestCache requestCache = new HttpSessionRequestCache();

    public UserAdminController(Auth0ManagementClient auth0,
            @Value("${app.auth0.management.connection}") String connection,
            @Value("${app.auth0.step-up-max-age}") Duration stepUpMaxAge,
            @Value("${app.auth0.step-up-claim}") String stepUpClaim,
            ObjectMapper json) {
        this.auth0 = auth0;
        this.connection = connection;
        this.stepUpMaxAge = stepUpMaxAge;
        this.stepUpClaim = stepUpClaim;
        this.json = json;
    }

    @GetMapping
    public String list(@RequestParam(defaultValue = "0") int page, Model model) {
        if (!auth0.isConfigured()) {
            return "admin/users-setup";
        }
        // One call per role (instead of one per user) keeps us well under Auth0's rate limits.
        Map<String, List<String>> rolesByUser = new TreeMap<>();
        for (Auth0Models.Role role : auth0.listRoles()) {
            for (String userId : auth0.roleMemberIds(role.id())) {
                rolesByUser.computeIfAbsent(userId, id -> new ArrayList<>()).add(role.name());
            }
        }
        Auth0Models.UserPage users = auth0.listUsers(Math.max(page, 0), PER_PAGE);

        model.addAttribute("users", users.users());
        model.addAttribute("rolesByUser", rolesByUser);
        model.addAttribute("total", users.total());
        model.addAttribute("page", page);
        model.addAttribute("hasPrevious", page > 0);
        model.addAttribute("hasNext", (long) (page + 1) * PER_PAGE < users.total());
        return "admin/users";
    }

    @GetMapping("/new")
    public String newUser(Model model) {
        if (!auth0.isConfigured()) {
            return "admin/users-setup";
        }
        model.addAttribute("form", NewUserForm.empty());
        model.addAttribute("allRoles", auth0.listRoles());
        return "admin/user-new";
    }

    @PostMapping
    public String createUser(@ModelAttribute("form") NewUserForm form, Model model, RedirectAttributes redirect) {
        if (!auth0.isConfigured()) {
            return "admin/users-setup";
        }
        List<Auth0Models.Role> allRoles = auth0.listRoles();
        if (!form.email().contains("@")) {
            return showNewUserFormAgain(form, allRoles, "Enter a valid email address.", model);
        }

        // Without an admin-chosen password, set a random one nobody knows and send a setup link instead.
        String password = form.adminSetsPassword() ? form.password() : PasswordGenerator.generate();
        Auth0Models.User created;
        try {
            created = auth0.createUser(connection, form.email(), form.name(), password);
        } catch (HttpClientErrorException ex) {
            // 400: e.g. password too weak; 409: the user already exists.
            return showNewUserFormAgain(form, allRoles, auth0Message(ex), model);
        }

        List<String> roleIds = allRoles.stream().map(Auth0Models.Role::id).filter(form.roleIds()::contains).toList();
        auth0.assignRoles(created.userId(), roleIds);

        if (!form.adminSetsPassword()) {
            String home = ServletUriComponentsBuilder.fromCurrentContextPath().path("/").toUriString();
            redirect.addFlashAttribute("setupLink",
                auth0.createPasswordSetupLink(created.userId(), home, SETUP_LINK_VALIDITY));
        }
        redirect.addFlashAttribute("message", "User created.");
        redirect.addAttribute("userId", created.userId());
        return "redirect:/admin/users/{userId}";
    }

    private String showNewUserFormAgain(NewUserForm form, List<Auth0Models.Role> allRoles, String error, Model model) {
        // Never send a typed password back to the browser.
        model.addAttribute("form", new NewUserForm(form.email(), form.name(), "", form.roleIds()));
        model.addAttribute("allRoles", allRoles);
        model.addAttribute("error", error);
        return "admin/user-new";
    }

    /** Auth0 errors look like {"statusCode":400,"message":"PasswordStrengthError: Password is too weak"}. */
    private String auth0Message(RestClientResponseException ex) {
        try {
            JsonNode message = json.readTree(ex.getResponseBodyAsString()).path("message");
            if (message.isTextual()) {
                return message.asText();
            }
        } catch (Exception ignored) {
            // Not JSON; fall through to the raw status.
        }
        return "Auth0 returned HTTP " + ex.getStatusCode().value();
    }

    @GetMapping("/{userId}")
    public String edit(@PathVariable String userId, Model model) {
        if (!auth0.isConfigured()) {
            return "admin/users-setup";
        }
        model.addAttribute("user", auth0.getUser(userId));
        model.addAttribute("allRoles", auth0.listRoles());
        model.addAttribute("assignedRoleIds", auth0.getUserRoles(userId).stream().map(Auth0Models.Role::id).toList());
        return "admin/user-edit";
    }

    /**
     * Saves the ticked roles. Removing roles happens straight away, but adding one is a
     * privilege grant, so it first requires the admin to have passed MFA recently
     * (step-up authentication). Otherwise the change is parked in the session and the
     * admin is sent to verify.
     */
    @PostMapping("/{userId}/roles")
    public String updateRoles(@PathVariable String userId,
            @RequestParam(name = "roleIds", required = false) List<String> selected,
            @AuthenticationPrincipal OidcUser currentUser,
            HttpSession session,
            RedirectAttributes redirect) {
        Set<String> wanted = selected == null ? Set.of() : new HashSet<>(selected);
        RoleChange change = RoleChange.of(auth0.listRoles(), auth0.getUserRoles(userId), wanted);

        if (selfLockout(userId, currentUser, change)) {
            redirect.addFlashAttribute("error", "You can't remove your own admin role. Ask another admin to do it.");
            return "redirect:/admin/users/{userId}";
        }
        if (!change.toAdd().isEmpty() && !steppedUp(currentUser)) {
            session.setAttribute(PendingRoleChange.SESSION_KEY, new PendingRoleChange(userId, wanted));
            return "redirect:/admin/users/{userId}/roles/verify";
        }
        return apply(userId, change, redirect);
    }

    /**
     * Step-up checkpoint. Without a recent MFA login, remember this URL and send the admin
     * to Auth0 to confirm with MFA; Spring Security brings them back here afterwards.
     * With one, show the pending change for a final confirmation.
     */
    @GetMapping("/{userId}/roles/verify")
    public String verifyRoleChange(@PathVariable String userId,
            @AuthenticationPrincipal OidcUser currentUser,
            HttpServletRequest request, HttpServletResponse response,
            HttpSession session, Model model) {
        PendingRoleChange pending = pendingFor(userId, session);
        if (pending == null) {
            return "redirect:/admin/users/{userId}";
        }
        if (!steppedUp(currentUser)) {
            // Already been to Auth0 and still no step-up claim: Auth0 isn't set up for it.
            // Show what to fix instead of redirecting in a loop.
            if (userId.equals(session.getAttribute(STEP_UP_ATTEMPTED))) {
                session.removeAttribute(STEP_UP_ATTEMPTED);
                model.addAttribute("userId", userId);
                return "admin/step-up-failed";
            }
            session.setAttribute(STEP_UP_ATTEMPTED, userId);
            requestCache.saveRequest(request, response);
            return "redirect:/oauth2/authorization/auth0?" + StepUpAuthorizationRequestResolver.STEP_UP_PARAMETER;
        }
        session.removeAttribute(STEP_UP_ATTEMPTED);
        model.addAttribute("verifiedAt", currentUser.getIssuedAt());
        model.addAttribute("user", auth0.getUser(userId));
        model.addAttribute("change", RoleChange.of(auth0.listRoles(), auth0.getUserRoles(userId), pending.wantedRoleIds()));
        return "admin/roles-confirm";
    }

    /** Applies the parked change once the admin confirms, re-checking MFA in case it went stale. */
    @PostMapping("/{userId}/roles/apply")
    public String applyPendingRoleChange(@PathVariable String userId,
            @AuthenticationPrincipal OidcUser currentUser,
            HttpSession session, RedirectAttributes redirect) {
        PendingRoleChange pending = pendingFor(userId, session);
        if (pending == null) {
            redirect.addFlashAttribute("error", "Nothing to apply. Please make the change again.");
            return "redirect:/admin/users/{userId}";
        }
        if (!steppedUp(currentUser)) {
            return "redirect:/admin/users/{userId}/roles/verify";
        }
        session.removeAttribute(PendingRoleChange.SESSION_KEY);
        RoleChange change = RoleChange.of(auth0.listRoles(), auth0.getUserRoles(userId), pending.wantedRoleIds());
        if (selfLockout(userId, currentUser, change)) {
            redirect.addFlashAttribute("error", "You can't remove your own admin role. Ask another admin to do it.");
            return "redirect:/admin/users/{userId}";
        }
        return apply(userId, change, redirect);
    }

    /** Drops a parked change, e.g. when the admin cancels on the confirmation page. */
    @PostMapping("/{userId}/roles/cancel")
    public String cancelPendingRoleChange(@PathVariable String userId, HttpSession session,
            RedirectAttributes redirect) {
        session.removeAttribute(PendingRoleChange.SESSION_KEY);
        redirect.addFlashAttribute("message", "No changes were made.");
        return "redirect:/admin/users/{userId}";
    }

    private boolean steppedUp(OidcUser user) {
        boolean verified = RecentMfa.verified(user, stepUpClaim, stepUpMaxAge, clock);
        // Visible in Railway's deploy logs: shows exactly what Auth0 sent back.
        log.info("Step-up check for {}: {}={}, amr={}, iat={}, auth_time={} -> {}",
            user.getSubject(), stepUpClaim, user.getClaims().get(stepUpClaim), user.getAuthenticationMethods(),
            user.getIssuedAt(), user.getAuthenticatedAt(), verified ? "verified" : "step-up needed");
        return verified;
    }

    private String apply(String userId, RoleChange change, RedirectAttributes redirect) {
        auth0.assignRoles(userId, change.toAdd().stream().map(Auth0Models.Role::id).toList());
        auth0.removeRoles(userId, change.toRemove().stream().map(Auth0Models.Role::id).toList());
        redirect.addFlashAttribute("message", change.isEmpty()
            ? "No changes."
            : "Roles updated. They take effect the next time this user logs in.");
        return "redirect:/admin/users/{userId}";
    }

    /** Stops admins from removing their own admin role and locking themselves out. */
    private static boolean selfLockout(String userId, OidcUser currentUser, RoleChange change) {
        return userId.equals(currentUser.getSubject())
            && change.toRemove().stream().anyMatch(r -> r.name().equalsIgnoreCase(ADMIN_ROLE));
    }

    private static PendingRoleChange pendingFor(String userId, HttpSession session) {
        return session.getAttribute(PendingRoleChange.SESSION_KEY) instanceof PendingRoleChange p
                && p.userId().equals(userId) ? p : null;
    }

    /** Which roles a save would add and remove, compared with what the user has now. */
    public record RoleChange(List<Auth0Models.Role> toAdd, List<Auth0Models.Role> toRemove) {

        static RoleChange of(List<Auth0Models.Role> allRoles, List<Auth0Models.Role> currentRoles, Set<String> wanted) {
            Set<String> current = new HashSet<>(currentRoles.stream().map(Auth0Models.Role::id).toList());
            List<Auth0Models.Role> toAdd = new ArrayList<>();
            List<Auth0Models.Role> toRemove = new ArrayList<>();
            for (Auth0Models.Role role : allRoles) {
                if (wanted.contains(role.id()) && !current.contains(role.id())) {
                    toAdd.add(role);
                } else if (!wanted.contains(role.id()) && current.contains(role.id())) {
                    toRemove.add(role);
                }
            }
            return new RoleChange(toAdd, toRemove);
        }

        public boolean isEmpty() {
            return toAdd.isEmpty() && toRemove.isEmpty();
        }
    }

    /** Shows Auth0 errors (e.g. a missing Management API scope) instead of a stack trace. */
    @ExceptionHandler(RestClientResponseException.class)
    @ResponseStatus(HttpStatus.BAD_GATEWAY)
    public String auth0Error(RestClientResponseException ex, Model model) {
        model.addAttribute("status", ex.getStatusCode().value());
        model.addAttribute("details", ex.getResponseBodyAsString());
        return "admin/users-error";
    }
}
