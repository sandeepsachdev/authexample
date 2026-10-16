package com.example.authexample.admin;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
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

/**
 * Lets admins see every user in the Auth0 tenant and change their roles ("groups").
 * Lives under /admin/**, so SecurityConfig already restricts it to ROLE_ADMIN.
 */
@Controller
@RequestMapping("/admin/users")
public class UserAdminController {

    static final int PER_PAGE = 25;
    private static final String ADMIN_ROLE = "admin";
    static final Duration SETUP_LINK_VALIDITY = Duration.ofDays(7);

    private final Auth0ManagementClient auth0;
    private final String connection;
    private final ObjectMapper json;

    public UserAdminController(Auth0ManagementClient auth0,
            @Value("${app.auth0.management.connection}") String connection,
            ObjectMapper json) {
        this.auth0 = auth0;
        this.connection = connection;
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

    @PostMapping("/{userId}/roles")
    public String updateRoles(@PathVariable String userId,
            @RequestParam(name = "roleIds", required = false) List<String> selected,
            @AuthenticationPrincipal OidcUser currentUser,
            RedirectAttributes redirect) {
        Set<String> wanted = selected == null ? Set.of() : new HashSet<>(selected);
        List<Auth0Models.Role> allRoles = auth0.listRoles();
        Set<String> current = new HashSet<>(auth0.getUserRoles(userId).stream().map(Auth0Models.Role::id).toList());

        // Stop admins from removing their own admin role and locking themselves out.
        boolean editingSelf = userId.equals(currentUser.getSubject());
        boolean droppingAdmin = allRoles.stream()
            .anyMatch(r -> r.name().equalsIgnoreCase(ADMIN_ROLE) && current.contains(r.id()) && !wanted.contains(r.id()));
        if (editingSelf && droppingAdmin) {
            redirect.addFlashAttribute("error", "You can't remove your own admin role. Ask another admin to do it.");
            return "redirect:/admin/users/{userId}";
        }

        List<String> toAdd = new ArrayList<>();
        List<String> toRemove = new ArrayList<>();
        for (Auth0Models.Role role : allRoles) {
            if (wanted.contains(role.id()) && !current.contains(role.id())) {
                toAdd.add(role.id());
            } else if (!wanted.contains(role.id()) && current.contains(role.id())) {
                toRemove.add(role.id());
            }
        }
        auth0.assignRoles(userId, toAdd);
        auth0.removeRoles(userId, toRemove);

        redirect.addFlashAttribute("message", toAdd.isEmpty() && toRemove.isEmpty()
            ? "No changes."
            : "Roles updated. They take effect the next time this user logs in.");
        return "redirect:/admin/users/{userId}";
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
