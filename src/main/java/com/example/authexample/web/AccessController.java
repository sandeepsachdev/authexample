package com.example.authexample.web;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/** Pages guarded by role in SecurityConfig. */
@Controller
public class AccessController {

    /** Requires the "member" (or "admin") role in Auth0. */
    @GetMapping("/members")
    public String members(@AuthenticationPrincipal OidcUser user, Model model) {
        model.addAttribute("name", HomeController.displayName(user));
        return "members";
    }

    /** Requires the "admin" role in Auth0. */
    @GetMapping("/admin")
    public String admin(@AuthenticationPrincipal OidcUser user, Model model) {
        model.addAttribute("name", HomeController.displayName(user));
        return "admin";
    }

    /** Shown when a signed-in user lacks the role a page needs. */
    @GetMapping("/access-denied")
    public String accessDenied() {
        return "access-denied";
    }
}
