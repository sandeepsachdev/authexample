package com.example.authexample.web;

import java.util.List;
import java.util.TreeMap;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    /** Public page: visible to everyone, shows different content once signed in. */
    @GetMapping("/")
    public String home(@AuthenticationPrincipal OidcUser user, Model model) {
        if (user != null) {
            model.addAttribute("name", displayName(user));
            model.addAttribute("picture", user.getPicture());
        }
        return "index";
    }

    /** Protected page: Spring Security redirects to Auth0 if the user is not signed in. */
    @GetMapping("/profile")
    public String profile(@AuthenticationPrincipal OidcUser user, Authentication authentication, Model model) {
        model.addAttribute("name", displayName(user));
        model.addAttribute("email", user.getEmail());
        model.addAttribute("picture", user.getPicture());
        model.addAttribute("claims", new TreeMap<>(user.getClaims()));
        model.addAttribute("roles", roles(authentication));
        return "profile";
    }

    /** The ROLE_* authorities granted from the Auth0 roles claim, without the prefix. */
    private static List<String> roles(Authentication authentication) {
        return authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .filter(a -> a.startsWith("ROLE_"))
            .map(a -> a.substring("ROLE_".length()))
            .sorted()
            .toList();
    }

    static String displayName(OidcUser user) {
        if (user.getFullName() != null) {
            return user.getFullName();
        }
        if (user.getNickName() != null) {
            return user.getNickName();
        }
        return user.getSubject();
    }
}
