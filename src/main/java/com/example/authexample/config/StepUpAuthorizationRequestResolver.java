package com.example.authexample.config;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

/**
 * Builds the redirect to Auth0's login page. For a "step-up" login
 * ({@code /oauth2/authorization/auth0?mfa}) it also asks Auth0 to:
 * <ul>
 *   <li>{@code prompt=login}: make the user log in again even if Auth0 still has a session, and</li>
 *   <li>{@code acr_values=...multi-factor}: require MFA. The Auth0 Action in
 *       auth0/require-mfa-for-step-up.js sees this value and challenges the user.</li>
 * </ul>
 */
public class StepUpAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    public static final String STEP_UP_PARAMETER = "mfa";
    public static final String MFA_ACR = "http://schemas.openid.net/pape/policies/2007/06/multi-factor";

    private final DefaultOAuth2AuthorizationRequestResolver defaults;

    public StepUpAuthorizationRequestResolver(ClientRegistrationRepository clientRegistrations) {
        this.defaults = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrations,
            OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        return stepUpIfRequested(request, defaults.resolve(request));
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        return stepUpIfRequested(request, defaults.resolve(request, clientRegistrationId));
    }

    private static OAuth2AuthorizationRequest stepUpIfRequested(HttpServletRequest request,
            OAuth2AuthorizationRequest authorizationRequest) {
        if (authorizationRequest == null || request.getParameter(STEP_UP_PARAMETER) == null) {
            return authorizationRequest;
        }
        return OAuth2AuthorizationRequest.from(authorizationRequest)
            .additionalParameters(params -> {
                params.put("prompt", "login");
                params.put("acr_values", MFA_ACR);
            })
            .build();
    }
}
