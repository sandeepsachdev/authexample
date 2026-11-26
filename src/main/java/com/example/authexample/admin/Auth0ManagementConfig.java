package com.example.authexample.admin;

import java.time.Clock;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;

@Configuration
class Auth0ManagementConfig {

    @Bean
    Auth0ManagementClient auth0ManagementClient(RestClient.Builder builder,
            @Value("${app.auth0.domain}") String domain,
            @Value("${app.auth0.management.client-id}") String clientId,
            @Value("${app.auth0.management.client-secret}") String clientSecret) {
        return new Auth0ManagementClient(builder, domain, clientId, clientSecret, Clock.systemUTC());
    }
}
