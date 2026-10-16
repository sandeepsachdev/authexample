package com.example.authexample.admin;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

/** The parts of Auth0 Management API responses this app uses. */
public final class Auth0Models {

    private Auth0Models() {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record User(String userId, String email, String name, String picture, String lastLogin,
            Integer loginsCount, Boolean blocked) {

        public String displayName() {
            return name != null ? name : email != null ? email : userId;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record UserPage(int start, int limit, int total, List<User> users) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Role(String id, String name, String description) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    record TokenResponse(String accessToken, long expiresIn) {
    }
}
