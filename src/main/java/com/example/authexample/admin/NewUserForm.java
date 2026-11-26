package com.example.authexample.admin;

import java.util.List;

/**
 * Fields of the "New user" form. Leaving the password blank means the user gets a
 * link to choose their own instead.
 */
public record NewUserForm(String email, String name, String password, List<String> roleIds) {

    public NewUserForm {
        email = email == null ? "" : email.trim();
        roleIds = roleIds == null ? List.of() : roleIds;
    }

    public static NewUserForm empty() {
        return new NewUserForm("", "", "", List.of());
    }

    public boolean adminSetsPassword() {
        return password != null && !password.isEmpty();
    }
}
