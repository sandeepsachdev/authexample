package com.example.authexample.admin;

import java.io.Serializable;
import java.util.Set;

/** Role selection an admin submitted, kept in the session while they complete the MFA step-up. */
record PendingRoleChange(String userId, Set<String> wantedRoleIds) implements Serializable {

    static final String SESSION_KEY = PendingRoleChange.class.getName();
}
