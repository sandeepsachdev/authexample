package com.example.authexample.admin;

import java.security.SecureRandom;

/**
 * Generates a throwaway password for users who will choose their own via a setup link.
 * Nobody ever sees it; it only has to satisfy Auth0's strongest password policy
 * (length, mixed character types, no 3 identical characters in a row).
 */
final class PasswordGenerator {

    private static final String LOWER = "abcdefghijkmnopqrstuvwxyz";
    private static final String UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    private static final String DIGITS = "23456789";
    private static final String SYMBOLS = "!@#$%^&*-_+=";
    private static final String ALL = LOWER + UPPER + DIGITS + SYMBOLS;
    private static final SecureRandom RANDOM = new SecureRandom();

    private PasswordGenerator() {
    }

    static String generate() {
        StringBuilder password = new StringBuilder();
        // Start with one of each type, then fill up with random characters.
        for (String chars : new String[] {LOWER, UPPER, DIGITS, SYMBOLS}) {
            password.append(randomChar(chars));
        }
        while (password.length() < 32) {
            char next = randomChar(ALL);
            int len = password.length();
            if (password.charAt(len - 1) != next || password.charAt(len - 2) != next) {
                password.append(next);
            }
        }
        return password.toString();
    }

    private static char randomChar(String chars) {
        return chars.charAt(RANDOM.nextInt(chars.length()));
    }
}
