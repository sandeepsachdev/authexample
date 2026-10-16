package com.example.authexample.admin;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.RepeatedTest;

class PasswordGeneratorTests {

    @RepeatedTest(200)
    void meetsAuth0ExcellentPasswordPolicy() {
        String password = PasswordGenerator.generate();

        assertThat(password).hasSize(32)
            .containsPattern("[a-z]").containsPattern("[A-Z]").containsPattern("[0-9]").containsPattern("[^a-zA-Z0-9]")
            .doesNotContainPattern("(.)\\1\\1");
    }
}
