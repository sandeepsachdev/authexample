package com.example.authexample.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

/**
 * Shows which commit is running in the page header, so you can tell whether Railway has
 * deployed your latest push. Railway sets RAILWAY_GIT_COMMIT_SHA and RAILWAY_GIT_BRANCH.
 */
@ControllerAdvice
public class AppVersionAdvice {

    private final String version;

    public AppVersionAdvice(@Value("${RAILWAY_GIT_COMMIT_SHA:}") String commit,
            @Value("${RAILWAY_GIT_BRANCH:}") String branch) {
        String shortCommit = commit.length() > 7 ? commit.substring(0, 7) : commit;
        this.version = shortCommit.isEmpty() ? "local" : branch.isEmpty() ? shortCommit : branch + "@" + shortCommit;
    }

    @ModelAttribute("appVersion")
    public String appVersion() {
        return version;
    }
}
