package io.mateu.security;

import io.mateu.mdd.shared.interfaces.UserPrincipal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

public interface MateuSecurityManager {

    UserPrincipal validate(HttpSession httpSession, String login, String password) throws Throwable;

    String getName(HttpSession httpSession);

    UserPrincipal getPrincipal(HttpSession httpSession);

    void set(HttpSession httpSession, String name) throws Throwable;

    boolean check(HttpSession httpSession, Private annotation);

    boolean isProfileAvailable(HttpSession httpSession);

    String recoverPassword(HttpSession httpSession, String nameOrEmail) throws Throwable;

    UserPrincipal getUserDataFromGitHubCode(HttpServletRequest req) throws Throwable;

    UserPrincipal getUserDataFromGoogleCode(HttpServletRequest req) throws Throwable;

    UserPrincipal getUserDataFromMicrosoftCode(HttpServletRequest req) throws Throwable;

    String getWelcomeMessage();

    String getWelcomeInfo();

    boolean hasFavicon();

    String getFavicon();

    String getByeMessage();

    String getByeInfo();

    boolean hasLogo();

    String getLogo();

    boolean isLoginSupported();

    String getRegistrationUrl();

    String getForgotternPasswordUrl();

    String getGithubClientId();

    String getGithubClientSecret();

    String getGoogleClientId();

    String getGoogleClientSecret();

    String getMicrosoftClientId();

    String getMicrosoftClientSecret();
}
