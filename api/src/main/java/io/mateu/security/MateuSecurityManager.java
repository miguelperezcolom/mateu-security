package io.mateu.security;

import io.mateu.mdd.shared.interfaces.UserPrincipal;

import javax.servlet.http.HttpSession;

public interface MateuSecurityManager {

    boolean validate(HttpSession httpSession, String login, String password) throws Throwable;

    String getName(HttpSession httpSession);

    UserPrincipal getPrincipal(HttpSession httpSession);

    void set(HttpSession httpSession, String name);

    boolean check(HttpSession httpSession, Private annotation);

    boolean isProfileAvailable(HttpSession httpSession);

    Object getProfile(HttpSession httpSession);

    String recoverPassword(HttpSession httpSession, String nameOrEmail);

}
