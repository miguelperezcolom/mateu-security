package io.mateu.security.fake;

import io.mateu.mdd.shared.interfaces.IResource;
import io.mateu.mdd.shared.interfaces.UserPrincipal;
import io.mateu.security.MateuSecurityManager;
import io.mateu.security.Private;

import java.util.ArrayList;
import java.util.List;


public class FakeMateuSecurityManagerImpl implements MateuSecurityManager {

    @Override
    public boolean validate(javax.servlet.http.HttpSession httpSession, String login, String password) throws Throwable {
        if (!"admin".equalsIgnoreCase(login)) throw new Exception("Invalid user");
        if (!"1".equalsIgnoreCase(password)) throw new Exception("Invalid password");
        httpSession.setAttribute("__user", new UserPrincipal() {
            @Override
            public String getLogin() {
                return login;
            }

            @Override
            public List<String> getRoles() {
                return new ArrayList<>();
            }

            @Override
            public String getName() {
                return "Mateu";
            }

            @Override
            public String getEmail() {
                return "test@test.ss";
            }

            @Override
            public IResource getPhoto() {
                return null;
            }
        });
        return true;
    }

    @Override
    public String getName(javax.servlet.http.HttpSession httpSession) {
        return "Mateu";
    }

    @Override
    public UserPrincipal getPrincipal(javax.servlet.http.HttpSession httpSession) {
        return (UserPrincipal) httpSession.getAttribute("__user");
    }

    @Override
    public void set(javax.servlet.http.HttpSession httpSession, String name) {

    }

    @Override
    public boolean check(javax.servlet.http.HttpSession httpSession, Private annotation) {
        return false;
    }

    @Override
    public boolean isProfileAvailable(javax.servlet.http.HttpSession httpSession) {
        return false;
    }

    @Override
    public Object getProfile(javax.servlet.http.HttpSession httpSession) {
        return null;
    }

    @Override
    public String recoverPassword(javax.servlet.http.HttpSession httpSession, String nameOrEmail) {
        return null;
    }
}
