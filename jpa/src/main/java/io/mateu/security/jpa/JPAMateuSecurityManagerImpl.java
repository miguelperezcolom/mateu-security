package io.mateu.security.jpa;

import io.mateu.mdd.core.model.authentication.USER_STATUS;
import io.mateu.mdd.core.model.authentication.User;
import io.mateu.mdd.shared.interfaces.UserPrincipal;
import io.mateu.security.MateuSecurityManager;
import io.mateu.security.Private;
import io.mateu.util.persistence.JPAHelper;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.net.URL;
import java.util.List;

public class JPAMateuSecurityManagerImpl implements MateuSecurityManager {
    @Override
    public UserPrincipal validate(javax.servlet.http.HttpSession httpSession, String login, String password) throws Throwable {
        User u = JPAHelper.find(User.class, login);
        if (u == null) throw new Exception("Unknown user");
        if (!USER_STATUS.ACTIVE.equals(u.getStatus())) throw new Exception("Invalid user");
        if (!u.checkPassword(password)) throw new Exception("Invalid password");
        return setPrincipal(httpSession, u);
    }

    @Override
    public String getName(HttpSession httpSession) {
        return getPrincipal(httpSession).getName();
    }

    @Override
    public UserPrincipal getPrincipal(HttpSession httpSession) {
        return (UserPrincipal) httpSession.getAttribute("__user");
    }

    @Override
    public void set(javax.servlet.http.HttpSession httpSession, String name) throws Throwable {
        JPAHelper.transact(em -> {
            User u = em.find(User.class, getPrincipal(httpSession).getLogin());
            u.setName(name);
            setPrincipal(httpSession, u);
        });
    }

    private UserPrincipal setPrincipal(HttpSession httpSession, User u) {
        UserPrincipal p;
        httpSession.setAttribute("__user", p = new UserPrincipal() {
            @Override
            public String getLogin() {
                return u.getLogin();
            }

            @Override
            public List<String> getRoles() {
                return u.getRoles();
            }

            @Override
            public String getName() {
                return u.getName();
            }

            @Override
            public String getEmail() {
                return u.getEmail();
            }

            @Override
            public URL getPhoto() {
                try {
                    return u.getPhoto() != null?new URL(u.getAvatar().toFileLocator().getUrl()):null;
                } catch (Exception e) {
                    e.printStackTrace();
                    return null;
                }
            }
        });
        return p;
    }

    @Override
    public boolean check(javax.servlet.http.HttpSession httpSession, Private annotation) {
        return true;
    }

    @Override
    public boolean isProfileAvailable(javax.servlet.http.HttpSession httpSession) {
        return true;
    }


    @Override
    public String recoverPassword(javax.servlet.http.HttpSession httpSession, String nameOrEmail) throws Throwable {
        JPAHelper.transact(em -> {
            User u = JPAHelper.find(User.class, nameOrEmail);
            if (u == null) {
                List<User> l = em.createQuery("select from " + User.class.getName() + " u where u.email = :e").setParameter("e", nameOrEmail).getResultList();
                if (l.size() > 1) throw new Exception("More than 1 user with this email");
                else if (l.size() == 1) u = l.get(0);
            }
            if (u == null) throw new Exception("Unknown user");
            if (!USER_STATUS.ACTIVE.equals(u.getStatus())) throw new Exception("Invalid user");
            u.sendForgottenPasswordEmail(em);
        });

        return "An email with instructions has been sent to your email address. Please check your inbox.";
    }

    @Override
    public UserPrincipal getUserDataFromGitHubCode(HttpServletRequest req) throws Throwable {
        UserPrincipal p = OAuthHelper.getUserDataFromGitHubCode(req.getParameter("code"));
        if (p == null) throw new Exception("Unable to gather user info from Github =(");
        System.out.println("login=" + p.getLogin());
        User u = JPAHelper.find(User.class, p.getLogin());
        if (!"true".equalsIgnoreCase(System.getProperty("oauth.newusersallowed")) && u == null) throw new Exception("I'm sorry but I don't know you =(");
        return p;
    }

    @Override
    public UserPrincipal getUserDataFromGoogleCode(HttpServletRequest req) throws Throwable {
        UserPrincipal p = OAuthHelper.getUserDataFromGoogleCode(req.getParameter("code"));
        if (p == null) throw new Exception("Unable to gather user info from Google =(");
        System.out.println("login=" + p.getLogin());
        User u = JPAHelper.find(User.class, p.getLogin());
        if (!"true".equalsIgnoreCase(System.getProperty("oauth.newusersallowed")) && u == null) throw new Exception("I'm sorry but I don't know you =(");
        return p;
    }

    @Override
    public UserPrincipal getUserDataFromMicrosoftCode(HttpServletRequest req) throws Throwable {
        UserPrincipal p = OAuthHelper.getUserDataFromMicrosoftCode(req.getParameter("code"));
        if (p == null) throw new Exception("Unable to gather user info from Microsoft =(");
        System.out.println("login=" + p.getLogin());
        User u = JPAHelper.find(User.class, p.getLogin());
        if (!"true".equalsIgnoreCase(System.getProperty("oauth.newusersallowed")) && u == null) throw new Exception("I'm sorry but I don't know you =(");
        return p;
    }


    @Override
    public String getWelcomeMessage() {
        return System.getProperty("welcome.message", "Welcome!");
    }

    @Override
    public String getWelcomeInfo() {
        return System.getProperty("welcome.info", "Please login");
    }

    @Override
    public boolean hasFavicon() {
        return System.getProperty("favIcon") != null;
    }

    @Override
    public String getFavicon() {
        return System.getProperty("favIcon");
    }

    @Override
    public String getByeMessage() {
        return System.getProperty("bye.message", "Thanks for visiting us.");
    }

    @Override
    public String getByeInfo() {
        return System.getProperty("bye.info", "Hope we will see you soon ;)");
    }

    @Override
    public boolean hasLogo() {
        return System.getProperty("logo") != null;
    }

    @Override
    public String getLogo() {
        return System.getProperty("logo");
    }

    @Override
    public boolean isLoginSupported() {
        return !"true".equalsIgnoreCase(System.getProperty("oauthonly"));
    }


    @Override
    public String getRegistrationUrl() {
        return System.getProperty("registrationUrl");
    }

    @Override
    public String getForgotternPasswordUrl() {
        return System.getProperty("passwordForgottenUrl");
    }

    @Override
    public String getGithubClientId() {
        return System.getProperty("oauth.github.client_id");
    }

    @Override
    public String getGithubClientSecret() {
        return System.getProperty("oauth.github.client_secret");
    }

    @Override
    public String getGoogleClientId() {
        return System.getProperty("oauth.google.client_id");
    }

    @Override
    public String getGoogleClientSecret() {
        return System.getProperty("oauth.google.client_secret");
    }

    @Override
    public String getMicrosoftClientId() {
        return System.getProperty("oauth.microsoft.client_id");
    }

    @Override
    public String getMicrosoftClientSecret() {
        return System.getProperty("oauth.microsoft.client_secret");
    }
}
