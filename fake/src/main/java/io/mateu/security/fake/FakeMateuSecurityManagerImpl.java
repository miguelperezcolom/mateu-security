package io.mateu.security.fake;

import io.mateu.mdd.shared.interfaces.UserPrincipal;
import io.mateu.security.MateuSecurityManager;
import io.mateu.security.Private;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;


public class FakeMateuSecurityManagerImpl implements MateuSecurityManager {

    @Override
    public UserPrincipal validate(HttpSession httpSession, String login, String password) throws Throwable {
        if (!"admin".equalsIgnoreCase(login)) throw new Exception("Invalid user");
        if (!"1".equalsIgnoreCase(password)) throw new Exception("Invalid password");
        return new UserPrincipal() {
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
            public URL getPhoto() {
                return null;
            }
        };
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
        return true;
    }

    @Override
    public boolean isProfileAvailable(javax.servlet.http.HttpSession httpSession) {
        return false;
    }


    @Override
    public String recoverPassword(javax.servlet.http.HttpSession httpSession, String nameOrEmail) throws Throwable {
        if (!"admin".equalsIgnoreCase(nameOrEmail)) throw new Exception("Unknown user");
        return "An email has been sent to you with instructions.";
    }

    @Override
    public UserPrincipal getUserDataFromGitHubCode(HttpServletRequest req) {
        return new UserPrincipal() {
            @Override
            public String getLogin() {
                return req.getParameter("code");
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
            public URL getPhoto() {
                return null;
            }
        };
    }

    @Override
    public UserPrincipal getUserDataFromGoogleCode(HttpServletRequest req) {
        return new UserPrincipal() {
            @Override
            public String getLogin() {
                return req.getParameter("code");
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
            public URL getPhoto() {
                return null;
            }
        };
    }

    @Override
    public UserPrincipal getUserDataFromMicrosoftCode(HttpServletRequest req) {
        return new UserPrincipal() {
            @Override
            public String getLogin() {
                return req.getParameter("code");
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
            public URL getPhoto() {
                return null;
            }
        };
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
        return !"false".equalsIgnoreCase(System.getProperty("oauthonly"));
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
