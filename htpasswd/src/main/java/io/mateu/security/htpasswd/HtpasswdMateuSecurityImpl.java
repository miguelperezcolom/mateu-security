package io.mateu.security.htpasswd;

import com.google.common.base.Strings;
import io.mateu.mdd.shared.interfaces.UserPrincipal;
import io.mateu.security.MateuSecurityManager;
import io.mateu.security.Private;
import io.mateu.util.Helper;
import io.mateu.util.SharedHelper;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.Crypt;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.Md5Crypt;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.File;
import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class HtpasswdMateuSecurityImpl implements MateuSecurityManager {

    private Map<String, String> htpasswd = new HashMap<>();

    public HtpasswdMateuSecurityImpl() {
        SharedHelper.loadProperties();
        if (System.getProperty("htpasswd") != null) {
            String r = null;
            File f = new File(System.getProperty("htpasswd"));
            if (f.exists()) r = Helper.leerFichero(System.getProperty("htpasswd"));
            else {
                InputStream s = getClass().getResourceAsStream(System.getProperty("htpasswd"));
                if (s != null) r = Helper.leerInputStream(s, "utf-8");
            }

            if (r == null) {
                System.out.println("" + System.getProperty("htpasswd") + " not found");
            } else {
                for (String l : r.split("\n")) if (!Strings.isNullOrEmpty(l) && !l.trim().startsWith("#")) {
                    String[] ts = l.split(":");
                    if (ts.length > 1) htpasswd.put(ts[0], ts[1]);
                }
            }
        } else {
            System.out.println("No htpasswd file provided. Please set htpasswd java property (e.g. java -Dhtpasswd=<path to htpasswd file> ...)");
        }
    }


    @Override
    public UserPrincipal validate(HttpSession httpSession, String login, String password) throws Throwable {
        if (!htpasswd.containsKey(login)) throw new Exception("Invalid user");
        boolean authenticated = false;
        String storedPwd = htpasswd.get(login);
        final String passwd = new String(password);

        // test Apache MD5 variant encrypted password
        if (storedPwd.startsWith("$apr1$")) {
            if (storedPwd.equals(Md5Crypt.apr1Crypt(passwd, storedPwd))) {
                System.out.println("Apache MD5 encoded password matched for user '" + login + "'");
                authenticated = true;
            }
        }
        // test unsalted SHA password
        else if (storedPwd.startsWith("{SHA}")) {
            String passwd64 = Base64.encodeBase64String(DigestUtils.sha1(passwd));
            if (storedPwd.substring("{SHA}".length()).equals(passwd64)) {
                System.out.println("Unsalted SHA-1 encoded password matched for user '" + login + "'");
                authenticated = true;
            }
        }
        // test libc crypt() encoded password
        else if (storedPwd.equals(Crypt.crypt(passwd, storedPwd))) {
            System.out.println("Libc crypt encoded password matched for user '" + login + "'");
            authenticated = true;
        }
        // test clear text
        else if (storedPwd.equals(passwd)){
            System.out.println("Clear text password matched for user '" + login + "'");
            authenticated = true;
        }

        if (!authenticated) throw new Exception("Invalid password");

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
                return login;
            }

            @Override
            public String getEmail() {
                return "";
            }

            @Override
            public URL getPhoto() {
                return null;
            }
        };
    }

    @Override
    public String getName(javax.servlet.http.HttpSession httpSession) {
        return getPrincipal(httpSession).getName();
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
