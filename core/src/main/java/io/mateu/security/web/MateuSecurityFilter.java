package io.mateu.security.web;

import freemarker.template.TemplateException;
import io.mateu.mdd.shared.VaadinHelper;
import io.mateu.mdd.shared.interfaces.UserPrincipal;
import io.mateu.security.MateuSecurityManager;
import io.mateu.util.Helper;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

@WebFilter("/zzz/private/*")
public class MateuSecurityFilter implements Filter {

    String byeFreemark = "Not initialized. Surely /security/bye.html was not found in the classpath.";
    String loginFormFreemark = "Not initialized. Surely /security/loginform.html was not found in the classpath.";
    String initializationErrorMsg;

    private ServletContext context;
    private MateuSecurityManager securityManager;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        context = filterConfig.getServletContext();

        try {
            securityManager = Helper.getImpl(MateuSecurityManager.class);
            loginFormFreemark = Helper.leerFichero(getClass().getResourceAsStream("/security/loginForm.html"));
            byeFreemark = Helper.leerFichero(getClass().getResourceAsStream("/security/bye.html"));
        } catch (Exception e) {
            e.printStackTrace();
            initializationErrorMsg = Helper.toString(e);
            context.log("MateuSecurityFilter initialization error", e);
        }

        context.log("MateuSecurityFilter initialized");
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) servletRequest;
        HttpServletResponse res = (HttpServletResponse) servletResponse;

        try {

            if (securityManager == null) filterChain.doFilter(req, res);
            else {

                if (initializationErrorMsg != null) print(res, initializationErrorMsg);
                String uri = req.getRequestURI(); //    /zzz/private/iuedwe/iuwede/weqiud
                this.context.log("Requested Resource::"+uri);

                HttpSession session = req.getSession(false);

                if (uri.endsWith("private/logout")) {
                    session.invalidate();
                    res.sendRedirect("bye");
                } else if (uri.endsWith("private/bye")) {
                    showBye(req, res);
                } else if (uri.contains("/oauth/github/callback") || uri.contains("/oauth/google/callback") || uri.contains("/oauth/microsoft/callback")) {

                    UserPrincipal p = null;
                    if (uri.contains("/oauth/github/callback")) p = securityManager.getUserDataFromGitHubCode(req);
                    if (uri.contains("/oauth/google/callback")) p = securityManager.getUserDataFromGoogleCode(req);
                    if (uri.contains("/oauth/microsoft/callback")) p = securityManager.getUserDataFromMicrosoftCode(req);
                    if (p != null) {
                        req.getSession().setAttribute("__user", p);
                    }
                    res.sendRedirect(session.getAttribute("__originalUrl") != null?"" + session.getAttribute("__originalUrl"):"/");

                } else if(session == null || securityManager.getPrincipal(session) == null) {

                    if (uri.endsWith("private/authenticate")) {
                        authenticate(req, res);
                    } else {
                        this.context.log("Unauthorized access request");
                        req.getSession().setAttribute("__originalUrl", req.getRequestURL().toString());
                        showLoginForm(req, res);
                        //res.sendRedirect("login");
                    }

                }else{
                    if (uri.endsWith("private/logout")) {
                        session.invalidate();
                        res.sendRedirect("bye");
                    } else {
                        // pass the request along the filter chain
                        filterChain.doFilter(req, res);
                    }
                }

            }

        } catch (Throwable e) {
            e.printStackTrace();
        }

    }



    private void showBye(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        String html = null;
        try {
            html = Helper.freemark(byeFreemark, getLoginFormProperties(req));
        } catch (TemplateException e) {
            e.printStackTrace();
            html = Helper.toString(e);
        }
        print(res, html);
    }

    private Map<String, Object> getByeProperties() {
        Map<String, Object> m = new HashMap<>();

        m.put("byeMessage", System.getProperty("bye.message", "Thanks for using " + "<here your app name>" + "."));
        m.put("byeInfo", System.getProperty("bye.info", "Hope we will see you soon ;)"));

        return m;
    }

    private void showLoginForm(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        String html = null;
        try {
            html = Helper.freemark(loginFormFreemark, getLoginFormProperties(req));
        } catch (TemplateException e) {
            e.printStackTrace();
            html = Helper.toString(e);
        }
        print(res, html);
    }

    private Map<String, Object> getLoginFormProperties(HttpServletRequest req) {
        Map<String, Object> m = new HashMap<>();

        m.put("welcomeMessage", System.getProperty("welcome.message", "Welcome to " + "<here your app name>" + "."));
        m.put("welcomeInfo", System.getProperty("welcome.info", "Here your welcome info"));
        m.put("hasLogo", System.getProperty("logo") != null);
        m.put("logo", System.getProperty("logo"));

        m.put("login", !"false".equalsIgnoreCase(System.getProperty("oauthonly")));
        m.put("hasRegistration", System.getProperty("registrationUrl") != null);
        m.put("registrationUrl", System.getProperty("registrationUrl"));


        req.getServletPath();
        req.getServletContext().getContextPath();
        req.getRequestURL();
        req.getRequestURI();
        String callbackUrl = req.getRequestURL().toString();
        callbackUrl = callbackUrl.substring(0, callbackUrl.indexOf("private") + "private".length());
        if (!callbackUrl.endsWith("/")) callbackUrl += "/";

        m.put("github", System.getProperty("oauth.github.client_id") != null && System.getProperty("oauth.github.client_secret") != null);
        if (System.getProperty("oauth.github.client_id") != null && System.getProperty("oauth.github.client_secret") != null) m.put("githubUrl", "https://github.com/login/oauth/authorize?client_id=" + System.getProperty("oauth.github.client_id"));

        m.put("google", System.getProperty("oauth.google.client_id") != null && System.getProperty("oauth.google.client_secret") != null);
        if (System.getProperty("oauth.google.client_id") != null && System.getProperty("oauth.google.client_secret") != null) {
            try {
                m.put("googleUrl", "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=" + System.getProperty("oauth.google.client_id")
                        + "&redirect_uri=" + URLEncoder.encode(callbackUrl + "/oauth/google/callback", "iso-8859-1") + "&scope=" + URLEncoder.encode("https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile", "iso-8859-1"));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        }

        m.put("microsoft", System.getProperty("oauth.micorsoft.client_id") != null && System.getProperty("oauth.microsoft.client_secret") != null);
        if (System.getProperty("oauth.microsoft.client_id") != null && System.getProperty("oauth.microsoft.client_secret") != null) {
            try {
                m.put("microsoftUrl", "https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&client_id=" + System.getProperty("oauth.microsoft.client_id")
                        + "&redirect_uri=" + URLEncoder.encode(callbackUrl + "/oauth/microsoft/callback", "iso-8859-1") + "&scope=" + URLEncoder.encode("email profile openid", "iso-8859-1"));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        }


        return m;
    }

    private void authenticate(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String login = req.getParameter("login");
        String password = req.getParameter("password");//req.getParameterNames()
        String msg = "";
        boolean valid = false;
        if (securityManager == null) msg = "No MateuSecurityManager implementation found.";
        else {
            try {
                UserPrincipal p = securityManager.validate(req.getSession(), login, password);
                valid = p != null;
                if (valid) req.getSession().setAttribute("__user", p);
                msg = valid?"Credentials are valid":"Invalid credentials";
            } catch (Throwable throwable) {
                msg = throwable.getMessage();
            }
        }
        String json = "{\"msg\": \"" + msg.replaceAll("\"", "\\\"") + "\", \"valid\": " + valid + "}";
        print(res, "application/json", json);
    }

    private void print(HttpServletResponse res, String body) throws IOException {
        print(res, "text/html", body);
    }

    private void print(HttpServletResponse res, String contentType, String body) throws IOException {
        res.setContentType("text/html");
        if (body == null) body = "";
        res.setContentLength(body.length());
        res.getWriter().print(body);
    }

    @Override
    public void destroy() {

    }

}
