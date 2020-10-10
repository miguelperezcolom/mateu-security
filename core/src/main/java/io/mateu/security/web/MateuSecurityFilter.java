package io.mateu.security.web;

import freemarker.template.TemplateException;
import io.mateu.security.MateuSecurityManager;
import io.mateu.util.Helper;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
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

        if (securityManager == null) filterChain.doFilter(req, res);

        if (initializationErrorMsg != null) print(res, initializationErrorMsg);
        String uri = req.getRequestURI(); //    /zzz/private/iuedwe/iuwede/weqiud
        this.context.log("Requested Resource::"+uri);

        HttpSession session = req.getSession(false);

        if (uri.endsWith("private/logout")) {
            session.invalidate();
            res.sendRedirect("bye");
        } else if (uri.endsWith("private/bye")) {
            showBye(req, res);
        } else if(session == null || securityManager.getPrincipal(session) == null) {

            /*
            boolean calledback = false;
            if ("oauth/github/callback".equalsIgnoreCase(state)) {

                //http://localhost:8080/callback?code=c0324687fdcdf68fde05

                //System.out.println("state = " + state);

                if (MDDUI.get().getCurrentUserLogin() == null) {

                    Map<String, String> params = Helper.parseQueryString(Page.getCurrent().getLocation().getQuery());

                    if (params.containsKey("code")) {
                        try {
                            MDDUIa.setCurrentUserLogin(OAuthHelper.getUserDataFromGitHubCode(params.get("code")));
                            state = "welcome";
                        } catch (Throwable throwable) {
                            v = new ProblemView(stack, "Error during authentication", throwable);
                        }
                    }

                } else {
                    state = "welcome";
                }

                calledback = true;

            } else if ("oauth/google/callback".equalsIgnoreCase(state)) {

                //http://localhost:8080/callback?code=c0324687fdcdf68fde05

                //System.out.println("state = " + state);

                if (MDDUI.get().getCurrentUserLogin() == null) {

                    Map<String, String> params = Helper.parseQueryString(Page.getCurrent().getLocation().getQuery());

                    if (params.containsKey("code")) {
                        try {
                            MDDUI.get().setCurrentUserLogin(OAuthHelper.getUserDataFromGoogleCode(params.get("code")));
                            state = "welcome";
                        } catch (Throwable throwable) {
                            v = new ProblemView(stack, "Error during authentication", throwable);
                        }
                    }

                } else {
                    state = "welcome";
                }

                calledback = true;

            } else if ("oauth/microsoft/callback".equalsIgnoreCase(state)) {

                //http://localhost:8080/callback?code=c0324687fdcdf68fde05

                //System.out.println("state = " + state);

                if (MDDUI.get().getCurrentUserLogin() == null) {

                    Map<String, String> params = Helper.parseQueryString(Page.getCurrent().getLocation().getQuery());

                    if (params.containsKey("code")) {
                        try {
                            MDDUI.get().setCurrentUserLogin(OAuthHelper.getUserDataFromMicrosoftCode(params.get("code")));
                            state = "welcome";
                        } catch (Throwable throwable) {
                            v = new ProblemView(stack, "Error during authentication", throwable);
                        }
                    }

                } else {
                    state = "welcome";
                }

                calledback = true;

            }
             */

            if (uri.endsWith("private/authenticate")) {
                authenticate(req, res);
            } else {
                this.context.log("Unauthorized access request");
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



    private void showBye(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        String html = null;
        try {
            html = Helper.freemark(byeFreemark, getLoginFormProperties());
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
            html = Helper.freemark(loginFormFreemark, getLoginFormProperties());
        } catch (TemplateException e) {
            e.printStackTrace();
            html = Helper.toString(e);
        }
        print(res, html);
    }

    private Map<String, Object> getLoginFormProperties() {
        Map<String, Object> m = new HashMap<>();

        m.put("welcomeMessage", System.getProperty("welcome.message", "Welcome to " + "<here your app name>" + "."));
        m.put("welcomeInfo", System.getProperty("welcome.info", "Here your welcome info"));

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
                valid = securityManager.validate(req.getSession(), login, password);
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
