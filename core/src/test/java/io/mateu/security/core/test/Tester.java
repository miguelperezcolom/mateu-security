package io.mateu.security.core.test;

import io.mateu.security.web.MateuSecurityFilter;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.DefaultServlet;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

import java.util.EnumSet;

import static javax.servlet.DispatcherType.REQUEST;

public class Tester {

    public static Server createServer(int port)
    {
        Server server = new Server(port);
        // This has a connector listening on port specified
        // and no handlers, meaning all requests will result
        // in a 404 response

        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");
        context.setResourceBase(System.getProperty("user.dir") + "/core/src/test/webapp");
        server.setHandler(context);

        ServletHolder staticContentServlet = new ServletHolder(
                "staticContentServlet", DefaultServlet.class);
        staticContentServlet.setInitParameter("dirAllowed", "true");
        context.addServlet(staticContentServlet, "/");

        //context.addServlet(DefaultServlet.class, "/");

        context.addFilter(MateuSecurityFilter.class, "/zzz/private/*", EnumSet.of(REQUEST));

        /*
        ServletHandler handler = new ServletHandler();
        server.setHandler(handler);

         */

        return server;
    }


    public static void main(String[] args) throws Exception {

        System.setProperty("oauth.github.client_id", "aaa");
        System.setProperty("oauth.github.client_secret", "aaa");

        System.setProperty("oauth.google.client_id", "aaa");
        System.setProperty("oauth.google.client_secret", "aaa");

        System.setProperty("oauth.microsoft.client_id", "aaa");
        System.setProperty("oauth.microsoft.client_secret", "aaa");

        System.setProperty("registrationUrl", "aaa");
        //System.setProperty("passwordForgottenUrl", "bbbb");


        int port = 8080; //ExampleUtil.getPort(args, "jetty.http.port", 8080);
        Server server = createServer(port);
        server.start();
        server.join();
    }

}
