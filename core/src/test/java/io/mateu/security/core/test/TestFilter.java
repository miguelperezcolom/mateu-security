package io.mateu.security.core.test;

import io.mateu.security.web.MateuSecurityFilter;

import javax.servlet.annotation.WebFilter;

@WebFilter("/zzz/private/*")
public class TestFilter extends MateuSecurityFilter {
}
