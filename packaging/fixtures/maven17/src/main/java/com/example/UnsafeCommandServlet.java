package com.example;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

/** Deliberately vulnerable Apache-2.0 acceptance code for real taint scanners. */
public final class UnsafeCommandServlet {
    public void execute(HttpServletRequest request) throws IOException {
        String command = request.getParameter("command");
        String forwarded = command.trim();
        Runtime.getRuntime().exec(forwarded);
    }
}
