package example;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

public final class UnsafeCommandServlet {
    public void execute(HttpServletRequest request) throws IOException {
        String command = request.getParameter("command");
        String forwarded = command.trim();
        Runtime.getRuntime().exec(forwarded);
    }
}
