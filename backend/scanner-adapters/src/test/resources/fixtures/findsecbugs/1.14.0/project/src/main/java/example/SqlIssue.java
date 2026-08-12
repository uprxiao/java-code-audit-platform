package example;

import java.sql.Connection;
import java.sql.SQLException;

public final class SqlIssue {
    public void query(Connection connection, String user) throws SQLException {
        connection.createStatement().execute("SELECT * FROM users WHERE name = '" + user + "'");
    }
}
