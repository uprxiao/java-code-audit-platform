package example;

import java.sql.Connection;

final class UnsafeController {
    void find(Connection connection, String userName) throws Exception {
        connection.createStatement().executeQuery("select * from users where name='" + userName + "'");
    }

    void execute(String argument) throws Exception {
        Runtime.getRuntime().exec("/usr/bin/example --value=" + argument);
    }
}
