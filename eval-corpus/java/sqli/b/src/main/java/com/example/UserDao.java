package com.example;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class UserDao {
    /** Look up a user by name. VULNERABLE: name concatenated into the SQL text. */
    public ResultSet getUser(Connection conn, String name) throws SQLException {
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT id, name, secret FROM users WHERE name = '" + name + "'");
    }
}
