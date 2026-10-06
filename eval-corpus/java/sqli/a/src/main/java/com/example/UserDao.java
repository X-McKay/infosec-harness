package com.example;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class UserDao {
    /** Look up a user by name. */
    public ResultSet getUser(Connection conn, String name) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT id, name, secret FROM users WHERE name = ?");
        ps.setString(1, name);
        return ps.executeQuery();
    }
}
