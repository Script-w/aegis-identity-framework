package com.aegis.util;

import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import javax.sql.DataSource;
import java.sql.Connection;

@Component
public class DbConnectionTest implements CommandLineRunner {

    private final DataSource dataSource;

    public DbConnectionTest(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public void run(String... args) throws Exception {
        System.out.println("🚀 PRE-FLIGHT CHECK: Testing PostgreSQL Connection...");
        try (Connection connection = dataSource.getConnection()) {
            if (connection != null && !connection.isClosed()) {
                System.out.println("✅ SUCCESS: Connected to PostgreSQL!");
                System.out.println("🔗 DB Metadata: " + connection.getMetaData().getDatabaseProductName());
            }

        } catch (Exception e) {
            System.err.println("❌ FAILURE: Could not connect to the database.");
            System.err.println("Error Detail: " + e.getMessage());
        }
    }
}
                                                                                                                                                