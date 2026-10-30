package com.spotix.authservice.data.persistence;

import com.spotix.authservice.core.domain.User;
import com.spotix.authservice.core.domain.UserRole;
import com.spotix.authservice.core.ports.UserStore;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import java.sql.Timestamp;
import java.util.Optional;
import java.util.UUID;

@Repository
public class JdbcUserStore implements UserStore {
    private static final String COLUMNS = "id, email, password_hash, display_name, role, enabled, created_at";
    private static final RowMapper<User> USER_MAPPER = (rs, row) -> new User(
            rs.getObject("id", UUID.class), rs.getString("email"), rs.getString("password_hash"),
            rs.getString("display_name"), UserRole.valueOf(rs.getString("role")),
            rs.getBoolean("enabled"), rs.getTimestamp("created_at").toInstant());

    private final JdbcTemplate jdbc;

    public JdbcUserStore(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public Optional<User> findByEmail(String normalizedEmail) {
        return jdbc.query("SELECT " + COLUMNS + " FROM users WHERE email = ?",
                USER_MAPPER, normalizedEmail).stream().findFirst();
    }

    @Override
    public Optional<User> findById(UUID id) {
        return jdbc.query("SELECT " + COLUMNS + " FROM users WHERE id = ?",
                USER_MAPPER, id).stream().findFirst();
    }

    @Override
    @Transactional
    public Optional<UUID> insert(User user) {
        return jdbc.query("""
                INSERT INTO users (id, email, password_hash, display_name, role, enabled, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (email) DO NOTHING RETURNING id
                """, (rs, row) -> rs.getObject("id", UUID.class), user.id(), user.email(),
                user.passwordHash(), user.displayName(), user.role().name(), user.enabled(),
                Timestamp.from(user.createdAt())).stream().findFirst();
    }
}
