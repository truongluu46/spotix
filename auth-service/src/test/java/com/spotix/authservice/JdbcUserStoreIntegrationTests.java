package com.spotix.authservice;

import com.spotix.authservice.core.domain.*;
import com.spotix.authservice.data.persistence.JdbcUserStore;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

import static org.assertj.core.api.Assertions.*;

/** Opt in with an isolated PostgreSQL test database; never point this at production. */
@EnabledIfEnvironmentVariable(named = "AUTH_TEST_DB_URL", matches = ".+")
class JdbcUserStoreIntegrationTests {
    JdbcTemplate jdbc;
    JdbcUserStore store;
    final List<UUID> created = new ArrayList<>();

    @BeforeEach
    void setup() {
        var source = new DriverManagerDataSource(System.getenv("AUTH_TEST_DB_URL"),
                System.getenv().getOrDefault("AUTH_TEST_DB_USERNAME", "postgres"),
                System.getenv("AUTH_TEST_DB_PASSWORD"));
        Flyway.configure().dataSource(source).load().migrate();
        jdbc = new JdbcTemplate(source);
        store = new JdbcUserStore(jdbc);
    }

    @AfterEach
    void cleanup() {
        created.forEach(id -> jdbc.update("DELETE FROM users WHERE id = ?", id));
    }

    @Test
    void migrationAndRoundTripPreserveUserFields() {
        var user = user("roundtrip-" + UUID.randomUUID() + "@example.com");
        assertThat(store.insert(user)).contains(user.id());
        var actual = store.findById(user.id()).orElseThrow();
        assertThat(actual.email()).isEqualTo(user.email());
        assertThat(actual.passwordHash()).isEqualTo(user.passwordHash());
        assertThat(actual.role()).isEqualTo(UserRole.USER);
        assertThat(actual.enabled()).isTrue();
        assertThat(store.findByEmail(user.email())).contains(actual);
        assertThat(jdbc.queryForObject("SELECT success FROM flyway_schema_history WHERE version = '1'", Boolean.class)).isTrue();
    }

    @Test
    void postgresUniqueConstraintHandlesConcurrentEmailInserts() throws Exception {
        String email = "race-" + UUID.randomUUID() + "@example.com";
        var first = user(email);
        var second = user(email);
        try (var pool = Executors.newFixedThreadPool(2)) {
            var gate = new CountDownLatch(1);
            var a = pool.submit(() -> { gate.await(); return store.insert(first); });
            var b = pool.submit(() -> { gate.await(); return store.insert(second); });
            gate.countDown();
            assertThat(List.of(a.get().isPresent(), b.get().isPresent())).containsExactlyInAnyOrder(true, false);
        }
        assertThat(jdbc.queryForObject("SELECT count(*) FROM users WHERE email = ?", Integer.class, email)).isEqualTo(1);
    }

    private User user(String email) {
        var id = UUID.randomUUID();
        created.add(id);
        return new User(id, email, "test-hash", "Integration test", UserRole.USER, true, Instant.now());
    }
}
