package com.spotix.authservice;

import com.spotix.authservice.configuration.*;
import com.spotix.authservice.core.domain.User;
import com.spotix.authservice.core.ports.*;
import com.spotix.authservice.data.security.*;
import com.spotix.authservice.entrypoints.http.RequestIdFilter;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.test.context.*;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.JacksonJsonHttpMessageConverter;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.json.JsonMapper;
import java.nio.file.*;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

import static org.assertj.core.api.Assertions.*;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(SpringExtension.class)
@WebAppConfiguration
@ContextConfiguration(classes = AuthHttpTests.Config.class)
class AuthHttpTests {
    @Configuration
    @EnableWebMvc
    @EnableWebSecurity
    @Import({ApplicationConfiguration.class, JwtConfiguration.class, SecurityConfiguration.class,
            BcryptPasswordHasher.class, JwtTokenIssuer.class})
    @ComponentScan("com.spotix.authservice.entrypoints.http")
    static class Config implements WebMvcConfigurer {
        @Bean MemoryUsers users() { return new MemoryUsers(); }
        @Bean JsonMapper mapper() {
            return JsonMapper.builder().enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES).build();
        }
        @Override
        public void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
            converters.add(new JacksonJsonHttpMessageConverter(mapper()));
        }
    }

    static class MemoryUsers implements UserStore {
        final ConcurrentMap<String, User> data = new ConcurrentHashMap<>();
        public Optional<User> findByEmail(String email) { return Optional.ofNullable(data.get(email)); }
        public Optional<User> findById(UUID id) {
            return data.values().stream().filter(u -> u.id().equals(id)).findFirst();
        }
        public Optional<UUID> insert(User user) {
            return data.putIfAbsent(user.email(), user) == null ? Optional.of(user.id()) : Optional.empty();
        }
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        var keys = generator.generateKeyPair();
        var directory = Files.createTempDirectory(Files.createDirectories(Path.of("target")), "test-keys-");
        var privateFile = directory.resolve("private.pem");
        var publicFile = directory.resolve("public.pem");
        Files.writeString(privateFile, pem("PRIVATE KEY", keys.getPrivate().getEncoded()));
        Files.writeString(publicFile, pem("PUBLIC KEY", keys.getPublic().getEncoded()));
        registry.add("app.jwt.private-key", () -> privateFile.toUri().toString());
        registry.add("app.jwt.public-key", () -> publicFile.toUri().toString());
        registry.add("app.jwt.issuer", () -> "spotix-auth");
        registry.add("app.jwt.audience", () -> "spotix-api");
        registry.add("app.jwt.access-token-seconds", () -> "900");
    }

    private static String pem(String label, byte[] bytes) {
        return "-----BEGIN " + label + "-----\n" + Base64.getMimeEncoder(64, new byte[]{'\n'})
                .encodeToString(bytes) + "\n-----END " + label + "-----\n";
    }

    @Autowired WebApplicationContext context;
    @Autowired MemoryUsers users;
    @Autowired PasswordHasher passwords;
    @Autowired ObjectMapper mapper;
    @Autowired JwtEncoder encoder;
    @Autowired JwtDecoder decoder;
    MockMvc http;

    @BeforeEach
    void setup() {
        users.data.clear();
        http = MockMvcBuilders.webAppContextSetup(context).addFilters(new RequestIdFilter())
                .apply(springSecurity()).build();
    }

    @Test
    void registerLoginAndMeUseRealBcryptAndSignedJwt() throws Exception {
        var created = http.perform(post("/api/auth/register").contentType("application/json")
                .header("X-Request-Id", "register-test").content(registration(" Buyer@Example.com ", " DemoPass123! ")))
                .andExpect(status().isCreated()).andExpect(header().string("Location", "/api/auth/me"))
                .andExpect(header().string("X-Request-Id", "register-test"))
                .andExpect(jsonPath("$.email").value("buyer@example.com"))
                .andExpect(jsonPath("$.displayName").value("Buyer"))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.passwordHash").doesNotExist()).andReturn();
        var stored = users.data.get("buyer@example.com");
        assertThat(passwords.matches(" DemoPass123! ", stored.passwordHash())).isTrue();
        assertThat(stored.toString()).doesNotContain(stored.passwordHash());
        var login = http.perform(post("/api/auth/login").contentType("application/json")
                .content(mapper.writeValueAsString(Map.of("email", "BUYER@example.com", "password", " DemoPass123! "))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.expiresIn").value(900))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.user.passwordHash").doesNotExist()).andReturn();
        var token = mapper.readTree(login.getResponse().getContentAsString()).get("accessToken").asText();
        var claims = decoder.decode(token);
        assertThat(claims.getSubject()).isEqualTo(stored.id().toString());
        assertThat(claims.getAudience()).containsExactly("spotix-api");
        assertThat(claims.getClaimAsStringList("roles")).containsExactly("USER");
        http.perform(get("/api/auth/me").header("Authorization", "Bearer " + token)
                .header("X-User-Id", UUID.randomUUID().toString()))
                .andExpect(status().isOk()).andExpect(content().json(created.getResponse().getContentAsString()));
    }

    @Test
    void duplicatesNormalizeAndConcurrentRequestsCreateOnlyOneUser() throws Exception {
        try (var pool = Executors.newFixedThreadPool(2)) {
            var gate = new CountDownLatch(1);
            Callable<Integer> register = () -> {
                gate.await();
                return http.perform(post("/api/auth/register").contentType("application/json")
                        .content(registration("Same@Example.com", "DemoPass123!")))
                        .andReturn().getResponse().getStatus();
            };
            var first = pool.submit(register);
            var second = pool.submit(register);
            gate.countDown();
            assertThat(List.of(first.get(), second.get())).containsExactlyInAnyOrder(201, 409);
        }
        assertThat(users.data).hasSize(1);
        http.perform(post("/api/auth/register").contentType("application/json")
                .content(registration(" SAME@example.com ", "DemoPass123!")))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.code").value("EMAIL_ALREADY_EXISTS"));
    }

    @Test
    void invalidInputAndPrivilegeFieldsAreRejected() throws Exception {
        for (var password : List.of("short", "a".repeat(73), "đ".repeat(37), " ".repeat(8))) {
            http.perform(post("/api/auth/register").contentType("application/json")
                    .content(registration("buyer@example.com", password)))
                    .andExpect(status().isBadRequest()).andExpect(jsonPath("$.fieldErrors.password").exists());
        }
        http.perform(post("/api/auth/register").contentType("application/json")
                .content(registration("invalid-email", "DemoPass123!"))).andExpect(status().isBadRequest());
        http.perform(post("/api/auth/register").contentType("application/json")
                .content("{\"email\":\"buyer@example.com\",\"password\":\"DemoPass123!\",\"displayName\":\"Buyer\",\"role\":\"ADMIN\"}"))
                .andExpect(status().isBadRequest());
        http.perform(post("/api/auth/register").contentType("application/json").content("{"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
        assertThat(users.data).isEmpty();
    }

    @Test
    void missingWrongAndDisabledCredentialsHaveTheSameResponse() throws Exception {
        var missing = loginError("missing@example.com", "DemoPass123!");
        http.perform(post("/api/auth/register").contentType("application/json")
                .content(registration("buyer@example.com", "DemoPass123!"))).andExpect(status().isCreated());
        var wrong = loginError("buyer@example.com", "WrongPassword!");
        assertThat(missing).isEqualTo(wrong);
        users.data.computeIfPresent("buyer@example.com", (email, u) -> new User(u.id(), u.email(),
                u.passwordHash(), u.displayName(), u.role(), false, u.createdAt()));
        assertThat(loginError("buyer@example.com", "DemoPass123!")).isEqualTo(missing);
    }

    @Test
    void tokenValidationRejectsInvalidClaimsExpiredAndTamperedTokens() throws Exception {
        http.perform(get("/api/auth/me")).andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", "Bearer"))
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
        for (var token : List.of("broken-token",
                signedToken("spotix-auth", "wrong-audience", UUID.randomUUID().toString(), Instant.now().plusSeconds(60)),
                signedToken("wrong-issuer", "spotix-api", UUID.randomUUID().toString(), Instant.now().plusSeconds(60)),
                signedToken("spotix-auth", "spotix-api", "not-a-uuid", Instant.now().plusSeconds(60)),
                signedToken("spotix-auth", "spotix-api", UUID.randomUUID().toString(), Instant.now().minusSeconds(120)))) {
            http.perform(get("/api/auth/me").header("Authorization", "Bearer " + token))
                    .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
        }
        var valid = signedToken("spotix-auth", "spotix-api", UUID.randomUUID().toString(), Instant.now().plusSeconds(60));
        var pieces = valid.split("\\.");
        var payload = Base64.getUrlEncoder().withoutPadding().encodeToString("{}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        http.perform(get("/api/auth/me").header("Authorization", "Bearer " + pieces[0] + "." + payload + "." + pieces[2]))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void unavailableUserAndForbiddenRouteDoNotExposeData() throws Exception {
        var token = signedToken("spotix-auth", "spotix-api", UUID.randomUUID().toString(), Instant.now().plusSeconds(60));
        http.perform(get("/api/auth/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("USER_UNAVAILABLE"));
        http.perform(get("/api/admin/private").header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("FORBIDDEN"));
    }

    private String loginError(String email, String password) throws Exception {
        var result = http.perform(post("/api/auth/login").header("X-Request-Id", "same-request")
                .contentType("application/json").content(mapper.writeValueAsString(Map.of("email", email, "password", password))))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"))
                .andReturn();
        return result.getResponse().getContentAsString();
    }

    private String registration(String email, String password) throws Exception {
        return mapper.writeValueAsString(Map.of("email", email, "password", password, "displayName", " Buyer "));
    }

    private String signedToken(String issuer, String audience, String subject, Instant expiry) {
        var claims = JwtClaimsSet.builder().issuer(issuer).audience(List.of(audience)).subject(subject)
                .issuedAt(Instant.now().minusSeconds(300)).expiresAt(expiry).claim("roles", List.of("USER")).build();
        return encoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(), claims)).getTokenValue();
    }
}
