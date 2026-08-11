package com.backendstudy.template;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final String LOGIN_ERROR =
            "이메일 또는 비밀번호가 올바르지 않습니다.";

    private final Map<String, User> users = new ConcurrentHashMap<>();
    private final BCryptPasswordEncoder passwordEncoder =
            new BCryptPasswordEncoder();
    private final JwtProvider jwtProvider;

    public AuthController(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(
            @Valid @RequestBody RegisterRequest request) {

        if (users.containsKey(request.email())) {
            throw new ApiException(
                    HttpStatus.CONFLICT,
                    "이미 등록된 이메일입니다."
            );
        }

        Instant now = Instant.now();
        User user = new User(
                UUID.randomUUID().toString(),
                request.email(),
                passwordEncoder.encode(request.password()),
                request.name(),
                now,
                now
        );

        users.put(user.getEmail(), user);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(UserResponse.from(user));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @Valid @RequestBody LoginRequest request) {

        User user = users.get(request.email());

        if (user == null
                || !passwordEncoder.matches(
                        request.password(),
                        user.getPassword())) {
            throw new ApiException(
                    HttpStatus.UNAUTHORIZED,
                    LOGIN_ERROR
            );
        }

        String token = jwtProvider.generateToken(user);

        return ResponseEntity.ok(
                new AuthResponse(token, UserResponse.from(user))
        );
    }
}

record RegisterRequest(
        @Email(message = "올바른 이메일 형식이 아닙니다.")
        @NotBlank(message = "이메일은 필수입니다.")
        String email,

        @NotBlank(message = "비밀번호는 필수입니다.")
        @Size(min = 8, message = "비밀번호는 8자 이상이어야 합니다.")
        String password,

        @NotBlank(message = "이름은 필수입니다.")
        String name
) {}

record LoginRequest(
        @Email(message = "올바른 이메일 형식이 아닙니다.")
        @NotBlank(message = "이메일은 필수입니다.")
        String email,

        @NotBlank(message = "비밀번호는 필수입니다.")
        String password
) {}

record UserResponse(
        String id,
        String email,
        String name,
        Instant createdAt,
        Instant updatedAt
) {
    static UserResponse from(User user) {
        return new UserResponse(
                user.getId(),
                user.getEmail(),
                user.getName(),
                user.getCreatedAt(),
                user.getUpdatedAt()
        );
    }
}

record AuthResponse(String token, UserResponse user) {}
