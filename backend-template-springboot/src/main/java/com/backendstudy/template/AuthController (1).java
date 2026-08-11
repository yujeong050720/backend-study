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

/**
 * 2주차 인증 API 컨트롤러
 *
 * 학습 포인트:
 *
 * - 사용자 등록 및 비밀번호 해싱 (BCrypt)
 * - JWT 토큰 생성 및 검증
 * - 인증 응답 구조
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    // 인메모리 사용자 저장소
    private final Map<String, User> users = new ConcurrentHashMap<>();
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private final JwtProvider jwtProvider;

    public AuthController(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    /**
     * POST /auth/register - 회원가입
     *
     * 구현 단계:
     *
     * 1. 요청 유효성 검증 — @Valid가 자동으로 처리합니다. 실패하면
     * GlobalExceptionHandler.handleValidation()이 400으로 변환해주니 따로 처리할 필요 없음.
     *
     * 2. 이메일 중복 확인 — users.containsKey(request.email())이 true면
     * throw new ApiException(HttpStatus.CONFLICT, "이미 등록된 이메일입니다.")
     *
     * 3. 비밀번호 해싱 — spring-security-crypto의 BCryptPasswordEncoder 사용.
     * new BCryptPasswordEncoder().encode(request.password())
     * (cost factor는 기본값 10 그대로 사용하면 됨, 학습 목적이라 튜닝 불필요.
     *
     * 매 요청마다 새로 만들지 말고 필드나 @Bean으로 한 번만 생성해서 재사용할 것)
     *
     * 4. 사용자 저장 — id는 java.util.UUID.randomUUID().toString(),
     * createdAt/updatedAt은 java.time.Instant.now()
     * (LocalDateTime이 아니라 Instant를 써야 JSON 응답에 "2026-08-05T10:00:00Z"처럼
     *
     * 'Z'가 붙은 UTC로 자동 직렬화됩니다 — User.java 필드 타입 참고)
     *
     * 5. UserResponse로 변환해서 201 Created 반환 (비밀번호 필드는 절대 포함 금지)
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        if (users.containsKey(request.email())) {
            throw new ApiException(HttpStatus.CONFLICT, "이미 등록된 이메일입니다.");
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

        users.put(request.email(), user);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(UserResponse.from(user));
    }

    /**
     * POST /auth/login - 로그인
     *
     * 구현 단계:
     *
     * 1. 요청 유효성 검증 — @Valid
     *
     * 2. 사용자 찾기 — users.get(request.email())이 null이면
     * throw new ApiException(HttpStatus.UNAUTHORIZED, "이메일 또는 비밀번호가 올바르지 않습니다.")
     * (이메일이 존재하지 않는 것과 비밀번호가 틀린 것을 같은 메시지로 응답해야
     *
     * "가입된 이메일 목록"이 새어나가지 않습니다 — 아래 3번도 실패 시 같은 메시지 사용)
     *
     * 3. 비밀번호 검증 — new BCryptPasswordEncoder().matches(request.password(), user.getPassword())
     * 가 false면 위와 동일한 메시지로 401
     *
     * 4. JWT 토큰 생성 — 아래 JwtProvider의 generateToken(user) 호출.
     * HS256, subject=user.getId(), claim("email", user.getEmail()),
     * 발급시각=now, 만료시각=now + 24시간
     *
     * 5. AuthResponse(token, userResponse)로 200 OK 반환
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        User user = users.get(request.email());

        if (user == null ||
                !passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new ApiException(
                    HttpStatus.UNAUTHORIZED,
                    "이메일 또는 비밀번호가 올바르지 않습니다."
            );
        }

        String token = jwtProvider.generateToken(user);

        return ResponseEntity.ok(
                new AuthResponse(token, UserResponse.from(user))
        );
    }
}


// TODO: User 엔티티 채우기 (User.java 파일에 필드 스켈레톤이 이미 있음)
// - 생성자, getter, setter 구현
// - createdAt/updatedAt은 Instant 타입 (선언되어 있음, 건드리지 마세요)


// RegisterRequest DTO — 유효성 검증 메시지는 GlobalExceptionHandler가 그대로 꺼내 쓰므로
// 여기 message 속성이 곧 사용자에게 보이는 에러 문구입니다.
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


// TODO: UserResponse DTO 정의
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


// TODO: AuthResponse DTO 정의
record AuthResponse(String token, UserResponse user) {}


// TODO: JWT 토큰 제공자 클래스 구현 (예: JwtProvider.java, @Component로 등록)
// - pom.xml에 추가된 io.jsonwebtoken:jjwt-api/impl/jackson 사용
// - 시크릿 키는 하드코딩 대신 application.properties의 jwt.secret을
//   @Value("${jwt.secret}")로 주입받아 사용
//
// JwtProvider는 이미 별도 파일에 있으므로 여기서는 추가 구현하지 않음.