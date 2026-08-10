package main

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

// 아래 TODO들을 채우다 보면 이 import 블록에 다음을 하나씩 추가하게 됩니다
// (Go는 안 쓰는 import를 컴파일 에러로 처리하므로, 지금 미리 넣어두지 않았습니다):
//   "time"                          — CreatedAt/UpdatedAt, JWT 만료시간
//   "github.com/golang-jwt/jwt/v5"  — JWT 생성/검증
//   "github.com/google/uuid"        — 이미 go.mod에 추가되어 있음, User.ID 생성용 (uuid.NewString())
//   "golang.org/x/crypto/bcrypt"    — 비밀번호 해싱

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Password  string    `json:"-"` // Password는 JSON 응답에 포함되지 않도록 `json:"-"` 태그 사용
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// TODO: User 구조체 정의
// - ID, Email, Name, Password, CreatedAt, UpdatedAt 필드 포함
// - Password는 JSON 응답에 포함되지 않도록 `json:"-"` 태그 사용
// - CreatedAt/UpdatedAt은 time.Time 타입 사용. encoding/json이 time.Time을 자동으로
//   RFC3339 UTC(예: "2026-08-05T10:00:00Z")로 직렬화해주므로, 저장할 때
//   time.Now().UTC()로 값을 넣기만 하면 명세가 요구하는 날짜 포맷을 그대로 만족합니다.

// TODO: RegisterRequest 구조체 정의
// - Email, Password, Name 필드 포함 (json 태그를 소문자로: `json:"email"` 등)
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

// TODO: LoginRequest 구조체 정의
// - Email, Password 필드 포함
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// TODO: UserResponse 구조체 정의
//   - ID, Email, Name, CreatedAt, UpdatedAt 필드 포함 (Password 없음)
//   - User -> UserResponse로 변환하는 toUserResponse(u User) UserResponse 함수를 만들어서
//     register/login 양쪽에서 재사용하면 실수로 비밀번호를 응답에 흘리는 걸 막을 수 있음
type UserResponse struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// TODO: AuthResponse 구조체 정의
// - Token, User 필드 포함 (User는 UserResponse 타입)

type AuthResponse struct {
	Token string       `json:"token"`
	User  UserResponse `json:"user"`
}

// TODO: JWT Claims 구조체 정의
// - UserID, Email 필드 포함
// - jwt.RegisteredClaims 임베딩 (ExpiresAt, IssuedAt 등은 여기서 채움)
type Claims struct {
	UserID string `json:"userId"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

// TODO: 인메모리 사용자 저장소
// var users = make(map[string]User)  // email을 key로 사용하면 중복 검사가 O(1)

var users = make(map[string]User)

func getEnvOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

// TODO: JWT 시크릿 키
// 하드코딩 대신 환경변수로 읽는 걸 권장합니다 (os.Getenv("JWT_SECRET"), 없으면 개발용 기본값).
// var jwtSecret = []byte(getEnvOrDefault("JWT_SECRET", "dev-only-secret-change-me
var jwtSecret = []byte(getEnvOrDefault("JWT_SECRET", "dev-only-secret-change-me"))

// registerUser handles POST /auth/register
// 학습 포인트: 사용자 등록, 비밀번호 해싱, 중복 검사, 입력 검증
func registerUser(c echo.Context) error {
	// TODO: 구현하기
	// 1. 요청 바디를 RegisterRequest로 파싱 — c.Bind(&req)
	var req RegisterRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "잘못된 요청입니다.")
	}

	// 2. 유효성 검사 — email에 "@" 포함 여부(strings.Contains), password 8자 이상,
	//    name 빈 문자열 아님. 실패 시 echo.NewHTTPError(http.StatusBadRequest, "...")
	//    (errors.go의 customHTTPErrorHandler가 { "error": "..." } 포맷으로 변환해줌)
	if !strings.Contains(req.Email, "@") {
		return echo.NewHTTPError(http.StatusBadRequest, "이메일 형식이 잘못되었습니다.")
	}
	if len(req.Password) < 8 {
		return echo.NewHTTPError(http.StatusBadRequest, "비밀번호는 8자리 이상 작성해야 합니다.")
	}

	if req.Name == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "이름을 입력하세요.")
	}

	// 3. 이메일 중복 확인 — users[req.Email]이 이미 있으면
	//    echo.NewHTTPError(http.StatusConflict, "이미 등록된 이메일입니다.")
	if _, exists := users[req.Email]; exists {
		return echo.NewHTTPError(http.StatusConflict, "이미 등록된 이메일입니다.")
	}

	// 4. 비밀번호 해싱 — bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	//    DefaultCost(10)면 충분함, 학습 목적이라 별도 튜닝 불필요
	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "비밀번호 해싱 중 오류가 발생했습니다.")
	}
	// 5. User 생성 및 저장 — ID는 uuid.NewString(), CreatedAt/UpdatedAt은 time.Now().UTC()
	user := User{
		ID:        uuid.NewString(),
		Email:     req.Email,
		Name:      req.Name,
		Password:  string(hashed),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	users[req.Email] = user
	// 6. toUserResponse(user)로 변환해서 c.JSON(http.StatusCreated, ...) 반환
	return c.JSON(http.StatusCreated, toUserResponse(user))
}

// loginUser handles POST /auth/login
// 학습 포인트: 인증 토큰 기반 인증, JWT 생성/검증
func loginUser(c echo.Context) error {
	// TODO: 구현하기
	// 1. 요청 바디를 LoginRequest로 파싱
	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "잘못된 요청입니다.")
	}

	// 2. 유효성 검사 (이메일, 비밀번호 필수)
	if req.Email == "" || req.Password == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "이메일, 비밀번호를 입력하세요.")
	}

	// 3. 사용자 찾기 — users[req.Email]이 없으면
	//    echo.NewHTTPError(http.StatusUnauthorized, "이메일 또는 비밀번호가 올바르지 않습니다.")
	//    (이메일이 존재하는지 여부가 새어나가지 않도록, 아래 4번 실패도 같은 메시지 사용)
	user, exists := users[req.Email]
	if !exists {
		return echo.NewHTTPError(http.StatusUnauthorized, "이메일 또는 비밀번호가 올바르지 않습니다.")
	}
	// 4. 비밀번호 검증 — bcrypt.CompareHashAndPassword(user.Password, []byte(req.Password))가
	//    nil이 아니면 위와 동일한 401
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "이메일 또는 비밀번호가 올바르지 않습니다.")
	}
	// 5. JWT 토큰 생성 — generateJWT(user) 호출 (아래 TODO)
	token, err := generateJWT(user)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "토큰 생성이 실패했습니다.")
	}
	// 6. AuthResponse{Token: token, User: toUserResponse(user)}로 200 반환
	return c.JSON(http.StatusOK, AuthResponse{
		Token: token,
		User:  toUserResponse(user),
	})
}

// TODO: generateJWT 함수 구현
// - JWT 토큰 생성 (HS256 알고리즘)
// - Claims에 UserID, Email, 만료시간(24시간) 포함
func generateJWT(u User) (string, error) {
	claims := Claims{
		UserID: u.ID,
		Email:  u.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// TODO: toUserResponse 함수 구현
// - User를 UserResponse로 변환 (비밀번호 제외)
func toUserResponse(u User) UserResponse {
	return UserResponse{
		ID:        u.ID,
		Email:     u.Email,
		Name:      u.Name,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}
}
