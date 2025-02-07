package ramadane.org.backendproject.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import ramadane.org.backendproject.config.JwtService;
import ramadane.org.backendproject.token.Token;
import ramadane.org.backendproject.token.TokenRepo;
import ramadane.org.backendproject.token.TokenType;
import ramadane.org.backendproject.user.User;
import ramadane.org.backendproject.user.UserRepository;

@Service
public class AuthenticationService {
    private final UserRepository repository;
    private final TokenRepo tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @Autowired
    public AuthenticationService(
            UserRepository repository,
            TokenRepo tokenRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService,
            AuthenticationManager authenticationManager
    ) {
        this.repository = repository;
        this.tokenRepository = tokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();
        var savedUser = repository.save(user);
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        saveUserToken(savedUser, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = repository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public User getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return repository.findByEmail(authentication.getName())
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));
    }

    public LogoutResponse logout() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null) {
                var user = getCurrentUser();
                revokeAllUserTokens(user);
                SecurityContextHolder.clearContext();
                return LogoutResponse.builder()
                        .message("Déconnexion réussie")
                        .success(true)
                        .build();
            }
            return LogoutResponse.builder()
                    .message("Aucune session active trouvée")
                    .success(false)
                    .build();
        } catch (Exception e) {
            return LogoutResponse.builder()
                    .message("Erreur lors de la déconnexion: " + e.getMessage())
                    .success(false)
                    .build();
        }
    }

    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(User user) {
        var validUserTokens = tokenRepository.findAllValidTokensByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    public AuthenticationResponse refreshToken(RefreshTokenRequest request) {
        final String refreshToken = request.getRefreshToken();
        final String userEmail = jwtService.extractUsername(refreshToken);
        
        if (userEmail == null) {
            throw new IllegalStateException("Token invalide ou expiré");
        }
        
        var user = repository.findByEmail(userEmail)
                .orElseThrow(() -> new IllegalStateException("Utilisateur non trouvé"));
                
        if (!jwtService.isTokenValid(refreshToken, user)) {
            throw new IllegalStateException("Refresh token invalide");
        }
        
        var accessToken = jwtService.generateToken(user);
        
        // Révoquer tous les tokens existants
        revokeAllUserTokens(user);
        // Sauvegarder le nouveau token
        saveUserToken(user, accessToken);
        
        return AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken) // On renvoie le même refresh token
                .build();
    }
} 