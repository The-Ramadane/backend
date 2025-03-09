package ramadane.org.backendproject.auth;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import ramadane.org.backendproject.user.User;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Authentication", description = "Endpoints d'authentification")
public class AuthenticationController {

    private final AuthenticationService service;

    @Autowired
    public AuthenticationController(AuthenticationService service) {
        this.service = service;
    }


    @Operation(
            description = "Endpoint pour l'inscription d'un nouvel utilisateur",
            summary = "Inscription d'un utilisateur",
            responses = {
                    @ApiResponse(
                            description = "Success",
                            responseCode = "200"
                    ),
                    @ApiResponse(
                            description = "Unauthorized / Invalid Token",
                            responseCode = "403"
                    )
            }
    )
    @PostMapping("/register")
    public ResponseEntity<Object> register(@RequestBody RegisterRequest request) {
        try {
            AuthenticationResponse auth = service.register(request);
            return ResponseEntity.ok(auth);
        } catch (ResponseStatusException ex) {
            Map<String, Object> errorDetails = new HashMap<>();
            errorDetails.put("status", ex.getStatusCode().value());
            errorDetails.put("error", ex.getReason());
            errorDetails.put("timestamp", LocalDateTime.now());

            return ResponseEntity.status(ex.getStatusCode()).body(errorDetails);
        }
    }


    @Operation(
            description = "Endpoint pour l'authentification d'un utilisateur",
            summary = "Authentification d'un utilisateur",
            responses = {
                    @ApiResponse(
                            description = "Success",
                            responseCode = "200"
                    ),
                    @ApiResponse(
                            description = "Unauthorized / Invalid Token",
                            responseCode = "403"
                    )
            }
    )
    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request
    ) {
        return ResponseEntity.ok(service.authenticate(request));
    }

    @Operation(
            description = "Endpoint pour récupérer les informations de l'utilisateur connecté",
            summary = "Informations de l'utilisateur connecté",
            responses = {
                    @ApiResponse(
                            description = "Success",
                            responseCode = "200"
                    ),
                    @ApiResponse(
                            description = "Unauthorized / Invalid Token",
                            responseCode = "403"
                    )
            }
    )
    @GetMapping("/me")
    public ResponseEntity<User> getCurrentUser() {
        return ResponseEntity.ok(service.getCurrentUser());
    }

    @Operation(
            description = "Endpoint pour la déconnexion de l'utilisateur",
            summary = "Déconnexion de l'utilisateur",
            responses = {
                    @ApiResponse(
                            description = "Success",
                            responseCode = "200"
                    ),
                    @ApiResponse(
                            description = "Unauthorized / Invalid Token",
                            responseCode = "403"
                    )
            }
    )
    @PostMapping("/logout")
    public ResponseEntity<LogoutResponse> logout() {
        return ResponseEntity.ok(service.logout());
    }

    @Operation(
            description = "Endpoint pour rafraîchir le token d'accès",
            summary = "Rafraîchissement du token",
            responses = {
                    @ApiResponse(
                            description = "Success",
                            responseCode = "200"
                    ),
                    @ApiResponse(
                            description = "Invalid Refresh Token",
                            responseCode = "403"
                    )
            }
    )
    @PostMapping("/refresh-token")
    public ResponseEntity<AuthenticationResponse> refreshToken(
            @RequestBody RefreshTokenRequest request
    ) {
        return ResponseEntity.ok(service.refreshToken(request));
    }
} 