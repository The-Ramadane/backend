package ramadane.org.backendproject.user;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.security.Principal;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Tag(name = "User", description = "Endpoints de gestion des utilisateurs")
public class UserController {

    private final UserService service;

    @Operation(
            description = "Endpoint pour changer le mot de passe de l'utilisateur connecté",
            summary = "Changement de mot de passe",
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
    @PatchMapping("/change-password")
    public ResponseEntity<?> changePassword(
            @RequestBody ChangePasswordRequest request,
            Principal connectedUser
    ) {
        try {
             service.changePassword(request, connectedUser);
             return ResponseEntity.ok("Mot de passe changé avec succès");
        } catch (ResponseStatusException ex) {
            Map<String, Object> errorDetails = new HashMap<>();
            errorDetails.put("status", ex.getStatusCode().value());
            errorDetails.put("error", ex.getReason());
            errorDetails.put("timestamp", LocalDateTime.now());

            return ResponseEntity.status(ex.getStatusCode()).body(errorDetails);
        }
    }
}
