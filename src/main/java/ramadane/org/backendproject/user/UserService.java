package ramadane.org.backendproject.user;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import ramadane.org.backendproject.auth.AuthenticationService;

import java.security.Principal;

@Service
@RequiredArgsConstructor
public class UserService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository repository;
    private final AuthenticationService authenticationService;

    public void changePassword(ChangePasswordRequest request, Principal connectedUser) {
        var user = (User) ((UsernamePasswordAuthenticationToken) connectedUser).getPrincipal();

        // Vérifions si le mot de passe actuel est correct
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,"Mot de passe actuel incorrect");
        }

        // Vérifier si le nouveau mot de passe et la confirmation correspondent
        if (!request.getNewPassword().equals(request.getConfirmationPassword())) {
             throw new ResponseStatusException(HttpStatus.FORBIDDEN,"Le nouveau mot de passe et la confirmation ne correspondent pas");
        }

        // Mettre à jour le mot de passe
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));

        // Sauvegarder l'utilisateur
        repository.save(user);
    }
}
