package com.javapablophelipe.cadastro_usuario.business;

import com.javapablophelipe.cadastro_usuario.infrastructure.entitys.User;
import com.javapablophelipe.cadastro_usuario.infrastructure.repository.UserRepository;
import com.javapablophelipe.cadastro_usuario.role.UserRole;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthorizationService {

    private final UserRepository repository;

    public AuthorizationService(UserRepository repository) {
        this.repository = repository;
    }

    public boolean userExists(String login) {
        return repository.findByUsername(login) != null;
    }

    public void registerUser(String login, String password, String roleStr) {
        if (userExists(login)) {
            throw  new RuntimeException("Login já existe");
        }

        String encryptedPassword = new BCryptPasswordEncoder().encode(password);
        UserRole roleEnum;
        try{
            roleEnum = UserRole.valueOf(roleStr);
        }catch (IllegalArgumentException e){
            throw new RuntimeException("Role invalido! Use ADMIN ou USER");
        }
        User newUser = new User(login, encryptedPassword, roleEnum);
            repository.save(newUser);
    }
    public User findByUsername(String username) {
        return repository.findByUsername(username);
    }

}
