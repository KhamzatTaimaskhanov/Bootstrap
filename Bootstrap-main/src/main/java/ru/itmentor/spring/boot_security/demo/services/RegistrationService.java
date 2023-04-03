package ru.itmentor.spring.boot_security.demo.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.itmentor.spring.boot_security.demo.model.Role;
import ru.itmentor.spring.boot_security.demo.model.User;
import ru.itmentor.spring.boot_security.demo.repositories.UserRepositories;

import java.util.Collections;

@Service
@Transactional
public class RegistrationService {
    private final UserRepositories userRepositories;
    private final RoleService roleService;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public RegistrationService(UserRepositories userRepositories, RoleService roleService, PasswordEncoder passwordEncoder) {
        this.userRepositories = userRepositories;
        this.roleService = roleService;
        this.passwordEncoder = passwordEncoder;
    }

    public boolean register(User user) {
        Role role = roleService.getByName("ROLE_USER");
        User userDB = userRepositories.findByEmail(user.getEmail());
        if (userDB != null) {
            return false;
        }
        user.setRoles(Collections.singleton(role));
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepositories.save(user);
        return true;
    }

    public boolean deleteUser(int userId) {
        if (userRepositories.findById(userId).isPresent()) {
            userRepositories.deleteById(userId);
            return true;
        }
        return false;
    }
}
