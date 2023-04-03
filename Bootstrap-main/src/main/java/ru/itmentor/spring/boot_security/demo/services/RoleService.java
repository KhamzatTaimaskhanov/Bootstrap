package ru.itmentor.spring.boot_security.demo.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import ru.itmentor.spring.boot_security.demo.model.Role;
import ru.itmentor.spring.boot_security.demo.repositories.RoleRepositories;

import java.util.List;
import java.util.Optional;
@Service
public class RoleService {

    private final RoleRepositories roleRepositories;

    @Autowired
    public RoleService(RoleRepositories roleRepositories) {
        this.roleRepositories = roleRepositories;
    }

    public Role getByName(String name) {
        Optional<Role> roleOptional = roleRepositories.findByName(name);
        return roleOptional.orElseThrow();
    }

    public List<Role> findAll(){
        return roleRepositories.findAll();
    }
}
