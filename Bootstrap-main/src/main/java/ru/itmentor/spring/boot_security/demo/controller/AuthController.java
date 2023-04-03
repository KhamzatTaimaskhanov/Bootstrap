package ru.itmentor.spring.boot_security.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import ru.itmentor.spring.boot_security.demo.services.RegistrationService;
import ru.itmentor.spring.boot_security.demo.services.RoleService;
import ru.itmentor.spring.boot_security.demo.services.UserService;

import java.util.Collection;
import java.util.Objects;
import java.util.Optional;

@Controller
public class AuthController {
    private final UserService userService;
    private final RoleService roleService;
    private final RegistrationService registrationService;

    @Autowired
    public AuthController(UserService userService, RoleService roleService, RegistrationService registrationService) {
        this.userService = userService;
        this.roleService = roleService;
        this.registrationService = registrationService;
    }
    @GetMapping(value = "login")
    public String loginPage() {
        return "users/login";
    }

    @RequestMapping("/userPage")
    public String getUserPage(Model model, Authentication authentication){
        model.addAttribute("users", userService.findAll());
        model.addAttribute("authentication",authentication.getPrincipal());
        model.addAttribute("roles", roleService.findAll());
        return "users/userPage";
    }
    @RequestMapping("/adminPage")
    public String getAdminPage(Model model, Authentication authentication ){
        model.addAttribute("users", userService.findAll());
        model.addAttribute("authentication",authentication.getPrincipal());
        model.addAttribute("roles", roleService.findAll());
        return "admin/adminPage";
    }

    private String userAdminRedirect(Authentication auth) {
        Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
        Optional<? extends GrantedAuthority> roleAdmin = authorities.stream()
                .filter(a -> Objects.equals("ROLE_ADMIN", a.getAuthority()))
                .findAny();
        if (roleAdmin.isPresent()) return "redirect:/admin";
        else return "redirect:/users";
    }
}

