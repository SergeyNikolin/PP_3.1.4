package ru.kata.spring.boot_security.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.*;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import ru.kata.spring.boot_security.demo.entities.Role;
import ru.kata.spring.boot_security.demo.entities.User;
import ru.kata.spring.boot_security.demo.services.RoleService;
import ru.kata.spring.boot_security.demo.services.UserService;

@Controller
@RequestMapping("/")
public class MainController {
    private final UserService userService;
    private final RoleService roleService;
    private final PasswordEncoder passwordEncoder;
    private static final String REDIRECTADMIN = "redirect:/admin";

    @Autowired
    public MainController(UserService userService, PasswordEncoder passwordEncoder, RoleService roleService) {
        this.roleService = roleService;
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    //---------------<<LOGIN PAGE>>---------------//

    @GetMapping("/login")
    public String showLoginPage() {
        return "login";
    }

    @PostMapping("/login")
    public String login(@RequestParam("username") String username,
                        @RequestParam("password") String password) {
        return "";
    }

    //---------------<<USER INFO PAGE>>---------------//

    @GetMapping("/user")
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    public String getUserProfile(Model model, @AuthenticationPrincipal org.springframework.security.core.userdetails.User currentUser, Authentication authentication) {
        User user = userService.findByUsername(currentUser.getUsername());
        model.addAttribute("userID", user.getId());
        model.addAttribute("userUsername", user.getUsername());
        model.addAttribute("userName", user.getName());
        model.addAttribute("userLastName", user.getLastName());
        model.addAttribute("userAge", user.getAge());
        model.addAttribute("curUsersRoles", authentication.getAuthorities().stream().map(r-> r.getAuthority()).toList());
        return "user";
    }

    //---------------<<ADMIN PAGE WITH USERS TABLE>>---------------//

    @GetMapping(value = "/admin")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String printWelcome(ModelMap model, @AuthenticationPrincipal org.springframework.security.core.userdetails.User currentUser) {
        Optional<User> user = Optional.ofNullable(userService.findByUsername(currentUser.getUsername()));
        if (user.isEmpty()) {
            return "redirect:/login";
        }
        User newUser = new User();
        Optional<Collection<Role>> roles = Optional.ofNullable(roleService.getAllRoles());
        if (roles.isEmpty()) {
            return "redirect:/admin/add";
        }
        Optional<List<User>> users = Optional.ofNullable(userService.findAll());
        if (users.isEmpty()) {
            return "redirect:/admin/add";
        }
        model.addAttribute("newUser", newUser);
        model.addAttribute("editUser", newUser);
        model.addAttribute("user", user.get());
        model.addAttribute("users", users.get());
        model.addAttribute("currUser", user.get());
        model.addAttribute("roles", roles.get());
        return "admin";
    }

    //---------------<<ADD USER>>---------------//

    @PostMapping("/admin/add")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String addUser(@RequestParam String username, @RequestParam String password, @RequestParam String name, @RequestParam String lastName, @RequestParam int age, @RequestParam String role, RedirectAttributes redirectAttributes) {
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setName(name);
        user.setLastName(lastName);
        user.setAge(age);
        user.setRoles(Collections.singletonList(roleService.findByName(role)));
        userService.saveUser(user);
        redirectAttributes.addFlashAttribute("message", "User added successfully");
        return REDIRECTADMIN;
    }

    //---------------<<EDIT USER>>---------------//

    @PostMapping("/admin/edit")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String updateUser(@RequestParam("id") Long id, @ModelAttribute("user") User updatedUser) {
        Optional<User> existingUser = Optional.ofNullable(userService.getUserById(id));
        if (existingUser.isEmpty()) {
            return REDIRECTADMIN;
        }
        existingUser.get().setUsername(updatedUser.getUsername());
        existingUser.get().setPassword(passwordEncoder.encode(updatedUser.getPassword()));
        existingUser.get().setName(updatedUser.getName());
        existingUser.get().setLastName(updatedUser.getLastName());
        existingUser.get().setAge(updatedUser.getAge());
        List<Role> roles = updatedUser.getRoles().stream()
                .map(role -> roleService.findByName(role.getName()))
                .collect(Collectors.toList());
        existingUser.get().setRoles(roles);
        userService.saveUser(existingUser.get());
        return REDIRECTADMIN;
    }

    //---------------<<DELETE USER>>---------------//

    @PostMapping("/admin/delete")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String deleteUser(@RequestParam("id") Long userId) {
        userService.deleteUser(userId);
        return REDIRECTADMIN;
    }

}