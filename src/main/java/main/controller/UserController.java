package main.controller;


import main.model.Role;
import main.model.User;
import main.repository.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import java.util.*;

@Controller
public class UserController {
    @Autowired
    private UserRepo userRepo;

    @Autowired
    private PasswordEncoder passwordEncoder;


    @GetMapping("/")
    public String greeting() {
        Collection<? extends GrantedAuthority> authorities = SecurityContextHolder.getContext().getAuthentication().getAuthorities();
        if (authorities.contains(Role.ADMIN)) {
            return "redirect:/admin/adminPage";
        }
        return "redirect:/user/userPageInfo";
    }

    @GetMapping("/newAdmin")
    public String newAdmin() {
        HashSet<Role> roles = new HashSet<>();
        roles.add(Role.ADMIN);
        roles.add(Role.USER);
        User user = new User("ADMIN", passwordEncoder.encode("ADMIN"),"LastName", 23, "asasd@asd.ru", roles);
        userRepo.save(user);
        return "/hello";
    }

//    @GetMapping("/admin/addUserPage")
//    public String addUserPage() {
//        return "addUserPage";
//    }

    @PostMapping("/admin/add")
    public String addUser(User user, @RequestParam("role") String role) {
        Set<Role> userRoles = getRoles(role);
        user.setUserRoles(userRoles);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepo.save(user);
        return "redirect:/admin/adminPage";
    }
    @GetMapping("/admin/adminPage")
    public ModelAndView listUsers(User user) {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Iterable<User> list = userRepo.findAll();
        ModelAndView modelAndView = new ModelAndView("adminPage");
        modelAndView.getModelMap().addAttribute("listUsers", list);
        modelAndView.getModelMap().addAttribute("currentUser", currentUser);
        return modelAndView;
    }

    @PostMapping("/admin/adminPage")
    public ModelAndView viewAdminPage(User user) {
        Iterable<User> list = userRepo.findAll();
        ModelAndView modelAndView = new ModelAndView("adminPage");
        modelAndView.getModelMap().addAttribute("listUsers", list);
        return modelAndView;
    }


//    @PostMapping("/admin/editUserPage")
//    public ModelAndView viewEditPage(@RequestParam Long id) {
//        Iterable<User> list = userRepo.findAllById(Collections.singleton(id));
//        ModelAndView modelAndView = new ModelAndView("editUserPage");
//        modelAndView.getModelMap().addAttribute("listUsers", list);
//        return modelAndView;
//    }

    @PostMapping("/admin/edit")
    public String editUser(User user, @RequestParam("role") String role) {
        User byId = userRepo.findById(user.getId()).get();
        if (user.getPassword() != null) {
           byId.setPassword(passwordEncoder.encode( user.getPassword()));
        }
        Set<Role> userRoles = getRoles(role);
        byId.setUserRoles(userRoles);
        byId.setName(user.getName());
        byId.setLastName(user.getLastName());
        byId.setAge(user.getAge());
        byId.setEmail(user.getEmail());


        userRepo.save(byId);
        return "redirect:/admin/adminPage";
    }

    @PostMapping("/admin/delete")
    public String delUser(@RequestParam("id") Long id) {
        userRepo.deleteById(id);
        return "redirect:/admin/adminPage";
    }

//    @PostMapping("/admin/delUserPage")
//    public ModelAndView viewDelPage(@RequestParam("id") Long id) {
//        Iterable<User> list = userRepo.findAllById(Collections.singleton(id));
//        ModelAndView modelAndView = new ModelAndView("delUserPage");
//        modelAndView.getModelMap().addAttribute("listUsers", list);
//        return modelAndView;
//    }

    @GetMapping("/user/userPageInfo")
    public ModelAndView printWelcome(User user) {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        ModelAndView modelAndView = new ModelAndView("userPageInfo");
        modelAndView.getModelMap().addAttribute("currentUser", currentUser);
        return modelAndView;
    }

//    @PostMapping("/user/userPageInfo")
//    public ModelAndView printWelcomeasd(User user) {
//        String name = SecurityContextHolder.getContext().getAuthentication().getName();
//        User byName = userRepo.findByName(name);
//        Iterable<User> list = userRepo.findAllById(Collections.singleton(byName.getId()));
//        ModelAndView modelAndView = new ModelAndView("userPageInfo");
//        modelAndView.getModelMap().addAttribute("listUsers", list);
//        return modelAndView;
//    }

    private Set<Role> getRoles(@RequestParam("role") String role) {
        Set<Role> userRoles = new HashSet<>();
        String[] split = role.split(",");
        for (String s : split) {
            userRoles.add(Role.valueOf(s));
        }
        return userRoles;
    }

//    @GetMapping("/reg")
//    private String showRegisterPage() {
//        return "reg";
//    }
//
//    @PostMapping("/reg")
//    private String showRegisterPageByAddNewUser(User user, Map<String, Object> model) {
//        User byName = userRepo.findByName(user.getName());
//        if (byName != null) {
//            model.put("message", "This isn't new User");
//            return "reg";
//        }
//        user.setUserRoles(Collections.singleton(Role.ADMIN));
//        userRepo.save(user);
//        return "redirect:/login";
//    }

}
