package main.controller;

import main.model.Role;
import main.model.User;
import main.service.ServiceUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.Set;

@RestController
@RequestMapping("/admin")
public class UserControllerRest {
    @Autowired
    private ServiceUser serviceUser;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/add")
    public User createUser(User user, @RequestParam("role") String userRoles) {
        HashSet<Role> roles = (HashSet<Role>) getRoles(userRoles);
        user.setUserRoles(roles);
        user.setPassword( passwordEncoder.encode(user.getPassword()));
        return serviceUser.save(user);
    }
//    @PostMapping("/add")
//    public User createUser(@RequestParam("name") String name,
//                           @RequestParam(value = "password", required = false) String password,
//                           @RequestParam("lastName") String lastName,
//                           @RequestParam("age") String age,
//                           @RequestParam("email") String email,
//                           @RequestParam("role") String userRoles) {
//        int ageInt = Integer.parseInt(age);
//        HashSet<Role> roles = (HashSet<Role>) getRoles(userRoles);
//        User user = new User(name, passwordEncoder.encode(password), lastName, ageInt, email, roles);
//        serviceUser.save(user);
//        User byName = serviceUser.findByName(name);
//        return byName;
//    }

    @PostMapping("/edit")
    public User update(@RequestParam("name") String name,
                       @RequestParam(value = "password", required = false) String password,
                       @RequestParam("lastName") String lastName,
                       @RequestParam("age") String age,
                       @RequestParam("email") String email,
                       @RequestParam("role") String userRoles,
                       @RequestParam("id") String idd) {
        Long id = Long.parseLong(idd);
        int ageInt = Integer.parseInt(age);
        HashSet<Role> roles = (HashSet<Role>) getRoles(userRoles);
        User byName = serviceUser.findById(id).get();
        if (!password.equals("")) {
            byName.setPassword(passwordEncoder.encode(password));
        }
        byName.setId(id);
        byName.setName(name);
        byName.setLastName(lastName);
        byName.setAge(ageInt);
        byName.setEmail(email);
        byName.setUserRoles(roles);
        serviceUser.save(byName);
        return byName;
    }


    @PostMapping("/delete")
    public HttpStatus delete(@RequestParam("id") String idd) {
        Long id = Long.parseLong(idd);
        serviceUser.deleteById(id);
        return HttpStatus.OK;
    }

    @GetMapping("/get/{id}")
    public User getUser(@PathVariable("id") String idd) {
        Long id = Long.parseLong(idd);
        User byId = serviceUser.findById(id).get();
        return byId;
    }

    private Set<Role> getRoles(@RequestParam("role") String role) {
        Set<Role> userRoles = new HashSet<>();
        String[] split = role.split(",");
        for (String s : split) {
            userRoles.add(Role.valueOf(s));
        }
        return userRoles;
    }
}
