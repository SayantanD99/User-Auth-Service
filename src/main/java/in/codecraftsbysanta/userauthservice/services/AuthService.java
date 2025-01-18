package in.codecraftsbysanta.userauthservice.services;

import in.codecraftsbysanta.userauthservice.exceptions.PasswordMismatchException;
import in.codecraftsbysanta.userauthservice.exceptions.UserAlreadyExistsException;
import in.codecraftsbysanta.userauthservice.exceptions.UserNotRegisteredException;
import in.codecraftsbysanta.userauthservice.models.Role;
import in.codecraftsbysanta.userauthservice.models.User;

import in.codecraftsbysanta.userauthservice.repos.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;

@Service
public class AuthService implements IAuthService{

    @Autowired
    private UserRepo userRepo;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public User signUp(String email, String password) throws UserAlreadyExistsException {
        Optional<User> user = userRepo.findByEmail(email);
        if(user.isPresent()){
            throw new UserAlreadyExistsException("User already exists with email. Please login");
        }
        User newUser = new User();
        newUser.setEmail(email);
        newUser.setPassword(bCryptPasswordEncoder.encode(password));
        newUser.setCreatedAt(new Date());
        newUser.setLastUpdatedAt(new Date());

        Role role = new Role();
        role.setValue("USER");

        List<Role> roles = new ArrayList<>();
        roles.add(role);

        newUser.setRoles(roles);

        userRepo.save(newUser);

        return newUser;

    }

    @Override
    public User login(String email, String password) throws UserNotRegisteredException, PasswordMismatchException{
        Optional<User> user = userRepo.findByEmail(email);
        if(user.isPresent()){
            throw new UserNotRegisteredException("User not registered. Please signup");
        }
        String storedPassword = user.get().getPassword();

        if(!bCryptPasswordEncoder.matches(password, storedPassword)){
            throw new PasswordMismatchException("Password mismatch. Please try again");
        }

//        if(!password.equals(storedPassword)){
//            throw new PasswordMismatchException("Password mismatch. Please try again");
//        }

        return user.get();

    }

}
