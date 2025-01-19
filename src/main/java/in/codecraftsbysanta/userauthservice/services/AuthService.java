package in.codecraftsbysanta.userauthservice.services;

import in.codecraftsbysanta.userauthservice.exceptions.PasswordMismatchException;
import in.codecraftsbysanta.userauthservice.exceptions.UserAlreadyExistsException;
import in.codecraftsbysanta.userauthservice.exceptions.UserNotRegisteredException;
import in.codecraftsbysanta.userauthservice.models.Role;
import in.codecraftsbysanta.userauthservice.models.User;
import in.codecraftsbysanta.userauthservice.repos.UserRepo;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.MacAlgorithm;
import org.antlr.v4.runtime.misc.Pair;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;

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
    public Pair<User, String> login(String email, String password) throws UserNotRegisteredException, PasswordMismatchException{
        Optional<User> user = userRepo.findByEmail(email);
        if(user.isEmpty()){
            throw new UserNotRegisteredException("User not registered. Please signup");
        }
        String storedPassword = user.get().getPassword();

        if(!bCryptPasswordEncoder.matches(password, storedPassword)){
            throw new PasswordMismatchException("Password mismatch. Please try again");
        }

        Map<String,Object> payload = new HashMap<>();
        Long nowInMillis = System.currentTimeMillis();
        payload.put("iat",nowInMillis);
        payload.put("exp",nowInMillis+100000);
        payload.put("userId",user.get().getId());
        payload.put("iss","scaler");
        payload.put("scope",user.get().getRoles());

        MacAlgorithm algorithm = Jwts.SIG.HS256;
        SecretKey secretKey = algorithm.key().build();
        String token = Jwts.builder().claims(payload).signWith(secretKey).compact();

        return new Pair<User,String>(user.get(),token);
    }

    //validateToken(userId, token) {
    // check if token stored in db is matching with this token or not
    // whether the token has expired or not ,
    // currentTimeStamp < expiryTimeStamp
    //In order to get expiryTimeStamp, we need to parse token and get payload(claims)
    // -> get expiry.
    //}

}
