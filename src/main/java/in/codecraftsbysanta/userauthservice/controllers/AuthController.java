package in.codecraftsbysanta.userauthservice.controllers;

import in.codecraftsbysanta.userauthservice.dtos.LoginRequest;
import in.codecraftsbysanta.userauthservice.dtos.SignUpRequest;
import in.codecraftsbysanta.userauthservice.dtos.UserDTO;

import in.codecraftsbysanta.userauthservice.exceptions.PasswordMismatchException;
import in.codecraftsbysanta.userauthservice.exceptions.UserAlreadyExistsException;
import in.codecraftsbysanta.userauthservice.exceptions.UserNotRegisteredException;
import in.codecraftsbysanta.userauthservice.models.User;
import in.codecraftsbysanta.userauthservice.services.IAuthService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private IAuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<UserDTO> signup(@RequestBody SignUpRequest signUpRequest){
        try{
                User user = authService.signUp(signUpRequest.getEmail(), signUpRequest.getPassword());
                return new ResponseEntity<>(from(user), HttpStatus.CREATED);
        }
        catch (UserAlreadyExistsException exception){
            return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<UserDTO> login(@RequestBody LoginRequest loginRequest){
        try{
            User user = authService.login(loginRequest.getEmail(), loginRequest.getPassword());
            return new ResponseEntity<>(from(user), HttpStatus.OK);
        }
        catch (UserNotRegisteredException exception){
            return new ResponseEntity<>(null, HttpStatus.NOT_FOUND);
        }
        catch (PasswordMismatchException exception){
            return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
        }
    }

    public UserDTO from(User user){
        UserDTO userDTO = new UserDTO();
        userDTO.setId(user.getId());
        userDTO.setEmail(user.getEmail());
        userDTO.setRoles(user.getRoles());
        return userDTO;
    }

}
