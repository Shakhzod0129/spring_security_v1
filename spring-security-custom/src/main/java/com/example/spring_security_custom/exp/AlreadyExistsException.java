package com.example.spring_security_custom.exp;//package com.example.spring_security_custom.exp;

public class AlreadyExistsException extends RuntimeException{
    public AlreadyExistsException(String message){
        super(message);
    }

}
