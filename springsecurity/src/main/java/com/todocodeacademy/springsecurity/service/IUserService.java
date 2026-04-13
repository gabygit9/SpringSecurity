package com.todocodeacademy.springsecurity.service;

import com.todocodeacademy.springsecurity.model.UserSec;

import java.util.List;
import java.util.Optional;

public interface IUserService {

    List<UserSec> findAll();
    Optional<UserSec> findById(Long id);
    UserSec save(UserSec user);
    void deleteById(Long id);
    UserSec update(UserSec user);
    public String encryptPassword(String password);
}
