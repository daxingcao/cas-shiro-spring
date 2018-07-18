package com.caodaxing.service;

import java.util.List;

import com.caodaxing.entity.LoginUser;
import com.caodaxing.entity.LoginUserExample;

public interface LoginUserService {

	long countByExample(LoginUserExample example);

    int insert(LoginUser record);

    int insertSelective(LoginUser record);

    List<LoginUser> selectByExample(LoginUserExample example);

    LoginUser selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(LoginUser record);

    int updateByPrimaryKey(LoginUser record);
	
}
