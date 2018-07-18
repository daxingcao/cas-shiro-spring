package com.caodaxing.service;

import java.util.List;

import com.caodaxing.entity.AuthRole;
import com.caodaxing.entity.AuthRoleExample;

public interface AuthRoleService {

	long countByExample(AuthRoleExample example);

    int insert(AuthRole record);

    int insertSelective(AuthRole record);

    List<AuthRole> selectByExample(AuthRoleExample example);

    AuthRole selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(AuthRole record);

    int updateByPrimaryKey(AuthRole record);
	
}
