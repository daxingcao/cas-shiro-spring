package com.caodaxing.service;

import java.util.List;

import com.caodaxing.entity.Role;
import com.caodaxing.entity.RoleExample;

public interface RoleService {

	long countByExample(RoleExample example);

    int insert(Role record);

    int insertSelective(Role record);

    List<Role> selectByExample(RoleExample example);

    Role selectByPrimaryKey(Long roleId);

    int updateByPrimaryKeySelective(Role record);

    int updateByPrimaryKey(Role record);
	
}
